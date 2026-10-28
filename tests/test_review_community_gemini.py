import json
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import review_community_gemini as reviewer
from scripts.review_community_gemini import (
    apply_reviews,
    build_review_input,
    parse_gemini_json,
    validate_reviews,
)


class GeminiReviewTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "incidents": [{
                "id": "incident-test123",
                "title": "VPN stops after upgrade",
                "summary": "Original deterministic summary",
                "symptom": "Original symptom",
                "impact": "",
                "solution": "",
                "products": ["FortiGate"],
                "versions": ["7.4.12"],
                "fixVersions": [],
                "sources": [{
                    "title": "Forum report",
                    "summary": "The VPN stopped after an upgrade.",
                    "url": "https://community.fortinet.com/example",
                    "sourceType": "forum_discussion",
                }],
            }]
        }

    def test_build_review_input_keeps_evidence_and_limits_sources(self):
        items = build_review_input(self.data)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "incident-test123")
        self.assertEqual(items[0]["versions"], ["7.4.12"])
        self.assertEqual(items[0]["sources"][0]["url"], "https://community.fortinet.com/example")

    def test_parse_gemini_json_accepts_markdown_fence(self):
        fenced = chr(96) * 3 + 'json\n[{"id":"a"}]\n' + chr(96) * 3
        self.assertEqual(parse_gemini_json(fenced), [{"id": "a"}])

    def test_parse_gemini_json_accepts_surrounding_text(self):
        self.assertEqual(parse_gemini_json('Resultat : [{"id":"a"}] fin'), [{"id": "a"}])

    def test_validate_reviews_requires_exact_ids_and_string_fields(self):
        payload = [{
            "id": "incident-test123",
            "summary": "Résumé reformulé",
            "symptom": "Symptôme reformulé",
            "impact": "",
            "solution": "",
            "reviewNote": "Source communautaire, non officielle.",
        }]
        result = validate_reviews({"incident-test123"}, payload)
        self.assertEqual(result["incident-test123"]["summary"], "Résumé reformulé")

    def test_validate_reviews_rejects_unknown_ids(self):
        with self.assertRaises(ValueError):
            validate_reviews({"incident-test123"}, [{
                "id": "invented-id", "summary": "", "symptom": "",
                "impact": "", "solution": "", "reviewNote": "",
            }])

    def test_validate_reviews_rejects_missing_incidents(self):
        with self.assertRaises(ValueError):
            validate_reviews({"incident-test123", "incident-second"}, [{
                "id": "incident-test123", "summary": "", "symptom": "",
                "impact": "", "solution": "", "reviewNote": "",
            }])

    def test_apply_reviews_keeps_authoritative_fields_unchanged(self):
        original_versions = list(self.data["incidents"][0]["versions"])
        original_solution = self.data["incidents"][0]["solution"]
        review = {
            "incident-test123": {
                "summary": "Résumé IA",
                "symptom": "Symptôme IA",
                "impact": "",
                "solution": "",
                "reviewNote": "À vérifier dans les sources.",
            }
        }
        apply_reviews(self.data, review, "2026-10-26T10:00:00+00:00")
        incident = self.data["incidents"][0]
        self.assertEqual(incident["versions"], original_versions)
        self.assertEqual(incident["solution"], original_solution)
        self.assertEqual(incident["aiReview"]["summary"], "Résumé IA")
        self.assertEqual(incident["aiReview"]["label"], "Relecture IA — à vérifier avec les sources")


    def test_missing_api_key_records_skipped_status_and_keeps_existing_review(self):
        data = json.loads(json.dumps(self.data))
        data["incidents"][0]["aiReview"] = {
            "summary": "Ancienne reformulation",
            "reviewedAt": "2026-10-26T10:00:00+00:00",
            "model": "gemini-3.5-flash-lite",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with patch.object(reviewer, "DATA", path), patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
                self.assertEqual(reviewer.main(), 0)
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(saved["aiReviewStatus"], "skipped")
        self.assertIn("GEMINI_API_KEY absente", saved["aiReviewMessage"])
        self.assertEqual(saved["incidents"][0]["aiReview"]["summary"], "Ancienne reformulation")

    def test_api_error_records_failure_without_disclosing_diagnostic_or_erasing_review(self):
        data = json.loads(json.dumps(self.data))
        data["incidents"][0]["aiReview"] = {
            "summary": "Reformulation toujours valide",
            "reviewedAt": "2026-10-26T10:00:00+00:00",
            "model": "gemini-3.5-flash-lite",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with (
                patch.object(reviewer, "DATA", path),
                patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}),
                patch.object(reviewer, "request_gemini", side_effect=RuntimeError("sensitive diagnostic")),
            ):
                self.assertEqual(reviewer.main(), 0)
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(saved["aiReviewStatus"], "error")
        self.assertNotIn("sensitive diagnostic", saved["aiReviewMessage"])
        self.assertEqual(saved["incidents"][0]["aiReview"]["summary"], "Reformulation toujours valide")



    def test_review_batch_splits_when_model_json_is_truncated(self):
        batch = [{"id": f"incident-{index}"} for index in range(4)]
        calls = []

        def fake_request(api_key, items):
            calls.append([item["id"] for item in items])
            if len(items) > 2:
                raise reviewer.GeminiOutputJSONError("truncated")
            return [{"id": item["id"]} for item in items]

        with patch.object(reviewer, "request_gemini", side_effect=fake_request):
            result = reviewer.review_batch("test-key", batch)

        self.assertEqual(set(result), {item["id"] for item in batch})
        self.assertEqual(calls[0], [item["id"] for item in batch])
        self.assertEqual(len(calls), 3)

    def test_request_gemini_wraps_malformed_model_json(self):
        envelope = {
            "candidates": [{
                "content": {"parts": [{"text": '[{"id":"incident-test123"'}]}
            }]
        }
        response = io.BytesIO(json.dumps(envelope).encode("utf-8"))
        with patch.object(reviewer.urllib.request, "urlopen", return_value=response):
            with self.assertRaises(reviewer.GeminiOutputJSONError):
                reviewer.request_gemini("test-key", [{"id": "incident-test123"}])


if __name__ == "__main__":
    unittest.main()
