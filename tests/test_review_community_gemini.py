import unittest

from scripts.review_community_gemini import (
    apply_reviews,
    build_review_input,
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


if __name__ == "__main__":
    unittest.main()
