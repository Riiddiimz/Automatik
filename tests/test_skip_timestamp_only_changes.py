import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.skip_timestamp_only_changes import (
    restore_previous_if_only_timestamps_changed,
    same_published_content,
)


class SnapshotComparisonTests(unittest.TestCase):
    def community_snapshot(self):
        return {
            "generatedAt": "2026-10-26T10:00:00+00:00",
            "synthesisGeneratedAt": "2026-10-26T10:00:01+00:00",
            "aiReviewGeneratedAt": "2026-10-26T10:00:02+00:00",
            "feedUrl": "https://community.fortinet.com/feed/topics?count=500",
            "partial": False,
            "errors": [],
            "topicCount": 1,
            "topics": [{
                "id": "https://community.fortinet.com/support-forum-92/example",
                "title": "VPN disconnects",
                "summary": "VPN disconnects after upgrade.",
                "lastSeen": "2026-10-26T10:00:00+00:00",
                "firstSeen": "2026-10-20T10:00:00+00:00",
            }],
            "incidentCount": 1,
            "incidents": [{
                "id": "incident-example",
                "summary": "VPN disconnects after upgrade.",
                "lastSeen": "2026-10-21T10:00:00+00:00",
                "aiReview": {
                    "summary": "La connexion VPN se coupe après la mise à niveau.",
                    "reviewedAt": "2026-10-26T10:00:02+00:00",
                    "model": "gemini-test",
                },
            }],
        }

    def test_community_ignores_only_collection_and_review_timestamps(self):
        previous = self.community_snapshot()
        current = copy.deepcopy(previous)
        current["generatedAt"] = "2026-10-26T16:00:00+00:00"
        current["synthesisGeneratedAt"] = "2026-10-26T16:00:01+00:00"
        current["aiReviewGeneratedAt"] = "2026-10-26T16:00:02+00:00"
        current["topics"][0]["lastSeen"] = "2026-10-26T16:00:00+00:00"
        current["incidents"][0]["aiReview"]["reviewedAt"] = "2026-10-26T16:00:02+00:00"
        self.assertTrue(same_published_content(previous, current, "community"))

    def test_community_preserves_real_source_and_health_changes(self):
        previous = self.community_snapshot()
        current = copy.deepcopy(previous)
        current["topics"][0]["summary"] = "A different documented symptom."
        self.assertFalse(same_published_content(previous, current, "community"))

        current = copy.deepcopy(previous)
        current["partial"] = True
        current["errors"] = ["Flux incomplet"]
        self.assertFalse(same_published_content(previous, current, "community"))

        current = copy.deepcopy(previous)
        current["incidents"][0]["aiReview"]["summary"] = "Une reformulation différente."
        self.assertFalse(same_published_content(previous, current, "community"))

    def test_veille_ignores_generated_at_but_not_new_data_or_errors(self):
        previous = {
            "generatedAt": "2026-10-26T10:00:00+00:00",
            "fortinet": [{"title": "Advisory", "url": "https://example.test/advisory"}],
            "cyber": [],
            "kev": [{"cveID": "CVE-2026-1234"}],
            "errors": [],
        }
        current = copy.deepcopy(previous)
        current["generatedAt"] = "2026-10-26T16:00:00+00:00"
        self.assertTrue(same_published_content(previous, current, "veille"))

        current["errors"] = ["CERT-FR indisponible"]
        self.assertFalse(same_published_content(previous, current, "veille"))

        current = copy.deepcopy(previous)
        current["kev"].append({"cveID": "CVE-2026-5678"})
        self.assertFalse(same_published_content(previous, current, "veille"))

    def test_timestamp_only_change_restores_exact_previous_snapshot(self):
        previous = self.community_snapshot()
        previous_text = json.dumps(previous, ensure_ascii=False, indent=2) + "\n"
        current = copy.deepcopy(previous)
        current["generatedAt"] = "2026-10-26T16:00:00+00:00"
        current["topics"][0]["lastSeen"] = "2026-10-26T16:00:00+00:00"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "community.json"
            target.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            restored = restore_previous_if_only_timestamps_changed(target, previous_text, "community")
            self.assertTrue(restored)
            self.assertEqual(target.read_text(encoding="utf-8"), previous_text)

    def test_content_change_does_not_restore_previous_snapshot(self):
        previous = self.community_snapshot()
        previous_text = json.dumps(previous, ensure_ascii=False, indent=2) + "\n"
        current = copy.deepcopy(previous)
        current["topics"][0]["summary"] = "A new symptom."
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "community.json"
            target.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            restored = restore_previous_if_only_timestamps_changed(target, previous_text, "community")
            self.assertFalse(restored)
            self.assertNotEqual(target.read_text(encoding="utf-8"), previous_text)


if __name__ == "__main__":
    unittest.main()
