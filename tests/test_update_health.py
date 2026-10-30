"""Regression tests for the collection health status published to the site."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "update_health.py"
SPEC = importlib.util.spec_from_file_location("update_health", MODULE_PATH)
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)


class UpdateHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.source_files = {
            "veille": root / "veille.json",
            "community": root / "community.json",
        }
        self.health_files = {
            "veille": root / "health-veille.json",
            "community": root / "health-community.json",
        }
        self.run_url = "https://github.com/Riiddiimz/Automatik/actions/runs/123"

    def write_json(self, path, payload):
        path.write_text(json.dumps(payload), encoding="utf-8")

    def run_health(self, workflow_status, dataset, existing=None, source="veille", raw=False):
        source_path = self.source_files[source]
        if raw:
            source_path.write_text(str(dataset), encoding="utf-8")
        else:
            self.write_json(source_path, dataset)
        if existing is not None:
            self.write_json(self.health_files[source], existing)

        with (
            patch.dict(health.SOURCE_FILES, self.source_files, clear=True),
            patch.dict(health.HEALTH_FILES, self.health_files, clear=True),
            patch.dict(os.environ, {
                "WORKFLOW_STATUS": workflow_status,
                "RUN_URL": self.run_url,
            }),
            patch.object(sys, "argv", ["update_health.py", source]),
        ):
            health.main()

        return json.loads(self.health_files[source].read_text(encoding="utf-8"))

    def test_success_records_current_check_as_last_complete_success(self):
        result = self.run_health("success", {"fortinet": [], "cyber": [], "kev": [], "partial": False, "errors": []})

        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["checkedAt"])
        self.assertEqual(result["lastSuccessAt"], result["checkedAt"])
        self.assertEqual(result["runUrl"], self.run_url)

    def test_partial_collection_preserves_previous_complete_success(self):
        previous_success = "2026-10-20T10:00:00+00:00"
        result = self.run_health(
            "success",
            {"fortinet": [], "cyber": [], "kev": [], "partial": True, "errors": ["Le flux public est incomplet."]},
            {
                "status": "ok",
                "lastSuccessAt": previous_success,
                "checkedAt": previous_success,
            },
        )

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["lastSuccessAt"], previous_success)
        self.assertIn("flux public est incomplet", result["message"])
        self.assertEqual(result["runUrl"], self.run_url)

    def test_failed_workflow_never_marks_stale_data_as_successful(self):
        previous_success = "2026-10-20T10:00:00+00:00"
        result = self.run_health(
            "failure",
            {"fortinet": [], "cyber": [], "kev": [], "partial": False, "errors": []},
            {
                "status": "ok",
                "lastSuccessAt": previous_success,
                "checkedAt": previous_success,
            },
        )

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["lastSuccessAt"], previous_success)
        self.assertIn("a échoué", result["message"])

    def test_clean_run_recovers_from_previous_error(self):
        previous_success = "2026-10-20T10:00:00+00:00"
        result = self.run_health(
            "success",
            {"fortinet": [], "cyber": [], "kev": [], "partial": False, "errors": []},
            {
                "status": "error",
                "lastSuccessAt": previous_success,
                "checkedAt": previous_success,
            },
        )

        self.assertEqual(result["status"], "ok")
        self.assertNotEqual(result["lastSuccessAt"], previous_success)
        self.assertEqual(result["lastSuccessAt"], result["checkedAt"])


    def test_success_with_invalid_dataset_schema_is_not_marked_ok(self):
        result = self.run_health(
            "success",
            {"fortinet": [], "cyber": [], "partial": False, "errors": []},
        )

        self.assertEqual(result["status"], "error")
        self.assertIn("Structure invalide", result["message"])
        self.assertNotIn("lastSuccessAt", result)

    def test_success_with_invalid_json_is_not_marked_ok(self):
        result = self.run_health("success", "{invalid json", raw=True)

        self.assertEqual(result["status"], "error")
        self.assertIn("absent, invalide", result["message"])
        self.assertNotIn("lastSuccessAt", result)

    def test_community_dataset_requires_topics_and_incidents(self):
        result = self.run_health(
            "success",
            {"topics": [], "partial": False, "errors": []},
            source="community",
        )

        self.assertEqual(result["status"], "error")
        self.assertIn("incidents", result["message"])
        self.assertNotIn("lastSuccessAt", result)

    def test_unknown_source_is_rejected(self):
        with patch.object(sys, "argv", ["update_health.py", "unknown"]):
            with self.assertRaises(SystemExit):
                health.main()


if __name__ == "__main__":
    unittest.main()
