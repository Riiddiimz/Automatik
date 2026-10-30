import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "scrap_commu_copie.py"
SPEC = importlib.util.spec_from_file_location("scrap_commu_copie", MODULE_PATH)
legacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(legacy)


class LegacyCommunityScraperSecurityTests(unittest.TestCase):
    def test_gemini_api_key_is_sent_in_header_not_url(self):
        payload = {
            "candidates": [{
                "content": {"parts": [{"text": "Analyse terminée"}]},
                "finishReason": "STOP",
            }]
        }
        response = io.BytesIO(json.dumps(payload).encode("utf-8"))
        with patch.object(legacy.urllib.request, "urlopen", return_value=response) as urlopen:
            result = legacy.appeler_gemini("test-secret-key", "prompt de test")

        request = urlopen.call_args.args[0]
        headers = {name.lower(): value for name, value in request.header_items()}
        self.assertEqual(result, "Analyse terminée")
        self.assertEqual(headers.get("x-goog-api-key"), "test-secret-key")
        self.assertNotIn("test-secret-key", request.full_url)
        self.assertNotIn("?key=", request.full_url)

    def test_gemini_http_error_does_not_echo_api_key(self):
        api_key = "test-secret-key"
        error = urllib.error.HTTPError(
            "https://generativelanguage.googleapis.com/test",
            400,
            "Bad Request",
            {},
            io.BytesIO(api_key.encode("utf-8")),
        )
        with patch.object(legacy.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                legacy.appeler_gemini(api_key, "prompt de test")
        self.assertNotIn(api_key, str(raised.exception))
        self.assertIn("[redacted]", str(raised.exception))

    def test_main_reads_api_key_from_environment_without_cli_argument(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-secret-key"}):
            with patch.object(legacy.sys, "argv", ["scrap_commu_copie.py"]):
                with patch.object(legacy, "afficher_menu") as show_menu:
                    with patch("builtins.input", return_value="4"):
                        legacy.main()
        show_menu.assert_called_once()

    def test_main_rejects_api_key_as_cli_argument(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-secret-key"}):
            with patch.object(legacy.sys, "argv", ["scrap_commu_copie.py", "test-secret-key"]):
                with contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        legacy.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertNotIn("test-secret-key", output.getvalue())
        self.assertIn("GEMINI_API_KEY", output.getvalue())

    def test_main_requires_environment_variable(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            with patch.object(legacy.sys, "argv", ["scrap_commu_copie.py"]):
                with contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        legacy.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("GEMINI_API_KEY", output.getvalue())


if __name__ == "__main__":
    unittest.main()
