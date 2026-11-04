import ast
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
    def test_top_level_function_definitions_are_unique(self):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        names = [
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.assertEqual(len(names), len(set(names)))

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
        self.assertEqual(result, "Analyse terminée")
        self.assertEqual(request.get_header("X-goog-api-key"), "test-secret-key")
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
        self.assertIn("détails masqués", str(raised.exception))

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

    def test_legacy_scraper_covers_all_six_product_families(self):
        self.assertEqual(
            set(legacy.PRODUITS_CIBLES),
            {
                "fortigate",
                "fortimanager",
                "fortiauthenticator",
                "fortianalyzer",
                "forticlient ems",
                "forticlient",
            },
        )

    def test_legacy_scraper_detects_versions_outside_the_manual_scope(self):
        text = (
            "FortiGate running FortiOS 7.4.13; FortiClient EMS 7.4.8; "
            "FortiAuthenticator 6.6.10; Firmware (7.6.8 / 7.4.13)"
        )
        products = legacy.detecter_produits(text)
        self.assertIn("fortiauthenticator", products)
        self.assertEqual(
            legacy.detecter_versions(text, products),
            ["6.6.10", "7.4.8", "7.4.13", "7.6.8"],
        )


    def test_legacy_scraper_recognizes_forticlient_ems_slash_alias_and_version(self):
        text = (
            "FortiGate version 7.4.12 and FortiClient/EMS version 7.4.8 "
            "are used by the connector."
        )
        products = legacy.detecter_produits(text)
        self.assertIn("forticlient ems", products)
        self.assertNotIn("forticlient", products)
        self.assertEqual(legacy.detecter_versions(text, products), ["7.4.8", "7.4.12"])

    def test_legacy_scraper_extracts_version_after_product_model(self):
        text = "FortiAnalyzer 1000F version 7.6.8 reports are sent even when empty."
        products = legacy.detecter_produits(text)
        self.assertEqual(legacy.detecter_versions(text, products), ["7.6.8"])

    def test_legacy_scraper_keeps_new_versions_by_default(self):
        item = {
            "title": "FortiGate FortiOS 7.4.13 VPN failure",
            "link": "https://community.fortinet.com/fortigate-3/vpn-failure-230001",
            "date": "",
            "summary": "VPN disconnects after upgrade.",
            "category": "",
        }
        result = legacy.filtrer_items([item])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["versions_detectees"], ["7.4.13"])


if __name__ == "__main__":
    unittest.main()
