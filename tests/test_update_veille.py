import importlib.util
import json
import os
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "update_veille.py"
SPEC = importlib.util.spec_from_file_location("update_veille", MODULE_PATH)
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


class FeedParserTests(unittest.TestCase):
    def test_parse_rss_extracts_title_link_and_summary(self):
        payload = b"""<?xml version="1.0"?><rss version="2.0"><channel><item><title>Test advisory</title><link>https://example.com/advisory</link><pubDate>Wed, 21 Oct 2026 08:00:00 GMT</pubDate><description><![CDATA[<p>Important <b>update</b></p>]]></description></item></channel></rss>"""
        items = updater.parse_rss(payload, "Example", "Test")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Test advisory")
        self.assertEqual(items[0]["url"], "https://example.com/advisory")
        self.assertEqual(items[0]["summary"], "Important update")
        self.assertIsNotNone(items[0]["date"])

    def test_parse_atom_feed(self):
        payload = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Atom advisory</title><link href="https://example.com/atom"/><updated>2026-10-21T08:00:00Z</updated><summary>Summary</summary></entry></feed>"""
        items = updater.parse_rss(payload, "Example", "Test")
        self.assertEqual(items[0]["title"], "Atom advisory")
        self.assertEqual(items[0]["url"], "https://example.com/atom")

    def test_parse_cisa_csaf_feed_index(self):
        payload = json.dumps({
            "feed": {
                "entry": [{
                    "id": "VA-26-001-01",
                    "title": "Example CISA advisory",
                    "published": "2026-10-22T17:14:18Z",
                    "content": {"src": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/example.json"}
                }]
            }
        }).encode()
        items = updater.parse_rss(payload, "CISA Cybersecurity Advisories", "CISA Cybersecurity Advisories")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Example CISA advisory")
        self.assertIn("raw.githubusercontent.com/cisagov/CSAF", items[0]["url"])
        self.assertEqual(items[0]["date"], "2026-10-22T17:14:18+00:00")
        self.assertIn("CSAF", items[0]["summary"])

    def test_naive_iso_dates_are_interpreted_as_utc_independent_of_runner_timezone(self):
        previous_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "Etc/GMT+5"
            time.tzset()
            self.assertEqual(
                updater.parse_date("2026-10-21T08:00:00"),
                "2026-10-21T08:00:00+00:00",
            )
        finally:
            if previous_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous_tz
            time.tzset()

    def test_invalid_xml_raises_parse_error(self):
        with self.assertRaises(Exception):
            updater.parse_rss(b"<rss><channel>", "Example", "Test")


class UpdatePreservationTests(unittest.TestCase):
    def test_failed_feed_keeps_previous_items_and_updates_other_sources(self):
        old = {
            "generatedAt": "2026-10-20T08:00:00+00:00",
            "fortinet": [],
            "cyber": [
                {"source": "FortiGuard Outbreak Alerts", "title": "Last known alert", "url": "https://example.com/old"},
                {"source": "CISA Cybersecurity Advisories", "title": "Old CISA advisory", "url": "https://example.com/cisa-old"}
            ],
            "kev": [{"cveID": "CVE-2026-0001", "shortDescription": "Previously known vulnerability"}],
            "errors": []
        }
        rss = b"""<rss version="2.0"><channel><item><title>Fresh PSIRT</title><link>https://example.com/psirt</link><description>Fresh item</description></item></channel></rss>"""
        cisa_rss = b"""<rss version="2.0"><channel><item><title>Fresh CISA advisory</title><link>https://example.com/cisa-new</link><description>Fresh CISA item</description></item></channel></rss>"""
        ciso_rss = b"""<rss version="2.0"><channel><item><title>Fortinet security hardening release</title><link>https://www.fortinet.com/blog/ciso-collective/fortinet-releases-security-hardening-release-for-multiple-products</link><description>Fixed FortiOS and FortiManager versions</description></item></channel></rss>"""
        cert_fr_rss = b"""<rss version="2.0"><channel><item><title>Fresh CERT-FR advisory</title><link>https://www.cert.ssi.gouv.fr/alerte/new</link><description>Fresh CERT-FR item</description></item></channel></rss>"""
        kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0002", "shortDescription": "New vulnerability"}]}).encode()
        responses = [rss, urllib.error.URLError("temporary outage"), cisa_rss, cert_fr_rss, ciso_rss, kev]

        with tempfile.TemporaryDirectory() as directory:
            out_path = Path(directory) / "veille.json"
            out_path.write_text(json.dumps(old), encoding="utf-8")
            with patch.object(updater, "OUT", out_path), patch.object(updater, "fetch", side_effect=responses):
                updater.main()
            result = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(result["fortinet"][0]["title"], "Fresh PSIRT")
        self.assertIn("Last known alert", [item["title"] for item in result["cyber"]])
        self.assertIn("Fresh CISA advisory", [item["title"] for item in result["cyber"]])
        self.assertIn("Fortinet security hardening release", [item["title"] for item in result["cyber"]])
        self.assertEqual(result["kev"][0]["cveID"], "CVE-2026-0002")
        self.assertTrue(any("FortiGuard Outbreak Alerts" in error for error in result["errors"]))

    def test_cisa_csaf_feeds_replace_blocked_rss_and_preserve_history(self):
        psirt = b"""<rss version="2.0"><channel><item><title>PSIRT</title><link>https://example.com/psirt</link></item></channel></rss>"""
        outbreak = b"""<rss version="2.0"><channel><item><title>Outbreak</title><link>https://example.com/outbreak</link></item></channel></rss>"""
        cisa_it = json.dumps({"feed": {"entry": [{
            "id": "VA-26-001-01", "title": "Fresh CISA IT advisory",
            "published": "2026-10-22T17:14:18Z",
            "content": {"src": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/example.json"}
        }]}}).encode()
        cisa_ot = json.dumps({"feed": {"entry": [{
            "id": "ICS-26-001-01", "title": "Fresh CISA ICS advisory",
            "published": "2026-10-22T06:00:00Z",
            "content": {"src": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/example.json"}
        }]}}).encode()
        cert_fr = b"""<rss version="2.0"><channel><item><title>CERT-FR security advisory</title><link>https://www.cert.ssi.gouv.fr/alerte/example</link></item></channel></rss>"""
        ciso_rss = b"""<rss version="2.0"><channel><item><title>Fortinet security hardening release</title><link>https://www.fortinet.com/blog/ciso-collective/fortinet-releases-security-hardening-release-for-multiple-products</link><description>Fixed FortiOS and FortiManager versions</description></item></channel></rss>"""
        kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0100"}]}).encode()
        responses = [psirt, outbreak, cisa_it, cisa_ot, cert_fr, ciso_rss, kev]
        old = {
            "fortinet": [],
            "cyber": [{
                "source": "CISA Cybersecurity Advisories",
                "title": "Previously collected CISA advisory",
                "url": "https://example.com/cisa-old"
            }],
            "kev": [],
            "errors": []
        }
        with tempfile.TemporaryDirectory() as directory:
            out_path = Path(directory) / "veille.json"
            out_path.write_text(json.dumps(old), encoding="utf-8")
            with patch.object(updater, "OUT", out_path), patch.object(updater, "fetch", side_effect=responses) as mock_fetch:
                updater.main()
            result = json.loads(out_path.read_text(encoding="utf-8"))
        titles = [item["title"] for item in result["cyber"]]
        self.assertIn("Previously collected CISA advisory", titles)
        self.assertIn("Fresh CISA IT advisory", titles)
        self.assertIn("Fresh CISA ICS advisory", titles)
        self.assertIn("CERT-FR security advisory", titles)
        self.assertIn("Fortinet security hardening release", titles)
        self.assertEqual(mock_fetch.call_args_list[2].args[0], updater.FEEDS[2][2])
        self.assertEqual(mock_fetch.call_args_list[3].args[0], updater.FEEDS[3][2])
        self.assertEqual(mock_fetch.call_args_list[4].args[0], "https://www.cert.ssi.gouv.fr/feed/")
        self.assertFalse(any("CISA Cybersecurity Advisories" in error for error in result["errors"]))

    def test_failed_kev_keeps_previous_catalogue(self):
        old = {
            "fortinet": [{"source": "FortiGuard PSIRT", "title": "Existing", "url": "https://example.com"}],
            "cyber": [],
            "kev": [{"cveID": "CVE-2026-0009"}]
        }
        rss = b"""<rss version="2.0"><channel><item><title>PSIRT</title><link>https://example.com/psirt</link></item></channel></rss>"""
        outbreak = b"""<rss version="2.0"><channel><item><title>Alert</title><link>https://example.com/alert</link></item></channel></rss>"""
        cisa = b"""<rss version="2.0"><channel><item><title>Advisory</title><link>https://example.com/advisory</link></item></channel></rss>"""
        ciso_rss = b"""<rss version="2.0"><channel><item><title>Fortinet security hardening release</title><link>https://www.fortinet.com/blog/ciso-collective/fortinet-releases-security-hardening-release-for-multiple-products</link><description>Fixed FortiOS and FortiManager versions</description></item></channel></rss>"""
        cert_fr = b"""<rss version="2.0"><channel><item><title>CERT-FR advisory</title><link>https://www.cert.ssi.gouv.fr/alerte/cert</link></item></channel></rss>"""
        responses = [rss, outbreak, cisa, cert_fr, ciso_rss, urllib.error.URLError("temporary outage")]
        with tempfile.TemporaryDirectory() as directory:
            out_path = Path(directory) / "veille.json"
            out_path.write_text(json.dumps(old), encoding="utf-8")
            with patch.object(updater, "OUT", out_path), patch.object(updater, "fetch", side_effect=responses):
                updater.main()
            result = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(result["kev"][0]["cveID"], "CVE-2026-0009")



    def test_failed_ciso_feed_preserves_previous_ciso_items(self):
        old = {
            "fortinet": [],
            "cyber": [{
                "source": "Fortinet CISO Collective",
                "title": "Old Fortinet hardening notice",
                "url": "https://www.fortinet.com/blog/ciso-collective/old-notice"
            }],
            "kev": [],
            "errors": []
        }
        psirt = b"""<rss version="2.0"><channel><item><title>PSIRT</title><link>https://example.com/psirt</link></item></channel></rss>"""
        outbreak = b"""<rss version="2.0"><channel><item><title>Outbreak</title><link>https://example.com/outbreak</link></item></channel></rss>"""
        cisa = b"""<rss version="2.0"><channel><item><title>Advisory</title><link>https://example.com/advisory</link></item></channel></rss>"""
        cert_fr = b"""<rss version="2.0"><channel><item><title>CERT-FR advisory</title><link>https://www.cert.ssi.gouv.fr/alerte/cert</link></item></channel></rss>"""
        kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0199"}]}).encode()
        responses = [psirt, outbreak, cisa, cert_fr, urllib.error.URLError("temporary outage"), kev]
        with tempfile.TemporaryDirectory() as directory:
            out_path = Path(directory) / "veille.json"
            out_path.write_text(json.dumps(old), encoding="utf-8")
            with patch.object(updater, "OUT", out_path), patch.object(updater, "fetch", side_effect=responses):
                updater.main()
            result = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertIn("Old Fortinet hardening notice", [item["title"] for item in result["cyber"]])
        self.assertTrue(any("Fortinet CISO Collective" in error for error in result["errors"]))

if __name__ == "__main__":
    unittest.main()
