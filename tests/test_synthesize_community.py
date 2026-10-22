import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "synthesize_community.py"
SPEC = importlib.util.spec_from_file_location("synthesize_community", MODULE_PATH)
synth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(synth)


class CommunitySynthesisTests(unittest.TestCase):
    def test_versions_ignore_ip_addresses_and_keep_major_minor_family(self):
        item = {"title": "DNS over TLS broken in Proxy Mode", "summary": "Issue in FortiOS version 7.6.4. IP 208.91.112.55; upgrade to 8.0.1."}
        exact, families = synth.extract_versions(item)
        self.assertIn("7.6.4", exact)
        self.assertIn("8.0.1", exact)
        self.assertNotIn("208.91.112", exact)
        self.assertIn("7.6", families)
        self.assertIn("8.0", families)

    def test_similar_topics_are_grouped_once(self):
        data = {"topics": [
            {"title": "FortiGate DNS over TLS broken in Proxy Mode", "summary": "FortiOS 7.6.4 DNS over TLS fails.", "url": "https://community.fortinet.com/a", "products": ["FortiGate"], "date": "2026-10-22"},
            {"title": "DNS over TLS fails in proxy mode on FortiGate", "summary": "FortiOS version 7.6.4 has broken DNS over TLS.", "url": "https://community.fortinet.com/b", "products": ["FortiGate"], "date": "2026-10-21"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        self.assertEqual(result["incidents"][0]["sourceCount"], 2)
        self.assertEqual(result["incidents"][0]["versionFamilies"], ["7.6"])

    def test_unrelated_products_are_not_merged(self):
        a = {"title": "FortiGate VPN disconnects", "summary": "VPN disconnects after upgrade", "products": ["FortiGate"], "versionFamilies": ["7.4"]}
        b = {"title": "FortiManager VPN disconnects", "summary": "VPN disconnects after upgrade", "products": ["FortiManager"], "versionFamilies": ["7.4"]}
        self.assertFalse(synth.similar(a, b))


    def test_single_unconfirmed_user_report_is_excluded(self):
        data = {"topics": [
            {"title": "FortiGate VPN disconnects after upgrade", "summary": "VPN disconnects on my device.", "url": "https://community.fortinet.com/support-forum-92/one-report", "products": ["FortiGate"], "date": "2026-10-22"}
        ]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 0)

    def test_official_version_scoped_behavior_change_is_included(self):
        item = {
            "title": "Proxy-related features no longer supported on low-memory FortiGate models",
            "summary": "Starting with FortiOS version 7.4.4, proxy-related features are no longer supported on FortiGate models with 2 GB RAM.",
            "url": "https://community.fortinet.com/fortigate-3/proxy-related-features",
            "products": ["FortiGate"],
        }
        self.assertTrue(synth.is_official_article(item))
        self.assertTrue(synth.has_documented_evidence(item))
        data = {"topics": [item]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        self.assertEqual(result["incidents"][0]["status"], "Documenté par Fortinet")
        self.assertEqual(result["incidents"][0]["versionFamilies"], ["7.4"])


if __name__ == "__main__":
    unittest.main()
