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
        item = {"title": "DNS over TLS broken in Proxy Mode", "summary": "Issue in FortiOS version 7.6.4. IP 208.91.112.55; upgrade to 8.0.1. Upgrade path from versions 7.2.13 to 7.4.12. Example command output: DiG 9.17.12. Resolver IP 1.1.1.1."}
        exact, families = synth.extract_versions(item)
        self.assertIn("7.6.4", exact)
        self.assertIn("8.0.1", exact)
        self.assertIn("7.2.13", exact)
        self.assertIn("7.4.12", exact)
        self.assertNotIn("208.91.112", exact)
        self.assertNotIn("9.17.12", exact)
        self.assertNotIn("1.1.1", exact)
        self.assertIn("7.6", families)
        self.assertIn("8.0", families)

    def test_similar_topics_are_grouped_once(self):
        data = {"topics": [
            {"title": "FortiGate DNS over TLS broken in Proxy Mode", "summary": "FortiOS 7.6.4 DNS over TLS fails.", "url": "https://community.fortinet.com/support-forum-92/dns-dot-1", "products": ["FortiGate"], "date": "2026-10-22"},
            {"title": "DNS over TLS fails in proxy mode on FortiGate", "summary": "FortiOS version 7.6.4 has broken DNS over TLS.", "url": "https://community.fortinet.com/support-forum-92/dns-dot-2", "products": ["FortiGate"], "date": "2026-10-21"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        self.assertEqual(result["incidents"][0]["sourceCount"], 2)
        self.assertEqual(result["incidents"][0]["versionFamilies"], ["7.6"])

    def test_radius_wording_variants_are_grouped(self):
        a = {"title": "FortiGate RADIUS authentication fails after upgrade", "products": ["FortiGate"], "versionFamilies": ["7.4"]}
        b = {"title": "FortiGate RADIUS server not responding after firmware update", "products": ["FortiGate"], "versionFamilies": ["7.4"]}
        self.assertTrue(synth.looks_like_problem(a))
        self.assertTrue(synth.looks_like_problem(b))
        self.assertTrue(synth.similar(a, b))

    def test_saml_and_ssl_vpn_aliases_are_normalized(self):
        saml_a = {"title": "SAML SSO login fails", "products": ["FortiGate"], "versionFamilies": ["7.6"]}
        saml_b = {"title": "SAML single sign on failure", "products": ["FortiGate"], "versionFamilies": ["7.6"]}
        vpn_a = {"title": "SSL VPN disconnects after upgrade", "products": ["FortiGate"], "versionFamilies": ["7.4"]}
        vpn_b = {"title": "SSlVPN disconnects after firmware update", "products": ["FortiGate"], "versionFamilies": ["7.4"]}
        self.assertTrue(synth.similar(saml_a, saml_b))
        self.assertTrue(synth.similar(vpn_a, vpn_b))

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
        self.assertEqual(synth.source_type(item), "fortinet_article")
        self.assertTrue(synth.has_documented_evidence(item))
        data = {"topics": [item]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        self.assertEqual(result["incidents"][0]["status"], "Documenté par Fortinet (version identifiée)")
        self.assertEqual(result["incidents"][0]["versionFamilies"], ["7.4"])


    def test_official_articles_do_not_count_as_multiple_people(self):
        data = {"topics": [
            {"title": "VPN disconnects after upgrade", "summary": "VPN disconnects after upgrade", "url": "https://community.fortinet.com/support-forum-92/report-1", "products": ["FortiGate"], "versionFamilies": ["7.4"]},
            {"title": "VPN disconnects after upgrade", "summary": "VPN disconnects after upgrade", "url": "https://community.fortinet.com/fortigate-3/official-tip", "products": ["FortiGate"], "versionFamilies": ["7.4"]},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 0)

    def test_two_distinct_forum_reports_are_retained(self):
        data = {"topics": [
            {"title": "FortiGate DNS over TLS broken in Proxy Mode", "summary": "FortiOS 7.6.4 DNS over TLS fails.", "url": "https://community.fortinet.com/support-forum-92/dns-dot-1", "products": ["FortiGate"], "date": "2026-10-22"},
            {"title": "DNS over TLS fails in proxy mode on FortiGate", "summary": "FortiOS version 7.6.4 has broken DNS over TLS.", "url": "https://community.fortinet.com/support-forum-92/dns-dot-2", "products": ["FortiGate"], "date": "2026-10-21"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        self.assertEqual(result["incidents"][0]["forumReportCount"], 2)
        self.assertEqual(result["incidents"][0]["status"], "Récurrent — 2 discussions distinctes")



    def test_legacy_t5_url_is_a_forum_report_not_official_documentation(self):
        item = {
            "title": "FortiGate 7.4.12 VPN fails",
            "summary": "Known issue reported by one user.",
            "url": "https://community.fortinet.com/t5/FortiGate/abc",
        }
        self.assertEqual(synth.source_type(item), "forum_discussion")
        self.assertFalse(synth.has_documented_evidence(item))

if __name__ == "__main__":
    unittest.main()
