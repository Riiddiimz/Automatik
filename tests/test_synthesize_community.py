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

    def test_unrelated_dotted_numbers_are_not_misread_as_firmware_versions(self):
        item = {
            "title": "CVE-2026-106175 record lists FortiPAM, FortiSASE and FortiOS/FortiProxy 7.0 as affected",
            "summary": (
                "The CVE record lists FortiPAM 1.0.0, FortiSASE 25.4 and FortiProxy 7.0.19, "
                "while FortiOS 7.6.8 is also mentioned. A Python example uses 3.11.8. "
                "Upgrade path from versions 7.2.13 to 7.4.12. "
                "After upgrading FortiGate from FortiOS v7.6.7 to v7.6.8, the keytab is removed."
            ),
        }
        exact, _ = synth.extract_versions(item)
        self.assertIn("7.6.8", exact)
        self.assertIn("7.6.7", exact)
        self.assertIn("7.2.13", exact)
        self.assertIn("7.4.12", exact)
        self.assertNotIn("1.0.0", exact)
        self.assertNotIn("25.4", exact)
        self.assertNotIn("7.0.19", exact)
        self.assertNotIn("3.11.8", exact)

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

    def test_ap_and_wifi_reports_after_same_upgrade_are_grouped(self):
        data = {"topics": [
            {
                "title": "After upgrade to 7.4.13 many AP are not connected",
                "summary": "After upgrading to 7.4.13, many APs are no longer connecting to the firewall. A small number are connected, but most are not.",
                "url": "https://community.fortinet.com/support-forum-92/after-upgrade-to-7-4-13-many-ap-are-not-connected-230800",
                "products": ["FortiGate", "FortiAP"],
                "date": "2026-10-23T08:00:00+00:00",
            },
            {
                "title": "Some Devices Unable to Connect to Wi-Fi After Upgrading to 7.4.13",
                "summary": "Some client devices cannot connect to Wi-Fi after upgrading our FortiGate 101F and FortiAP 231F environment to FortiOS 7.4.13.",
                "url": "https://community.fortinet.com/support-forum-92/some-devices-unable-to-connect-to-wi-fi-after-upgrading-to-7-4-13-230816",
                "products": ["FortiGate", "FortiAP"],
                "date": "2026-10-23T09:44:13+00:00",
            },
        ]}
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize(data, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        self.assertEqual(result["incidents"][0]["forumReportCount"], 2)
        self.assertEqual(result["incidents"][0]["sourceCount"], 2)
        self.assertEqual(result["incidents"][0]["versionFamilies"], ["7.4"])
        self.assertEqual(result["incidents"][0]["products"], ["FortiAP", "FortiGate"])

    def test_conflicting_inspection_modes_are_not_merged(self):
        proxy = {
            "title": "DNS over TLS broken in Proxy Mode",
            "summary": "DescriptionDNS filtering fails in proxy mode. ScopeFortiGate. SolutionKnown issue affects proxy mode.",
            "url": "https://community.fortinet.com/fortigate-3/dns-over-tls-proxy-mode",
        }
        flow = {
            "title": "DNS over TLS and DNS over HTTPS version 2 broken in Flow Mode",
            "summary": "DescriptionDNS filtering fails in flow mode. ScopeFortiGate. SolutionThe IPS engine does not recognize port 853.",
            "url": "https://community.fortinet.com/fortigate-3/dns-over-tls-flow-mode",
        }

        self.assertFalse(synth.similar(proxy, flow))
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize({"topics": [proxy, flow]}, Path(directory) / "community.json")

        self.assertEqual(result["incidentCount"], 2)
        self.assertEqual(
            {incident["title"] for incident in result["incidents"]},
            {proxy["title"], flow["title"]},
        )
        self.assertTrue(all(incident["sourceCount"] == 1 for incident in result["incidents"]))

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

    def test_password_policy_wording_variants_are_grouped(self):
        a = {"title": "FortiGate password policy failure", "products": ["FortiGate"], "versionFamilies": ["7.4"]}
        b = {"title": "FortiGate password complexity policy not working", "products": ["FortiGate"], "versionFamilies": ["7.4"]}
        self.assertTrue(synth.similar(a, b))

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


    def test_official_scoped_issue_excludes_versions_marked_unaffected(self):
        item = {
            "title": "Administrator SSO authentication fails after upgrade to FortiOS 7.6.8",
            "summary": (
                "DescriptionAfter upgrade to FortiOS 7.6.8, administrator SSO authentication fails. "
                "ScopeFortiOS 7.6.8. SolutionAfter upgrade, administrator SSO will fail. "
                "Confirmed not affected: VPN user SSO authentication. Other FortiOS versions including "
                "FortiOS 7.2.14, 7.4.13, 7.6.7 and 8.0.2. A Python example uses 3.11.8."
            ),
            "url": "https://community.fortinet.com/fortigate-3/administrator-sso-authentication-fails-after-upgrade-to-fortios-7-6-8-230826",
        }
        self.assertEqual(synth.extract_versions(item), (["7.6.8"], ["7.6"]))
        self.assertTrue(synth.has_documented_evidence(item))
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize({"topics": [item]}, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        self.assertEqual(result["incidents"][0]["versions"], ["7.6.8"])
        self.assertEqual(result["incidents"][0]["versionFamilies"], ["7.6"])


    def test_official_scoped_issue_without_version_is_published_as_unknown(self):
        item = {
            "title": "Troubleshooting Tip: LDAP search 'Timed out' in 5 seconds, ignoring timeout settings",
            "summary": (
                "DescriptionThis article describes a known issue where an LDAP search fails within five seconds. "
                "ScopeFortiAuthenticator, LDAP, FSSO. "
                "SolutionCollect the LDAP debug logs and open a support case if the timeout persists."
            ),
            "url": "https://community.fortinet.com/fortiauthenticator-8/troubleshooting-tip-ldap-search-timed-out-in-5-seconds-ignoring-timeout-settings-230479",
        }
        self.assertEqual(synth.extract_versions(item), ([], []))
        self.assertTrue(synth.has_documented_evidence(item))
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize({"topics": [item]}, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        incident = result["incidents"][0]
        self.assertEqual(incident["products"], ["FortiAuthenticator"])
        self.assertEqual(incident["versions"], [])
        self.assertEqual(incident["versionFamilies"], [])
        self.assertEqual(incident["status"], "Documenté par Fortinet (version non précisée)")


    def test_fixed_version_is_separate_from_affected_versions(self):
        item = {
            "title": "Administrator SSO authentication fails after upgrade to FortiOS 7.6.8",
            "summary": (
                "DescriptionAfter upgrade to FortiOS 7.6.8, administrator SSO authentication fails. "
                "ScopeFortiOS 7.6.8. "
                "SolutionThe issue is under investigation and scheduled for fix in FortiOS 7.6.9."
            ),
            "url": "https://community.fortinet.com/fortigate-3/administrator-sso-authentication-fails-after-upgrade-to-fortios-7-6-8-230826",
        }
        self.assertEqual(synth.extract_versions(item), (["7.6.8"], ["7.6"]))
        self.assertEqual(synth.extract_fixed_versions(item), ["7.6.9"])
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize({"topics": [item]}, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 1)
        incident = result["incidents"][0]
        self.assertEqual(incident["versions"], ["7.6.8"])
        self.assertEqual(incident["versionFamilies"], ["7.6"])
        self.assertEqual(incident["fixVersions"], ["7.6.9"])
        self.assertIn("scheduled for fix", incident["solution"])

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


    def test_platform_versions_and_elapsed_time_are_not_firmware_versions(self):
        item = {
            "title": "FortiClient VPN 7.4.11 on iPadOS 26.7.1 fails",
            "summary": "FortiOS 7.4.12 also fails. Environment: macOS Tahoe 26.7.1. Tunnel drops within ~0.7 seconds.",
        }
        exact, families = synth.extract_versions(item)
        self.assertEqual(exact, ["7.4.11", "7.4.12"])
        self.assertEqual(families, ["7.4"])


    def test_official_article_scope_can_include_multiple_products(self):
        item = {
            "title": 'Upgrade firmware fails with "New image is too big"',
            "summary": "Description of the issue.ScopeFortiManager-VM, FortiAnalyzer-VM.Solution: expand the flash disk.",
            "url": "https://community.fortinet.com/fortianalyzer-6/upgrade-firmware-fails-with-new-image-is-too-big-230675",
        }
        self.assertEqual(set(synth.extract_products(item)), {"FortiManager", "FortiAnalyzer"})


    def test_synthesized_incident_exposes_explicit_symptom_and_solution(self):
        item = {
            "title": "Troubleshooting Tip: DNS over TLS fails in proxy mode",
            "summary": "DescriptionDNS filtering fails to inspect DNS over TLS queries in proxy mode.ScopeFortiGate 7.6.4.SolutionThis known issue occurs because the IPS engine skips DNS decoding.Workaround: add port 853 to the IPS decoder list.",
            "url": "https://community.fortinet.com/fortigate-3/dns-over-tls-example",
            "products": ["FortiGate"],
        }
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize({"topics": [item]}, Path(directory) / "community.json")
        incident = result["incidents"][0]
        self.assertIn("DNS filtering fails", incident["symptom"])
        self.assertIn("Contournement : add port 853", incident["solution"])
        self.assertEqual(incident["impact"], "")

    def test_user_discussion_does_not_receive_an_invented_solution(self):
        item = {
            "title": "VPN disconnects after upgrade",
            "summary": "VPN disconnects after upgrade for one user.",
            "url": "https://community.fortinet.com/support-forum-92/vpn-disconnects",
        }
        self.assertEqual(synth.extract_sections(item), {"symptom": "", "impact": "", "solution": ""})


    def test_unchanged_evidence_preserves_ai_review(self):
        topics = [
            {
                "title": "FortiGate DNS over TLS broken in Proxy Mode",
                "summary": "FortiOS 7.6.4 DNS over TLS fails.",
                "url": "https://community.fortinet.com/support-forum-92/dns-dot-1",
                "products": ["FortiGate"],
                "date": "2026-10-22T08:00:00+00:00",
            },
            {
                "title": "DNS over TLS fails in proxy mode on FortiGate",
                "summary": "FortiOS version 7.6.4 has broken DNS over TLS.",
                "url": "https://community.fortinet.com/support-forum-92/dns-dot-2",
                "products": ["FortiGate"],
                "date": "2026-10-21T08:00:00+00:00",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "community.json"
            previous = synth.synthesize({"topics": topics}, target)
            previous["incidents"][0]["aiReview"] = {
                "summary": "Reformulation relue par IA",
                "reviewedAt": "2026-10-26T10:00:00+00:00",
                "model": "gemini-3.5-flash-lite",
            }
            refreshed = synth.synthesize({
                "topics": topics,
                "_previousIncidents": previous["incidents"],
                "aiReviewGeneratedAt": "2026-10-26T10:00:00+00:00",
                "aiReviewModel": "gemini-3.5-flash-lite",
                "aiReviewNote": "Relecture séparée",
            }, target)

        self.assertEqual(refreshed["incidents"][0]["aiReview"]["summary"], "Reformulation relue par IA")
        self.assertEqual(refreshed["aiReviewGeneratedAt"], "2026-10-26T10:00:00+00:00")
        self.assertNotIn("_previousIncidents", refreshed)
        self.assertEqual(refreshed["aiReviewStatus"], "pending")

    def test_changed_source_evidence_discards_stale_ai_review(self):
        topics = [
            {
                "title": "FortiGate DNS over TLS broken in Proxy Mode",
                "summary": "FortiOS 7.6.4 DNS over TLS fails.",
                "url": "https://community.fortinet.com/support-forum-92/dns-dot-1",
                "products": ["FortiGate"],
                "date": "2026-10-22T08:00:00+00:00",
            },
            {
                "title": "DNS over TLS fails in proxy mode on FortiGate",
                "summary": "FortiOS version 7.6.4 has broken DNS over TLS.",
                "url": "https://community.fortinet.com/support-forum-92/dns-dot-2",
                "products": ["FortiGate"],
                "date": "2026-10-21T08:00:00+00:00",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "community.json"
            previous = synth.synthesize({"topics": topics}, target)
            previous["incidents"][0]["aiReview"] = {
                "summary": "Ancienne reformulation",
                "reviewedAt": "2026-10-26T10:00:00+00:00",
                "model": "gemini-3.5-flash-lite",
            }
            changed_topics = [dict(topic) for topic in topics]
            changed_topics[0]["summary"] = "FortiOS 7.6.4 DNS over TLS fails with a new documented symptom."
            refreshed = synth.synthesize({
                "topics": changed_topics,
                "_previousIncidents": previous["incidents"],
                "aiReviewGeneratedAt": "2026-10-26T10:00:00+00:00",
                "aiReviewModel": "gemini-3.5-flash-lite",
            }, target)

        self.assertNotIn("aiReview", refreshed["incidents"][0])
        self.assertNotIn("aiReviewGeneratedAt", refreshed)


    def test_index_only_official_source_does_not_claim_multiple_discussions(self):
        item = {
            "title": "Known issue in FortiOS 7.6.8",
            "summary": "",
            "url": "https://community.fortinet.com/fortigate-3/known-issue-in-fortios-7-6-8-230826",
        }
        summary = synth.build_summary([item])
        self.assertIn("index", summary.lower())
        self.assertIn("fiche Fortinet", summary)
        self.assertNotIn("Plusieurs discussions", summary)


    def test_unwatched_product_board_does_not_inherit_stale_cross_tags(self):
        item = {
            "title": "GUI inaccessible after upgrading to FortiSOAR version 8.0.0 due to nginx failure",
            "summary": "DescriptionThe FortiSOAR GUI is inaccessible after upgrading to FortiSOAR 8.0.0. ScopeFortiSOAR. SolutionRemove the obsolete nginx directive.",
            "url": "https://community.fortinet.com/fortisoar-35/gui-inaccessible-after-upgrading-to-fortisoar-version-8-0-0-due-to-nginx-failure-230910",
            "products": ["FortiGate", "FortiManager", "FortiAnalyzer", "FortiAuthenticator", "FortiClient"],
        }
        self.assertEqual(synth.extract_products(item), [])
        with tempfile.TemporaryDirectory() as directory:
            result = synth.synthesize({"topics": [item]}, Path(directory) / "community.json")
        self.assertEqual(result["incidentCount"], 0)


if __name__ == "__main__":
    unittest.main()
