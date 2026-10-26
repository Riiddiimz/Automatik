import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "collect_community.py"
SPEC = importlib.util.spec_from_file_location("collect_community", MODULE_PATH)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class CommunityFeedTests(unittest.TestCase):
    def test_rss_filters_fortinet_products_and_extracts_versions(self):
        payload = b"""<rss version="2.0"><channel>
          <item><title>FortiGate 7.4.12 VPN disconnects</title><link>https://community.fortinet.com/t5/FortiGate/abc</link><pubDate>Wed, 21 Oct 2026 08:00:00 GMT</pubDate><description><![CDATA[VPN drops after update &amp; reconnects]]></description></item>
          <item><title>Unrelated product issue</title><link>https://community.fortinet.com/t5/Other/abc</link><description>Something else</description></item>
          <item><title>FortiClient EMS issue</title><link>https://community.fortinet.com/t5/EMS/abc</link><description>EMS deployment fails</description></item>
          <item><title>Preserving wireless clients across VLANs</title><link>https://community.fortinet.com/fortiap-5/wifi-roaming-issue</link><description>Layer 3 roaming feature</description></item>
        </channel></rss>"""
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 3)
        gate = next(item for item in items if item["products"] == ["FortiGate"])
        self.assertEqual(gate["versions"], ["7.4.12"])
        self.assertIn("VPN drops", gate["summary"])
        self.assertEqual(gate["status"], "À vérifier")
        ap = next(item for item in items if "FortiAP" in item["products"])
        self.assertEqual(ap["products"], ["FortiAP"])
        ems = next(item for item in items if "FortiClient EMS" in item["products"])
        self.assertNotIn("FortiClient", ems["products"])

    def test_official_article_versions_follow_scope_not_unaffected_versions(self):
        payload = b"""<rss version="2.0"><channel>
          <item>
            <title>Administrator SSO authentication fails after upgrade to FortiOS 7.6.8</title>
            <link>https://community.fortinet.com/fortigate-3/administrator-sso-authentication-fails-after-upgrade-to-fortios-7-6-8-230826</link>
            <description><![CDATA[DescriptionAfter upgrade to FortiOS 7.6.8, administrator SSO authentication fails. ScopeFortiOS 7.6.8.SolutionAfter upgrade, administrator SSO fails. Confirmed not affected: Other FortiOS versions including FortiOS 7.2.14, 7.4.13, 7.6.7 and 8.0.2. A Python example uses 3.11.8; host address 208.91.112.55.]]></description>
          </item>
        </channel></rss>"""
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["versions"], ["7.6.8"])


    def test_official_fix_version_is_not_reported_as_affected_version(self):
        payload = b"""<rss version="2.0"><channel>
          <item>
            <title>Troubleshooting Tip: LDAP authentication fails</title>
            <link>https://community.fortinet.com/fortiauthenticator-8/ldap-authentication-fails-230999</link>
            <description><![CDATA[DescriptionLDAP authentication fails. ScopeFortiAuthenticator. SolutionThe issue will be fixed in FortiAuthenticator version 8.0.4.]]></description>
          </item>
        </channel></rss>"""
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["versions"], [])
        self.assertEqual(items[0]["fixVersions"], ["8.0.4"])

    def test_long_official_summary_keeps_late_fix_version(self):
        description = (
            "DescriptionAdministrator SSO authentication fails. "
            + ("technical details " * 100)
            + "ScopeFortiOS 7.6.8. "
            + "SolutionThe issue is under investigation and scheduled for fix in FortiOS 7.6.9."
        )
        payload = f"""<rss version="2.0"><channel>
          <item>
            <title>Administrator SSO authentication fails after upgrade to FortiOS 7.6.8</title>
            <link>https://community.fortinet.com/fortigate-3/administrator-sso-authentication-fails-after-upgrade-to-fortios-7-6-8-230826</link>
            <description><![CDATA[{description}]]></description>
          </item>
        </channel></rss>""".encode("utf-8")
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 1)
        self.assertGreater(len(items[0]["summary"]), 1200)
        self.assertIn("scheduled for fix in FortiOS 7.6.9", items[0]["summary"])
        self.assertEqual(items[0]["versions"], ["7.6.8"])
        self.assertEqual(items[0]["fixVersions"], ["7.6.9"])

    def test_rss_categories_identify_products_missing_from_title_and_summary(self):
        payload = b"""<rss version="2.0"><channel>
          <item>
            <title>After upgrade to 7.4.13 many AP are not connected</title>
            <link>https://community.fortinet.com/support-forum-92/after-upgrade-to-7-4-13-many-ap-are-not-connected-230800</link>
            <pubDate>Sat, 24 Oct 2026 08:00:00 GMT</pubDate>
            <category>FortiGate</category><category>FortiAP</category>
            <description>Many APs no longer connect after the upgrade.</description>
          </item>
        </channel></rss>"""
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["products"], ["FortiGate", "FortiAP"])
        self.assertEqual(items[0]["categories"], ["FortiGate", "FortiAP"])
        self.assertEqual(items[0]["versions"], ["7.4.13"])
        self.assertEqual(items[0]["summary"], "Many APs no longer connect after the upgrade.")

    def test_product_aliases_accept_plural_names(self):
        payload = b"""<rss version="2.0"><channel>
          <item>
            <title>FortiAPs are offline but can be pinged from the firewall</title>
            <link>https://community.fortinet.com/support-forum-92/fortiaps-are-offline-230835</link>
            <description>FortiGates can ping the FortiAPs, but the APs are not connected.</description>
          </item>
        </channel></rss>"""
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["products"], ["FortiGate", "FortiAP"])

    def test_topic_product_tag_parser_recognizes_product_board_slug_suffixes(self):
        page = """<html><body>
          <div class="lia-component-tags">
            <a href="/forticlient-ems-25">FortiClient EMS</a>
          </div>
        </body></html>"""
        self.assertEqual(collector.parse_topic_products(page), ["FortiClient EMS"])

    def test_topic_product_tag_parser_ignores_footer_navigation(self):
        page = """<html><body>
          <div class="lia-component-tags">
            <a href="/fortigate-3">FortiGate</a>
            <a href="/fortiap-5">FortiAP</a>
          </div>
          <button aria-label="Like"></button>
          <footer><a href="/fortimanager-27">FortiManager</a></footer>
        </body></html>"""
        self.assertEqual(collector.parse_topic_products(page), ["FortiGate", "FortiAP"])

    def test_unclassified_upgrade_topic_is_enriched_from_public_tags(self):
        payload = b"""<rss version="2.0"><channel>
          <item>
            <title>After upgrade to 7.4.13 many AP are not connected</title>
            <link>https://community.fortinet.com/support-forum-92/after-upgrade-to-7-4-13-many-ap-are-not-connected-230800</link>
            <pubDate>Sat, 24 Oct 2026 08:00:00 GMT</pubDate>
            <category>Support Forum</category>
            <description>Many APs no longer connect after the upgrade.</description>
          </item>
        </channel></rss>"""
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["needsProductEnrichment"])
        self.assertEqual(items[0]["versions"], ["7.4.13"])
        errors = []
        enriched = collector.enrich_unclassified_topics(
            items, lambda url: ["FortiGate", "FortiAP"], errors
        )
        self.assertEqual(enriched[0]["products"], ["FortiGate", "FortiAP"])
        self.assertNotIn("needsProductEnrichment", enriched[0])
        self.assertEqual(errors, [])

    def test_stale_overclassified_topic_is_rechecked_from_public_tags(self):
        old_url = "https://community.fortinet.com/support-forum-92/after-upgrade-to-7-4-13-many-ap-are-not-connected-230800"
        old_topic = {
            "id": old_url,
            "url": old_url,
            "title": "After upgrade to 7.4.13 many ap are not connected",
            "summary": "Many APs no longer connect after the upgrade.",
            "categories": ["Support Forum", "FortiGate", "FortiManager", "FortiAP", "FortiAuthenticator", "FortiAnalyzer", "FortiClient"],
            "products": ["FortiGate", "FortiManager", "FortiAnalyzer", "FortiAuthenticator", "FortiClient", "FortiAP"],
            "versions": ["7.4.13"],
            "date": "2026-10-23T08:00:00+00:00",
        }
        payload = b"""<rss version="2.0"><channel>
          <item><title>FortiGate 7.4.12 VPN disconnects</title><link>https://community.fortinet.com/fortigate-3/known-issue-230001</link><description>VPN drops after update</description></item>
        </channel></rss>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            path.write_text(json.dumps({"topics": [old_topic]}), encoding="utf-8")
            result = collector.collect(
                fetcher=lambda: payload,
                topic_fetcher=lambda url: ["FortiGate", "FortiAP"],
                out=path,
            )
        repaired = next(topic for topic in result["topics"] if topic["url"] == old_url)
        self.assertEqual(repaired["products"], ["FortiGate", "FortiAP"])
        self.assertEqual(repaired["categories"], ["Support Forum", "FortiGate", "FortiAP"])
        self.assertEqual(len(result["topics"]), 2)

    def test_failed_topic_detail_preserves_other_valid_topics(self):
        payload = b"""<rss version="2.0"><channel>
          <item><title>FortiGate 7.4.12 VPN disconnects</title><link>https://community.fortinet.com/fortigate-3/known-issue-230001</link><description>VPN drops after update</description></item>
          <item><title>After upgrade to 7.4.13 many AP are not connected</title><link>https://community.fortinet.com/support-forum-92/after-upgrade-to-7-4-13-many-ap-are-not-connected-230800</link><description>Many APs no longer connect after the upgrade.</description></item>
        </channel></rss>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            result = collector.collect(
                fetcher=lambda: payload,
                topic_fetcher=lambda url: (_ for _ in ()).throw(urllib.error.URLError("403 Forbidden")),
                out=path,
            )
        self.assertTrue(result["partial"])
        self.assertEqual(len(result["topics"]), 1)
        self.assertTrue(any("Lecture des tags Community impossible" in error for error in result["errors"]))

    def test_extended_feed_falls_back_and_marks_collection_partial(self):
        payload = b"""<rss version="2.0"><channel>
          <item><title>FortiGate 7.4.12 VPN issue</title><link>https://community.fortinet.com/t5/FortiGate/new</link><description>VPN disconnects</description></item>
        </channel></rss>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            with patch.object(
                collector.urllib.request,
                "urlopen",
                side_effect=[urllib.error.URLError("extended feed forbidden"), io.BytesIO(payload)],
            ) as mocked:
                result = collector.collect(out=path)

        self.assertTrue(result["partial"])
        self.assertEqual(result["feedUrl"], collector.FEED_URL)
        self.assertTrue(any("Flux étendu indisponible" in error for error in result["errors"]))
        self.assertEqual(len(result["topics"]), 1)
        self.assertEqual(mocked.call_count, 2)
        self.assertIn("count=500", mocked.call_args_list[0].args[0].full_url)
        self.assertEqual(mocked.call_args_list[1].args[0].full_url, collector.FEED_URL)


    def test_underfilled_extended_feed_is_marked_partial(self):
        payload = b"""<rss version="2.0"><channel>
          <item><title>FortiGate 7.4.12 VPN issue</title><link>https://community.fortinet.com/t5/FortiGate/new</link><description>VPN disconnects</description></item>
        </channel></rss>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            with patch.object(collector.urllib.request, "urlopen", return_value=io.BytesIO(payload)):
                result = collector.collect(out=path)

        self.assertTrue(result["partial"])
        self.assertEqual(result["feedUrl"], collector.EXTENDED_FEED_URL)
        self.assertTrue(any("500 demandés" in error for error in result["errors"]))


    def test_atom_feed_is_supported(self):
        payload = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>FortiManager topic</title><link href="https://community.fortinet.com/t5/FortiManager/atom"/><updated>2026-10-21T08:00:00Z</updated><summary>Policy issue</summary></entry></feed>"""
        items = collector.parse_feed(payload)
        self.assertEqual(items[0]["title"], "FortiManager topic")
        self.assertEqual(items[0]["products"], ["FortiManager"])

    def test_invalid_xml_raises(self):
        with self.assertRaises(Exception):
            collector.parse_feed(b"<rss><channel>")

    def test_collect_deduplicates_and_preserves_history_on_failure(self):
        payload = b"""<rss version="2.0"><channel><item><title>FortiGate new issue</title><link>https://community.fortinet.com/t5/FortiGate/new</link><description>VPN issue</description></item></channel></rss>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            path.write_text(json.dumps({"topics": [{"id": "https://community.fortinet.com/t5/FortiGate/old", "url": "https://community.fortinet.com/t5/FortiGate/old", "title": "Old topic"}]}), encoding="utf-8")
            result = collector.collect(fetcher=lambda: payload, out=path)
            self.assertEqual(len(result["topics"]), 2)
            result = collector.collect(fetcher=lambda: payload, out=path)
            self.assertEqual(len(result["topics"]), 2)
            failed = collector.collect(fetcher=lambda: (_ for _ in ()).throw(urllib.error.URLError("offline")), out=path)
            self.assertTrue(failed["partial"])
            self.assertEqual(len(failed["topics"]), 2)
            self.assertTrue(failed["errors"])


    def test_empty_valid_feed_is_partial_and_preserves_history(self):
        unrelated = b"""<rss version="2.0"><channel>
          <item><title>Unrelated product issue</title><link>https://community.fortinet.com/support-forum-92/unrelated</link><description>Something else</description></item>
        </channel></rss>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            old_topic = {"id": "https://community.fortinet.com/support-forum-92/old",
                         "url": "https://community.fortinet.com/support-forum-92/old",
                         "title": "Previously collected FortiGate issue"}
            path.write_text(json.dumps({"topics": [old_topic]}), encoding="utf-8")
            result = collector.collect(fetcher=lambda: unrelated, out=path)

        self.assertTrue(result["partial"])
        self.assertEqual([topic["id"] for topic in result["topics"]], [old_topic["id"]])
        self.assertTrue(any("aucun sujet Fortinet reconnu" in error for error in result["errors"]))

    def test_empty_valid_feed_without_history_fails_loudly(self):
        unrelated = b"""<rss version="2.0"><channel>
          <item><title>Unrelated product issue</title><link>https://community.fortinet.com/support-forum-92/unrelated</link><description>Something else</description></item>
        </channel></rss>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "community.json"
            with self.assertRaisesRegex(RuntimeError, "aucun historique exploitable"):
                collector.collect(fetcher=lambda: unrelated, out=path)


if __name__ == "__main__":
    unittest.main()
