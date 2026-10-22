import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "fortinet_community.py"
SPEC = importlib.util.spec_from_file_location("fortinet_community", MODULE)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class CommunityParserTests(unittest.TestCase):
    def test_extracts_topic_url_and_version(self):
        html = """<html><a href="/support-forum-92/fortios-7-4-11-issue-230259">FortiOS 7.4.11 issue after upgrade</a></html>"""
        items = collector.parse_topics(html, "FortiGate / FortiOS", "https://community.fortinet.com/support-forum-92")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["url"], "https://community.fortinet.com/support-forum-92/fortios-7-4-11-issue-230259")
        self.assertEqual(items[0]["versionLabel"], "7.4.11")
        self.assertEqual(items[0]["status"], "bug rapporté non confirmé")

    def test_version_missing_is_explicit(self):
        items = collector.parse_topics('<a href="/support-forum-92/vpn-question-230259">VPN question without build</a>', "FortiClient", "https://community.fortinet.com")
        self.assertEqual(items[0]["versionLabel"], "non précisé")
        self.assertEqual(items[0]["versions"], [])

    def test_deduplicates_urls_and_preserves_history_on_source_failure(self):
        old = [{"product": "FortiGate / FortiOS", "url": "https://community.fortinet.com/support-forum-92/old-230259", "title": "Old topic"}]
        def broken(_url):
            raise OSError("403")
        items, errors, successes = collector.collect(old, fetcher=broken)
        self.assertIn(old[0], items)
        self.assertEqual(len(errors), 6)
        self.assertEqual(successes, [])

    def test_successful_fetches_are_deduplicated(self):
        html = '<a href="/support-forum-92/fortios-7-4-11-issue-230259">FortiOS 7.4.11 issue after upgrade</a>'
        items, errors, successes = collector.collect([], fetcher=lambda url: (html if "support-forum-92" not in url else html.replace("FortiOS 7.4.11 issue after upgrade", "FortiClient EMS 7.4.7 issue after upgrade")) )
        self.assertEqual(len(items), 1)
        self.assertEqual(len(successes), 6)
        self.assertEqual(errors, [])

    def test_only_official_forum_links_are_collected(self):
        html = '<a href="https://example.com/issue-123456">Fake issue title</a><a href="/support-forum-92/real-topic-230259">Real FortiGate topic</a>'
        items = collector.parse_topics(html, "FortiGate / FortiOS", "https://community.fortinet.com")
        self.assertEqual(len(items), 1)
        self.assertIn("community.fortinet.com", items[0]["url"])


if __name__ == "__main__":
    unittest.main()
