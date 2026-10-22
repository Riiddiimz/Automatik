import importlib.util
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
        </channel></rss>"""
        items = collector.parse_feed(payload)
        self.assertEqual(len(items), 2)
        gate = next(item for item in items if item["products"] == ["FortiGate"])
        self.assertEqual(gate["versions"], ["7.4.12"])
        self.assertIn("VPN drops", gate["summary"])
        self.assertEqual(gate["status"], "À vérifier")
        ems = next(item for item in items if "FortiClient EMS" in item["products"])
        self.assertNotIn("FortiClient", ems["products"])

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


if __name__ == "__main__":
    unittest.main()
