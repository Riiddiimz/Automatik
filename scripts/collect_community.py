#!/usr/bin/env python3
"""Collecteur non interactif du flux Fortinet Community, sans IA ni clé API."""
from __future__ import annotations

import html
import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEED_URL = "https://community.fortinet.com/feed/topics"
OUT = ROOT / "data" / "community.json"
USER_AGENT = "AutomatikCommunityWatch/1.0 (+https://github.com/Riiddiimz/Automatik)"
MAX_HISTORY = 500

PRODUCT_ALIASES = {
    "FortiGate": (r"\bfortigate\b", r"\bfortios\b", r"\bforti[- ]?gate\b"),
    "FortiManager": (r"\bfortimanager\b",),
    "FortiAnalyzer": (r"\bfortianalyzer\b",),
    "FortiAuthenticator": (r"\bfortiauthenticator\b",),
    "FortiClient EMS": (r"\bforticlient\s*ems\b", r"\bfcems\b"),
    "FortiClient": (r"\bforticlient\b",),
    "FortiSwitch": (r"\bfortiswitch\b",),
    "FortiAP": (r"\bfortiap\b",),
}
# Only treat a dotted number as firmware when it is tied to a Fortinet
# product/firmware marker or appears in an explicit upgrade path.
VERSION_CONTEXT_RE = re.compile(
    r"\b(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s+(?:ems|vpn))?|fortiswitch|fortiap|firmware)\s*"
    r"(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)",
    re.I,
)
UPGRADE_PATH_RE = re.compile(
    r"\b(?:upgrad(?:e|ed|ing|es)|firmware update)\b[^.!?]{0,120}?"
    r"\b(?:from\s+)?(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b"
    r"[^.!?]{0,80}?\bto\s+(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
UPGRADE_TARGET_RE = re.compile(
    r"\b(?:upgrad(?:e|ed|ing|es)|firmware update)\b[^.!?]{0,100}?"
    r"\bto\s+(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
NON_FORTINET_VERSION_RE = re.compile(
    r"\b(?:(?:huawei\s+cloud\s+)?euleros|centos|rhel|red\s+hat\s+enterprise\s+linux|"
    r"ubuntu|debian|fedora|rocky\s+linux|almalinux|oracle\s+linux|windows(?:\s+server)?|"
    r"macos(?:\s+[a-z]+)?|mac\s+os(?:\s+[a-z]+)?|os\s+x|android|ipados?|ios|"
    r"vmware\s+esxi|esxi|proxmox|freebsd|openbsd|suse|opensuse)\s*"
    r"(?:version\s*)?v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?\b",
    re.I,
)
TAG_RE = re.compile(r"<[^>]+>")


def clean(value: str | None) -> str:
    value = html.unescape(value or "")
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", value)).strip()


def extract_versions(title: str, summary: str, url: str = "") -> list[str]:
    # RSS/HTML cleanup can concatenate section labels and values, e.g. ScopeFortiOS.
    summary = re.sub(
        r"\b(?i:Description|Scope|Solution|Workaround|Impact)(?=[A-Z])",
        lambda match: match.group(0) + " ",
        summary,
    )
    text = f"{title} {summary}"
    official_article = bool(re.match(
        r"https?://community\.fortinet\.com/(?:fortigate-|fortimanager-|fortianalyzer-|"
        r"fortiauthenticator-|forticlient-ems-|forticlient-|fortiswitch-|fortiap-)",
        url, re.I,
    ))
    if official_article:
        scope = re.search(
            r"\bScope\s*:?\s*(.*?)(?=\b(?:Solution|Workaround|Impact|Description)\b|$)",
            summary, re.I | re.S,
        )
        if scope:
            scoped_text = f"{title} {scope.group(1)}"
            # When Fortinet explicitly scopes a version, don't mix in versions
            # listed later as unaffected or merely mentioned in the solution.
            if VERSION_CONTEXT_RE.search(scoped_text) or UPGRADE_PATH_RE.search(scoped_text) or UPGRADE_TARGET_RE.search(scoped_text):
                text = scoped_text
    # Exclude IP addresses, platform/tool versions and elapsed-time decimals.
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text)
    text = NON_FORTINET_VERSION_RE.sub(" ", text)
    text = re.sub(
        r"\b\d+(?:\.\d+)?\s*(?:seconds?|secs?|milliseconds?|msecs?|minutes?|mins?|hours?|hrs?)\b",
        " ", text, flags=re.I,
    )
    text = re.sub(
        r"\b(?:dig|openssl|python|curl|wget|iperf3?|ping)\s+v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?\b",
        " ", text, flags=re.I,
    )
    found = set(VERSION_CONTEXT_RE.findall(text))
    for source_version, target_version in UPGRADE_PATH_RE.findall(text):
        found.update((source_version, target_version))
    found.update(UPGRADE_TARGET_RE.findall(text))
    return sorted(found, key=lambda version: tuple(int(part) for part in version.split(".")))


def parse_date(value: str) -> str | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def fetch_feed(url: str = FEED_URL) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def parse_feed(payload: bytes) -> list[dict]:
    root = ET.fromstring(payload)
    entries = root.findall(".//item")
    atom_ns = "{http://www.w3.org/2005/Atom}"
    if not entries:
        entries = root.findall(f".//{atom_ns}entry")
    result = []
    for entry in entries:
        title = clean(entry.findtext("title") if entry.tag != f"{atom_ns}entry" else entry.findtext(f"{atom_ns}title"))
        if entry.tag == f"{atom_ns}entry":
            link_el = entry.find(f"{atom_ns}link")
            link = (link_el.get("href", "") if link_el is not None else "").strip()
            date_raw = entry.findtext(f"{atom_ns}published") or entry.findtext(f"{atom_ns}updated") or ""
            summary_raw = entry.findtext(f"{atom_ns}summary") or entry.findtext(f"{atom_ns}content") or ""
        else:
            link = (entry.findtext("link") or "").strip()
            date_raw = entry.findtext("pubDate") or entry.findtext("published") or ""
            summary_raw = entry.findtext("description") or entry.findtext("summary") or ""
        summary = clean(summary_raw)
        if not title or not link.startswith("https://community.fortinet.com/"):
            continue
        text = f"{title} {summary}"
        products = [name for name, patterns in PRODUCT_ALIASES.items() if any(re.search(pattern, text, re.I) for pattern in patterns)]
        # The forum board identifies the primary product even when the article body mentions another device.
        board = re.match(r"https?://community\.fortinet\.com/([^/]+)", link, re.I)
        if board:
            slug = board.group(1).lower()
            board_products = {
                "fortigate": "FortiGate", "fortimanager": "FortiManager",
                "fortianalyzer": "FortiAnalyzer", "fortiauthenticator": "FortiAuthenticator",
                "forticlient-ems": "FortiClient EMS", "forticlientems": "FortiClient EMS",
                "forticlient": "FortiClient", "fortiswitch": "FortiSwitch", "fortiap": "FortiAP",
            }
            primary = next((product for prefix, product in board_products.items() if slug.startswith(prefix)), None)
            if primary:
                products = list(dict.fromkeys([primary] + [p for p in products if p in title]))
        if not products:
            continue
        if "FortiClient EMS" in products:
            products = [p for p in products if p != "FortiClient"]
        versions = extract_versions(title, summary, link)
        result.append({
            "id": link.rstrip("/"),
            "title": title,
            "url": link,
            "date": parse_date(date_raw),
            "summary": summary[:1200],
            "products": products,
            "versions": versions,
            "status": "À vérifier",
            "statusNote": "Le flux RSS seul ne permet pas de confirmer qu'une solution est validée.",
            "source": "Fortinet Community",
        })
    return result


def load_previous(path: Path = OUT) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("topics"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"topics": []}


def collect(fetcher=fetch_feed, out: Path = OUT) -> dict:
    previous = load_previous(out)
    now = datetime.now(timezone.utc).isoformat()
    errors = []
    try:
        fresh = parse_feed(fetcher())
        if not fresh:
            raise ValueError("flux accessible mais aucun sujet Fortinet reconnu; collecte considérée partielle")
    except (OSError, urllib.error.URLError, ET.ParseError, ValueError, TimeoutError) as exc:
        errors.append(f"Fortinet Community: {type(exc).__name__}: {exc}")
        if not previous.get("topics"):
            raise RuntimeError("Le flux a échoué et aucun historique exploitable n'existe.") from exc
        result = {**previous, "generatedAt": now, "partial": True, "errors": errors}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result

    merged = {item.get("id") or item.get("url"): item for item in previous.get("topics", []) if item.get("id") or item.get("url")}
    for item in fresh:
        key = item["id"]
        old = merged.get(key, {})
        merged[key] = {**old, **item, "firstSeen": old.get("firstSeen", now), "lastSeen": now}
    topics = sorted(merged.values(), key=lambda item: item.get("date") or item.get("firstSeen") or "", reverse=True)[:MAX_HISTORY]
    result = {"generatedAt": now, "feedUrl": FEED_URL, "partial": False, "errors": errors, "topicCount": len(topics), "topics": topics}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    result = collect()
    print(f"Collecte terminée : {len(result.get('topics', []))} sujets conservés; partielle={result.get('partial', False)}")
    for error in result.get("errors", []):
        print(f"AVERTISSEMENT: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
