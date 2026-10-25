#!/usr/bin/env python3
"""Collecteur non interactif du flux Fortinet Community, sans IA ni clé API."""
from __future__ import annotations

import html
from html.parser import HTMLParser
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
EXTENDED_FEED_COUNT = 500
EXTENDED_FEED_URL = f"{FEED_URL}?count={EXTENDED_FEED_COUNT}"
OUT = ROOT / "data" / "community.json"
USER_AGENT = "AutomatikCommunityWatch/1.0 (+https://github.com/Riiddiimz/Automatik)"
MAX_HISTORY = 500
MAX_TOPIC_PRODUCT_LOOKUPS = 8

PRODUCT_ALIASES = {
    "FortiGate": (r"\bforti[- ]?gates?\b", r"\bfortios\b"),
    "FortiManager": (r"\bfortimanagers?\b",),
    "FortiAnalyzer": (r"\bfortianalyzers?\b",),
    "FortiAuthenticator": (r"\bfortiauthenticators?\b",),
    "FortiClient EMS": (r"\bforticlient\s*ems\b", r"\bfcems\b"),
    "FortiClient": (r"\bforticlients?\b",),
    "FortiSwitch": (r"\bfortiswitch(?:es)?\b",),
    "FortiAP": (r"\bforti[- ]?aps?\b",),
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


PRODUCT_BOARD_SLUGS = {
    "fortigate-3": "FortiGate",
    "fortimanager-27": "FortiManager",
    "fortianalyzer-6": "FortiAnalyzer",
    "fortiauthenticator-8": "FortiAuthenticator",
    "forticlient-4": "FortiClient",
    "fortiap-5": "FortiAP",
}
ISSUE_CONTEXT_RE = re.compile(
    r"\b(?:not\s+connect(?:ed|ing)?|unable\s+to\s+connect|cannot\s+connect|"
    r"can't\s+connect|disconnect(?:ed|ing|s)?|fail(?:s|ed|ure)?|broken|"
    r"not\s+working|stuck|offline|does\s+not\s+work|no\s+longer)\b",
    re.I,
)


def needs_product_enrichment(title: str, summary: str) -> bool:
    text = f"{title} {summary}"
    has_version = bool(
        VERSION_CONTEXT_RE.search(text)
        or UPGRADE_TARGET_RE.search(text)
        or UPGRADE_PATH_RE.search(text)
    )
    return has_version and bool(ISSUE_CONTEXT_RE.search(text))


class TopicProductTagParser(HTMLParser):
    """Read product labels from the public topic page, before the reaction/footer links."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.products: list[str] = []
        self.anchor: dict | None = None
        self.stopped = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.stopped:
            return
        if tag.lower() == "a":
            self.anchor = {"href": dict(attrs).get("href", "") or "", "text": []}

    def handle_data(self, data: str) -> None:
        if self.stopped:
            return
        if self.anchor is not None:
            self.anchor["text"].append(data)
        elif data.strip().casefold() in {"like", "follow"}:
            # Khoros renders the reaction bar as buttons on some pages, not links.
            # Stop before footer navigation, which links to every product board.
            self.stopped = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self.anchor is None:
            return
        anchor = self.anchor
        self.anchor = None
        label = clean("".join(anchor["text"]))
        if label.casefold() in {"like", "follow"}:
            self.stopped = True
            return
        product = next(
            (name for name in PRODUCT_ALIASES if label.casefold() == name.casefold()),
            None,
        )
        if product is None:
            match = re.match(
                r"^(?:https?://community\.fortinet\.com)?/([^/?#]+)",
                anchor["href"],
                re.I,
            )
            slug = match.group(1).lower() if match else ""
            product = PRODUCT_BOARD_SLUGS.get(slug)
        if product and product not in self.products:
            self.products.append(product)


def parse_topic_products(payload: str | bytes) -> list[str]:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    parser = TopicProductTagParser()
    parser.feed(payload)
    parser.close()
    return parser.products


def fetch_topic_products(url: str) -> list[str]:
    """Read public product tags only; never retry by bypassing a 403 or access control."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        payload = response.read(1_000_000)
    return parse_topic_products(payload)


def enrich_unclassified_topics(items: list[dict], detail_fetcher, errors: list[str]) -> list[dict]:
    result = []
    lookups = 0
    deferred = 0
    for raw in items:
        if not raw.get("needsProductEnrichment"):
            result.append(raw)
            continue
        if detail_fetcher is None:
            continue
        if lookups >= MAX_TOPIC_PRODUCT_LOOKUPS:
            deferred += 1
            continue
        lookups += 1
        try:
            topic_products = detail_fetcher(raw["url"])
        except (OSError, urllib.error.URLError, TimeoutError, UnicodeError) as exc:
            errors.append(
                f"Lecture des tags Community impossible ({raw['url']}): {type(exc).__name__}: {exc}"
            )
            continue
        categories = list(dict.fromkeys([*raw.get("categories", []), *topic_products]))
        text = f"{raw.get('title', '')} {raw.get('summary', '')} {' '.join(categories)}"
        products = [
            name for name, patterns in PRODUCT_ALIASES.items()
            if any(re.search(pattern, text, re.I) for pattern in patterns)
        ]
        if "FortiClient EMS" in products:
            products = [product for product in products if product != "FortiClient"]
        if not products:
            continue
        item = {**raw, "categories": categories, "products": products}
        item.pop("needsProductEnrichment", None)
        result.append(item)
    if deferred:
        errors.append(
            f"{deferred} sujets potentiels supplémentaires n'ont pas été enrichis "
            f"(limite de {MAX_TOPIC_PRODUCT_LOOKUPS} pages publiques par collecte)."
        )
    return result


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


def fetch_feed(url: str = EXTENDED_FEED_URL) -> bytes:
    # Khoros RSS supports a count parameter. Request a wider window for the
    # initial 30-day backfill; fall back to the documented community feed URL
    # if the parameterized endpoint is unavailable.
    candidates = [url]
    if url == EXTENDED_FEED_URL:
        candidates.append(FEED_URL)
    failures = []
    for candidate in candidates:
        request = urllib.request.Request(
            candidate,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
            fetch_feed.last_url = candidate
            fetch_feed.last_errors = [
                f"Flux étendu indisponible ({failed_url}): {type(exc).__name__}: {exc}; repli sur le flux standard."
                for failed_url, exc in failures
            ]
            return payload
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            failures.append((candidate, exc))
    fetch_feed.last_url = None
    fetch_feed.last_errors = [
        f"{failed_url}: {type(exc).__name__}: {exc}" for failed_url, exc in failures
    ]
    raise failures[-1][1]


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
            categories = [
                clean(category.get("term", "") or category.text or "")
                for category in entry.findall(f"{atom_ns}category")
            ]
        else:
            link = (entry.findtext("link") or "").strip()
            date_raw = entry.findtext("pubDate") or entry.findtext("published") or ""
            summary_raw = entry.findtext("description") or entry.findtext("summary") or ""
            categories = [
                clean(category.text or "")
                for category in entry.findall("category")
            ]
            categories.extend(
                clean(subject.text or "")
                for subject in entry.findall("{http://purl.org/dc/elements/1.1/}subject")
            )
        categories = list(dict.fromkeys(category for category in categories if category))
        summary = clean(summary_raw)
        if not title or not link.startswith("https://community.fortinet.com/"):
            continue
        # Khoros forum topics can mention products only in their tags/categories.
        # Include those labels for product detection without polluting the symptom summary.
        text = f"{title} {summary} {' '.join(categories)}"
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
        needs_enrichment = not products and needs_product_enrichment(title, summary)
        if not products and not needs_enrichment:
            continue
        if "FortiClient EMS" in products:
            products = [p for p in products if p != "FortiClient"]
        versions = extract_versions(title, summary, link)
        item = {
            "id": link.rstrip("/"),
            "title": title,
            "url": link,
            "date": parse_date(date_raw),
            "summary": summary[:1200],
            "categories": categories,
            "products": products,
            "versions": versions,
            "status": "À vérifier",
            "statusNote": "Le flux RSS seul ne permet pas de confirmer qu'une solution est validée.",
            "source": "Fortinet Community",
        }
        if needs_enrichment:
            item["needsProductEnrichment"] = True
        result.append(item)
    return result


def load_previous(path: Path = OUT) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("topics"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"topics": []}


def collect(fetcher=fetch_feed, out: Path = OUT, topic_fetcher=None) -> dict:
    previous = load_previous(out)
    now = datetime.now(timezone.utc).isoformat()
    errors = []
    if topic_fetcher is None and fetcher is fetch_feed:
        topic_fetcher = fetch_topic_products
    try:
        fresh = enrich_unclassified_topics(parse_feed(fetcher()), topic_fetcher, errors)
        feed_url = getattr(fetcher, "last_url", None) or FEED_URL
        if not fresh and fetcher is fetch_feed and feed_url == EXTENDED_FEED_URL:
            # A syntactically valid but empty extended response is not evidence
            # that there are no topics; try the standard public feed as well.
            fallback = enrich_unclassified_topics(parse_feed(fetcher(FEED_URL)), topic_fetcher, errors)
            if fallback:
                fresh = fallback
                feed_url = getattr(fetcher, "last_url", None) or FEED_URL
                errors.append("Flux étendu accessible mais sans sujets reconnus; repli sur le flux standard.")
        if not fresh:
            raise ValueError("flux accessible mais aucun sujet Fortinet reconnu; collecte considérée partielle")
        errors.extend(getattr(fetcher, "last_errors", []))
        if fetcher is fetch_feed and feed_url == EXTENDED_FEED_URL and len(fresh) < EXTENDED_FEED_COUNT:
            errors.append(
                f"Le flux Community a renvoyé {len(fresh)} sujets sur {EXTENDED_FEED_COUNT} demandés; "
                "la couverture complète des 30 derniers jours n'est pas garantie."
            )
    except (OSError, urllib.error.URLError, ET.ParseError, ValueError, TimeoutError) as exc:
        errors.extend(getattr(fetcher, "last_errors", []))
        errors.append(f"Fortinet Community: {type(exc).__name__}: {exc}")
        if not previous.get("topics"):
            raise RuntimeError("Le flux a échoué et aucun historique exploitable n'existe.") from exc
        result = {
            **previous,
            "generatedAt": now,
            "feedUrl": getattr(fetcher, "last_url", None) or previous.get("feedUrl", FEED_URL),
            "partial": True,
            "errors": errors,
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result

    merged = {item.get("id") or item.get("url"): item for item in previous.get("topics", []) if item.get("id") or item.get("url")}
    for item in fresh:
        key = item["id"]
        old = merged.get(key, {})
        merged[key] = {**old, **item, "firstSeen": old.get("firstSeen", now), "lastSeen": now}
    topics = sorted(merged.values(), key=lambda item: item.get("date") or item.get("firstSeen") or "", reverse=True)[:MAX_HISTORY]
    result = {
        "generatedAt": now,
        "feedUrl": feed_url,
        "partial": bool(errors),
        "errors": errors,
        "topicCount": len(topics),
        "topics": topics,
    }
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
