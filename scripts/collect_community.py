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
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
FEED_URL = "https://community.fortinet.com/feed/topics"
EXTENDED_FEED_COUNT = 500
FEED_PAGE_SIZE = 100
EXTENDED_FEED_URL = f"{FEED_URL}?count={FEED_PAGE_SIZE}&start=0"
OUT = ROOT / "data" / "community.json"
USER_AGENT = "AutomatikCommunityWatch/1.0 (+https://github.com/Riiddiimz/Automatik)"
MAX_HISTORY = 1000
MAX_TOPIC_PRODUCT_LOOKUPS = 8
MAX_BOARD_PAGES = 5
# The cross-product Support Forum index is much busier than individual boards.
# Ten pages reach roughly 25–28 days of discussions in the observed public index.
SUPPORT_FORUM_MAX_PAGES = 10
MAX_BOARD_DETAIL_LOOKUPS = 12
DETAIL_PARSER_VERSION = 2
DETAIL_FAILURE_RETRY_HOURS = 2
BOARD_DETAIL_RE = re.compile(
    r"\b(?:fail(?:s|ed|ure)?|not working|not loading|not supported|unsupported|unable|cannot|can\x27t|"
    r"error|issue|bug|crash|stuck|disconnect(?:s|ed|ing)?|no longer|wrong|incorrect|"
    r"unavailable|blocked|timeout|missing|regression|does not work|slow|expired|expiration|"
    r"invalid|authentication|certificate|connection reset)\b",
    re.I,
)

# Secondary public discovery path for the product indexes.
# EMS topics also appear in the FortiClient index and are classified from titles/tags.
BOARD_SOURCES = {
    "FortiGate": "https://community.fortinet.com/fortigate-3",
    "FortiManager": "https://community.fortinet.com/fortimanager-27",
    "FortiAuthenticator": "https://community.fortinet.com/fortiauthenticator-8",
    "FortiAnalyzer": "https://community.fortinet.com/fortianalyzer-6",
    "FortiClient": "https://community.fortinet.com/forticlient-4",
    # General user discussions expose recent cross-product incidents missed by
    # the global RSS cap; parse only topics with a recognizable Fortinet product.
    "Support Forum": "https://community.fortinet.com/support-forum-92",
}

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
    r"forticlient(?:\s+(?:ems|vpn))?|fortiswitch|fortiap|firmware)\s*[\(:-]?\s*"
    r"(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)",
    re.I,
)
FIRMWARE_VERSION_LIST_RE = re.compile(r"\bfirmware\s*\(([^)]{1,120})\)", re.I)
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
FIXED_VERSION_RE = re.compile(
    r"\b(?:will\s+be\s+fixed|will\s+be\s+resolved|is\s+scheduled\s+to\s+be\s+fixed|"
    r"scheduled\s+to\s+be\s+fixed|scheduled\s+for\s+(?:a\s+)?fix|planned\s+fix|fixed|resolved|corrected|addressed|"
    r"(?:fix|patch|correction)\s+(?:is\s+)?(?:available|included|provided))\s+"
    r"(?:in|with|from)\s+(?:(?:fortios|fortigate|fortimanager|fortianalyzer|"
    r"fortiauthenticator|forticlient(?:\s+(?:ems|vpn))?|fortiswitch|fortiap|firmware)\s*)?"
    r"(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
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
    "forticlient-ems": "FortiClient EMS",
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
    """Extract product labels from the topic tags, never from global footer navigation."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.products: list[str] = []
        self.tagged_products: list[str] = []
        self.anchor: dict | None = None
        self.tag_capture: dict | None = None
        self.tag_depth = 0
        self.stopped = False
        self.boundary_seen = False

    def _record_product(self, label: str, href: str = "", target: list[str] | None = None) -> None:
        target = self.products if target is None else target
        product = next(
            (name for name in PRODUCT_ALIASES if label.casefold() == name.casefold()),
            None,
        )
        if product is None:
            match = re.match(
                r"^(?:https?://community\.fortinet\.com)?/([^/?#]+)",
                href,
                re.I,
            )
            slug = match.group(1).lower() if match else ""
            product = PRODUCT_BOARD_SLUGS.get(slug) or next(
                (name for prefix, name in PRODUCT_BOARD_SLUGS.items() if slug.startswith(prefix)),
                None,
            )
        if product and product not in target:
            target.append(product)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.stopped:
            return
        attributes = dict(attrs)
        class_names = (attributes.get("class", "") or "").lower()
        element_id = (attributes.get("id", "") or "").lower()
        if tag.lower() == "footer" or "footer" in class_names or "footer" in element_id:
            self.stopped = True
            self.boundary_seen = True
            return
        for key in ("aria-label", "title", "data-testid", "data-action"):
            if (attributes.get(key, "") or "").strip().casefold() in {"like", "follow"}:
                self.stopped = True
                self.boundary_seen = True
                return
        if self.tag_capture is not None:
            self.tag_depth += 1
        elif any("tag" in token for token in class_names.split()):
            self.tag_capture = {"text": []}
            self.tag_depth = 1
        if tag.lower() == "a":
            self.anchor = {"href": attributes.get("href", "") or "", "text": []}

    def handle_data(self, data: str) -> None:
        if self.stopped:
            return
        if self.anchor is not None:
            self.anchor["text"].append(data)
        if self.tag_capture is not None:
            self.tag_capture["text"].append(data)
        elif self.anchor is None and data.strip().casefold() in {"like", "follow"}:
            self.stopped = True
            self.boundary_seen = True

    def handle_endtag(self, tag: str) -> None:
        if self.stopped:
            return
        if tag.lower() == "a" and self.anchor is not None:
            anchor = self.anchor
            self.anchor = None
            label = clean("".join(anchor["text"]))
            if label.casefold() in {"like", "follow"}:
                self.stopped = True
                self.boundary_seen = True
                return
            target = self.tagged_products if self.tag_capture is not None else self.products
            self._record_product(label, anchor["href"], target)
        if self.tag_capture is not None:
            self.tag_depth -= 1
            if self.tag_depth <= 0:
                label = clean("".join(self.tag_capture["text"]))
                self._record_product(label, target=self.tagged_products)
                self.tag_capture = None
                self.tag_depth = 0


def parse_topic_products(payload: str | bytes) -> list[str]:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    parser = TopicProductTagParser()
    parser.feed(payload)
    parser.close()
    if parser.tagged_products:
        return parser.tagged_products
    # If no clear tag container was found, trust link labels only when a
    # reaction/footer boundary was observed. Otherwise the page may be a
    # partial response and global navigation could be mistaken for topic tags.
    return parser.products if parser.boundary_seen else []


def fetch_topic_products(url: str) -> list[str]:
    """Read public product tags only; never retry by bypassing a 403 or access control."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        payload = response.read(1_000_000)
    return parse_topic_products(payload)


def enrich_unclassified_topics(
    items: list[dict],
    detail_fetcher,
    errors: list[str],
    known_topics: list[dict] | None = None,
) -> list[dict]:
    """Enrichir les sujets non classés sans jamais perdre une entrée faute de métadonnées."""
    now = datetime.now(timezone.utc)
    failure_cutoff = (now - timedelta(hours=DETAIL_FAILURE_RETRY_HOURS)).isoformat()
    known_by_url = {
        str(item.get("url") or item.get("id") or "").rstrip("/"): item
        for item in (known_topics or [])
        if isinstance(item, dict) and (item.get("url") or item.get("id"))
    }
    result = []
    lookups = 0
    deferred = 0
    pending = 0
    recently_failed = 0
    unclassified = 0

    for raw in items:
        if not raw.get("needsProductEnrichment"):
            result.append(raw)
            continue

        url = str(raw.get("url") or raw.get("id") or "").rstrip("/")
        known = known_by_url.get(url, {})
        known_products = known.get("products") or []

        # Reuse a prior successful classification rather than repeatedly fetching the same topic.
        if known.get("productEnrichmentStatus") == "resolved" and known_products:
            categories = list(dict.fromkeys([
                *(raw.get("categories") or []),
                *(known.get("categories") or []),
                *known_products,
            ]))
            item = {
                **raw,
                "categories": categories,
                "products": list(dict.fromkeys([*(raw.get("products") or []), *known_products])),
                "productEnrichmentStatus": "resolved",
            }
            if known.get("productEnrichmentCheckedAt"):
                item["productEnrichmentCheckedAt"] = known["productEnrichmentCheckedAt"]
            item.pop("needsProductEnrichment", None)
            result.append(item)
            continue

        status = known.get("productEnrichmentStatus", raw.get("productEnrichmentStatus"))
        checked_at = str(known.get("productEnrichmentCheckedAt") or raw.get("productEnrichmentCheckedAt") or "")
        attempted_at = str(known.get("productEnrichmentAttemptedAt") or raw.get("productEnrichmentAttemptedAt") or "")
        deferred_at = str(known.get("productEnrichmentDeferredAt") or raw.get("productEnrichmentDeferredAt") or "")

        # Respect backoff and retain the record while waiting; a failed lookup is not an absent topic.
        if status == "unclassified" and checked_at >= success_cutoff:
            result.append({**raw, "products": [], "productEnrichmentStatus": "unclassified",
                           "productEnrichmentCheckedAt": checked_at})
            unclassified += 1
            continue
        if status == "failed" and attempted_at >= failure_cutoff:
            result.append({**raw, "products": [], "productEnrichmentStatus": "failed",
                           "productEnrichmentAttemptedAt": attempted_at})
            recently_failed += 1
            continue
        if status == "deferred" and deferred_at >= success_cutoff:
            result.append({**raw, "products": [], "productEnrichmentStatus": "deferred",
                           "productEnrichmentDeferredAt": deferred_at})
            deferred += 1
            continue

        if detail_fetcher is None:
            result.append({**raw, "products": raw.get("products") or [],
                           "productEnrichmentStatus": "pending"})
            pending += 1
            continue
        if lookups >= MAX_TOPIC_PRODUCT_LOOKUPS:
            result.append({**raw, "products": raw.get("products") or [],
                           "productEnrichmentStatus": "deferred",
                           "productEnrichmentDeferredAt": now.isoformat()})
            deferred += 1
            continue

        lookups += 1
        try:
            topic_products = detail_fetcher(url)
            if not isinstance(topic_products, (list, tuple)):
                raise ValueError("les tags produit ne sont pas une liste valide")
            topic_products = [
                clean(product) for product in topic_products
                if isinstance(product, str) and clean(product)
            ]
            categories = list(dict.fromkeys([*(raw.get("categories") or []), *topic_products]))
            text = f"{raw.get('title', '')} {raw.get('summary', '')} {' '.join(categories)}"
            products = [
                name for name, patterns in PRODUCT_ALIASES.items()
                if any(re.search(pattern, text, re.I) for pattern in patterns)
            ]
            if "FortiClient EMS" in products:
                products = [product for product in products if product != "FortiClient"]

            item = {
                **raw,
                "categories": categories,
                "products": products,
                "productEnrichmentCheckedAt": now.isoformat(),
            }
            item.pop("productEnrichmentAttemptedAt", None)
            item.pop("productEnrichmentDeferredAt", None)
            if products:
                item.pop("needsProductEnrichment", None)
                item["productEnrichmentStatus"] = "resolved"
            else:
                item["needsProductEnrichment"] = True
                item["productEnrichmentStatus"] = "unclassified"
                unclassified += 1
            result.append(item)
        except (OSError, urllib.error.URLError, TimeoutError, UnicodeError, ValueError) as exc:
            errors.append(
                f"Lecture des tags Community impossible ({url}): {type(exc).__name__}: {exc}"
            )
            result.append({
                **raw,
                "products": raw.get("products") or [],
                "productEnrichmentStatus": "failed",
                "productEnrichmentAttemptedAt": now.isoformat(),
            })

    if pending:
        errors.append(
            f"{pending} sujet(s) potentiel(s) conservé(s) sans classification produit, "
            "car la lecture des tags n'était pas disponible."
        )
    if deferred:
        errors.append(
            f"{deferred} sujet(s) potentiel(s) conservé(s) en attente d'enrichissement "
            f"(limite de {MAX_TOPIC_PRODUCT_LOOKUPS} pages publiques par collecte ou délai de reprise)."
        )
    if recently_failed:
        errors.append(
            f"{recently_failed} sujet(s) potentiel(s) conservé(s) en attente du délai de reprise "
            f"de {DETAIL_FAILURE_RETRY_HOURS} heure(s) après un échec de lecture."
        )
    if unclassified:
        errors.append(
            f"{unclassified} sujet(s) potentiel(s) conservé(s) mais non classé(s): "
            "les tags publics ne permettent pas encore d'identifier le produit."
        )
    return result


def pending_product_enrichment_candidates(previous_topics: list[dict], observed_ids: set[str]) -> list[dict]:
    """Queue older unresolved RSS topics for a later retry, without duplicating current-feed entries."""
    candidates = []
    for raw in previous_topics:
        if not isinstance(raw, dict) or not raw.get("needsProductEnrichment"):
            continue
        if raw.get("products"):
            continue
        url = str(raw.get("url") or raw.get("id") or "").rstrip("/")
        if not url or url in observed_ids:
            continue
        if not url.startswith("https://community.fortinet.com/"):
            continue
        candidates.append(dict(raw))
    return candidates

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
            # The title and Scope describe the affected product/release. Never
            # infer affected versions from a Solution/Workaround (often a fixed release).
            text = f"{title} {scope.group(1)}"
    # Exclude IP addresses, platform/tool versions and elapsed-time decimals.
    # A version explicitly described as fixed is not an affected version.
    text = FIXED_VERSION_RE.sub(" ", text)
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
    for version_list in FIRMWARE_VERSION_LIST_RE.findall(text):
        found.update(re.findall(r"\b(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b", version_list))
    for source_version, target_version in UPGRADE_PATH_RE.findall(text):
        found.update((source_version, target_version))
    found.update(UPGRADE_TARGET_RE.findall(text))
    return sorted(found, key=lambda version: tuple(int(part) for part in version.split(".")))


def extract_fixed_versions(title: str, summary: str, url: str = "") -> list[str]:
    """Return only explicitly documented fixed releases from Fortinet-authored articles."""
    official_article = bool(re.match(
        r"https?://community\.fortinet\.com/(?:fortigate-|fortimanager-|fortianalyzer-|"
        r"fortiauthenticator-|forticlient-ems-|forticlient-|fortiswitch-|fortiap-)",
        url, re.I,
    ))
    if not official_article:
        return []
    found = set(FIXED_VERSION_RE.findall(f"{title} {summary}"))
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
    # The current public endpoint repeats the same 100 topics for later start
    # offsets. Stop when pagination fails instead of retrying unsupported parameters.
    if url != EXTENDED_FEED_URL:
        offsets = [None]
    else:
        offsets = range(0, EXTENDED_FEED_COUNT, FEED_PAGE_SIZE)

    all_entries = []
    seen = set()
    failures = []

    def read_page(page_url: str):
        request = urllib.request.Request(
            page_url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
        root = ET.fromstring(payload)
        entries = root.findall(".//item")
        atom = False
        if not entries:
            entries = root.findall(".//{http://www.w3.org/2005/Atom}entry")
            atom = bool(entries)
        return entries, atom

    def append_unique(entries, atom: bool) -> int:
        new_count = 0
        for entry in entries:
            if atom:
                link_el = entry.find("{http://www.w3.org/2005/Atom}link")
                key = link_el.get("href", "") if link_el is not None else ""
            else:
                key = (entry.findtext("link") or "").strip()
            if not key:
                key = ET.tostring(entry, encoding="unicode")
            if key in seen:
                continue
            seen.add(key)
            all_entries.append(entry)
            new_count += 1
        return new_count

    for offset in offsets:
        page_url = url if offset is None else f"{FEED_URL}?count={FEED_PAGE_SIZE}&start={offset}"
        try:
            entries, atom = read_page(page_url)
        except (OSError, urllib.error.URLError, TimeoutError, ET.ParseError, ValueError) as exc:
            if url == EXTENDED_FEED_URL and offset:
                failures.append(
                    f"Pagination Community impossible à {offset}: {type(exc).__name__}: {exc}"
                )
                break
            failures.append(f"{page_url}: {type(exc).__name__}: {exc}")
            break

        if not entries:
            if not all_entries:
                failures.append(f"{page_url}: flux RSS valide mais sans entrées")
            break

        new_entries = append_unique(entries, atom)
        if url == EXTENDED_FEED_URL and offset and new_entries == 0:
            failures.append(
                f"Le flux Community ignore le paramètre start à {offset}; les sujets précédents se répètent."
            )
            break
        if new_entries == 0:
            failures.append(
                "Le flux RSS a répété les mêmes sujets; aucune entrée distincte supplémentaire n'a été récupérée."
            )
            break
        if len(entries) < FEED_PAGE_SIZE:
            break

    if all_entries:
        combined = ET.Element("rss", {"version": "2.0"})
        channel = ET.SubElement(combined, "channel")
        for entry in all_entries:
            channel.append(entry)
        fetch_feed.last_url = EXTENDED_FEED_URL if url == EXTENDED_FEED_URL else url
        fetch_feed.last_errors = failures
        return ET.tostring(combined, encoding="utf-8", xml_declaration=True)
    if url == EXTENDED_FEED_URL:
        # If the paged endpoint fails completely, preserve a standard-feed fallback.
        fallback_request = urllib.request.Request(
            FEED_URL,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml"},
        )
        try:
            with urllib.request.urlopen(fallback_request, timeout=30) as response:
                payload = response.read()
            fetch_feed.last_url = FEED_URL
            fetch_feed.last_errors = [f"Flux étendu indisponible ({error}); repli sur le flux standard." for error in failures]
            return payload
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            failures.append(f"{FEED_URL}: {type(exc).__name__}: {exc}")
    fetch_feed.last_url = None
    fetch_feed.last_errors = failures
    raise RuntimeError("Aucune page du flux Community n'a pu être récupérée: " + "; ".join(failures))

def count_feed_entries(payload: bytes) -> int:
    """Count raw RSS/Atom entries before product filtering."""
    root = ET.fromstring(payload)
    entries = root.findall(".//item")
    if not entries:
        entries = root.findall(".//{http://www.w3.org/2005/Atom}entry")
    return len(entries)

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
            elif not slug.startswith("support-forum") and slug != "t5":
                # Non-forum boards can carry broad cross-product tags in RSS.
                # Trust target products explicitly named in the title, not those tags.
                products = [
                    name for name, patterns in PRODUCT_ALIASES.items()
                    if any(re.search(pattern, title, re.I) for pattern in patterns)
                ]
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
            "summary": summary[:5000],
            "categories": categories,
            "products": products,
            "versions": versions,
            "fixVersions": extract_fixed_versions(title, summary, link),
            "status": "À vérifier",
            "statusNote": "Le flux RSS seul ne permet pas de confirmer qu'une solution est validée.",
            "source": "Fortinet Community",
        }
        if needs_enrichment:
            item["needsProductEnrichment"] = True
        result.append(item)
    return result



class BoardTopicParser(HTMLParser):
    """Extract topic links from one public product index, ignoring site navigation."""

    def __init__(self, board_url: str):
        super().__init__(convert_charrefs=True)
        self.board_path = urlparse(board_url).path.rstrip("/")
        self.anchor: dict | None = None
        self.topics: list[dict] = []
        self.seen: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.anchor is not None and tag.lower() in {"div", "p", "h1", "h2", "h3", "h4", "li", "section", "article"}:
            self.anchor["text"].append(" ")
        if tag.lower() != "a":
            return
        attributes = dict(attrs)
        href = (attributes.get("href") or "").strip()
        if not href:
            return
        absolute = urljoin("https://community.fortinet.com/", href)
        parsed = urlparse(absolute)
        if parsed.scheme != "https" or parsed.netloc.lower() != "community.fortinet.com":
            return
        path = parsed.path.rstrip("/")
        if not path.startswith(self.board_path + "/"):
            return
        if not re.search(r"-\d{4,}$", path):
            return
        url = f"https://community.fortinet.com{path}"
        self.anchor = {"url": url, "text": []}

    def handle_data(self, data: str) -> None:
        if self.anchor is not None:
            self.anchor["text"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if self.anchor is not None and tag.lower() in {"div", "p", "h1", "h2", "h3", "h4", "li", "section", "article"}:
            self.anchor["text"].append(" ")
        if tag.lower() != "a" or self.anchor is None:
            return
        anchor = self.anchor
        self.anchor = None
        title = clean("".join(anchor["text"]))
        url = anchor["url"]
        if not title or url in self.seen:
            return
        self.seen.add(url)
        self.topics.append({"title": title, "url": url})


def split_board_title_and_summary(raw_text: str, url: str) -> tuple[str, str]:
    """Split a forum card's title from its preview using the public URL slug."""
    text = clean(raw_text)
    slug = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]
    slug = re.sub(r"-\d{4,}$", "", slug)
    slug_tokens = re.findall(r"[a-z0-9]+", slug.lower())
    text_matches = list(re.finditer(r"[a-z0-9]+", text, re.I))
    text_tokens = [match.group(0).lower() for match in text_matches]
    common = 0
    for slug_token, text_token in zip(slug_tokens, text_tokens):
        if slug_token != text_token:
            break
        common += 1
    if not slug_tokens or common < min(3, len(slug_tokens)) or common < len(slug_tokens) * 0.6:
        return text, ""
    title_end = text_matches[common - 1].end()
    title = text[:title_end].strip(" \t\r\n-–:|")
    summary = text[title_end:].strip(" \t\r\n-–:|")
    return title or text, summary


def parse_board_page(payload: str | bytes, board_url: str, product: str) -> list[dict]:
    """Convert public product indexes into cautious topic records; preserve support-forum previews."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    parser = BoardTopicParser(board_url)
    parser.feed(payload)
    parser.close()
    result = []
    for entry in parser.topics:
        raw_text, url = entry["title"], entry["url"]
        is_support_forum = product == "Support Forum"
        if is_support_forum:
            title, summary = split_board_title_and_summary(raw_text, url)
            product_text = f"{title} {summary}"
            products = [
                name for name, patterns in PRODUCT_ALIASES.items()
                if any(re.search(pattern, product_text, re.I) for pattern in patterns)
            ]
            if not products:
                continue
        else:
            title, summary = raw_text, ""
            title_products = [
                name for name, patterns in PRODUCT_ALIASES.items()
                if any(re.search(pattern, title, re.I) for pattern in patterns)
            ]
            products = list(dict.fromkeys([product, *title_products]))
        if "FortiClient EMS" in products:
            products = [name for name in products if name != "FortiClient"]
        result.append({
            "id": url,
            "title": title,
            "url": url,
            "date": None,
            "summary": summary[:5000],
            "products": products,
            "versions": extract_versions(title, summary, url),
            "fixVersions": extract_fixed_versions(title, summary, url),
            "discoverySource": "index produit public",
        })
    return result


class TopicMetadataParser(HTMLParser):
    """Read public metadata and visible text without relying on private endpoints."""

    IGNORED_TAGS = {"script", "style", "noscript", "svg"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.time_values: list[str] = []
        self.text_parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        if tag_name in self.IGNORED_TAGS:
            self.ignored_depth += 1
        attributes = dict(attrs)
        if tag_name == "meta":
            key = (
                attributes.get("property")
                or attributes.get("name")
                or attributes.get("itemprop")
                or ""
            ).strip().lower()
            value = (attributes.get("content") or "").strip()
            if key and value and key not in self.meta:
                self.meta[key] = value
        elif tag_name == "time":
            value = (attributes.get("datetime") or "").strip()
            if value:
                self.time_values.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self.IGNORED_TAGS and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.ignored_depth == 0 and data.strip():
            self.text_parts.append(data)


def extract_public_article_summary(value: str) -> str:
    """Extract explicit Description/Scope/Solution sections from a public article body."""
    text = clean(value)
    lowered = text.lower()
    starts = [lowered.find(marker) for marker in ("description", "scope")]
    starts = [position for position in starts if position >= 0]
    if not starts:
        return ""
    article = text[min(starts):]
    article_lower = article.lower()
    if "scope" not in article_lower or "solution" not in article_lower:
        return ""
    endings = [
        article_lower.find(marker)
        for marker in (
            "reference articles",
            "related document",
            "related articles",
            "upgrade procedure",
            "was this article helpful",
            "did you find this article helpful",
        )
    ]
    endings = [position for position in endings if position > 0]
    if endings:
        article = article[:min(endings)]
    return clean(article)[:5000]


def parse_topic_metadata(payload: str | bytes) -> dict:
    """Extract public article sections and explicit publication/update dates."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    parser = TopicMetadataParser()
    parser.feed(payload)
    parser.close()
    meta_summary = next((
        parser.meta[key]
        for key in ("og:description", "description", "twitter:description", "dc.description")
        if parser.meta.get(key)
    ), "")
    body_summary = extract_public_article_summary(" ".join(parser.text_parts))
    summary = body_summary or meta_summary
    date_value = next((
        parser.meta[key]
        for key in (
            "article:published_time", "datepublished", "datecreated",
            "dc.date.issued", "date", "og:updated_time", "article:modified_time",
        )
        if parser.meta.get(key)
    ), "")
    if not date_value and parser.time_values:
        date_value = parser.time_values[0]
    return {
        "summary": clean(summary)[:5000],
        "date": parse_date(date_value) if date_value else None,
    }


def fetch_topic_metadata(url: str) -> dict:
    """Fetch metadata from an ordinary public Community topic URL."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "community.fortinet.com":
        raise ValueError("URL Community invalide; seule la source publique Fortinet est autorisée.")
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        payload = response.read(1_000_000)
    return parse_topic_metadata(payload)


def enrich_board_topic_metadata(
    items: list[dict],
    known_topics: list[dict],
    detail_fetcher,
    errors: list[str],
    max_lookups: int = MAX_BOARD_DETAIL_LOOKUPS,
) -> list[dict]:
    """Enrich a small, fair sample of likely problems; keep index-only fields explicitly unknown."""
    now = datetime.now(timezone.utc)
    success_cutoff = (now - timedelta(hours=24)).isoformat()
    failure_cutoff = (now - timedelta(hours=DETAIL_FAILURE_RETRY_HOURS)).isoformat()
    known_by_url = {
        str(item.get("url") or item.get("id") or "").rstrip("/"): item
        for item in known_topics
        if isinstance(item, dict) and (item.get("url") or item.get("id"))
    }
    grouped: dict[str, list[dict]] = {}
    for item in items:
        if item.get("discoverySource") != "index produit public":
            continue
        title = item.get("title", "")
        url = str(item.get("url") or "").rstrip("/")
        if not url or not BOARD_DETAIL_RE.search(title):
            continue
        known = known_by_url.get(url, {})
        # Re-read every index-discovered topic once for a new parser version,
        # even when RSS already supplied a title, summary and date.
        if (
            known.get("detailFetchStatus") == "success"
            and known.get("detailParserVersion") == DETAIL_PARSER_VERSION
        ):
            continue
        attempted_at = str(known.get("detailAttemptedAt") or "")
        if attempted_at and attempted_at >= failure_cutoff:
            continue
        product = next(iter(item.get("categories") or item.get("products") or ["Autre"]), "Autre")
        grouped.setdefault(product, []).append(item)

    # Round-robin product families so FortiGate volume cannot starve the others.
    product_order = list(BOARD_SOURCES) + [p for p in grouped if p not in BOARD_SOURCES]
    selected: list[dict] = []
    while len(selected) < max_lookups:
        added = False
        for product in product_order:
            candidates = grouped.get(product) or []
            if candidates and len(selected) < max_lookups:
                selected.append(candidates.pop(0))
                added = True
        if not added:
            break

    for item in selected:
        url = item["url"]
        try:
            details = detail_fetcher(url)
            if not isinstance(details, dict):
                raise ValueError("la page détaillée n’a pas renvoyé de métadonnées valides")
            if details.get("summary"):
                item["summary"] = clean(str(details["summary"]))[:5000]
            if details.get("date"):
                item["date"] = details["date"]
            item["detailCheckedAt"] = now.isoformat()
            item["detailFetchStatus"] = "success"
            item["detailParserVersion"] = DETAIL_PARSER_VERSION
            item.pop("detailAttemptedAt", None)
        except (OSError, urllib.error.URLError, TimeoutError, UnicodeError, ValueError) as exc:
            errors.append(
                f"Enrichissement de la fiche Community impossible ({url}): "
                f"{type(exc).__name__}: {exc}; le titre et le lien d’index sont conservés."
            )
            # A failed request is not a successful check. Retry after a short
            # backoff rather than suppressing this URL for a full day.
            item["detailAttemptedAt"] = now.isoformat()
            item["detailFetchStatus"] = "failed"
            item.pop("detailCheckedAt", None)
            item.pop("detailParserVersion", None)
    return items


def fetch_board_topics(
    board_sources: dict[str, str] | None = None,
    max_pages: int | None = None,
    opener=None,
) -> dict:
    """Read a bounded set of public product-index pages without bypassing access controls."""
    sources = BOARD_SOURCES if board_sources is None else board_sources
    open_url = opener or urllib.request.urlopen
    discovered: dict[str, dict] = {}
    errors: list[str] = []
    pages: list[str] = []

    for product, board_url in sources.items():
        page_limit = max_pages if max_pages is not None else (
            SUPPORT_FORUM_MAX_PAGES if product == "Support Forum" else MAX_BOARD_PAGES
        )
        board_seen: set[str] = set()
        for page_number in range(1, page_limit + 1):
            page_url = (
                board_url.rstrip("/")
                if page_number == 1
                else f"{board_url.rstrip('/')}/index{page_number}.html"
            )
            request = urllib.request.Request(
                page_url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml",
                },
            )
            try:
                with open_url(request, timeout=12) as response:
                    payload = response.read(1_500_000)
            except urllib.error.HTTPError as exc:
                if exc.code == 404 and page_number > 1:
                    break
                errors.append(
                    f"Index Community {product} page {page_number} inaccessible "
                    f"(HTTP {exc.code}); les données déjà collectées sont conservées."
                )
                break
            except (OSError, urllib.error.URLError, TimeoutError, UnicodeError) as exc:
                errors.append(
                    f"Index Community {product} page {page_number} inaccessible "
                    f"({type(exc).__name__}: {exc}); les données déjà collectées sont conservées."
                )
                break

            entries = parse_board_page(payload, board_url, product)
            pages.append(page_url)
            if not entries:
                if page_number == 1:
                    errors.append(
                        f"Aucun sujet exploitable dans l’index public {product}; "
                        "la page peut être incomplète ou avoir changé."
                    )
                break

            new_entries = [entry for entry in entries if entry["url"] not in board_seen]
            if not new_entries:
                errors.append(
                    f"Pagination de l’index Community {product} répétée à la page {page_number}; arrêt de cette source."
                )
                break
            board_seen.update(entry["url"] for entry in new_entries)

            for entry in new_entries:
                key = entry["url"]
                if key not in discovered:
                    discovered[key] = entry
                    continue
                existing = discovered[key]
                existing["products"] = list(dict.fromkeys([
                    *(existing.get("products") or []),
                    *(entry.get("products") or []),
                ]))
                existing["categories"] = list(dict.fromkeys([
                    *(existing.get("categories") or []),
                    *(entry.get("categories") or []),
                ]))

    return {
        "topics": list(discovered.values()),
        "errors": errors,
        "pages": pages,
        "pageCount": len(pages),
        "topicCount": len(discovered),
    }


def merge_discovered_topics(primary: list[dict], secondary: list[dict]) -> list[dict]:
    """Merge RSS and index discoveries by canonical URL, preferring richer RSS metadata."""
    merged: dict[str, dict] = {}
    for item in [*primary, *secondary]:
        raw_key = item.get("url") or item.get("id")
        if not isinstance(raw_key, str) or not raw_key.strip():
            continue
        key = raw_key.rstrip("/")
        normalized = {**item, "id": key, "url": item.get("url") or key}
        if key not in merged:
            merged[key] = normalized
            continue
        existing = merged[key]
        combined = {**normalized, **existing}
        for field in ("products", "categories"):
            combined[field] = list(dict.fromkeys([
                *(existing.get(field) or []),
                *(normalized.get(field) or []),
            ]))
        # An index preview may reveal firmware versions that the capped RSS
        # entry omitted. Merge these explicit values instead of letting an
        # empty primary field erase the secondary discovery.
        for field in ("versions", "fixVersions"):
            versions = set(existing.get(field) or []) | set(normalized.get(field) or [])
            combined[field] = sorted(
                versions,
                key=lambda version: tuple(int(part) for part in str(version).split(".")),
            )
        for field in ("date", "summary"):
            if not combined.get(field) and normalized.get(field):
                combined[field] = normalized[field]
        if existing.get("summary"):
            combined.pop("discoverySource", None)
        elif not combined.get("discoverySource") and normalized.get("discoverySource"):
            combined["discoverySource"] = normalized["discoverySource"]
        merged[key] = combined
    return list(merged.values())


def legacy_tag_recheck_candidates(previous: dict, observed_ids: set[str]) -> list[dict]:
    """Repair older support-forum entries polluted by global product navigation."""
    candidates = []
    for raw in previous.get("topics", []):
        url = raw.get("url", "")
        if not url.startswith("https://community.fortinet.com/support-forum-92/"):
            continue
        topic_id = raw.get("id") or url
        if topic_id in observed_ids:
            continue
        title = raw.get("title", "")
        summary = raw.get("summary", "")
        if not needs_product_enrichment(title, summary):
            continue
        text = f"{title} {summary}"
        if any(
            re.search(pattern, text, re.I)
            for patterns in PRODUCT_ALIASES.values()
            for pattern in patterns
        ):
            continue
        products = raw.get("products", [])
        if len(products) < 4:
            continue
        item = dict(raw)
        item["products"] = []
        item["categories"] = [
            category for category in raw.get("categories", [])
            if category not in PRODUCT_ALIASES
        ]
        item["needsProductEnrichment"] = True
        candidates.append(item)
    return candidates


def load_previous(path: Path = OUT) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("topics"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"topics": []}


def collect(fetcher=fetch_feed, out: Path = OUT, topic_fetcher=None, board_fetcher=None, detail_fetcher=None) -> dict:
    previous = load_previous(out)
    now = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []
    raw_feed_count = 0
    feed_url = getattr(fetcher, "last_url", None) or previous.get("feedUrl", FEED_URL)
    fresh: list[dict] = []
    observed_ids: set[str] = set()
    board_page_count = 0
    board_topic_count = 0

    if topic_fetcher is None and fetcher is fetch_feed:
        topic_fetcher = fetch_topic_products

    try:
        feed_payload = fetcher()
        raw_feed_count = count_feed_entries(feed_payload)
        parsed = parse_feed(feed_payload)
        observed_ids = {item.get("id") or item.get("url") for item in parsed}
        fresh = enrich_unclassified_topics(parsed, topic_fetcher, errors, previous.get("topics", []))
        feed_url = getattr(fetcher, "last_url", None) or FEED_URL

        if topic_fetcher:
            stale_candidates = legacy_tag_recheck_candidates(previous, observed_ids)
            repaired = enrich_unclassified_topics(stale_candidates, topic_fetcher, errors, previous.get("topics", []))
            fresh = merge_discovered_topics(fresh, repaired)

        if not fresh and fetcher is fetch_feed and feed_url == EXTENDED_FEED_URL:
            # A syntactically valid but empty extended response is not evidence
            # that there are no topics; try the standard public feed as well.
            fallback_payload = fetcher(FEED_URL)
            raw_feed_count = count_feed_entries(fallback_payload)
            fallback_parsed = parse_feed(fallback_payload)
            observed_ids.update(item.get("id") or item.get("url") for item in fallback_parsed)
            fallback = enrich_unclassified_topics(fallback_parsed, topic_fetcher, errors, previous.get("topics", []))
            if topic_fetcher:
                stale_candidates = legacy_tag_recheck_candidates(previous, observed_ids)
                repaired = enrich_unclassified_topics(stale_candidates, topic_fetcher, errors, previous.get("topics", []))
                fallback = merge_discovered_topics(fallback, repaired)
            if fallback:
                fresh = fallback
                feed_url = getattr(fetcher, "last_url", None) or FEED_URL
                errors.append("Flux étendu accessible mais sans sujets reconnus; repli sur le flux standard.")

        errors.extend(getattr(fetcher, "last_errors", []))
        if fetcher is fetch_feed and feed_url == EXTENDED_FEED_URL and raw_feed_count < EXTENDED_FEED_COUNT:
            errors.append(
                f"Le flux Community a renvoyé {raw_feed_count} entrées brutes sur {EXTENDED_FEED_COUNT} demandées; "
                "la couverture complète des 30 derniers jours n'est pas garantie."
            )
    except (OSError, urllib.error.URLError, ET.ParseError, ValueError, TimeoutError) as exc:
        errors.extend(getattr(fetcher, "last_errors", []))
        errors.append(f"Flux RSS Fortinet Community indisponible: {type(exc).__name__}: {exc}")

    # Retry older unresolved records even when they have fallen out of the capped RSS feed.
    if topic_fetcher is not None:
        pending = pending_product_enrichment_candidates(previous.get("topics", []), observed_ids)
        if pending:
            retried = enrich_unclassified_topics(
                pending, topic_fetcher, errors, previous.get("topics", [])
            )
            fresh = merge_discovered_topics(fresh, retried)

    if board_fetcher is not None:
        try:
            board_result = board_fetcher()
            if not isinstance(board_result, dict):
                raise ValueError("le collecteur des index produit n’a pas renvoyé un objet de résultat")
            board_items = board_result.get("topics", [])
            if not isinstance(board_items, list):
                raise ValueError("la liste de sujets des index produit est invalide")
            board_errors = board_result.get("errors", [])
            if isinstance(board_errors, list):
                errors.extend(str(error) for error in board_errors if error)
            board_page_count = int(board_result.get("pageCount", len(board_result.get("pages", []))) or 0)
            board_topic_count = len(board_items)
            if detail_fetcher is not None:
                board_items = enrich_board_topic_metadata(
                    board_items,
                    [*previous.get("topics", []), *fresh],
                    detail_fetcher,
                    errors,
                )
            fresh = merge_discovered_topics(fresh, board_items)
        except (OSError, urllib.error.URLError, ValueError, TimeoutError) as exc:
            errors.append(
                f"Index produit Fortinet Community indisponibles: {type(exc).__name__}: {exc}; "
                "les données RSS et l’historique sont conservés."
            )

    if not fresh:
        if not any("aucun sujet Fortinet reconnu" in error for error in errors):
            errors.append("Flux RSS accessible mais aucun sujet Fortinet reconnu; collecte partielle.")
        if not previous.get("topics"):
            raise RuntimeError(
                "Aucune source Community n’a fourni de sujet Fortinet reconnu et aucun historique exploitable n’existe."
            )
        result = {
            **previous,
            "generatedAt": now,
            "feedUrl": feed_url or previous.get("feedUrl", FEED_URL),
            "partial": True,
            "errors": errors or ["Aucune source n’a fourni de nouveau sujet; l’historique existant est conservé."],
        }
        if board_fetcher is not None:
            result["boardPageCount"] = board_page_count
            result["boardTopicCount"] = board_topic_count
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        return result

    merged = {}
    for item in previous.get("topics", []):
        if not isinstance(item, dict):
            continue
        raw_key = item.get("id") or item.get("url")
        if isinstance(raw_key, str) and raw_key.strip():
            merged[raw_key.rstrip("/")] = item

    for item in fresh:
        raw_key = item.get("id") or item.get("url")
        if not isinstance(raw_key, str) or not raw_key.strip():
            continue
        key = raw_key.rstrip("/")
        old = merged.get(key, {})
        record = {
            **old,
            **item,
            "id": key,
            "url": item.get("url") or old.get("url") or key,
            "firstSeen": old.get("firstSeen", now),
            "lastSeen": now,
        }
        # A product index only supplies a title and link. It must never erase
        # richer metadata collected earlier from RSS or a detail page.
        if item.get("discoverySource") == "index produit public":
            for field in ("date", "summary", "versions", "fixVersions"):
                if old.get(field):
                    record[field] = old[field]
            record["products"] = list(dict.fromkeys([
                *(old.get("products") or []),
                *(item.get("products") or []),
            ]))
            for field in ("categories", "status", "statusNote", "source"):
                record.pop(field, None)
        if item.get("products") and not item.get("needsProductEnrichment"):
            record.pop("needsProductEnrichment", None)
        merged[key] = record

    topics = sorted(
        merged.values(),
        key=lambda item: item.get("date") or item.get("firstSeen") or "",
        reverse=True,
    )[:MAX_HISTORY]
    result = {
        "generatedAt": now,
        "feedUrl": feed_url,
        "feedItemCount": raw_feed_count,
        "requestedFeedItemCount": EXTENDED_FEED_COUNT if feed_url == EXTENDED_FEED_URL else None,
        "partial": bool(errors),
        "errors": errors,
        "topicCount": len(topics),
        "topics": topics,
        "_previousIncidents": previous.get("incidents", []),
    }
    if board_fetcher is not None:
        result["boardPageCount"] = board_page_count
        result["boardTopicCount"] = board_topic_count
    for key in (
        "aiReviewGeneratedAt", "aiReviewModel", "aiReviewNote",
        "aiReviewStatus", "aiReviewMessage", "aiReviewCheckedAt",
    ):
        if key in previous:
            result[key] = previous[key]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return result


def main() -> int:
    result = collect(board_fetcher=fetch_board_topics, detail_fetcher=fetch_topic_metadata)
    print(f"Collecte terminée : {len(result.get('topics', []))} sujets conservés; partielle={result.get('partial', False)}")
    for error in result.get("errors", []):
        print(f"AVERTISSEMENT: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
