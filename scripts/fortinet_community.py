#!/usr/bin/env python3
"""Collect public Fortinet Community topic pages without authentication.

This scraper deliberately does not bypass access controls. Unavailable category pages
are reported as partial collection and their previously collected records are retained.
"""
from datetime import datetime, timezone, timedelta
from html.parser import HTMLParser
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "veille.json"
BASE = "https://community.fortinet.com"
USER_AGENT = "AutomatikCyberVeille/1.0 (+https://github.com/Riiddiimz/Automatik)"
WINDOW_DAYS = 30
MAX_TOPICS_PER_PRODUCT = 40
PRODUCTS = {
    "FortiGate / FortiOS": ("https://community.fortinet.com/fortigate-3/", ("fortigate", "fortios", "fortigate-")),
    "FortiManager": ("https://community.fortinet.com/fortimanager-27/", ("fortimanager", "fmg")),
    "FortiAuthenticator": ("https://community.fortinet.com/fortiauthenticator-8/", ("fortiauthenticator", "fac")),
    "FortiClient EMS": ("https://community.fortinet.com/support-forum-92/", ("forticlient ems", "forticlient-ems", "ems")),
    "FortiAnalyzer": ("https://community.fortinet.com/fortianalyzer-6/", ("fortianalyzer", "faz")),
    "FortiClient": ("https://community.fortinet.com/forticlient-4/", ("forticlient", "forti client")),
}
VERSION_RE = re.compile(r"(?i)\b(?:FortiOS|FortiGate|FortiManager|FortiAuthenticator|FortiClient(?:\s+EMS)?|FortiAnalyzer)?\s*v?((?:[5678]\.\d+(?:\.\d+){0,2})(?:\s*build\s*\d+)?)\b")


def clean(value):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", value or "")).strip()


class TopicParser(HTMLParser):
    """Extract topic-like links and their surrounding card text from public HTML."""
    def __init__(self, page_url):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links = []
        self.current = None
        self.depth = 0
        self.capture = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        href = attrs.get("href", "")
        full = urljoin(self.page_url, href)
        path = urlparse(full).path
        is_topic = urlparse(full).netloc.endswith("fortinet.com") and (
            "/support-forum-92/" in path or "/t5/" in path or re.search(r"-\d{5,}(?:/|$)", path)
        )
        if tag == "a" and is_topic and not self.capture:
            self.current = {"url": full, "title": "", "text": ""}
            self.capture = True
        if self.capture:
            self.depth += 1

    def handle_data(self, data):
        if self.capture and self.current is not None:
            text = clean(data)
            if text:
                self.current["text"] += " " + text

    def handle_endtag(self, tag):
        if self.capture:
            self.depth -= 1
            if tag == "a" and self.current is not None:
                item = self.current
                item["text"] = clean(item["text"])
                item["title"] = item["text"][:240]
                self.links.append(item)
                self.current = None
                self.capture = False
                self.depth = 0


def fetch_page(url, timeout=20):
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}")
        return response.read().decode("utf-8", errors="replace")


def classify(title, body=""):
    text = (title + " " + body).lower()
    if any(word in text for word in ("fixed in", "resolved in", "workaround", "solution", "solved")):
        return "solution/correctif signalé"
    if any(word in text for word in ("bug", "regression", "regression", "crash", "hang", "fails", "not working", "issue", "error")):
        return "bug rapporté non confirmé"
    if any(word in text for word in ("how to", "how do i", "configure", "configuration", "question", "help")):
        return "question de configuration"
    return "demande d'aide ou discussion"


def extract_version(text):
    match = VERSION_RE.search(text or "")
    return match.group(1).strip() if match else "non précisé"


def parse_topics(html, product, page_url, now=None, keywords=()):
    now = now or datetime.now(timezone.utc)
    parser = TopicParser(page_url)
    parser.feed(html)
    cutoff = now - timedelta(days=WINDOW_DAYS)
    output, seen = [], set()
    for item in parser.links:
        url = item["url"].split("#", 1)[0]
        if url in seen or not item["title"] or len(item["title"]) < 8:
            continue
        seen.add(url)
        title = item["title"]
        if keywords and not any(word.lower() in title.lower() for word in keywords):
            continue
        # Topic-card timestamps are not consistently exposed in the new public UI;
        # do not invent a publication date when it cannot be parsed.
        version = extract_version(title + " " + item["text"])
        output.append({
            "product": product,
            "category": "Communauté Fortinet",
            "title": title,
            "url": url,
            "publishedAt": None,
            "updatedAt": None,
            "versions": [version] if version != "non précisé" else [],
            "versionLabel": version,
            "symptom": title,
            "impact": "À confirmer dans le sujet source.",
            "status": classify(title),
            "resolution": "non précisé",
            "fixedVersion": "à confirmer",
            "confidence": "faible — métadonnées à vérifier dans la page du sujet",
            "sourcePage": page_url,
        })
        if len(output) >= MAX_TOPICS_PER_PRODUCT:
            break
    return output


def collect(previous=None, fetcher=fetch_page, now=None):
    previous = previous or []
    now = now or datetime.now(timezone.utc)
    result, errors, successes = [], [], []
    old_by_url = {item.get("url"): item for item in previous if item.get("url")}
    for product, (url, keywords) in PRODUCTS.items():
        try:
            html = fetcher(url)
            items = parse_topics(html, product, url, now, keywords=keywords)
            if not items:
                raise ValueError("aucun sujet reconnu dans le HTML public")
            successes.append(product)
            for item in items:
                old = old_by_url.get(item["url"], {})
                # Preserve useful metadata from previous manually/previously enriched records.
                for field in ("publishedAt", "updatedAt", "symptom", "impact", "status", "resolution", "fixedVersion", "confidence", "versions", "versionLabel"):
                    if (not item.get(field) or item.get(field) in ("non précisé", "à confirmer", "À confirmer dans le sujet source.", "faible — métadonnées à vérifier dans la page du sujet")) and old.get(field):
                        item[field] = old[field]
                result.append(item)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            errors.append(f"{product}: {type(exc).__name__}: {exc}")
            # Preserve previous records for this product on a failed category fetch.
            result.extend(item for item in previous if item.get("product") == product)
    # Keep history; URL is the stable deduplication key and newly collected details win.
    by_url = {item["url"]: item for item in result if item.get("url")}
    for item in previous:
        if item.get("url") and item["url"] not in by_url:
            by_url[item["url"]] = item
    return sorted(by_url.values(), key=lambda item: item.get("publishedAt") or item.get("updatedAt") or "", reverse=True), errors, successes


def update_file():
    try:
        data = json.loads(OUT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    previous = data.get("community", [])
    items, errors, successes = collect(previous)
    # A total source failure must never erase the last known good collection.
    if successes:
        data["community"] = items
    data.setdefault("errors", [])
    data["errors"] = [e for e in data["errors"] if not e.startswith("Fortinet Community:")]
    data["errors"].extend("Fortinet Community: " + e for e in errors)
    data["communityStatus"] = {
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "status": "partial" if errors else ("ok" if successes else "failed"),
        "successfulProducts": successes,
        "failedProducts": errors,
        "windowDays": WINDOW_DAYS,
    }
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Fortinet Community: {len(items)} sujets conservés; {len(successes)}/6 catégories consultées.")
    for error in errors:
        print(f"Source communauté en erreur: {error}")


if __name__ == "__main__":
    update_file()
