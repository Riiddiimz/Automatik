#!/usr/bin/env python3
"""Fetch official public security feeds and write a normalized JSON file."""
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "veille.json"
USER_AGENT = "AutomatikCyberVeille/1.0 (+https://github.com/Riiddiimz/Automatik)"
FEEDS = [
    ("fortinet", "FortiGuard PSIRT", "https://fortiguard.fortinet.com/rss/ir.xml"),
    ("cyber", "FortiGuard Outbreak Alerts", "https://filestore.fortinet.com/fortiguard/rss/outbreakalert.xml"),
    ("cyber", "CISA Cybersecurity Advisories", "https://www.cisa.gov/news-events/cybersecurity-advisories?feed=rss"),
]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(url, timeout=25):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/json, */*"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def text_of(parent, *names):
    for name in names:
        element = parent.find(name)
        if element is not None and element.text:
            return element.text.strip()
    return ""


def clean_html(value):
    value = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", value or "", flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def parse_date(value):
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError):
            return value


def parse_rss(payload, source, label, limit=20):
    root = ET.fromstring(payload)
    entries = []
    # RSS 2.0
    for item in root.findall(".//item")[:limit]:
        entries.append({
            "source": source,
            "label": label,
            "title": text_of(item, "title") or "Publication sans titre",
            "url": text_of(item, "link"),
            "date": parse_date(text_of(item, "pubDate", "{http://purl.org/dc/elements/1.1/}date")),
            "summary": clean_html(text_of(item, "description", "{http://www.w3.org/2005/Atom}summary"))[:360],
        })
    # Atom fallback
    if not entries:
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for item in root.findall(".//atom:entry", ns)[:limit]:
            link = item.find("atom:link", ns)
            entries.append({
                "source": source,
                "label": label,
                "title": text_of(item, "{http://www.w3.org/2005/Atom}title") or "Publication sans titre",
                "url": link.attrib.get("href", "") if link is not None else "",
                "date": parse_date(text_of(item, "{http://www.w3.org/2005/Atom}published", "{http://www.w3.org/2005/Atom}updated")),
                "summary": clean_html(text_of(item, "{http://www.w3.org/2005/Atom}summary", "{http://www.w3.org/2005/Atom}content"))[:360],
            })
    return entries


def main():
    previous = {"fortinet": [], "cyber": [], "kev": []}
    try:
        previous = json.loads(OUT.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        # First run or invalid old data: continue with empty fallbacks.
        pass

    data = {"generatedAt": datetime.now(timezone.utc).isoformat(), "fortinet": [], "cyber": [], "kev": [], "errors": []}
    for section, source, url in FEEDS:
        try:
            items = parse_rss(fetch(url), source, "PSIRT" if section == "fortinet" else source, limit=20)
            if not items:
                raise ValueError("flux accessible mais aucun élément RSS reconnu")
            data[section].extend(items)
        except (urllib.error.URLError, TimeoutError, ET.ParseError, OSError, ValueError) as exc:
            data["errors"].append(f"{source}: {type(exc).__name__}: {exc}")
            # Keep the last known records from this specific feed instead of erasing them.
            stale_items = [item for item in previous.get(section, []) if item.get("source") == source]
            data[section].extend(stale_items)

    try:
        payload = json.loads(fetch(KEV_URL).decode("utf-8"))
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            raise ValueError("réponse KEV invalide ou vide")
        data["kev"] = vulnerabilities[:100]
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        data["errors"].append(f"CISA KEV: {type(exc).__name__}: {exc}")
        # Keep the previous catalogue if the upstream endpoint fails temporarily.
        data["kev"] = previous.get("kev", [])[:100]

    # Sort newest first while keeping records without dates at the end.
    for section in ("fortinet", "cyber"):
        data[section].sort(key=lambda item: item.get("date") or "", reverse=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not data["fortinet"] and not data["cyber"] and not data["kev"]:
        raise SystemExit("Aucune source n'a fourni de données et aucun cache précédent n'est disponible.")
    print(f"Écrit {OUT} : {len(data['fortinet'])} avis Fortinet, {len(data['cyber'])} actualités, {len(data['kev'])} entrées KEV.")
    if data["errors"]:
        print("Sources en erreur (les données précédentes sont conservées lorsqu'elles existent) :")
        for error in data["errors"]:
            print(f"- {error}")


if __name__ == "__main__":
    main()
