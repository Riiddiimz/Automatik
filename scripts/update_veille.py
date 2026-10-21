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
    data = {"generatedAt": datetime.now(timezone.utc).isoformat(), "fortinet": [], "cyber": [], "kev": [], "errors": []}
    for section, source, url in FEEDS:
        try:
            items = parse_rss(fetch(url), source, "PSIRT" if section == "fortinet" else source, limit=20)
            data[section].extend(items)
            if not items:
                data["errors"].append(f"{source}: flux accessible mais aucun élément RSS reconnu.")
        except (urllib.error.URLError, TimeoutError, ET.ParseError, OSError, ValueError) as exc:
            data["errors"].append(f"{source}: {type(exc).__name__}: {exc}")
    try:
        payload = json.loads(fetch(KEV_URL).decode("utf-8"))
        data["kev"] = payload.get("vulnerabilities", [])[:100]
        if not data["kev"]:
            data["errors"].append("CISA KEV: aucun élément trouvé dans la réponse JSON.")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        data["errors"].append(f"CISA KEV: {type(exc).__name__}: {exc}")
    # Sort newest first while keeping records without dates at the end.
    for section in ("fortinet", "cyber"):
        data[section].sort(key=lambda item: item.get("date") or "", reverse=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Écrit {OUT.relative_to(ROOT)} : {len(data['fortinet'])} avis Fortinet, {len(data['cyber'])} actualités, {len(data['kev'])} entrées KEV.")
    if data["errors"]:
        print("Sources en erreur :")
        for error in data["errors"]:
            print(f"- {error}")
    # Don't fail the whole update because one external source is temporarily unavailable.
    if not data["fortinet"] and not data["cyber"] and not data["kev"]:
        raise SystemExit("Aucune source n'a fourni de données : le fichier n'a pas de contenu utile.")


if __name__ == "__main__":
    main()
