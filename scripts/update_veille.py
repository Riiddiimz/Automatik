#!/usr/bin/env python3
"""Fetch official public security feeds and write a normalized JSON file."""
from datetime import datetime, timezone
from html.parser import HTMLParser
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
    # CISA's official CSAF feeds are mirrored in its public GitHub repository.
    # They remain machine-readable when cisa.gov RSS endpoints return HTTP 403
    # to hosted automation runners.
    ("cyber", "CISA Cybersecurity Advisories", "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json"),
    ("cyber", "CISA ICS Advisories", "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"),
    # CERT-FR is an independent source, not a substitute for CISA. Collect it
    # separately so a CISA outage is visible and the previous CISA cache survives.
    ("cyber", "CERT-FR", "https://www.cert.ssi.gouv.fr/feed/"),
    # Official Fortinet CISO Collective feed: catches coordinated security releases
    # that may precede the detailed PSIRT advisories.
    ("cyber", "Fortinet CISO Collective", "https://feeds.fortinet.com/fortinet/blog/ciso-collective"),
]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FORTINET_SECURITY_MATRIX_URL = "https://www.fortinet.com/blog/ciso-collective/fortinet-releases-security-hardening-release-for-multiple-products"


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


class SecurityMatrixTableParser(HTMLParser):
    """Extract table rows without depending on third-party HTML libraries."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self.current_row = None
        self.current_cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            if self.current_row is not None:
                self._finish_row()
            self.current_row = []
        elif tag in ("td", "th") and self.current_row is not None:
            self.current_cell = []

    def handle_data(self, data):
        if self.current_cell is not None:
            self.current_cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.current_cell is not None and self.current_row is not None:
            self.current_row.append(re.sub(r"\s+", " ", " ".join(self.current_cell)).strip())
            self.current_cell = None
        elif tag == "tr":
            self._finish_row()

    def _finish_row(self):
        if self.current_cell is not None and self.current_row is not None:
            self.current_row.append(re.sub(r"\s+", " ", " ".join(self.current_cell)).strip())
        if self.current_row:
            self.rows.append(self.current_row)
        self.current_row = None
        self.current_cell = None


def _published_year(published_at):
    if published_at:
        try:
            return datetime.fromisoformat(published_at.replace("Z", "+00:00")).year
        except (AttributeError, TypeError, ValueError):
            pass
    return datetime.now(timezone.utc).year


def _availability_date(value, published_at):
    year = _published_year(published_at)
    if value.strip().lower() == "today":
        try:
            return datetime.fromisoformat(published_at.replace("Z", "+00:00")).date().isoformat()
        except (AttributeError, TypeError, ValueError):
            return None
    try:
        return datetime.strptime(f"{value.strip()} {year}", "%B %d %Y").date().isoformat()
    except (TypeError, ValueError):
        return None


def parse_fortinet_security_matrix(payload, published_at=None, checked_at=None):
    """Parse Fortinet's published affected/fixed-version matrix from its CISO article."""
    if isinstance(payload, bytes):
        html_document = payload.decode("utf-8", errors="replace")
    else:
        html_document = str(payload or "")

    parser = SecurityMatrixTableParser()
    parser.feed(html_document)
    parser.close()

    header_index = None
    for index, row in enumerate(parser.rows):
        normalized = [
            re.sub(r"[^a-z]+", " ", cell.lower()).strip()
            for cell in row[:4]
        ]
        if (
            len(normalized) == 4
            and normalized[0] == "product"
            and normalized[1] == "affected versions"
            and normalized[2] == "fixed version"
            and normalized[3] == "availability"
        ):
            header_index = index
            break

    if header_index is None:
        raise ValueError("tableau officiel des versions affectées/corrigées introuvable")

    items = []
    for row in parser.rows[header_index + 1:]:
        if len(row) < 4:
            continue
        product_match = re.match(r"^(Forti[A-Za-z]+)\s+(\d{1,2}\.\d{1,2})$", row[0], re.I)
        if not product_match:
            continue
        product, branch = product_match.groups()
        affected_versions, fixed_version, availability = (value.strip() for value in row[1:4])
        if not affected_versions or not fixed_version or not availability:
            continue
        items.append({
            "product": product,
            "branch": branch,
            "affectedVersions": affected_versions,
            "fixedVersion": fixed_version,
            "availability": availability,
            "availableAt": _availability_date(availability, published_at),
        })

    if not items:
        raise ValueError("le tableau officiel a été trouvé mais aucune ligne produit exploitable n'a été extraite")

    plain_text = clean_html(html_document)
    disclosure_match = re.search(
        r"public advisories will be made available at the next Patch Tuesday on\s+([A-Za-z]+\s+\d{1,2})",
        plain_text,
        re.I,
    )
    disclosure_date = None
    if disclosure_match:
        try:
            disclosure_date = datetime.strptime(
                f"{disclosure_match.group(1)} {_published_year(published_at)}",
                "%B %d %Y",
            ).date().isoformat()
        except ValueError:
            pass

    severity_note = (
        "Fortinet qualifie globalement ces mises à jour de correctifs critiques et élevés; "
        "la sévérité par CVE n'est pas détaillée dans cette annonce."
        if re.search(r"critical and high-severity fixes", plain_text, re.I)
        else "Le niveau de sévérité n'est pas précisé dans cette annonce."
    )
    return {
        "title": "Fortinet Releases Security Hardening Release for Multiple Products",
        "source": FORTINET_SECURITY_MATRIX_URL,
        "publishedAt": published_at,
        "checkedAt": checked_at or datetime.now(timezone.utc).isoformat(),
        "disclosureDate": disclosure_date,
        "severityNote": severity_note,
        "note": (
            "Cette matrice indique les plages affectées et les versions correctives annoncées. "
            "Les identifiants CVE et les détails techniques par vulnérabilité ne figurent pas dans cette page; "
            "consulter les avis PSIRT détaillés avant toute décision de remédiation."
        ),
        "items": items,
    }


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
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            # Naive ISO timestamps have no declared timezone; interpret them as UTC
            # instead of inheriting the runner's local timezone.
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError):
            return value


def parse_rss(payload, source, label, limit=20):
    # CISA publishes official CSAF/ROLIE JSON feeds as well as RSS.
    # Parse the feed index directly; individual advisory links remain canonical raw JSON.
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        document = None
    feed = document.get("feed") if isinstance(document, dict) else None
    if isinstance(feed, dict) and isinstance(feed.get("entry"), list):
        entries = []
        for item in feed["entry"][:limit]:
            content = item.get("content") or {}
            links = item.get("link") or []
            url = content.get("src") or next(
                (link.get("href", "") for link in links if link.get("rel") == "self"),
                "",
            )
            if not url:
                continue
            entries.append({
                "source": source,
                "label": label,
                "title": item.get("title") or item.get("id") or "Avis CISA sans titre",
                "url": url,
                "date": parse_date(item.get("published") or item.get("updated") or ""),
                "summary": "Avis de sécurité CISA publié au format structuré CSAF.",
            })
        return entries

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

    data = {"generatedAt": datetime.now(timezone.utc).isoformat(), "fortinet": [], "cyber": [], "kev": [], "errors": [], "fortinetSecurityUpdates": previous.get("fortinetSecurityUpdates")}
    for section, source, configured_urls in FEEDS:
        urls = configured_urls if isinstance(configured_urls, (tuple, list)) else (configured_urls,)
        last_error = None
        items = []
        for configured_url in urls:
            if isinstance(configured_url, (tuple, list)) and len(configured_url) == 2:
                url, feed_source = configured_url
            else:
                url, feed_source = configured_url, source
            try:
                items = parse_rss(fetch(url), feed_source, "PSIRT" if section == "fortinet" else feed_source, limit=20)
                if not items:
                    raise ValueError("flux accessible mais aucun élément RSS reconnu")
                break
            except (urllib.error.URLError, TimeoutError, ET.ParseError, OSError, ValueError) as exc:
                last_error = exc
        if items:
            data[section].extend(items)
        else:
            exc = last_error or ValueError("aucun flux de secours disponible")
            data["errors"].append(f"{source}: {type(exc).__name__}: {exc}")
            # Keep the last known records from this specific feed instead of erasing them.
            stale_items = [item for item in previous.get(section, []) if item.get("source") == source]
            data[section].extend(stale_items)

    hardening_notice = next(
        (
            item for item in data["cyber"]
            if item.get("source") == "Fortinet CISO Collective"
            and "security hardening release" in (item.get("title") or "").lower()
        ),
        None,
    )
    if hardening_notice:
        try:
            article_payload = fetch(FORTINET_SECURITY_MATRIX_URL)
            data["fortinetSecurityUpdates"] = parse_fortinet_security_matrix(
                article_payload,
                published_at=hardening_notice.get("date"),
                checked_at=data["generatedAt"],
            )
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError) as exc:
            data["errors"].append(
                f"Matrice de sécurité Fortinet: {type(exc).__name__}: {exc}; "
                "la dernière matrice valide est conservée."
            )

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
    display_path = OUT.relative_to(ROOT) if OUT.is_relative_to(ROOT) else OUT
    print(f"Écrit {display_path} : {len(data['fortinet'])} avis Fortinet, {len(data['cyber'])} actualités, {len(data['kev'])} entrées KEV.")
    if data["errors"]:
        print("Sources en erreur (les données précédentes sont conservées lorsqu'elles existent) :")
        for error in data["errors"]:
            print(f"- {error}")


if __name__ == "__main__":
    main()
