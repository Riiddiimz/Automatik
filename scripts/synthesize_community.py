#!/usr/bin/env python3
"""Construit des fiches de veille regroupées à partir des sujets Fortinet collectés.

Sans service IA externe : regroupement déterministe et synthèse structurée depuis les sources.
Les fiches restent des signaux à vérifier, pas des bugs officiellement confirmés.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "community.json"
STOP = {
    "the", "and", "for", "with", "from", "when", "after", "before", "into", "using",
    "this", "that", "have", "has", "are", "was", "were", "not", "unable", "issue",
    "problem", "troubleshooting", "tip", "technical", "fortinet", "fortigate", "fortios",
    "forticlient", "fortimanager", "fortianalyzer", "fortiauthenticator", "version",
    "versions", "user", "users", "device", "devices", "solution", "how", "to",
}

# Explicitly different FortiGate inspection modes can describe different failure paths.
MODE_CONTEXTS = ("proxy mode", "flow mode", "transparent mode", "tunnel mode")
ISSUE_RE = re.compile(
    r"\b(bug|broken|fail(?:s|ed|ure)?|error|unable|not working|stops? working|"
    r"does not work|doesn't work|not responding|does not respond|no response from|rejects? authentication|crash(?:es|ed)?|hang(?:s|ing)?|drop(?:s|ped|ping)?|"
    r"disconnect(?:s|ed|ion)?|intermittent|regression|unexpected|incorrect|wrong|"
    r"no longer|after upgrade|since upgrade|change(?:d|s)? behavior|behavio[u]?r change|"
    r"not displayed|not shown|not included|not supported|cannot|can't|cannot save|packet loss|bypass(?:es|ed)?|"
    r"fails to|missing|stuck|timeout|timed out)\b",
    re.I,
)
VERSION_CONTEXT_RE = re.compile(
    r"\b(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|forticlient(?:\s+(?:ems|vpn))?|fortiswitch|fortiap|firmware)\s*(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)",
    re.I,
)
UPGRADE_PATH_RE = re.compile(
    r"\b(?:upgrad(?:e|ed|ing|es)|firmware update)\b[^.!?]{0,120}?\b(?:from\s+)?(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b[^.!?]{0,80}?\bto\s+(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
UPGRADE_TARGET_RE = re.compile(
    r"\b(?:upgrad(?:e|ed|ing|es)|firmware update)\b[^.!?]{0,100}?\bto\s+(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
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
    r"macos(?:\s+[a-z]+)?|mac\s+os(?:\s+[a-z]+)?|os\s+x|android|ipados?|ios|vmware\s+esxi|esxi|proxmox|freebsd|openbsd|"
    r"suse|opensuse)\s*(?:version\s*)?v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?\b",
    re.I,
)
PRODUCT_PATTERNS = {
    "FortiGate": r"\bfortigate\b|\bfortios\b",
    "FortiManager": r"\bfortimanager\b",
    "FortiAnalyzer": r"\bfortianalyzer\b",
    "FortiAuthenticator": r"\bfortiauthenticator\b",
    "FortiClient EMS": r"\bforticlient\s*ems\b|\bfcems\b",
    "FortiClient": r"\bforticlient\b",
    "FortiSwitch": r"\bfortiswitch\b",
    "FortiAP": r"\bfortiap\b",
}


def norm(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower()).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def words(text: str) -> set[str]:
    return {w for w in norm(text).split() if len(w) > 2 and w not in STOP and not w.isdigit()}


def extract_products(item: dict) -> list[str]:
    title = item.get("title", "")
    summary = item.get("summary", "")
    url = item.get("url", "")
    # The forum board slug is a better product signal than a mention in an article's body.
    board_match = re.search(r"https?://community\.fortinet\.com/([^/]+)", url, re.I)
    board = board_match.group(1).lower() if board_match else ""
    board_aliases = {
        "fortigate": "FortiGate", "fortimanager": "FortiManager",
        "fortianalyzer": "FortiAnalyzer", "fortiauthenticator": "FortiAuthenticator",
        "forticlient-ems": "FortiClient EMS", "forticlientems": "FortiClient EMS", "forticlient": "FortiClient",
        "fortiswitch": "FortiSwitch", "fortiap": "FortiAP",
    }
    primary = next((name for slug, name in board_aliases.items() if board.startswith(slug)), None)
    # Prefer products explicitly named in the title; use the body only as a fallback.
    title_found = [name for name, pattern in PRODUCT_PATTERNS.items() if re.search(pattern, title, re.I)]
    if primary:
        found = list(dict.fromkeys([primary] + title_found))
        # Official knowledge articles often scope one issue to several products
        # even when the article is hosted on a single product board.
        if source_type(item) == "fortinet_article":
            scope = re.search(
                r"\bScope\s*[:\-]?\s*(.*?)(?=Solution|Workaround|$)",
                summary, re.I | re.S,
            )
            if scope:
                scope_products = [
                    name for name, pattern in PRODUCT_PATTERNS.items()
                    if re.search(pattern, scope.group(1), re.I)
                ]
                found = list(dict.fromkeys(found + scope_products))
    else:
        text = title + " " + summary
        found = [name for name, pattern in PRODUCT_PATTERNS.items() if re.search(pattern, text, re.I)]
    if "FortiClient EMS" in found:
        found = [p for p in found if p != "FortiClient"]
    return found or item.get("products", [])


def extract_versions(item: dict) -> tuple[list[str], list[str]]:
    title = item.get("title", "")
    summary = item.get("summary", "")
    # RSS/HTML cleanup can concatenate section labels and their values.
    summary = re.sub(
        r"\b(?i:Description|Scope|Solution|Workaround|Impact)(?=[A-Z])",
        lambda match: match.group(0) + " ",
        summary,
    )
    text = title + " " + summary
    if source_type(item) == "fortinet_article":
        scope = re.search(
            r"\bScope\s*:?\s*(.*?)(?=\b(?:Solution|Workaround|Impact|Description)\b|$)",
            summary, re.I | re.S,
        )
        if scope:
            # Use the title and Scope only; Solution/Workaround versions may be fixes,
            # not releases affected by the problem.
            text = title + " " + scope.group(1)
    # Remove complete IPv4 addresses before looking for dotted version numbers.
    text_without_ips = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text)
    # Do not misclassify a documented fixed release as an affected release.
    text_without_ips = FIXED_VERSION_RE.sub(" ", text_without_ips)
    # Exclude operating-system/platform versions, which are not Fortinet firmware.
    text_without_ips = NON_FORTINET_VERSION_RE.sub(" ", text_without_ips)
    # Exclude elapsed-time decimals such as "0.7 seconds".
    text_without_ips = re.sub(
        r"\b\d+(?:\.\d+)?\s*(?:seconds?|secs?|milliseconds?|msecs?|minutes?|mins?|hours?|hrs?)\b",
        " ", text_without_ips, flags=re.I,
    )
    text_without_ips = re.sub(
        r"\b(?:dig|openssl|python|curl|wget|iperf3?|ping)\s+v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?\b",
        " ", text_without_ips, flags=re.I,
    )
    found = set(VERSION_CONTEXT_RE.findall(text_without_ips))
    for source_version, target_version in UPGRADE_PATH_RE.findall(text_without_ips):
        found.update((source_version, target_version))
    found.update(UPGRADE_TARGET_RE.findall(text_without_ips))
    exact = sorted(found, key=lambda v: tuple(int(x) for x in v.split(".")))
    families = sorted({ ".".join(v.split(".")[:2]) for v in exact }, key=lambda v: tuple(int(x) for x in v.split(".")))
    return exact, families


def looks_like_problem(item: dict) -> bool:
    title = item.get("title", "")
    summary = item.get("summary", "")
    # Do not turn an ordinary how-to article into an incident just because its instructions mention
    # something that cannot be configured. For those articles, require an explicit failure in title.
    if re.match(r"^(technical tip|how to|configuration guide)", title, re.I) and not ISSUE_RE.search(title):
        return False
    if ISSUE_RE.search(title):
        return True
    return bool(re.search(r"\b(known issue|known bug|bug id|regression|issue occurs|failure occurs|stops working|not working|broken after upgrade)\b", summary[:1200], re.I))


def title_tokens(item: dict) -> set[str]:
    """Normalize common Fortinet wording variants before comparing issue titles."""
    title = norm(item.get("title", ""))
    # These are phrasing variants, not evidence that two reports are the same bug.
    # Product/version compatibility and the similarity threshold still apply.
    replacements = (
        (r"\b(?:firmware|software) update\b", "upgrade"),
        (r"\b(?:upgrading|upgraded)\b", "upgrade"),
        (r"\b(?:not responding|does not respond|no response from|unresponsive)\b", "failure"),
        (r"\b(?:does not work|doesnt work|not working|broken|fails?|failed|failing|failure|errors?)\b", "failure"),
        (r"\b(?:wi\s+fi|wifi|wireless)\b", "wireless"),
        (r"\b(?:fortiap|aps?|access points?)\b", "wireless"),
        (r"\b(?:not connected|unable to connect|cannot connect|can't connect|not connecting|no longer connecting)\b", "connectivity"),
        (r"\b(?:single sign on|single sign-on|sso)\b", "sso"),
        (r"\b(?:ssl vpn|sslvpn)\b", "sslvpn"),
        (r"\b(?:password policy|password complexity policy|password requirements)\b", "passwordpolicy"),
        (r"\b(?:radius authentication|authentication via radius|authentication using radius)\b", "radius"),
        (r"\b(?:saml authentication|saml single sign on|saml sso)\b", "saml"),
    )
    for pattern, replacement in replacements:
        title = re.sub(pattern, replacement, title)
    return {w for w in title.split() if len(w) > 2 and w not in STOP and not w.isdigit()}


def source_type(item: dict) -> str:
    """Distinguish user reports from Fortinet-authored Community knowledge articles."""
    match = re.search(r"https?://community\.fortinet\.com/([^/]+)/", item.get("url", ""), re.I)
    if not match:
        return "unknown"
    slug = match.group(1).lower()
    if slug.startswith("support-forum") or slug == "t5":
        return "forum_discussion"
    official_prefixes = (
        "fortigate-", "fortimanager-", "fortianalyzer-", "fortiauthenticator-",
        "forticlient-ems-", "forticlient-", "fortiswitch-", "fortiap-",
    )
    if slug.startswith(official_prefixes):
        return "fortinet_article"
    return "unknown"


def extract_sections(item: dict) -> dict:
    """Extract only explicitly labelled sections from Fortinet-authored articles."""
    empty = {"symptom": "", "impact": "", "solution": ""}
    if source_type(item) != "fortinet_article":
        return empty

    text = re.sub(r"\s+", " ", item.get("summary", "")).strip()
    text = re.sub(
        r"\b(?i:Description|Scope|Solution|Workaround|Impact)(?=[A-Z])",
        lambda match: match.group(0) + " ",
        text,
    )

    def section(label: str, stop_labels: str) -> str:
        match = re.search(rf"{label}\s*:?\s*(.*?)(?={stop_labels}|$)", text, re.S)
        if not match:
            return ""
        value = re.sub(r"\s+", " ", match.group(1)).strip(" \t\r\n:.-")
        return value[:1200]

    symptom = section("Description", r"Scope|Solution|Workaround|Impact")
    impact = section("Impact", r"Scope|Solution|Workaround|Description")
    solution = section("Solution", r"Workaround|Impact|Scope|Description")
    workaround = section("Workaround", r"Impact|Scope|Description|Solution")
    if workaround:
        solution = f"{solution} Contournement : {workaround}".strip()
    return {"symptom": symptom, "impact": impact, "solution": solution}


def extract_fixed_versions(item: dict) -> list[str]:
    """Return explicitly stated fixed releases from Fortinet-authored articles only."""
    if source_type(item) != "fortinet_article":
        return []
    found = set(FIXED_VERSION_RE.findall(
        f"{item.get('title', '')} {item.get('summary', '')}"
    ))
    return sorted(found, key=lambda version: tuple(int(part) for part in version.split(".")))


def has_documented_evidence(item: dict) -> bool:
    """Require an explicit, scoped Fortinet issue; missing versions remain explicitly unknown."""
    if source_type(item) != "fortinet_article":
        return False
    title = item.get("title", "")
    text = title + " " + item.get("summary", "")
    known_issue = re.search(r"\b(known issue|known bug|bug id|bug #[0-9]+|bug number)\b", text, re.I)
    behavior_change = re.search(
        r"(no longer supported|not supported on|will no longer|will be removed|"
        r"removed from|feature removal|starting from|starting with|as of fortios|"
        r"from fortios version|beginning with|behavior change|behaviour change|"
        r"changed behavior|changed behaviour|is now required|is mandatory|"
        r"mandatory by default|required by default|replaces? \w+|is disabled by default|"
        r"will be disabled|requires? .*certificate|must be signed)",
        text, re.I,
    )
    normalized_summary = re.sub(
        r"\b(?i:Description|Scope|Solution|Workaround|Impact)(?=[A-Z])",
        lambda match: match.group(0) + " ", item.get("summary", ""),
    )
    troubleshooting = bool(
        re.search(r"\btroubleshooting tip\b", title, re.I)
        and ISSUE_RE.search(title)
        and re.search(r"\bsolution\b", normalized_summary, re.I)
    )
    scoped_issue = bool(
        ISSUE_RE.search(title)
        and re.search(r"\bScope\b", normalized_summary, re.I)
        and re.search(r"\bSolution\b", normalized_summary, re.I)
    )
    has_version = bool(extract_versions(item)[0])
    return bool(scoped_issue or (has_version and (known_issue or behavior_change or troubleshooting)))


def forum_report_count(items: list[dict]) -> int:
    """Count distinct user-discussion URLs, not editor-authored articles."""
    return len({
        item.get("url", "").rstrip("/")
        for item in items
        if source_type(item) == "forum_discussion" and item.get("url")
    })


def similar(a: dict, b: dict) -> bool:
    # Do not merge reports that explicitly name different inspection modes just
    # because they share protocol terms (for example, DNS over TLS).
    title_a, title_b = norm(a.get("title", "")), norm(b.get("title", ""))
    modes_a = {mode for mode in MODE_CONTEXTS if mode in title_a}
    modes_b = {mode for mode in MODE_CONTEXTS if mode in title_b}
    if modes_a and modes_b and modes_a.isdisjoint(modes_b):
        return False

    pa, pb = set(a.get("products", [])), set(b.get("products", []))
    if pa and pb and not pa.intersection(pb):
        return False
    va, vb = set(a.get("versionFamilies", [])), set(b.get("versionFamilies", []))
    if va and vb and not va.intersection(vb):
        return False
    wa, wb = title_tokens(a), title_tokens(b)
    if not wa or not wb:
        return False
    overlap = len(wa & wb) / min(len(wa), len(wb))
    jaccard = len(wa & wb) / len(wa | wb)
    return overlap >= 0.72 or jaccard >= 0.48


def build_summary(items: list[dict]) -> str:
    # Use the clearest source description; do not invent a root cause or fix.
    best = max(items, key=lambda x: min(len(x.get("summary", "")), 1600))
    text = re.sub(r"\s+", " ", best.get("summary", "")).strip()
    if not text:
        return "Plusieurs discussions semblent décrire un problème proche. Ouvrir les sources pour confirmer les symptômes et le périmètre."
    # Prefer a compact lead, stopping at the first clear sentence after a minimum useful length.
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text)
    selected = []
    for sentence in sentences:
        sentence = sentence.strip()
        if sentence and len(" ".join(selected)) < 420:
            selected.append(sentence)
        if len(" ".join(selected)) >= 420:
            break
    result = " ".join(selected) or text[:500]
    if len(result) > 560:
        result = result[:557].rsplit(" ", 1)[0] + "…"
    return result


def review_evidence_signature(incident: dict) -> tuple:
    """Fingerprint the evidence used by the AI wording review."""
    sources = []
    for source in incident.get("sources", []):
        if not isinstance(source, dict):
            continue
        sources.append((
            str(source.get("url", "") or ""),
            str(source.get("title", "") or ""),
            str(source.get("summary", "") or ""),
            str(source.get("symptom", "") or ""),
            str(source.get("impact", "") or ""),
            str(source.get("solution", "") or ""),
            str(source.get("sourceType", "") or ""),
            tuple(sorted(str(value) for value in (source.get("products", []) or []))),
            tuple(sorted(str(value) for value in (source.get("versions", []) or []))),
            tuple(sorted(str(value) for value in (source.get("fixVersions", []) or []))),
        ))
    return (
        str(incident.get("title", "") or ""),
        tuple(sorted(sources)),
        tuple(sorted(str(value) for value in (incident.get("products", []) or []))),
        tuple(sorted(str(value) for value in (incident.get("versions", []) or []))),
        tuple(sorted(str(value) for value in (incident.get("fixVersions", []) or []))),
    )


def preserve_unchanged_ai_reviews(incidents: list[dict], previous_incidents: list[dict]) -> int:
    """Carry forward AI wording only when the underlying evidence is unchanged."""
    previous_by_id = {
        str(item.get("id")): item
        for item in previous_incidents
        if isinstance(item, dict) and item.get("id")
    }
    carried = 0
    for incident in incidents:
        previous = previous_by_id.get(str(incident.get("id", "")))
        if not previous or not isinstance(previous.get("aiReview"), dict):
            continue
        if review_evidence_signature(previous) != review_evidence_signature(incident):
            continue
        incident["aiReview"] = previous["aiReview"]
        carried += 1
    return carried


def synthesize(data: dict, out: Path = DATA) -> dict:
    previous_incidents = data.pop("_previousIncidents", data.get("incidents", []))
    if not isinstance(previous_incidents, list):
        previous_incidents = []
    topics = data.get("topics", [])
    enriched = []
    for raw in topics:
        item = dict(raw)
        item["products"] = extract_products(item)
        item["versions"], item["versionFamilies"] = extract_versions(item)
        item["fixVersions"] = extract_fixed_versions(item)
        item["potentialProblem"] = looks_like_problem(item)
        enriched.append(item)

    candidates = [item for item in enriched if item["potentialProblem"]]
    candidates.sort(key=lambda x: x.get("date") or "", reverse=True)
    clusters: list[list[dict]] = []
    for item in candidates:
        match = next((cluster for cluster in clusters if any(similar(item, member) for member in cluster)), None)
        if match is None:
            clusters.append([item])
        else:
            match.append(item)

    incidents = []
    for cluster in clusters:
        products = sorted({p for item in cluster for p in item.get("products", [])})
        exact_versions = sorted({v for item in cluster for v in item.get("versions", [])}, key=lambda v: tuple(int(x) for x in v.split(".")))
        families = sorted({v for item in cluster for v in item.get("versionFamilies", [])}, key=lambda v: tuple(int(x) for x in v.split(".")))
        fixed_versions = sorted({v for item in cluster for v in item.get("fixVersions", [])}, key=lambda v: tuple(int(x) for x in v.split(".")))
        sources = [{
            "title": item.get("title", "Sujet sans titre"),
            "url": item.get("url", ""),
            "date": item.get("date"),
            "summary": item.get("summary", "")[:1000],
            "products": item.get("products", []),
            "versions": item.get("versions", []),
            "versionFamilies": item.get("versionFamilies", []),
            "sourceType": source_type(item),
            "fixVersions": extract_fixed_versions(item),
            **extract_sections(item),
        } for item in cluster]
        symptom = next((source["symptom"] for source in sources if source.get("symptom")), "")
        impact = next((source["impact"] for source in sources if source.get("impact")), "")
        solution = next((source["solution"] for source in sources if source.get("solution")), "")
        newest = max((item.get("date") or "" for item in cluster), default="")
        documented_sources = [item for item in cluster if has_documented_evidence(item)]
        reports = forum_report_count(cluster)
        # Forum-only incidents require at least two distinct user discussions.
        if reports < 2 and not documented_sources:
            continue
        documented = bool(documented_sources)
        incidents.append({
            "id": "incident-" + hashlib.sha1((" ".join(sorted(words(cluster[0].get("title", "")))) + "|" + "|".join(products)).encode("utf-8")).hexdigest()[:12],
            "title": cluster[0].get("title", "Problème potentiel Fortinet"),
            "summary": build_summary(cluster),
            "symptom": symptom or build_summary(cluster),
            "impact": impact,
            "solution": solution,
            "products": products,
            "versions": exact_versions,
            "versionFamilies": families,
            "fixVersions": fixed_versions,
            "sourceCount": len(sources),
            "forumReportCount": reports,
            "documentedSourceCount": len(documented_sources),
            "sources": sources,
            "lastSeen": newest or None,
            "status": (
                "Documenté par Fortinet (version identifiée)" if documented and reports < 2 and exact_versions
                else "Documenté par Fortinet (version non précisée)" if documented and reports < 2
                else "Documenté par Fortinet + récurrent" if documented
                else f"Récurrent — {reports} discussions distinctes"
            ),
            "confidence": (
                "Documentation Fortinet versionnée" if documented and exact_versions
                else "Documentation Fortinet (version non précisée)" if documented
                else "Plusieurs discussions distinctes"
            ),
            "evidenceType": "official_documentation" if documented else "repeated_reports",
            "synthesisMethod": "Règles de preuve : article Fortinet versionné et explicite, ou au moins deux discussions distinctes; pas d'IA générative.",
        })
    incidents.sort(key=lambda x: (x["sourceCount"], x.get("lastSeen") or ""), reverse=True)
    carried_reviews = preserve_unchanged_ai_reviews(incidents, previous_incidents)
    if not carried_reviews:
        for key in ("aiReviewGeneratedAt", "aiReviewModel", "aiReviewNote"):
            data.pop(key, None)
    data["aiReviewStatus"] = "pending"
    data["aiReviewMessage"] = (
        "La synthèse est actualisée; la relecture IA sera actualisée si le service est disponible."
        if carried_reviews
        else "Synthèse déterministe prête; relecture IA en attente."
    )
    data["topics"] = enriched
    data["incidents"] = incidents
    data["incidentCount"] = len(incidents)
    data["synthesisGeneratedAt"] = datetime.now(timezone.utc).isoformat()
    data["synthesisNote"] = "Un point n'est affiché que s'il est documenté par un article Fortinet versionné et explicite, ou décrit dans au moins deux discussions distinctes d'utilisateurs. Les articles officiels ne comptent pas comme des personnes supplémentaires. Les signalements isolés non documentés sont exclus."
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return data


def main() -> int:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    result = synthesize(data)
    print(f"Synthèse terminée : {len(result.get('incidents', []))} groupes potentiels depuis {len(result.get('topics', []))} sujets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
