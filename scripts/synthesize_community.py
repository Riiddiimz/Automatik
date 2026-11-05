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
    r"not displayed|not shown|not included|no record found|not loading|not supported|unreachable|not reachable|inaccessible|not accessible|"
    r"cannot|can't|cannot save|packet loss|connection reset|bypass(?:es|ed)?|"
    r"fails to|missing|stuck|timeout|timed out|attributes?\s+(?:of\s+users?\s+)?(?:are\s+)?(?:cleared|deleted|removed)|"
    r"conserve\s+mode|high\s+memory|memory\s+(?:usage|pressure|consumption|leak))\b",
    re.I,
)
EXPLICIT_BUG_CAUSE_RE = re.compile(
    r"\b(?:a|the)\s+bug\b[^.!?]{0,160}\b(?:causes?|causing|results?\s+in|leads?\s+to)\b",
    re.I,
)
UNEXPECTED_DISABLED_BEHAVIOR_RE = re.compile(
    r"\b(?:generat(?:e|es|ed|ing)|produc(?:e|s|ed|ing)|creat(?:e|s|ed|ing)|"
    r"send(?:s|ing)?|log(?:s|ged|ging)?)\b[^.!?]{0,140}\b(?:despite|even when|although)\b"
    r"[^.!?]{0,100}\b(?:disabled|turned off|switched off)\b",
    re.I,
)
SCOPE_EXACT_VERSION_RE = re.compile(r"(?<!\d)(\d{1,2}\.\d{1,2}\.\d{1,3})(?!\d)")
VERSION_CONTEXT_RE = re.compile(
    r"\b(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|fortiswitch|fortiap|firmware)\s*[\(:-]?\s*(?:versions?\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)",
    re.I,
)
VERSION_LIST_TAIL_RE = re.compile(
    r"(?:,|/|\band\b|\bor\b)\s*(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
AFFECTED_VERSION_CONTEXT_RE = re.compile(
    r"\b(?:known\s+(?:issue|bug|defect)|affected\s+versions?|affected\s+releases?)\b"
    r"[^.!?]{0,140}?\b(?:in|on|:|affects?)\s*"
    r"(?:(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|firmware)\s*)?"
    r"(?:versions?\s*)?v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?"
    r"(?:\s*(?:,|and|or|/)\s*v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)*",
    re.I,
)
FIRMWARE_VERSION_LIST_RE = re.compile(r"\bfirmware\s*\(([^)]{1,120})\)", re.I)
REPORTED_FIRMWARE_VERSION_RE = re.compile(
    r"\b(?:reported|tested|observed|reproduced|running|runs|on)\s+"
    r"(?:(?:firmware|software|fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|fortiswitch|fortiap)\s+)?"
    r"version\s*[:=]?\s*v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
UPGRADE_PATH_RE = re.compile(
    r"\b(?:upgrad(?:e|ed|ing|es)|firmware update)\b[^.!?]{0,120}?\b(?:from\s+)?(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b[^.!?]{0,80}?\bto\s+(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
UPGRADE_SEGMENT_RE = re.compile(
    r"\b(?:upgrad(?:e|ed|ing|es)|firmware update)\b(.*?)(?=(?:\.(?=\s+[A-Z])|[!?]|$))",
    re.I | re.S,
)
UPGRADE_TARGET_RE = re.compile(
    r"\b(?:upgrad(?:e|ed|ing|es)|firmware update)\b[^.!?]{0,100}?\bto\s+(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
) 
FIXED_VERSION_RE = re.compile(
    r"\b(?:will\s+be\s+fixed|will\s+be\s+resolved|is\s+scheduled\s+to\s+be\s+fixed|"
    r"scheduled\s+to\s+be\s+fixed|scheduled\s+for\s+(?:a\s+)?fix|"
    r"has\s+(?:a\s+)?(?:fix|patch|correction)|have\s+(?:a\s+)?(?:fix|patch|correction)|"
    r"planned\s+fix|fixed|resolved|corrected|addressed|"
    r"(?:fix|patch|correction)\s+(?:is\s+)?(?:available|included|provided))\s+"
    r"(?:in|with|from)\s+(?:(?:the\s+)?(?:upcoming|next|future|forthcoming)\s+)?"
    r"(?:(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|fortiswitch|fortiap|firmware)\s*)?"
    r"(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
NOT_PRESENT_VERSION_RE = re.compile(
    r"\b(?:behavior|behaviour|issue|problem)\s+is\s+not\s+present\s+in\s+"
    r"(?:(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|firmware)\s*)?"
    r"(?:versions?\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
PERMANENT_SOLUTION_SECTION_RE = re.compile(
    r"\bpermanent\s+solution\b\s*[:.]?\s*(.*?)"
    r"(?=\b(?:workaround|related\s+articles|note|scope|description|impact)\b|$)",
    re.I | re.S,
)
FIXED_VERSION_TAIL_RE = VERSION_LIST_TAIL_RE
FIXED_VERSION_CONTEXT_RE = re.compile(
    r"\b(?:versions?|firmware)\s+"
    r"((?:v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)"
    r"(?:\s*(?:,|and|or|/)\s*v?\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)*)"
    r"(?=[^.!?]{0,80}\b(?:include|contain|have)\s+(?:a\s+)?(?:fix|patch|correction)\b)",
    re.I,
)
FIXED_VERSION_UPGRADE_RE = re.compile(
    r"\b(?:permanent solution|resolution|fix|solution)\s*(?::|is\s+to)?\s*"
    r"(?:update|upgrade)\s+(?:the\s+)?"
    r"(?:(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|firmware)(?:\s+(?:device|appliance|firewall|unit)s?)?\s+)?"
    r"(?:to\s+)?"
    r"(?:(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|firmware)\s+)?"
    r"(?:versions?\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
FIXED_VERSION_UPGRADE_TO_RESOLVE_RE = re.compile(
    r"\b(?:upgrade|update)\b[^.!?]{0,120}?\bto\s+"
    r"(?:(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|firmware)\s+)?"
    r"(?:version\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b"
    r"[^.!?]{0,120}\bto\s+(?:resolve|fix|address)\s+(?:this|the)\s+(?:issue|problem)\b",
    re.I,
)

FIXED_VERSION_LIST_RE = re.compile(
    r"\b(?:fix|patch|correction)\s+(?:is\s+)?(?:available|included|provided|expected|planned)\s+"
    r"in\s+(?:the\s+following\s+versions\s*:?\s*)?(.*?)(?=(?:upgrade procedure|related articles|see:|workaround|note:)|$)",
    re.I | re.S,
)
FIXED_VERSION_LIST_TOKEN_RE = re.compile(
    r"(?<!\d)(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)(?=[A-Za-z\s,;:.]|$)"
)
PERMANENT_FIX_VERSION_RE = re.compile(
    r"\b(?:permanent|final|long[- ]term)\s+fix\b[^.!?]{0,180}?"
    r"\b(?:included|available|provided)\s+in\s+"
    r"(?:(?:fortios|fortigate|fortimanager|fortianalyzer|fortiauthenticator|"
    r"forticlient(?:\s*(?:[/&-]\s*)?(?:ems|vpn))?|firmware)\s+)?"
    r"(?:versions?\s*)?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b",
    re.I,
)
# A wildcard such as 7.4.x identifies a release family, not an exact firmware.
VERSION_FAMILY_RE = re.compile(r"(?<!\d)(\d{1,2}\.\d{1,2})\.x\b", re.I)
AFFECTED_VERSIONS_SECTION_RE = re.compile(
    r"\b(?:affected\s+versions?|affected\s+releases?)\s*:?\s*(.*?)"
    r"(?=\b(?:resolved\s+versions?|fixed\s+versions?|corrected\s+versions?|"
    r"resolved\s+releases?|fixed\s+releases?|workaround|related\s+articles|note)\b|$)",
    re.I | re.S,
)
FIXED_VERSIONS_SECTION_RE = re.compile(
    r"\b(?:resolved\s+versions?|fixed\s+versions?|corrected\s+versions?|"
    r"resolved\s+releases?|fixed\s+releases?)\s*:?\s*(.*?)"
    r"(?=\b(?:affected\s+versions?|workaround|related\s+articles|note|scope|description|impact)\b|$)",
    re.I | re.S,
)
FIXED_BUILD_RE = re.compile(
    r"\b(?:special|engineering|hotfix|custom)\s+build\s+(\d{3,6})\b",
    re.I,
)
FIXED_ENGINE_BUILD_RE = re.compile(
    r"\b(?:resolved|fixed|corrected)\s+in\s+IPS\s*Engine\s+v?(\d{1,2}\.\d{5})\b",
    re.I,
)
FIXED_ENGINE_BUILD_MENTION_RE = re.compile(
    r"\b(?:obtain|download|install)\s+IPS\s*Engine\s+v?(\d{1,2}\.\d{4,5})\b",
    re.I,
)
FIXED_ENGINE_RELEASE_CUE_RE = re.compile(
    r"\b(?:resolved|fixed|corrected)\s+in\s*:?",
    re.I,
)
IPS_ENGINE_RELEASE_RE = re.compile(
    r"\bIPS\s*Engine\s+v?(\d{1,2}\.\d{1,2}\.\d{1,3})\s*"
    r"(?:\(\s*Build\s*(\d{1,6})\s*\)|Build\s*(\d{1,6}))?",
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
    "FortiClient EMS": r"\bforticlient\s*(?:[/&-]\s*)?ems\b|\bfcems\b",
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
    unwatched_product_board = bool(board) and not primary and not board.startswith("support-forum") and board != "t5"
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
        # On a non-forum board, body text can mention many unrelated products.
        # Match the title only; support-forum discussions may use title and body.
        text = title if unwatched_product_board else title + " " + summary
        found = [name for name, pattern in PRODUCT_PATTERNS.items() if re.search(pattern, text, re.I)]
    if "FortiClient EMS" in found:
        found = [p for p in found if p != "FortiClient"]
    if unwatched_product_board and not found:
        return []
    return found or ([] if unwatched_product_board else item.get("products", []))


def extract_labeled_versions(text: str, pattern: re.Pattern) -> set[str]:
    """Extract firmware numbers from an explicitly labelled affected/fixed-version section."""
    found = set()
    for match in pattern.finditer(text):
        section = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", match.group(1))
        section = NON_FORTINET_VERSION_RE.sub(" ", section)
        found.update(
            re.findall(r"(?<!\d)(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)(?!\d)", section)
        )
    return found


def normalize_article_sections(text: str) -> str:
    """Separate section labels and IPS Engine releases concatenated by HTML text extraction."""
    text = re.sub(
        r"(?<!\s)(?i:Description|Scope|Solution|Workaround|Impact|Resolution|Affected Versions|Resolved Versions|Fixed Versions)(?=[A-Z])",
        lambda match: " " + match.group(0) + " ",
        text,
    )
    text = re.sub(
        r"\b(?i:Description|Scope|Solution|Workaround|Impact|Resolution|Affected Versions|Resolved Versions|Fixed Versions)(?=[A-Z])",
        lambda match: match.group(0) + " ",
        text,
    )
    return re.sub(
        r"(?<=[A-Za-z0-9])(?i:IPS\s*Engine)(?=\s+\d)",
        lambda match: " " + match.group(0),
        text,
    )


def permanent_fix_evidence(text: str) -> tuple[set[str], list[tuple[int, int]]]:
    """Return fixed versions and sentence spans explicitly introduced as permanent fixes."""
    versions = set()
    spans = []
    for match in PERMANENT_FIX_VERSION_RE.finditer(text):
        tail = text[match.start():]
        sentence_end = re.search(r"[.!?](?=\s|$)", tail)
        end = match.start() + (sentence_end.end() if sentence_end else len(tail))
        sentence = text[match.start():end]
        clause = re.search(r"\b(?:included|available|provided)\s+in\b(.*)", sentence, re.I)
        if clause:
            versions.update(
                re.findall(r"(?<!\d)(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)(?!\d)", clause.group(1))
            )
        spans.append((match.start(), end))
    return versions, spans


def extract_versions(item: dict) -> tuple[list[str], list[str]]:
    title = item.get("title", "")
    summary = normalize_article_sections(item.get("summary", ""))
    text = title + " " + summary
    reported_versions = []
    affected_upgrade_versions = set()
    scope_text = ""
    scope_families = set()
    scope_exact_versions = set()
    description_versions = set()
    if source_type(item) == "fortinet_article":
        scope = re.search(
            r"\bScope\s*:?\s*(.*?)(?=\b(?:Solution|Workaround|Impact|Description)\b|$)",
            summary, re.I | re.S,
        )
        # "Known issue ... has a fix in 7.6.9" must not make 7.6.9 an affected release.
        affected_summary = FIXED_VERSION_RE.sub(" ", summary)
        affected_summary = FIXED_VERSION_CONTEXT_RE.sub(" ", affected_summary)
        affected_summary = FIXED_VERSION_LIST_RE.sub(" ", affected_summary)
        affected_summary = NOT_PRESENT_VERSION_RE.sub(" ", affected_summary)
        affected_summary = PERMANENT_SOLUTION_SECTION_RE.sub(" ", affected_summary)
        _, permanent_fix_spans = permanent_fix_evidence(affected_summary)
        for start, end in reversed(permanent_fix_spans):
            affected_summary = affected_summary[:start] + " " + affected_summary[end:]
        # Explicit resolved/fixed sections must never leak into the affected-version list.
        affected_summary = FIXED_VERSIONS_SECTION_RE.sub(" ", affected_summary)
        # Remove an explicit remediation upgrade before extracting affected upgrade releases.
        affected_summary = FIXED_VERSION_UPGRADE_RE.sub(" ", affected_summary)
        affected_summary = FIXED_VERSION_UPGRADE_TO_RESOLVE_RE.sub(" ", affected_summary)
        for source_version, target_version in UPGRADE_PATH_RE.findall(affected_summary):
            affected_upgrade_versions.update((source_version, target_version))
        for upgrade_match in UPGRADE_SEGMENT_RE.finditer(affected_summary):
            segment = upgrade_match.group(1)
            context_matches = list(VERSION_CONTEXT_RE.finditer(segment))
            if context_matches:
                for context in context_matches:
                    affected_upgrade_versions.add(context.group(1))
                    affected_upgrade_versions.update(VERSION_LIST_TAIL_RE.findall(segment[context.end():]))
            else:
                target_match = UPGRADE_TARGET_RE.search("upgrade " + segment)
                if target_match:
                    affected_upgrade_versions.add(target_match.group(1))
                    tail = ("upgrade " + segment)[target_match.end():]
                    affected_upgrade_versions.update(VERSION_LIST_TAIL_RE.findall(tail))
        affected_contexts = [
            match.group(0) for match in AFFECTED_VERSION_CONTEXT_RE.finditer(affected_summary)
        ]
        # Preserve an explicitly reported/tested firmware version even when
        # the article's Scope section names only the product family.
        reported_versions = REPORTED_FIRMWARE_VERSION_RE.findall(affected_summary)
        description = re.search(
            r"\bDescription\s*(.*?)(?=\b(?:Scope|Solution|Workaround|Impact)\b|$)",
            summary, re.I | re.S,
        )
        description_versions = set()
        if description:
            description_text = description.group(1)
            description_text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", description_text)
            description_text = FIXED_VERSION_RE.sub(" ", description_text)
            description_text = NON_FORTINET_VERSION_RE.sub(" ", description_text)
            for match in VERSION_CONTEXT_RE.finditer(description_text):
                description_versions.add(match.group(1))
                tail = re.split(r"[!?]|\.(?=\s|$)", description_text[match.end():], maxsplit=1)[0]
                description_versions.update(VERSION_LIST_TAIL_RE.findall(tail))
        if scope or affected_contexts or reported_versions or affected_upgrade_versions or description_versions:
            scope_text = scope.group(1) if scope else ""
            scope_families = set(VERSION_FAMILY_RE.findall(scope_text))
            scope_exact_versions = set(SCOPE_EXACT_VERSION_RE.findall(scope_text))
            if scope_exact_versions:
                # An exact Scope range is authoritative. Do not classify the
                # source version in a title's upgrade path as affected as well.
                reported_versions = [version for version in reported_versions if version in scope_exact_versions]
                affected_upgrade_versions.intersection_update(scope_exact_versions)
                description_versions.intersection_update(scope_exact_versions)
                text = scope_text
            else:
                text = title + " " + scope_text + " " + " ".join(affected_contexts)
    affected_section_versions = extract_labeled_versions(summary, AFFECTED_VERSIONS_SECTION_RE)
    # Remove complete IPv4 addresses before looking for dotted version numbers.
    text_without_ips = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text)
    # Do not misclassify documented fixed releases as affected releases.
    text_without_ips = FIXED_VERSION_RE.sub(" ", text_without_ips)
    text_without_ips = FIXED_VERSION_CONTEXT_RE.sub(" ", text_without_ips)
    text_without_ips = FIXED_VERSION_UPGRADE_TO_RESOLVE_RE.sub(" ", text_without_ips)
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
    found = scope_exact_versions | set(reported_versions) | affected_upgrade_versions | affected_section_versions | description_versions
    for match in VERSION_CONTEXT_RE.finditer(text_without_ips):
        found.add(match.group(1))
        sentence_tail = re.split(r"[!?]|\.(?=\s|$)", text_without_ips[match.end():], maxsplit=1)[0]
        found.update(VERSION_LIST_TAIL_RE.findall(sentence_tail))
    for version_list in FIRMWARE_VERSION_LIST_RE.findall(text_without_ips):
        found.update(re.findall(r"\b(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)\b", version_list))
    for source_version, target_version in UPGRADE_PATH_RE.findall(text_without_ips):
        found.update((source_version, target_version))
    found.update(UPGRADE_TARGET_RE.findall(text_without_ips))
    exact = sorted(found - scope_families, key=lambda v: tuple(int(x) for x in v.split(".")))
    families = sorted(
        {".".join(v.split(".")[:2]) for v in exact} | scope_families,
        key=lambda v: tuple(int(x) for x in v.split(".")),
    )
    return exact, families


def looks_like_problem(item: dict) -> bool:
    title = item.get("title", "")
    summary = item.get("summary", "")
    # Do not turn an ordinary how-to article into an incident just because its instructions mention
    # something that cannot be configured. For those articles, require an explicit failure in title.
    if re.match(r"^(technical tip|how to|configuration guide)", title, re.I) and not ISSUE_RE.search(title):
        return False
    if (
        ISSUE_RE.search(title)
        or EXPLICIT_BUG_CAUSE_RE.search(summary[:1200])
        or UNEXPECTED_DISABLED_BEHAVIOR_RE.search(f"{title} {summary[:1200]}")
    ):
        return True
    return bool(
        ISSUE_RE.search(summary[:1200])
        or re.search(
            r"\b(known issue|known bug|bug id|regression|issue occurs|failure occurs|stops working|not working|broken after upgrade)\b",
            summary[:1200], re.I,
        )
    )


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

    text = re.sub(r"\s+", " ", normalize_article_sections(item.get("summary", ""))).strip()

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
    text = normalize_article_sections(f"{item.get('title', '')} {item.get('summary', '')}")
    found = set()
    for pattern in (FIXED_VERSION_RE, FIXED_VERSION_UPGRADE_RE, FIXED_VERSION_UPGRADE_TO_RESOLVE_RE):
        for match in pattern.finditer(text):
            found.add(match.group(1))
            sentence_tail = re.split(r"[!?]|\.(?=\s|$)", text[match.end():], maxsplit=1)[0]
            found.update(FIXED_VERSION_TAIL_RE.findall(sentence_tail))
    for match in FIXED_VERSION_CONTEXT_RE.finditer(text):
        found.update(re.findall(r"\d{1,2}\.\d{1,2}(?:\.\d{1,3})?", match.group(1)))
    for match in NOT_PRESENT_VERSION_RE.finditer(text):
        found.add(match.group(1))
    found.update(extract_labeled_versions(text, PERMANENT_SOLUTION_SECTION_RE))
    # Some official articles list several fixed branches after one shared cue,
    # and HTML-to-text extraction can concatenate the version and next product name.
    for match in FIXED_VERSION_LIST_RE.finditer(text):
        found.update(FIXED_VERSION_LIST_TOKEN_RE.findall(match.group(1)))
    permanent_versions, _ = permanent_fix_evidence(text)
    found.update(permanent_versions)
    found.update(extract_labeled_versions(text, FIXED_VERSIONS_SECTION_RE))
    return sorted(found, key=lambda version: tuple(int(part) for part in version.split(".")))


def extract_fixed_builds(item: dict) -> list[str]:
    """Return explicit fix builds, including special builds and IPSEngine builds, from Fortinet articles."""
    if source_type(item) != "fortinet_article":
        return []
    text = f"{item.get('title', '')} {item.get('summary', '')}"
    return sorted(set(
        FIXED_BUILD_RE.findall(text)
        + FIXED_ENGINE_BUILD_RE.findall(text)
        + FIXED_ENGINE_BUILD_MENTION_RE.findall(text)
    ))


def extract_fixed_engine_releases(item: dict) -> list[dict]:
    """Return IPS Engine releases only when an official article explicitly marks them as fixed."""
    if source_type(item) != "fortinet_article":
        return []
    text = normalize_article_sections(f"{item.get('title', '')} {item.get('summary', '')}")
    releases = {}
    for cue in FIXED_ENGINE_RELEASE_CUE_RE.finditer(text):
        tail = text[cue.end():]
        boundary = re.search(
            r"\b(?:after upgrading|once the|workaround|note:|related articles|like|follow)\b",
            tail,
            re.I,
        )
        section = tail[:boundary.start()] if boundary else tail[:700]
        for match in IPS_ENGINE_RELEASE_RE.finditer(section):
            version = match.group(1)
            build = match.group(2) or match.group(3) or None
            key = (version, build or "")
            releases[key] = {
                "engine": "IPS Engine",
                "version": version,
                "build": build,
            }
    return sorted(
        releases.values(),
        key=lambda release: (
            tuple(int(part) for part in release["version"].split(".")),
            release.get("build") or "",
        ),
    )


def extract_fixed_build_note(item: dict) -> str:
    """Flag contradictory IPSEngine build numbers instead of selecting one silently."""
    if source_type(item) != "fortinet_article":
        return ""
    text = f"{item.get('title', '')} {item.get('summary', '')}"
    builds = sorted(set(
        FIXED_ENGINE_BUILD_RE.findall(text)
        + FIXED_ENGINE_BUILD_MENTION_RE.findall(text)
    ))
    if len(builds) > 1:
        return (
            "La source cite plusieurs builds IPSEngine différents "
            f"({', '.join(builds)}). Le build exact est à confirmer auprès du support Fortinet "
            "avant déploiement."
        )
    return ""


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
    normalized_summary = normalize_article_sections(item.get("summary", ""))
    troubleshooting = bool(
        re.search(r"\btroubleshooting tip\b", title, re.I)
        and ISSUE_RE.search(title)
        and re.search(r"\bsolution\b", normalized_summary, re.I)
    )
    scoped_issue = bool(
        (
            ISSUE_RE.search(title)
            or EXPLICIT_BUG_CAUSE_RE.search(normalized_summary)
            or UNEXPECTED_DISABLED_BEHAVIOR_RE.search(f"{title} {normalized_summary}")
        )
        and re.search(r"\bScope\b", normalized_summary, re.I)
        and re.search(r"\bSolution\b", normalized_summary, re.I)
    )
    has_version = bool(extract_versions(item)[0])
    return bool(scoped_issue or (has_version and (known_issue or behavior_change or troubleshooting)))


def is_configuration_guidance(item: dict) -> bool:
    """Identify official configuration workarounds that should not be labelled as confirmed firmware bugs."""
    if source_type(item) != "fortinet_article":
        return False
    if extract_fixed_versions(item) or extract_fixed_engine_releases(item):
        return False
    text = normalize_article_sections(item.get("summary", ""))
    if re.search(
        r"\b(?:known issue|known bug|bug id|engineering ticket|permanent fix|resolved in|fixed in|corrected in|affected versions?|under investigation)\b",
        text,
        re.I,
    ):
        return False
    title = item.get("title", "")
    return bool(
        re.search(
            r"\b(?:unset\s+[a-z0-9_-]+|set\s+[a-z0-9_-]+\s+(?:enable|disable|block|allow)|"
            r"configure\b[^.!?]{0,180}\b(?:bypass|disable|enable|ignore)|"
            r"to resolve this issue\b[^.!?]{0,120}\bconfigure)\b",
            text,
            re.I,
        )
        or re.match(r"^(?:technical tip|troubleshooting tip|how to|configuration guide)\b", title, re.I)
        or re.search(
            r"\b(?:platform selected in the template|platform of the assigned device|"
            r"template platform|platform mismatch|does not match the platform|"
            r"doesn't match the platform)\b",
            text,
            re.I,
        )
    )


def is_version_behavior_change(item: dict) -> bool:
    """Identify a documented release-behavior change separately from a confirmed bug."""
    if source_type(item) != "fortinet_article":
        return False
    text = normalize_article_sections(item.get("summary", ""))
    if re.search(r"\b(?:known issue|known bug|bug id|engineering ticket)\b", text, re.I):
        return False
    has_behavior_cue = re.search(
        r"\b(?:change in behavior|change in behaviour|behavior change|behaviour change|"
        r"differs from|not present in)\b",
        text,
        re.I,
    )
    has_version_evidence = bool(extract_versions(item)[0] or extract_fixed_versions(item))
    return bool(has_behavior_cue and has_version_evidence)


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
        if all(source_type(item) == "fortinet_article" for item in items):
            return (
                "La page d’index ne fournit pas de résumé détaillé. Consultez la fiche Fortinet "
                "pour vérifier le périmètre, l’impact et la solution."
            )
        return (
            "Les résumés ne sont pas disponibles dans les sources récupérées. Consultez les "
            "discussions d’origine pour confirmer les symptômes et le périmètre."
        )
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
            tuple(sorted(str(value) for value in (source.get("fixBuilds", []) or []))),
            tuple(sorted(
                (
                    str(reply.get("author", "") or ""),
                    str(reply.get("authorRole", "") or ""),
                    str(reply.get("date", "") or ""),
                    str(reply.get("text", "") or ""),
                )
                for reply in (source.get("replies", []) or [])
                if isinstance(reply, dict)
            )),
            tuple(sorted(
                (
                    str(release.get("engine", "") or ""),
                    str(release.get("version", "") or ""),
                    str(release.get("build", "") or ""),
                )
                for release in (source.get("fixEngineReleases", []) or [])
                if isinstance(release, dict)
            )),
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
        item["fixBuilds"] = extract_fixed_builds(item)
        item["fixEngineReleases"] = extract_fixed_engine_releases(item)
        item["fixBuildNote"] = extract_fixed_build_note(item)
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
        fixed_builds = sorted({build for item in cluster for build in item.get("fixBuilds", [])})
        fixed_engine_releases = {
            (
                str(release.get("engine", "IPS Engine")),
                str(release.get("version", "")),
                str(release.get("build") or ""),
            )
            for item in cluster
            for release in item.get("fixEngineReleases", [])
            if isinstance(release, dict) and release.get("version")
        }
        sources = [{
            "title": item.get("title", "Sujet sans titre"),
            "url": item.get("url", ""),
            "date": item.get("date"),
            "updatedAt": item.get("updatedAt"),
            "summary": item.get("summary", "")[:1000],
            "products": item.get("products", []),
            "versions": item.get("versions", []),
            "versionFamilies": item.get("versionFamilies", []),
            "sourceType": source_type(item),
            "fixVersions": extract_fixed_versions(item),
            "fixBuilds": extract_fixed_builds(item),
            "fixEngineReleases": extract_fixed_engine_releases(item),
            "fixBuildNote": extract_fixed_build_note(item),
            "replies": [
                reply for reply in (item.get("replies", []) or [])
                if isinstance(reply, dict)
            ][:20],
            "replyExtractionStatus": item.get("replyExtractionStatus", ""),
            **extract_sections(item),
        } for item in cluster]
        symptom = next((source["symptom"] for source in sources if source.get("symptom")), "")
        impact = next((source["impact"] for source in sources if source.get("impact")), "")
        solution = next((source["solution"] for source in sources if source.get("solution")), "")
        newest = max(
            (
                str(value)
                for item in cluster
                for value in (item.get("date"), item.get("updatedAt"))
                if value
            ),
            default="",
        )
        documented_sources = [item for item in cluster if has_documented_evidence(item)]
        reports = forum_report_count(cluster)
        # Forum-only incidents require at least two distinct user discussions.
        if reports < 2 and not documented_sources:
            continue
        documented = bool(documented_sources)
        configuration_only = bool(documented_sources) and all(
            is_configuration_guidance(item) for item in documented_sources
        )
        version_behavior_change = bool(documented_sources) and all(
            is_version_behavior_change(item) for item in documented_sources
        )
        has_documented_fix = bool(fixed_versions or fixed_builds or fixed_engine_releases)
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
            "fixBuilds": fixed_builds,
            "fixEngineReleases": [
                {"engine": engine, "version": version, "build": build or None}
                for engine, version, build in sorted(
                    fixed_engine_releases,
                    key=lambda value: (
                        tuple(int(part) for part in value[1].split(".")),
                        value[2],
                    ),
                )
            ],
            "replyCount": sum(len(source.get("replies", [])) for source in sources),
            "fixBuildNote": " ".join(dict.fromkeys(
                item["fixBuildNote"] for item in cluster if item.get("fixBuildNote")
            )),
            "sourceCount": len(sources),
            "forumReportCount": reports,
            "documentedSourceCount": len(documented_sources),
            "sources": sources,
            "lastSeen": newest or None,
            "status": (
                "Configuration documentée par Fortinet" if configuration_only and reports < 2
                else "Configuration documentée par Fortinet + récurrent" if configuration_only
                else "Changement de comportement / incompatibilité documenté par Fortinet" if version_behavior_change and reports < 2
                else "Changement de comportement / incompatibilité documenté par Fortinet + récurrent" if version_behavior_change
                else "Correctif documenté par Fortinet" if documented and has_documented_fix and exact_versions and reports < 2
                else "Correctif documenté par Fortinet (version affectée non précisée)" if documented and has_documented_fix and not exact_versions and reports < 2
                else "Correctif documenté par Fortinet + récurrent" if documented and has_documented_fix
                else "Documenté par Fortinet (version identifiée)" if documented and reports < 2 and exact_versions
                else "Documenté par Fortinet (version non précisée)" if documented and reports < 2
                else "Documenté par Fortinet + récurrent" if documented
                else f"Récurrent — {reports} discussions distinctes"
            ),
            "confidence": (
                "Documentation Fortinet (configuration)" if configuration_only
                else "Documentation Fortinet (changement de comportement)" if version_behavior_change
                else "Documentation Fortinet (correctif indiqué)" if documented and has_documented_fix
                else "Documentation Fortinet versionnée" if documented and exact_versions
                else "Documentation Fortinet (version non précisée)" if documented
                else "Plusieurs discussions distinctes"
            ),
            "evidenceType": (
                "official_configuration" if configuration_only
                else "official_version_behavior" if version_behavior_change
                else "official_fix_documented" if documented and has_documented_fix
                else "official_documentation" if documented
                else "repeated_reports"
            ),
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
    out.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return data


def main() -> int:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    result = synthesize(data)
    print(f"Synthèse terminée : {len(result.get('incidents', []))} groupes potentiels depuis {len(result.get('topics', []))} sujets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
