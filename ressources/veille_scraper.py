#!/usr/bin/env python3
"""
Scraper de veille Fortinet - Bugs terrain & solutions communautaires
Recherche web classique (DuckDuckGo) + extraction IA (Gemini, sans grounding, gratuit).
Filtre les résultats pour ne garder que les sujets récents (par défaut : 60 jours).

Génère automatiquement veille_fortinet.html.

Usage:
    python veille_scraper.py --gemini-key VOTRE_CLE_GEMINI
"""

import argparse
import json
import time
import re
from datetime import datetime, timedelta

import requests
from bs4 import BeautifulSoup
from ddgs import DDGS

from google import genai

# --- Configuration ---

GEMINI_MODEL = "gemini-3.5-flash-lite"
OUTPUT_FILE = "veille_fortinet.html"
PAGES_PER_TARGET = 5        # nombre de pages web analysées par cible produit/version
REQUEST_TIMEOUT = 15        # timeout HTTP en secondes
MAX_TEXT_LENGTH = 6000      # troncature du texte de page envoyé à Gemini (limite tokens)
MAX_AGE_DAYS = 60           # ne garder que les sujets publiés dans les N derniers jours

# Cibles produit/version à analyser
TARGETS = [
    {"product": "FortiGate", "version": "7.4"},
    {"product": "FortiGate", "version": "7.6"},
    {"product": "FortiManager", "version": "7.4"},
    {"product": "FortiManager", "version": "7.6"},
    {"product": "FortiAnalyzer", "version": "7.4"},
    {"product": "FortiAnalyzer", "version": "7.6"},
    {"product": "FortiClientEMS", "version": "7.4"},
    {"product": "FortiClient", "version": "7.4"},
    {"product": "FortiClient", "version": "7.6"},
]

EXCLUDED_DOMAINS = [
    "fortinet.com/products",
    "wikipedia.org",
    "answers.microsoft.com",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}


# --- Fonctions utilitaires ---

def js_escape(text):
    """Échappe les caractères problématiques pour insertion dans une chaîne JavaScript."""
    if text is None:
        return ""
    return (
        str(text).replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "")
    )


def configure_gemini(api_key):
    """Configure le client Gemini (SDK google-genai)."""
    return genai.Client(api_key=api_key)


def is_excluded(url):
    """Vérifie si une URL appartient à un domaine à exclure."""
    return any(domain in url for domain in EXCLUDED_DOMAINS)


def ddgs_timelimit_for_days(max_age_days):
    """
    Convertit un nombre de jours en paramètre 'timelimit' DDGS le plus proche.
    DDGS ne propose que d/w/m/y — on prend le préréglage le plus proche sans être trop restrictif.
    """
    if max_age_days <= 7:
        return "w"
    elif max_age_days <= 31:
        return "m"
    else:
        return "y"


# --- Recherche web via DuckDuckGo (multi-requêtes ciblées + filtre de fraîcheur) ---

def build_search_queries(product, version):
    """Construit plusieurs requêtes ciblées pour maximiser la pertinence des résultats."""
    return [
        f'site:community.fortinet.com "{product}" "{version}" issue OR bug OR problem',
        f'site:docs.fortinet.com "{product}" "{version}" known issues OR release notes',
        f'"{product}" "{version}" bug OR issue forum (reddit OR spiceworks OR "fortinet community")',
    ]


def search_web_urls(product, version, max_results=PAGES_PER_TARGET, max_age_days=MAX_AGE_DAYS):
    """
    Recherche des pages web pertinentes via plusieurs requêtes ciblées.
    Applique le filtre de fraîcheur DDGS (timelimit) en pré-filtrage.
    Retourne une liste d'URLs dédupliquées et filtrées (le filtrage fin par date
    se fait ensuite sur le contenu réel de la page, voir fetch_page_text).
    """
    queries = build_search_queries(product, version)
    timelimit = ddgs_timelimit_for_days(max_age_days)
    urls = []
    seen = set()

    for query in queries:
        print(f"[Recherche] {query} (timelimit={timelimit})")
        try:
            with DDGS() as ddgs:
                results = ddgs.text(query, max_results=5, timelimit=timelimit)
                for r in results:
                    url = r.get("href") or r.get("url")
                    if not url or url in seen or is_excluded(url):
                        continue
                    seen.add(url)
                    urls.append(url)
        except Exception as e:
            print(f"[Recherche] Erreur DuckDuckGo pour '{query}' : {e}")
        time.sleep(1)

    urls = urls[:max_results]
    print(f"[Recherche] {len(urls)} URL(s) retenue(s) après filtrage domaine.")
    return urls
# --- Détection de la date de publication d'une page ---

DATE_PATTERNS = [
    r"\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b",
    r"\b(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\s+(20\d{2})\b",
    r"\b(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\s+(\d{1,2}),?\s+(20\d{2})\b",
]

MONTHS = {
    "jan": 1, "january": 1, "feb": 2, "february": 2, "mar": 3, "march": 3,
    "apr": 4, "april": 4, "may": 5, "jun": 6, "june": 6, "jul": 7, "july": 7,
    "aug": 8, "august": 8, "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10, "nov": 11, "november": 11, "dec": 12, "december": 12,
}


def _parse_date_string(raw):
    """Tente de parser une chaîne de date en objet datetime, plusieurs formats supportés."""
    raw = raw.strip()

    iso_match = re.match(r"(20\d{2})-(\d{1,2})-(\d{1,2})", raw)
    if iso_match:
        try:
            y, m, d = int(iso_match.group(1)), int(iso_match.group(2)), int(iso_match.group(3))
            return datetime(y, m, d)
        except ValueError:
            pass

    iso_slash = re.match(r"(20\d{2})/(\d{1,2})/(\d{1,2})", raw)
    if iso_slash:
        try:
            y, m, d = int(iso_slash.group(1)), int(iso_slash.group(2)), int(iso_slash.group(3))
            return datetime(y, m, d)
        except ValueError:
            pass

    for pattern in DATE_PATTERNS[1:]:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            groups = match.groups()
            try:
                if groups[0].isdigit():
                    day, month_str, year = groups
                else:
                    month_str, day, year = groups
                month = MONTHS.get(month_str.lower()[:3]) or MONTHS.get(month_str.lower())
                if month:
                    return datetime(int(year), month, int(day))
            except (ValueError, AttributeError):
                continue

    return None


def extract_page_date(soup, text):
    """
    Tente d'extraire une date de publication depuis les métadonnées HTML,
    puis en dernier recours depuis le texte brut de la page.
    Retourne un objet datetime ou None si aucune date fiable n'est trouvée.
    """
    meta_candidates = [
        ("meta", {"property": "article:published_time"}),
        ("meta", {"property": "article:modified_time"}),
        ("meta", {"name": "date"}),
        ("meta", {"itemprop": "datePublished"}),
        ("time", {}),
    ]
    for tag_name, attrs in meta_candidates:
        tag = soup.find(tag_name, attrs=attrs) if attrs else soup.find(tag_name)
        if tag:
            raw = tag.get("content") or tag.get("datetime") or tag.get_text(strip=True)
            if raw:
                parsed = _parse_date_string(raw)
                if parsed:
                    return parsed

    for pattern in DATE_PATTERNS:
        match = re.search(pattern, text[:3000])
        if match:
            parsed = _parse_date_string(match.group(0))
            if parsed:
                return parsed

    return None


def is_page_recent_enough(page_date, max_age_days=MAX_AGE_DAYS):
    """
    Vérifie si une date de page est suffisamment récente.
    Si aucune date n'a pu être détectée, on garde la page par défaut.
    """
    if page_date is None:
        return True
    cutoff = datetime.now() - timedelta(days=max_age_days)
    return page_date >= cutoff


# --- Récupération du contenu texte d'une page (avec vérification de date) ---

def fetch_page_text(url, timeout=REQUEST_TIMEOUT, max_length=MAX_TEXT_LENGTH, max_age_days=MAX_AGE_DAYS):
    """
    Télécharge une page web, vérifie sa date de publication, et en extrait le texte brut.
    Retourne un dict {text, date} ou None si la page est inexploitable ou trop ancienne.
    """
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[Page] Échec de récupération de {url} : {e}")
        return None

    content_type = resp.headers.get("Content-Type", "")
    if "text/html" not in content_type and "text/plain" not in content_type:
        print(f"[Page] Type de contenu non supporté pour {url} ({content_type})")
        return None

    try:
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        print(f"[Page] Erreur de parsing HTML pour {url} : {e}")
        return None

    raw_text_for_date = soup.get_text(separator=" ", strip=True)

    page_date = extract_page_date(soup, raw_text_for_date)
    if not is_page_recent_enough(page_date, max_age_days):
        print(f"[Page] Rejetée (trop ancienne, date détectée : {page_date.strftime('%d/%m/%Y')}) : {url}")
        return None

    if page_date:
        print(f"[Page] Date détectée : {page_date.strftime('%d/%m/%Y')} — {url}")
    else:
        print(f"[Page] Aucune date détectée (page conservée) — {url}")

    for tag in soup(["script", "style", "nav", "footer", "header", "aside", "noscript", "form"]):
        tag.decompose()

    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) < 200:
        print(f"[Page] Contenu trop court/vide pour {url}, ignoré.")
        return None

    truncated = text[:max_length]

    print(f"[Page] {len(text)} caractères extraits de {url} (tronqué à {len(truncated)}).")
    return {"text": truncated, "date": page_date}


def fetch_pages_for_target(urls, max_age_days=MAX_AGE_DAYS):
    """
    Récupère le contenu texte de chaque URL d'une liste, en filtrant les pages trop anciennes.
    Retourne une liste de dicts {url, text, date} pour les pages exploitables et récentes.
    """
    pages = []
    for url in urls:
        result = fetch_page_text(url, max_age_days=max_age_days)
        if result:
            pages.append({"url": url, "text": result["text"], "date": result["date"]})
        time.sleep(0.5)
    return pages
# --- Extraction des bugs via Gemini (sans grounding, gratuit) ---

def build_extraction_prompt(product, version, page_text, source_url, page_date=None):
    """Construit le prompt demandant à Gemini d'extraire les bugs/solutions d'un texte de page."""
    date_context = ""
    if page_date:
        date_context = f"Cette page a été publiée/modifiée le {page_date.strftime('%d/%m/%Y')}. "

    return f"""Tu es un expert Fortinet. Voici le contenu textuel brut d'une page web (forum, blog technique,
communauté) qui pourrait contenir des retours d'utilisateurs sur des BUGS RÉELS rencontrés avec
{product} en version {version}, et éventuellement leurs solutions.

{date_context}Contenu de la page (source : {source_url}) :
---
{page_text}
---

Analyse ce texte et extrais UNIQUEMENT les problèmes concrets remontés par des utilisateurs/administrateurs
concernant {product} {version} (pas des CVE de sécurité officielles, pas des questions générales de config).

IMPORTANT : Si le texte mentionne des dates explicites de rencontre du problème (ex: "en 2022", "version 6.4"),
et que celles-ci indiquent clairement un contexte ancien ou une version différente de {version}, IGNORE ce cas.
Ne retiens que les problèmes dont rien n'indique qu'ils sont obsolètes ou liés à une autre version.

Réponds UNIQUEMENT avec un tableau JSON valide (pas de texte autour, pas de balises markdown), où chaque
élément a exactement cette structure :
[
  {{
    "title": "titre court et clair du problème (max 100 caractères, en français)",
    "symptom": "description du bug/comportement observé, en français, 2-4 phrases, basée uniquement sur le texte fourni",
    "solution": "solution ou contournement mentionné dans le texte, en français, avec commande CLI si présente dans le texte. Si aucune solution n'est mentionnée, indique 'Aucune solution mentionnée dans la source.'"
  }}
]

Si le texte ne contient aucun bug concret pertinent pour {product} {version}, retourne un tableau vide [].
Ne fournis aucune autre explication, uniquement le tableau JSON."""


def extract_json_array(raw_text):
    """Extrait un tableau JSON d'une réponse texte, même si entouré de markdown ou de texte parasite."""
    text = raw_text.strip()

    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def extract_bugs_from_page(client, product, version, page, delay=1.0):
    """
    Envoie le texte d'une page à Gemini pour en extraire les bugs/solutions.
    Retourne une liste de dicts {title, symptom, solution, source}.
    """
    prompt = build_extraction_prompt(
        product, version, page["text"], page["url"], page.get("date")
    )

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )
    except Exception as e:
        print(f"[Gemini] Erreur d'extraction pour {page['url']} : {e}")
        time.sleep(delay)
        return []

    raw_text = response.text or ""
    bugs = extract_json_array(raw_text)

    if bugs is None:
        print(f"[Gemini] Réponse non-JSON pour {page['url']}, ignorée.")
        time.sleep(delay)
        return []

    result = []
    for b in bugs:
        result.append({
            "title": b.get("title", "Sans titre"),
            "symptom": b.get("symptom", ""),
            "solution": b.get("solution", ""),
            "source": page["url"],
        })

    print(f"[Gemini] {len(result)} bug(s) extrait(s) de {page['url']}.")
    time.sleep(delay)
    return result
# --- Orchestration par cible produit/version ---

def process_target(client, product, version, delay=1.0, max_age_days=MAX_AGE_DAYS):
    """
    Pipeline complet pour une cible donnée :
    recherche web -> récupération des pages (filtrées par date) -> extraction IA -> liste de bugs structurés.
    """
    print(f"\n--- Cible : {product} {version} ---")

    urls = search_web_urls(product, version, max_age_days=max_age_days)
    if not urls:
        print(f"[Cible] Aucune URL trouvée pour {product} {version}.")
        return []

    pages = fetch_pages_for_target(urls, max_age_days=max_age_days)
    if not pages:
        print(f"[Cible] Aucune page exploitable/récente pour {product} {version}.")
        return []

    all_bugs = []
    for page in pages:
        bugs = extract_bugs_from_page(client, product, version, page, delay=delay)
        for b in bugs:
            b["product"] = product
            b["version"] = version
            all_bugs.append(b)

    print(f"[Cible] {len(all_bugs)} bug(s) au total pour {product} {version}.")
    return all_bugs


# --- Agrégation de toutes les cibles ---

def collect_all_bugs(client, delay=1.0, max_age_days=MAX_AGE_DAYS):
    """Parcourt toutes les cibles définies dans TARGETS et agrège les bugs trouvés."""
    all_bugs = []
    total = len(TARGETS)

    for idx, target in enumerate(TARGETS, start=1):
        print(f"\n=== Cible {idx}/{total} ===")
        bugs = process_target(client, target["product"], target["version"], delay=delay, max_age_days=max_age_days)
        all_bugs.extend(bugs)

    for i, b in enumerate(all_bugs, start=1):
        b["id"] = f"{b['product'].upper()}-{b['version']}-{i}"

    print(f"\n[Résumé] {len(all_bugs)} bugs terrain collectés au total.")
    return all_bugs


# --- Génération du JavaScript (données) ---

def build_js_array(bugs):
    """Construit la chaîne JS 'var bugData = [...]' à partir de la liste de bugs trouvés."""
    entries = []
    for b in bugs:
        entry = (
            "  {"
            f'id:"{js_escape(b["id"])}",'
            f'title:"{js_escape(b["title"])}",'
            f'product:"{js_escape(b["product"])}",'
            f'version:"{js_escape(b["version"])}",'
            f'symptom:"{js_escape(b["symptom"])}",'
            f'solution:"{js_escape(b["solution"])}",'
            f'source:"{js_escape(b["source"])}"'
            "}"
        )
        entries.append(entry)

    if not entries:
        return "var bugData = [];"

    return "var bugData = [\n" + ",\n".join(entries) + "\n];"
# --- Template HTML (head + CSS) ---

HTML_HEAD = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veille Fortinet — Bugs terrain & solutions</title>
<style>
:root{
  --bg:#0b1220; --card:#111a2e; --hover:#15213a; --border:#1f2b45;
  --text:#e8edf7; --muted:#93a1bd; --accent:#3b82f6; --purple:#8b5cf6; --green:#22c55e;
}
*{box-sizing:border-box;}
body{margin:0;font-family:Arial,sans-serif;background:var(--bg);color:var(--text);padding:24px;}
.title{font-size:1.6rem;font-weight:700;}
.subtitle{color:var(--muted);margin-top:6px;font-size:0.85rem;}
.menu-label{font-size:.72rem;text-transform:uppercase;color:var(--muted);margin:16px 0 8px;}
.filters{display:flex;gap:10px;flex-wrap:wrap;}
.btn{background:var(--card);border:1px solid var(--border);color:var(--text);padding:8px 16px;border-radius:20px;cursor:pointer;font-size:.9rem;display:flex;align-items:center;gap:6px;}
.btn:hover{background:var(--hover);}
.btn.active-product{background:var(--accent);border-color:var(--accent);color:#fff;}
.btn.active-version{background:var(--purple);border-color:var(--purple);color:#fff;}
.btn .count{background:rgba(255,255,255,.15);padding:1px 7px;border-radius:10px;font-size:.75rem;font-weight:700;}
.btn.zero{opacity:.45;}
.searchbox{margin-top:16px;}
.searchbox input{width:100%;max-width:420px;padding:10px 14px;border-radius:20px;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:.9rem;outline:none;}
.searchbox input:focus{border-color:var(--accent);}
.list{margin-top:20px;display:flex;flex-direction:column;gap:10px;}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden;}
.card-header{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;cursor:pointer;gap:12px;}
.card-header:hover{background:var(--hover);}
.card-header > div:first-child{flex:1;min-width:0;}
.card-title{font-weight:600;}
.card-sub{color:var(--muted);font-size:.78rem;margin-top:3px;}
.card-header-right{display:flex;align-items:center;flex-shrink:0;}
.badge{padding:4px 10px;border-radius:12px;font-size:.75rem;font-weight:700;margin-left:8px;white-space:nowrap;}
.badge.prod{background:rgba(59,130,246,.15);color:var(--accent);border:1px solid var(--accent);}
.badge.ver{background:rgba(139,92,246,.15);color:var(--purple);border:1px solid var(--purple);}
.card-body{display:none;padding:0 16px 16px;}
.card.open .card-body{display:block;}
.card.open .chev{transform:rotate(180deg);}
.chev{transition:transform .2s;color:var(--muted);flex-shrink:0;margin-left:8px;}
.lbl{font-size:.72rem;text-transform:uppercase;color:var(--muted);margin:10px 0 4px;}
.val{font-size:.9rem;line-height:1.5;}
.mono{font-family:monospace;background:#0d1526;padding:8px;border-radius:6px;border:1px solid var(--border);white-space:pre-wrap;}
.source a{color:var(--green);text-decoration:none;font-size:.8rem;}
.source a:hover{text-decoration:underline;}
.empty{text-align:center;color:var(--muted);padding:30px;}
.results-count{color:var(--muted);font-size:.82rem;margin-top:14px;}
footer{margin-top:30px;text-align:center;color:var(--muted);font-size:.8rem;}
</style>
</head>
<body>
"""


# --- Template HTML (body) ---

def build_html_body(generated_at, max_age_days):
    """Construit le corps HTML avec les infos de génération dynamiques."""
    return f"""
<div class="title">🛡️ Veille Fortinet — Bugs terrain & solutions communautaires</div>
<div class="subtitle">Généré le {generated_at} · Sujets des {max_age_days} derniers jours · Toutes les entrées sont visibles ci-dessous, cliquez pour dérouler les détails</div>

<div class="menu-label">Produit</div>
<div class="filters" id="productMenu"></div>

<div class="menu-label">Version</div>
<div class="filters" id="versionMenu"></div>

<div class="searchbox">
<input type="text" id="searchInput" placeholder="Rechercher un mot-clé (titre, symptôme)...">
</div>

<div class="results-count" id="resultsCount"></div>
<div class="list" id="list"></div>

<footer>Vérifier les sources avant application en production</footer>
"""
# --- JavaScript de rendu ---

JS_RENDER_LOGIC = """
<script>
var state = {product:"ALL", version:"ALL", search:""};

var PRODUCTS = ["FortiGate", "FortiManager", "FortiAnalyzer", "FortiClientEMS", "FortiClient"];
var VERSIONS = ["7.4", "7.6"];

function countFor(product, version){
  return bugData.filter(function(v){
    var okP = (product === "ALL") || (v.product === product);
    var okV = (version === "ALL") || (v.version === version);
    return okP && okV;
  }).length;
}

function buildMenus(){
  var pMenu = document.getElementById("productMenu");
  var totalAll = bugData.length;
  var htmlP = ['<button class="btn active-product" data-product="ALL">Tous <span class="count">'+totalAll+'</span></button>'];
  PRODUCTS.forEach(function(p){
    var c = countFor(p, "ALL");
    htmlP.push('<button class="btn'+(c===0?' zero':'')+'" data-product="'+p+'">'+p+' <span class="count">'+c+'</span></button>');
  });
  pMenu.innerHTML = htmlP.join("");

  var vMenu = document.getElementById("versionMenu");
  var htmlV = ['<button class="btn active-version" data-version="ALL">Toutes <span class="count">'+totalAll+'</span></button>'];
  VERSIONS.forEach(function(v){
    var c = countFor("ALL", v);
    htmlV.push('<button class="btn'+(c===0?' zero':'')+'" data-version="'+v+'">'+v+' <span class="count">'+c+'</span></button>');
  });
  vMenu.innerHTML = htmlV.join("");

  bindMenuEvents();
}

function bindMenuEvents(){
  var prodBtns = document.querySelectorAll("#productMenu .btn");
  for(var p=0;p<prodBtns.length;p++){
    prodBtns[p].addEventListener("click", function(){
      for(var x=0;x<prodBtns.length;x++){ prodBtns[x].classList.remove("active-product"); }
      this.classList.add("active-product");
      state.product = this.getAttribute("data-product");
      render();
    });
  }
  var verBtns = document.querySelectorAll("#versionMenu .btn");
  for(var v=0;v<verBtns.length;v++){
    verBtns[v].addEventListener("click", function(){
      for(var y=0;y<verBtns.length;y++){ verBtns[y].classList.remove("active-version"); }
      this.classList.add("active-version");
      state.version = this.getAttribute("data-version");
      render();
    });
  }
}

function render(){
  var list = document.getElementById("list");
  var countEl = document.getElementById("resultsCount");

  var items = bugData.filter(function(v){
    var okP = (state.product === "ALL") || (v.product === state.product);
    var okV = (state.version === "ALL") || (v.version === state.version);
    var okS = true;
    if(state.search){
      var s = state.search.toLowerCase();
      okS = (v.title && v.title.toLowerCase().indexOf(s) !== -1) ||
            (v.symptom && v.symptom.toLowerCase().indexOf(s) !== -1);
    }
    return okP && okV && okS;
  });

  countEl.textContent = items.length + " résultat(s)";

  if(items.length === 0){
    list.innerHTML = '<div class="empty">Aucun bug ne correspond aux filtres sélectionnés.</div>';
    return;
  }

  var html = [];
  items.forEach(function(v, i){
    html.push('<div class="card" data-i="'+i+'">');
    html.push('<div class="card-header">');
    html.push('<div><div class="card-title">'+v.title+'</div><div class="card-sub">'+v.id+'</div></div>');
    html.push('<div class="card-header-right">');
    html.push('<span class="badge prod">'+v.product+'</span>');
    html.push('<span class="badge ver">'+v.version+'</span>');
    html.push('<span class="chev">▼</span>');
    html.push('</div></div>');
    html.push('<div class="card-body">');
    html.push('<div class="lbl">Symptôme observé</div><div class="val">'+v.symptom+'</div>');
    html.push('<div class="lbl">Solution / contournement</div><div class="val mono">'+v.solution+'</div>');
    html.push('<div class="lbl">Source</div><div class="val source"><a href="'+v.source+'" target="_blank" rel="noopener">'+v.source+'</a></div>');
    html.push('</div></div>');
  });

  list.innerHTML = html.join("");

  var cards = list.querySelectorAll(".card");
  for(var c=0;c<cards.length;c++){
    cards[c].querySelector(".card-header").addEventListener("click", function(){
      this.parentElement.classList.toggle("open");
    });
  }
}

document.getElementById("searchInput").addEventListener("input", function(){
  state.search = this.value;
  render();
});

buildMenus();
render();
</script>
</body>
</html>
"""


# --- Point d'entrée principal ---

def main():
    parser = argparse.ArgumentParser(
        description="Veille Fortinet — recherche web + extraction IA des bugs terrain récents"
    )
    parser.add_argument("--gemini-key", type=str, required=True,
        help="Clé API Gemini (obligatoire)")
    parser.add_argument("--output", type=str, default=OUTPUT_FILE,
        help=f"Nom du fichier de sortie (par défaut : {OUTPUT_FILE})")
    parser.add_argument("--delay", type=float, default=1.0,
        help="Délai en secondes entre chaque appel Gemini (par défaut : 1.0)")
    parser.add_argument("--max-age-days", type=int, default=MAX_AGE_DAYS,
        help=f"Âge maximum des sujets à conserver, en jours (par défaut : {MAX_AGE_DAYS})")
    args = parser.parse_args()

    print("=== Veille Fortinet — Bugs terrain — démarrage ===\n")
    print(f"[Config] Filtre de fraîcheur : {args.max_age_days} jours maximum\n")

    client = configure_gemini(args.gemini_key)
    bugs = collect_all_bugs(client, delay=args.delay, max_age_days=args.max_age_days)
    bug_js = build_js_array(bugs)

    generated_at = datetime.now().strftime("%d/%m/%Y à %H:%M")
    html_body = build_html_body(generated_at, args.max_age_days)

    full_html = (
        HTML_HEAD
        + html_body
        + "\n<script>\n"
        + bug_js
        + "\n</script>\n"
        + JS_RENDER_LOGIC
    )

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(full_html)

    print(f"\n=== Terminé ===")
    print(f"{len(bugs)} bugs terrain intégrés au total.")
    print(f"Fichier généré : {args.output}")


if __name__ == "__main__":
    main()
