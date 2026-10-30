#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scrap_commu.py
==============
Veille Fortinet Community avec analyse Gemini.

USAGE :
    export GEMINI_API_KEY="VOTRE_CLE_API_GEMINI"
    python scripts/scrap_commu_copie.py

Sous PowerShell :
    $env:GEMINI_API_KEY = "VOTRE_CLE_API_GEMINI"
    python scripts/scrap_commu_copie.py

Le script propose un menu :
  1) Lancer un scraping + analyse complète (Gemini analyse tout)
  2) Poser une consigne précise à Gemini (recherche ciblée dans les résultats)
  3) Afficher le scope de versions actuellement configuré
  4) Quitter

Le scope de versions surveillées est modifiable directement dans ce fichier,
section VERSION_SCOPE ci-dessous.
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime

# ------------------------------------------------------------------
# CONFIGURATION GÉNÉRALE
# ------------------------------------------------------------------

FEED_URL = "https://community.fortinet.com/feed/topics"
HISTORIQUE_FICHIER = "historique.json"
DOSSIER_SORTIE = "."
MODELE_GEMINI = "gemini-3.6-flash"

# ------------------------------------------------------------------
# SCOPE DES PRODUITS ET VERSIONS SURVEILLÉS
# Modifiez librement les listes ci-dessous pour changer le périmètre.
# ------------------------------------------------------------------

VERSION_SCOPE = {
    "fortigate": ["7.4.12", "7.4.11", "7.6.7", "7.6.6"],
    "fortimanager": ["7.4.11", "7.4.10", "7.6.7", "7.6.6"],
    "fortianalyzer": ["7.4.11", "7.4.10", "7.6.7", "7.6.6"],
    "forticlient ems": ["7.4.8", "7.4.7", "7.6.7", "7.6.6"],
    "forticlient": ["7.4.8", "7.4.7", "7.6.7", "7.6.6"],
}

PRODUITS_CIBLES = list(VERSION_SCOPE.keys())


# ------------------------------------------------------------------
# RÉCUPÉRATION DU FLUX
# ------------------------------------------------------------------

def recuperer_flux(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (FortinetWatchBot)"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parser_flux(xml_text):
    items = []
    root = ET.fromstring(xml_text)

    rss_items = root.findall(".//item")
    atom_items = root.findall(".//{http://www.w3.org/2005/Atom}entry")

    if rss_items:
        for it in rss_items:
            title = (it.findtext("title") or "").strip()
            link = (it.findtext("link") or "").strip()
            date_txt = (it.findtext("pubDate") or "").strip()
            summary = (it.findtext("description") or "").strip()
            category = (it.findtext("category") or "").strip()
            items.append({
                "title": title, "link": link, "date": date_txt,
                "summary": summary, "category": category,
            })
    elif atom_items:
        ns = "{http://www.w3.org/2005/Atom}"
        for it in atom_items:
            title = (it.findtext(f"{ns}title") or "").strip()
            link_el = it.find(f"{ns}link")
            link = link_el.get("href") if link_el is not None else ""
            date_txt = (it.findtext(f"{ns}updated") or it.findtext(f"{ns}published") or "").strip()
            summary = (it.findtext(f"{ns}summary") or it.findtext(f"{ns}content") or "").strip()
            category_el = it.find(f"{ns}category")
            category = category_el.get("term") if category_el is not None else ""
            items.append({
                "title": title, "link": link, "date": date_txt,
                "summary": summary, "category": category,
            })

    return items


# ------------------------------------------------------------------
# FILTRAGE PAR PRODUIT + VERSION
# ------------------------------------------------------------------

def detecter_produits(texte):
    texte_lower = texte.lower()
    trouves = []
    for produit in PRODUITS_CIBLES:
        if produit in texte_lower:
            trouves.append(produit)
    if "forticlient ems" in trouves and "forticlient" in trouves:
        trouves.remove("forticlient")
    return trouves


def detecter_versions(texte, produits):
    """Retourne la liste des versions du scope détectées dans le texte,
    pour les produits déjà identifiés dans cet item."""
    trouvees = []
    for produit in produits:
        for version in VERSION_SCOPE.get(produit, []):
            if version in texte:
                trouvees.append(version)
    return sorted(set(trouvees))


def filtrer_items(items, filtrer_par_version=True):
    """
    Filtre les items par produit ciblé.
    Si filtrer_par_version=True, ne garde que les items dont une version
    du scope est explicitement mentionnée, OU qui ne mentionnent aucune
    version du tout (pour ne pas perdre les sujets génériques pertinents).
    """
    resultat = []
    for it in items:
        texte_complet = f"{it['title']} {it['summary']} {it['category']}"
        produits = detecter_produits(texte_complet)
        if not produits:
            continue

        versions_trouvees = detecter_versions(texte_complet, produits)

        # Détecte si une version quelconque (hors scope) est mentionnée,
        # pour distinguer "aucune version" de "version hors scope"
        toute_version_pattern = r"\b\d+\.\d+\.\d+\b"
        mention_version_quelconque = bool(re.search(toute_version_pattern, texte_complet))

        if filtrer_par_version:
            if versions_trouvees:
                garder = True
            elif not mention_version_quelconque:
                garder = True  # sujet générique sans version précisée -> on garde par prudence
            else:
                garder = False  # une version est mentionnée mais hors scope -> on exclut
        else:
            garder = True

        if garder:
            it_copie = dict(it)
            it_copie["produits"] = produits
            it_copie["versions_detectees"] = versions_trouvees
            resultat.append(it_copie)

    return resultat
# ------------------------------------------------------------------
# GESTION DE L'HISTORIQUE
# ------------------------------------------------------------------

def charger_historique(chemin):
    if os.path.exists(chemin):
        with open(chemin, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"entrees": []}


def sauvegarder_historique(chemin, historique):
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(historique, f, ensure_ascii=False, indent=2)


def fusionner_historique(historique, nouveaux_items):
    """Ajoute les nouveaux items à l'historique s'ils n'y sont pas déjà (par lien)."""
    liens_connus = {e["link"] for e in historique["entrees"]}
    horodatage = datetime.now().isoformat()

    for item in nouveaux_items:
        if item["link"] not in liens_connus:
            item["premiere_detection"] = horodatage
            historique["entrees"].append(item)
            liens_connus.add(item["link"])

    return historique


# ------------------------------------------------------------------
# APPEL À L'API GEMINI
# ------------------------------------------------------------------

def appeler_gemini(cle_api, prompt, modele=MODELE_GEMINI):
    """
    Envoie un prompt à l'API Gemini (REST, sans dépendance externe)
    et retourne le texte de la réponse.
    """
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{modele}:generateContent"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 32768,
        }
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": cle_api,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            reponse_brute = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Do not include the response body: upstream diagnostics can echo request data.
        raise RuntimeError(f"Erreur API Gemini ({e.code}); détails masqués.") from None

    try:
        candidat = reponse_brute["candidates"][0]
        texte = candidat["content"]["parts"][0]["text"]
        raison_fin = candidat.get("finishReason", "")
    except (KeyError, IndexError):
        raise RuntimeError(f"Réponse Gemini inattendue : {reponse_brute}")

    if raison_fin == "MAX_TOKENS":
        print("       ⚠ ATTENTION : la réponse Gemini a été tronquée (limite de tokens atteinte).")
        print("         Réduisez le nombre de sujets envoyés ou augmentez maxOutputTokens.")

    return texte


def nettoyer_reponse_html(texte):
    """Retire les éventuels blocs de code Markdown (```html ... ```) autour du HTML."""
    texte = texte.strip()
    texte = re.sub(r"^```(?:html)?\s*", "", texte)
    texte = re.sub(r"\s*```$", "", texte)
    return texte.strip()


def preparer_items_pour_gemini(items, limite=60):
    """
    Prépare une version compacte des items (pour limiter la taille du prompt)
    à envoyer à Gemini : titre, lien, date, produits, versions, résumé tronqué.
    """
    items_tries = sorted(items, key=lambda x: x.get("date", ""), reverse=True)[:limite]
    compact = []
    for it in items_tries:
        compact.append({
            "titre": it.get("title", ""),
            "lien": it.get("link", ""),
            "date": it.get("date", ""),
            "produits": it.get("produits", []),
            "versions": it.get("versions_detectees", []),
            "resume": (it.get("summary", "") or "")[:500],
        })
    return compact


# ------------------------------------------------------------------
# CONSTRUCTION DES PROMPTS
# ------------------------------------------------------------------

def construire_prompt_analyse_complete(items_compacts, scope_versions):
    scope_txt = json.dumps(scope_versions, ensure_ascii=False, indent=2)
    items_txt = json.dumps(items_compacts, ensure_ascii=False, indent=2)

    prompt = f"""Tu es un expert Fortinet chargé d'analyser des sujets du forum Fortinet Community.

SCOPE DES PRODUITS ET VERSIONS SURVEILLÉS :
{scope_txt}

VOICI LES SUJETS BRUTS RÉCUPÉRÉS (JSON) :
{items_txt}

TA MISSION :
1. Analyse chaque sujet et regroupe-les par CATÉGORIE de problème (ex: "VPN SSL - déconnexions", "GUI - bugs d'affichage", "Performance CPU/mémoire", "DHCP", etc.)
2. Pour chaque sujet ou groupe de sujets similaires, identifie s'il existe une solution ou un workaround mentionné (dans le résumé ou déductible du contexte). Si aucune solution n'est visible, indique "Non résolu / à surveiller".
3. Génère une page HTML COMPLÈTE et AUTONOME (avec balises <html>, <head>, <style> inline, <body>) qui présente :
   - Un titre et un résumé en haut (nombre total de sujets, nombre de catégories)
   - Une section par catégorie de problème, avec un titre de section clair
   - Dans chaque section : un tableau ou des cartes listant les sujets concernés, avec :
     * Titre du sujet (cliquable vers le lien d'origine)
     * Date
     * Produit(s) et version(s) concernée(s)
     * Solution/workaround identifié (ou "Non résolu / à surveiller")
   - Un design propre, moderne, lisible (utilise des couleurs pour distinguer résolu/non résolu)
   - Le HTML doit être interactif si possible (ex: sections repliables/dépliables en JavaScript pur, sans dépendance externe)

IMPORTANT : Réponds UNIQUEMENT avec le code HTML complet, sans aucun texte d'explication avant ou après, sans balises Markdown de code (pas de ```html)."""

    return prompt


def construire_prompt_recherche_ciblee(items_compacts, consigne):
    items_txt = json.dumps(items_compacts, ensure_ascii=False, indent=2)

    prompt = f"""Tu es un expert Fortinet. Un technicien te décrit un problème qu'il rencontre.
Ta mission est de chercher dans la liste de sujets ci-dessous (issus du forum Fortinet Community)
ceux qui correspondent le mieux à sa description, et de lui indiquer les liens pertinents ainsi
que les solutions/workarounds identifiés.

DESCRIPTION DU PROBLÈME DU TECHNICIEN :
"{consigne}"

VOICI LES SUJETS DISPONIBLES (JSON) :
{items_txt}

TA MISSION :
1. Identifie les sujets les plus pertinents par rapport à la description (même si les mots ne correspondent pas exactement, cherche par sens).
2. Si tu trouves des sujets pertinents, génère une page HTML COMPLÈTE et AUTONOME (avec <html>, <head>, <style> inline, <body>) présentant :
   - La description du problème rappelée en haut
   - Une liste des sujets pertinents trouvés, classés par pertinence décroissante, avec : titre (cliquable), date, produit/version, résumé, et solution/workaround si identifié
   - Si aucun sujet pertinent n'est trouvé, affiche clairement un message "Aucun sujet correspondant trouvé dans les données actuelles" avec un design propre
3. Design moderne et lisible.

IMPORTANT : Réponds UNIQUEMENT avec le code HTML complet, sans aucun texte d'explication avant ou après, sans balises Markdown de code (pas de ```html)."""

    return prompt

# ------------------------------------------------------------------
# APPEL À L'API GEMINI
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# CONSTRUCTION DES PROMPTS
# ------------------------------------------------------------------

def construire_prompt_analyse_complete(items_compacts, scope_versions):
    scope_txt = json.dumps(scope_versions, ensure_ascii=False, indent=2)
    items_txt = json.dumps(items_compacts, ensure_ascii=False, indent=2)

    prompt = f"""Tu es un expert Fortinet chargé d'analyser des sujets du forum Fortinet Community.

SCOPE DES PRODUITS ET VERSIONS SURVEILLÉS :
{scope_txt}

VOICI LES SUJETS BRUTS RÉCUPÉRÉS (JSON) :
{items_txt}

TA MISSION :
1. Analyse chaque sujet et regroupe-les par CATÉGORIE de problème (ex: "VPN SSL - déconnexions", "GUI - bugs d'affichage", "Performance CPU/mémoire", "DHCP", etc.)
2. Pour chaque sujet ou groupe de sujets similaires, identifie s'il existe une solution ou un workaround mentionné (dans le résumé ou déductible du contexte). Si aucune solution n'est visible, indique "Non résolu / à surveiller".
3. Génère une page HTML COMPLÈTE et AUTONOME (avec balises <html>, <head>, <style> inline, <body>) qui présente :
   - Un titre et un résumé en haut (nombre total de sujets, nombre de catégories)
   - Une section par catégorie de problème, avec un titre de section clair
   - Dans chaque section : un tableau ou des cartes listant les sujets concernés, avec :
     * Titre du sujet (cliquable vers le lien d'origine)
     * Date
     * Produit(s) et version(s) concernée(s)
     * Solution/workaround identifié (ou "Non résolu / à surveiller")
   - Un design propre, moderne, lisible (utilise des couleurs pour distinguer résolu/non résolu)
   - Le HTML doit être interactif si possible (ex: sections repliables/dépliables en JavaScript pur, sans dépendance externe)

IMPORTANT : Réponds UNIQUEMENT avec le code HTML complet, sans aucun texte d'explication avant ou après, sans balises Markdown de code (pas de ```html)."""

    return prompt


def construire_prompt_recherche_ciblee(items_compacts, consigne):
    items_txt = json.dumps(items_compacts, ensure_ascii=False, indent=2)

    prompt = f"""Tu es un expert Fortinet. Un technicien te décrit un problème qu'il rencontre.
Ta mission est de chercher dans la liste de sujets ci-dessous (issus du forum Fortinet Community)
ceux qui correspondent le mieux à sa description, et de lui indiquer les liens pertinents ainsi
que les solutions/workarounds identifiés.

DESCRIPTION DU PROBLÈME DU TECHNICIEN :
"{consigne}"

VOICI LES SUJETS DISPONIBLES (JSON) :
{items_txt}

TA MISSION :
1. Identifie les sujets les plus pertinents par rapport à la description (même si les mots ne correspondent pas exactement, cherche par sens).
2. Si tu trouves des sujets pertinents, génère une page HTML COMPLÈTE et AUTONOME (avec <html>, <head>, <style> inline, <body>) présentant :
   - La description du problème rappelée en haut
   - Une liste des sujets pertinents trouvés, classés par pertinence décroissante, avec : titre (cliquable), date, produit/version, résumé, et solution/workaround si identifié
   - Si aucun sujet pertinent n'est trouvé, affiche clairement un message "Aucun sujet correspondant trouvé dans les données actuelles" avec un design propre
3. Design moderne et lisible.

IMPORTANT : Réponds UNIQUEMENT avec le code HTML complet, sans aucun texte d'explication avant ou après, sans balises Markdown de code (pas de ```html)."""

    return prompt
# ------------------------------------------------------------------
# SAUVEGARDE DU RAPPORT HTML
# ------------------------------------------------------------------

def sauvegarder_rapport_html(contenu_html, prefixe="rapport"):
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    nom_fichier = f"{prefixe}_{horodatage}.html"
    chemin_complet = os.path.join(DOSSIER_SORTIE, nom_fichier)
    with open(chemin_complet, "w", encoding="utf-8") as f:
        f.write(contenu_html)
    return chemin_complet


# ------------------------------------------------------------------
# ACTIONS DU MENU
# ------------------------------------------------------------------

def action_scraping_complet(cle_api, filtrer_par_version):
    print("=" * 60)
    print("Scraping complet - démarrage")
    print("=" * 60)

    try:
        print(f"[1/6] Téléchargement du flux : {FEED_URL}")
        xml_brut = recuperer_flux(FEED_URL)
    except Exception as e:
        print(f"ERREUR lors du téléchargement du flux : {e}", file=sys.stderr)
        return

    try:
        print("[2/6] Analyse du flux XML...")
        tous_items = parser_flux(xml_brut)
        print(f"       -> {len(tous_items)} sujets trouvés dans le flux")
    except Exception as e:
        print(f"ERREUR lors du parsing XML : {e}", file=sys.stderr)
        return

    print("[3/6] Filtrage sur les produits et versions du scope...")
    items_filtres = filtrer_items(tous_items, filtrer_par_version=filtrer_par_version)
    print(f"       -> {len(items_filtres)} sujets correspondants")

    if not items_filtres:
        print("Aucun sujet ne correspond au scope actuel. Arrêt.")
        return

    print(f"[4/6] Mise à jour de l'historique ({HISTORIQUE_FICHIER})...")
    historique = charger_historique(HISTORIQUE_FICHIER)
    historique = fusionner_historique(historique, items_filtres)
    sauvegarder_historique(HISTORIQUE_FICHIER, historique)
    print(f"       -> {len(historique['entrees'])} sujets au total dans l'historique")

    print("[5/6] Préparation des données et envoi à Gemini...")
    items_compacts = preparer_items_pour_gemini(historique["entrees"])
    prompt = construire_prompt_analyse_complete(items_compacts, VERSION_SCOPE)

    try:
        reponse = appeler_gemini(cle_api, prompt)
    except Exception as e:
        print(f"ERREUR lors de l'appel à Gemini : {e}", file=sys.stderr)
        return

    print("[6/6] Génération du rapport HTML...")
    html_propre = nettoyer_reponse_html(reponse)
    chemin = sauvegarder_rapport_html(html_propre, prefixe="rapport_analyse")

    print("=" * 60)
    print(f"Terminé. Rapport généré : {chemin}")
    print("=" * 60)


def action_recherche_ciblee(cle_api, filtrer_par_version):
    print("=" * 60)
    print("Recherche ciblée - démarrage")
    print("=" * 60)

    consigne = input(
        "\nDécrivez le problème rencontré (laissez vide pour tout analyser) :\n> "
    ).strip()

    try:
        print(f"[1/5] Téléchargement du flux : {FEED_URL}")
        xml_brut = recuperer_flux(FEED_URL)
    except Exception as e:
        print(f"ERREUR lors du téléchargement du flux : {e}", file=sys.stderr)
        return

    try:
        print("[2/5] Analyse du flux XML...")
        tous_items = parser_flux(xml_brut)
        print(f"       -> {len(tous_items)} sujets trouvés dans le flux")
    except Exception as e:
        print(f"ERREUR lors du parsing XML : {e}", file=sys.stderr)
        return

    print("[3/5] Filtrage sur les produits et versions du scope...")
    items_filtres = filtrer_items(tous_items, filtrer_par_version=filtrer_par_version)
    print(f"       -> {len(items_filtres)} sujets correspondants")

    historique = charger_historique(HISTORIQUE_FICHIER)
    historique = fusionner_historique(historique, items_filtres)
    sauvegarder_historique(HISTORIQUE_FICHIER, historique)

    if not historique["entrees"]:
        print("Aucun sujet disponible dans l'historique. Arrêt.")
        return

    print("[4/5] Préparation des données et envoi à Gemini...")
    items_compacts = preparer_items_pour_gemini(historique["entrees"])

    if consigne:
        prompt = construire_prompt_recherche_ciblee(items_compacts, consigne)
        prefixe = "rapport_recherche"
    else:
        print("       (consigne vide -> analyse complète de tous les sujets)")
        prompt = construire_prompt_analyse_complete(items_compacts, VERSION_SCOPE)
        prefixe = "rapport_analyse"

    try:
        reponse = appeler_gemini(cle_api, prompt)
    except Exception as e:
        print(f"ERREUR lors de l'appel à Gemini : {e}", file=sys.stderr)
        return

    print("[5/5] Génération du rapport HTML...")
    html_propre = nettoyer_reponse_html(reponse)
    chemin = sauvegarder_rapport_html(html_propre, prefixe=prefixe)

    print("=" * 60)
    print(f"Terminé. Rapport généré : {chemin}")
    print("=" * 60)


def action_afficher_scope():
    print("=" * 60)
    print("SCOPE DE VERSIONS ACTUELLEMENT CONFIGURÉ")
    print("=" * 60)
    for produit, versions in VERSION_SCOPE.items():
        print(f"  {produit.title()} : {', '.join(versions)}")
    print("=" * 60)
    print("Pour modifier ce scope, éditez la variable VERSION_SCOPE")
    print("en haut du fichier scrap_commu.py, puis relancez le script.")
    print("=" * 60)


# ------------------------------------------------------------------
# MENU PRINCIPAL
# ------------------------------------------------------------------

def afficher_menu():
    print("\n" + "=" * 60)
    print("VEILLE FORTINET COMMUNITY - MENU")
    print("=" * 60)
    print("1) Lancer un scraping + analyse complète (Gemini analyse tout)")
    print("2) Poser une consigne précise à Gemini (recherche ciblée)")
    print("3) Afficher le scope de versions actuellement configuré")
    print("4) Quitter")
    print("=" * 60)


def main():
    if len(sys.argv) > 1:
        print(
            "ERREUR : ne passez pas la clé API Gemini en argument. "
            "Utilisez la variable d'environnement GEMINI_API_KEY."
        )
        sys.exit(2)

    cle_api = os.environ.get("GEMINI_API_KEY", "").strip()
    if not cle_api:
        print("ERREUR : la variable d'environnement GEMINI_API_KEY est absente.")
        print('Usage : export GEMINI_API_KEY="VOTRE_CLE_API_GEMINI"')
        print("Puis : python scripts/scrap_commu_copie.py")
        sys.exit(1)

    # Si vous voulez filtrer STRICTEMENT sur les versions du scope
    # (exclure aussi les sujets sans version précisée), passez False -> True ici :
    filtrer_par_version = True

    while True:
        afficher_menu()
        choix = input("Votre choix : ").strip()

        if choix == "1":
            action_scraping_complet(cle_api, filtrer_par_version)
        elif choix == "2":
            action_recherche_ciblee(cle_api, filtrer_par_version)
        elif choix == "3":
            action_afficher_scope()
        elif choix == "4":
            print("Fermeture du programme.")
            break
        else:
            print("Choix invalide, veuillez entrer 1, 2, 3 ou 4.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur.")
    except Exception as e:
        print(f"\nERREUR INATTENDUE : {e}", file=sys.stderr)
    input("\nAppuyez sur Entrée pour fermer...")