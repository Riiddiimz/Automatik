# Automatik — Cyber veille

Tableau de bord statique en français pour suivre les avis Fortinet, les vulnérabilités exploitées et l'actualité cybersécurité. Le projet privilégie les sources vérifiables et conserve les liens vers les publications originales.

## Ce que le site propose

- **Fortinet / FortiGate** : avis de sécurité et publications du flux de veille.
- **Fortinet Community** : points de vigilance regroupés, avec recherche et filtres par produit, famille de versions et statut.
- **CVE et vulnérabilités exploitées** : catalogue CISA Known Exploited Vulnerabilities (KEV) et recherche.
- **Actualités cyber** : publications issues de flux publics.
- **Traçabilité** : dates des données publiées, liens vers les sources et distinction entre documentation Fortinet et discussions d'utilisateurs.

## Critères de publication — Fortinet Community

Une fiche est affichée uniquement si elle remplit l'un des critères suivants :

1. Un article Fortinet documente explicitement un problème avec une version identifiable, ou fournit un périmètre `Scope` et une `Solution` explicites pour un problème dont la version n'est pas précisée.
2. Au moins deux URL distinctes de discussions d'utilisateurs décrivent un problème suffisamment similaire.

Un article officiel ne compte jamais comme plusieurs utilisateurs. Les signalements isolés non documentés sont exclus. Lorsqu'une fiche officielle ne donne pas de version, l'interface affiche explicitement « Version : non précisée par la source » au lieu de suggérer une version. Les fiches restent des points de vigilance à vérifier, et non une confirmation que chaque équipement est concerné.

Le regroupement principal utilise des règles déterministes, des variantes de termes et une comparaison de titres. Une seconde passe facultative, `scripts/review_community_gemini.py`, peut utiliser Gemini pour reformuler en français les champs `summary`, `symptom`, `impact` et `solution`. Elle ne modifie pas les produits, versions affectées, versions de correctif, statuts ni URL. Les textes reformulés sont signalés « RELECTURE IA · À VÉRIFIER » et ne constituent pas une validation officielle. La collecte ne lit pas encore l'intégralité des réponses des discussions : des informations ajoutées dans les commentaires peuvent donc manquer du flux publié, et les sources doivent être consultées avant toute décision technique.

Les versions sont extraites lorsqu'elles sont explicitement liées à un produit/firmware Fortinet ou à un parcours de mise à niveau. Les nombres décimaux sans lien clair avec une version de firmware (par exemple une version d'outil ou de plateforme) ne doivent pas être affichés comme versions Fortinet. La version de correctif mentionnée est présentée séparément lorsqu'un article Fortinet l'indique explicitement; elle n'est pas ajoutée aux versions affectées.

## Collecte et publication

- Le workflow **Collecte Fortinet Community** s'exécute toutes les six heures (planification UTC) et peut aussi être lancé manuellement depuis l'onglet Actions.
- Les workflows ne republient pas un JSON lorsque seuls les horodatages techniques changent et que le contenu, les avertissements de source et les synthèses restent identiques. `generatedAt` désigne donc le dernier état publié, pas chaque tentative de collecte; cela évite des builds Vercel sans changement visible.
- Il parcourt le flux public par pages de 100 (jusqu’à 500 entrées distinctes) avec `start=0`, `100`, `200`, `300` et `400`. En complément, il parcourt jusqu’à cinq pages de chaque index public FortiGate, FortiManager, FortiAuthenticator, FortiAnalyzer, FortiClient (dont EMS via titres/tags) et Support Forum. Les sujets sont dédupliqués par URL; les versions explicites des index complètent le RSS sans effacer les métadonnées plus riches. L’enrichissement des fiches est équilibré entre produits; un échec de lecture est réessayé après deux heures, tandis qu’une page lue avec succès sans métadonnées n’est pas retentée en boucle. Si une page répète les sujets précédents ou si une requête échoue, les entrées distinctes déjà récupérées sont conservées et la collecte est signalée partielle. Le flux RSS observé ne permet pas actuellement une pagination fiable; la couverture complète des 30 derniers jours n’est donc pas garantie. Si le flux étendu échoue dès la première page, il se replie sur le flux RSS standard.
- En complément, le collecteur explore jusqu’à trois pages publiques par produit pour FortiGate, FortiManager, FortiAuthenticator, FortiAnalyzer et FortiClient. Les sujets EMS visibles sur le tableau FortiClient sont classés à partir du titre et des tags disponibles. Sur les autres tableaux communautaires, les catégories transversales ne suffisent pas à attribuer un problème à un produit surveillé : hors forums de discussion et tableaux surveillés, le produit doit apparaître dans le titre. Cette découverte par index permet de repérer des liens absents du flux RSS; les index ne fournissent pas toujours la date ou le résumé détaillé. Pour jusqu’à 12 sujets à potentiel problème et sans résumé, il tente de lire les métadonnées de la page publique, avec une vérification limitée à une fois par sujet sur 24 heures. Les champs non fournis restent explicitement inconnus. Le site affiche le nombre de pages d’index consultées et de liens repérés. Les erreurs HTTP/anti-bot sont signalées sans contournement et les données déjà collectées sont conservées. L’historique est plafonné à 1 000 sujets dans `data/community.json`.
- Pour un sujet du flux qui mentionne une version et un problème mais aucun produit, il consulte sa page publique pour lire les tags produit (8 pages maximum par collecte).
- Si moins de 500 entrées brutes distinctes sont récupérées, la collecte est marquée partielle et l’interface affiche l’avertissement. Cela signale que la couverture des 30 derniers jours n’est pas garantie; ce n’est pas une preuve d’absence de problèmes, et l’historique déjà collecté reste conservé.
- Le workflow **Vérification du projet** contrôle la syntaxe Python et JavaScript, les tests unitaires, les fichiers JSON et le parcours navigateur Playwright/Chromium.
- Les modifications poussées sur `main` sont déployées par l'intégration Vercel du dépôt.

La collecte et la synthèse déterministe fonctionnent sans clé IA. Pour activer la relecture facultative, configure `GEMINI_API_KEY` dans les secrets GitHub Actions (jamais dans le dépôt). Le workflow utilise `gemini-3.5-flash-lite` et relit au maximum 40 fiches par exécution. Si la clé manque ou si l'appel échoue, le site affiche l'état de la relecture et conserve la synthèse déterministe; les relectures antérieures ne sont gardées que si leurs sources et champs probatoires n'ont pas changé. Les horodatages de contrôle seuls ne déclenchent pas de publication. Vérifie les quotas et conditions actuelles de Google AI Studio avant d'activer le service.

Le fichier historique `scripts/scrap_commu_copie.py` reste un outil manuel distinct : il demande une clé Gemini en argument et génère ses propres fichiers `historique.json`/rapports HTML. Il n'est appelé ni par le site ni par les workflows. Pour les données publiées dans `data/community.json`, la chaîne active est `scripts/collect_community.py`, puis `scripts/synthesize_community.py`, puis la relecture facultative `scripts/review_community_gemini.py`.

## Vérifier le projet

### En local

Prérequis : Python 3.12+, Node.js 22+ et npm.

```bash
python -m unittest discover -s tests -v
python -m py_compile scripts/update_veille.py scripts/collect_community.py scripts/synthesize_community.py
node --check app.js
```

Pour servir le site localement :

```bash
python -m http.server 4173
```

Puis ouvrir http://127.0.0.1:4173.

Le test navigateur est exécuté en CI avec Playwright et Chromium. Pour le reproduire localement, installer Playwright avec npm, installer Chromium, puis exécuter `node tests/e2e.js` pendant que le serveur local tourne.

### Workflows GitHub

- [Vérification du projet](https://github.com/Riiddiimz/Automatik/actions/workflows/quality.yml)
- [Collecte Fortinet Community](https://github.com/Riiddiimz/Automatik/actions/workflows/collect-community.yml)

## Sources de référence

- [FortiGuard PSIRT](https://fortiguard.fortinet.com/psirt)
- [Flux RSS PSIRT Fortinet](https://fortiguard.fortinet.com/rss/ir.xml)
- [Fortinet News & Research](https://www.fortinet.com/lat/rss-feeds)
- [Fortinet CISO Collective — annonces de sécurité](https://www.fortinet.com/blog/ciso-collective)
- [Fortinet Community](https://community.fortinet.com/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/feed/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)

Les informations publiées par Automatik sont une aide à la veille, pas un avis de remédiation. Toujours vérifier la version exacte, le modèle concerné et les recommandations de l'éditeur avant d'agir.
