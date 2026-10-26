# Automatik — Cyber veille

Tableau de bord statique en français pour suivre les avis Fortinet, les vulnérabilités exploitées et l'actualité cybersécurité. Le projet privilégie les sources vérifiables et conserve les liens vers les publications originales.

## Ce que le site propose

- **Fortinet / FortiGate** : avis de sécurité et publications du flux de veille.
- **Fortinet Community** : points de vigilance regroupés, avec recherche et filtres par produit, famille de versions et statut.
- **CVE et vulnérabilités exploitées** : catalogue CISA Known Exploited Vulnerabilities (KEV) et recherche.
- **Actualités cyber** : publications issues de flux publics.
- **Traçabilité** : dates de collecte, liens vers les sources et distinction entre documentation Fortinet et discussions d'utilisateurs.

## Critères de publication — Fortinet Community

Une fiche est affichée uniquement si elle remplit l'un des critères suivants :

1. Un article Fortinet documente explicitement un problème avec une version identifiable, ou fournit un périmètre `Scope` et une `Solution` explicites pour un problème dont la version n'est pas précisée.
2. Au moins deux URL distinctes de discussions d'utilisateurs décrivent un problème suffisamment similaire.

Un article officiel ne compte jamais comme plusieurs utilisateurs. Les signalements isolés non documentés sont exclus. Lorsqu'une fiche officielle ne donne pas de version, l'interface affiche explicitement « Version : non précisée par la source » au lieu de suggérer une version. Les fiches restent des points de vigilance à vérifier, et non une confirmation que chaque équipement est concerné.

Le regroupement actuel utilise des règles déterministes, des variantes de termes et une comparaison de titres. **Il n'utilise pas de modèle d'IA générative** et ne lit pas encore l'intégralité des réponses des discussions : des formulations très différentes peuvent donc ne pas être rapprochées, et les sources doivent être consultées avant toute décision technique.

Les versions sont extraites lorsqu'elles sont explicitement liées à un produit/firmware Fortinet ou à un parcours de mise à niveau. Les nombres décimaux sans lien clair avec une version de firmware (par exemple une version d'outil ou de plateforme) ne doivent pas être affichés comme versions Fortinet. La version corrigée est présentée séparément lorsqu'un article Fortinet l'indique explicitement; elle n'est pas ajoutée aux versions affectées.

## Collecte et publication

- Le workflow **Collecte Fortinet Community** s'exécute toutes les six heures (planification UTC) et peut aussi être lancé manuellement depuis l'onglet Actions.
- Il demande d’abord le flux public avec `count=500`, puis utilise l’URL RSS standard si ce paramètre échoue. Pour un sujet récent qui mentionne une version et un problème mais aucun produit, il consulte sa page publique pour lire les tags produit (8 pages maximum par collecte). Un refus d’accès n’est pas contourné : il est signalé et les données déjà collectées sont conservées. L’historique est plafonné, les URL sont dédupliquées et `data/community.json` est actualisé.
- Si moins de 500 sujets sont renvoyés, la collecte est marquée partielle et l’interface affiche l’avertissement. Cela signale que la couverture des 30 derniers jours n’est pas garantie; ce n’est pas une preuve d’absence de problèmes, et l’historique déjà collecté reste conservé.
- Le workflow **Vérification du projet** contrôle la syntaxe Python et JavaScript, les tests unitaires, les fichiers JSON et le parcours navigateur Playwright/Chromium.
- Les modifications poussées sur `main` sont déployées par l'intégration Vercel du dépôt.

Aucune clé d'API IA payante n'est nécessaire pour les collecteurs actuels.

Le fichier historique `scripts/scrap_commu_copie.py` est un outil manuel distinct : il demande une clé Gemini en argument et génère ses propres fichiers `historique.json`/rapports HTML. Il n'est appelé ni par le site ni par les workflows. Pour les données publiées dans `data/community.json`, la chaîne active est `scripts/collect_community.py` puis `scripts/synthesize_community.py` ; elle fonctionne sans clé IA.

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
