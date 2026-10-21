# Automatik — Cyber veille

Tableau de bord de veille en français consacré à Fortinet/FortiGate, aux vulnérabilités et à l'actualité cybersécurité.

## Fonctionnalités prévues
- Avis de sécurité Fortinet via le flux PSIRT officiel.
- Actualités de recherche et de sécurité issues de flux publics.
- Catalogue CISA Known Exploited Vulnerabilities (KEV), avec recherche.
- Liens vers les sources originales et date de dernière synchronisation.
- Actualisation des données par GitHub Actions, sans serveur à maintenir.
- Interface statique compatible avec GitHub Pages.

## Sources
- FortiGuard PSIRT : https://fortiguard.fortinet.com/psirt
- Flux RSS PSIRT Fortinet : https://fortiguard.fortinet.com/rss/ir.xml
- Flux RSS Fortinet / recherche : https://www.fortinet.com/lat/rss-feeds
- Catalogue CISA KEV : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST NVD : https://nvd.nist.gov/

Les données du tableau de bord sont une aide à la veille, pas une confirmation qu'un équipement précis est vulnérable. Toujours vérifier les versions concernées et les mesures de correction dans l'avis éditeur.

## Déploiement
Le site est statique. Active GitHub Pages dans **Settings → Pages** en choisissant la branche `main` et le dossier `/ (root)`. Le workflow de synchronisation publiera ensuite le fichier `data/veille.json` régulièrement.

## Exécution locale
Ouvre le site via un serveur HTTP local (pas directement en `file://`), par exemple :

```bash
python -m http.server 8000
```

Puis ouvre http://localhost:8000.
