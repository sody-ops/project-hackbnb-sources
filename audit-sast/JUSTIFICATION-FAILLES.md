# Justification des vulnérabilités par analyse statique (SAST) — HackBNB

Deux outils complémentaires :
- **SonarQube Community** (serveur local Docker) — bugs, code smells, vulnérabilités hors taint-analysis.
- **Semgrep** (règles dédiées HackBNB, offline, `audit-sast/hackbnb-rules.yml`) — flux d'injection
  (SQLi, path traversal, SSRF) que SonarQube Community ne couvre pas.
- **Bandit** en appoint.

Reproduire :
```
# SonarQube : docker run -d --name sonarqube -p 9000:9000 sonarqube:community
sonar-scanner -Dsonar.host.url=http://localhost:9000 -Dsonar.token=<TOKEN>
# Semgrep :
semgrep --config audit-sast/hackbnb-rules.yml back docker-compose.yml
```

## Couverture des 8 failles du pentest

| ID | Faille | Fichier:ligne | SonarQube | Semgrep | CWE | Statut |
|----|--------|---------------|-----------|---------|-----|--------|
| D1 | Injection SQL (f-string dans `text()`) | rooms_api.py:18 | ❌ taint = éd. payante | ✅ `hackbnb-d1` | CWE-89 | Justifié (Semgrep) |
| D2 | Path traversal (`send_file`+input) | uploads_api.py:7 | ❌ | ✅ `hackbnb-d2` | CWE-22 | Justifié (Semgrep) |
| D3 | SSRF (URL Stripe + input) | stripe.py:32 | ❌ | ✅ `hackbnb-d3` | CWE-918 | Justifié (Semgrep) |
| D4 | Secret de paiement prévisible (hash d'un timestamp) | bookings_api.py:95 | ~ S2245 ligne 91 (PRNG réf.) | ✅ `hackbnb-d4` | CWE-330 | Justifié (Semgrep ; Sonar sur faille sœur ligne 91) |
| D5 | E-mail hôte exposé dans `/api/rooms` | rooms_models.py:34-35 | ❌ | ❌ | CWE-200 | Revue manuelle |
| D6 | Clé API Stripe en clair (versionnée) | docker-compose.yml:10 | ❌ (fichier hors scan) | ✅ `hackbnb-d6` | CWE-798 | Justifié (Semgrep) |
| D7 | En-têtes de sécurité absents | apache-prod.conf | ❌ | ❌ | CWE-693 | Scan d'en-têtes (`curl -I` préprod) |
| D8 | Flask `debug=True` en prod | app.py:43 | ✅ `python:S4507` | ✅ `hackbnb-d8` | CWE-489 | Justifié (2 outils) |

## Failles supplémentaires révélées par SonarQube (hors pentest initial)

| Règle SonarQube | Fichier:ligne | Sévérité | Description | CWE |
|-----------------|---------------|----------|-------------|-----|
| `python:S4790` | users_models.py:26 et 29 | CRITICAL | Mots de passe hachés en **MD5** (pas de sel) — aussi vu par Bandit B324 | CWE-327 |
| `python:S4502` | app.py:16 | CRITICAL | **Protection CSRF désactivée** | CWE-352 |
| `python:S8392` | app.py:42 | BLOCKER | Application liée à **toutes les interfaces** (0.0.0.0) — aussi Bandit B104 | CWE-605 |
| `python:S2245` | bookings_api.py:91 | MAJOR | PRNG non sûr (`random`) pour la référence de réservation | CWE-330 |

> Argument de soutenance : l'analyse SAST **confirme** D8 de façon outillée et **révèle 4 vulnérabilités
> non détectées par le pentest de juin 2026** (dont CSRF désactivé et MD5 sur les mots de passe).

## Bilan couverture
- **8/8** failles du pentest justifiées (6 outillées Semgrep/Sonar, 2 par revue manuelle / scan d'en-têtes).
- **+4** vulnérabilités supplémentaires via SonarQube.
