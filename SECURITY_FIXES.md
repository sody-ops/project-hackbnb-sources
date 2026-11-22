# Correctifs de sécurité — HackBNB (post-incident du 07/11/2026)

Branche : `fix/securite`. Les 8 vulnérabilités du rapport de pentest sont corrigées et chaque attaque a été rejouée après correction.

## Récapitulatif des corrections

| # | Gravité | Vulnérabilité | Fichier | Avant | Après |
|---|---|---|---|---|---|
| D1 | Critique | Injection SQL | `back/api/rooms/rooms_api.py` l.18 | `Room.query.filter(text(f"category = '{category}'"))` | `Room.query.filter(Room.category == category)` (requête paramétrée par l'ORM), import `text` retiré |
| D2 | Critique | Path traversal | `back/api/uploads/uploads_api.py` l.7 | `send_file('uploads/' + request.args.get("name"))` | refus (400) si le nom est vide ou contient `/`, `\` ou `..`, puis `send_from_directory('uploads', name)` (qui applique `safe_join`) |
| D3 | Critique | SSRF vers l'API Stripe | `back/services/stripe.py` `get_checkout_lines` | ID injecté tel quel dans l'URL authentifiée Stripe | liste blanche `^cs_[A-Za-z0-9_]+$`, sinon `ValueError` → 404, **avant** tout appel réseau |
| D4 | Critique | Secret de paiement prévisible | `back/api/bookings/bookings_api.py` l.94-95 | `sha512(str(int(time.time())))` | `secrets.token_urlsafe(32)` (256 bits), comparaison en temps constant (`secrets.compare_digest`) et **vérification du statut réel auprès de Stripe** (`payment_status == "paid"`) avant `is_paid = True`. La référence de réservation utilise aussi `secrets.choice` (au lieu de `random`) |
| D5 | Majeure | E-mail de l'hôte exposé | `back/api/rooms/rooms_models.py` l.34-35 | `output["host"] = self.host_user.to_dict()` (avec `email`) | `{"id": ..., "name": ...}` uniquement |
| D6 | Majeure | Clé API Stripe versionnée | `docker-compose.yml` l.10 | `STRIPE_API_KEY: sk_test_51RhVf…` en clair | `${STRIPE_API_KEY:?…}` lu depuis un `.env` non versionné (`.gitignore` + `.env.example`) |
| D7 | Majeure | En-têtes de sécurité absents | `apache/apache-prod.conf` | aucun | `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| D8 | Mineure | Flask en mode debug | `back/app.py` l.43 | `debug=True` | `debug=os.getenv("FLASK_DEBUG", "0") == "1"` (désactivé par défaut) |

**CSP (D7)** : la politique `default-src 'self'` seule bloquerait la police Google Fonts importée par `front/src/index.css`. Elle est donc complétée par `style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`.

## Résultats de vérification (attaques rejouées)

Tests en local : back Flask sur :9001, Apache 2.4.58 avec `apache-prod.conf`, Stripe simulé pour D3 et D4.

| # | Attaque | Avant | Après |
|---|---|---|---|
| D1 | `/rooms/?category=hut' OR 1=1 -- ` | les 10 chambres | `[]` (2 pour `hut` légitime) |
| D1 | `… UNION SELECT id,name,email,password_hash,… FROM users -- ` | dump des utilisateurs | `[]` |
| D2 | `/uploads/?name=../app.py`, `../../etc/passwd`, `/etc/passwd`, `..\app.py`, `..%2Fapp.py` | contenu des fichiers | **400** (`room-1.jpg` → 200) |
| D3 | `checkout_session_id=../../customers#` (et variantes) | données clients Stripe | **404**, 0 requête sortante ; `cs_test_abc123` légitime → 200 |
| D4 | `confirm-checkout` avec secret calculé sur l'horodatage / faux / absent | paiement validé | **422** |
| D4 | bon secret mais paiement Stripe non `paid` | — | **422** (validé seulement si Stripe confirme : 200) |
| D4 | deux nouvelles réservations | secret déductible | secrets aléatoires distincts de 43 caractères |
| D5 | `/rooms/1` | `host.email` présent | `host = {id, name}` |
| D7 | `curl -I /` | aucun en-tête | les 4 en-têtes présents, `apache2ctl configtest` OK |
| D8 | erreur 500 (`POST /bookings/` vide), `/console` | trace Werkzeug + console de debug | page 500 générique, `/console` → 404, log « Debug mode: off » |

## Actions restantes hors code (obligatoires)

1. **Révoquer la clé Stripe** `sk_test_51RhVfI…` dans le dashboard Stripe et en générer une nouvelle, à placer uniquement dans `.env` / les secrets de déploiement.
2. **Purger l'historique Git** : la clé est toujours présente dans le commit `4aec6cd` (« chore: implement Docker Compose deployment setup »). Il faut réécrire l'historique (`git filter-repo --replace-text` ou BFG) puis faire un force-push coordonné avec l'équipe. La révocation (point 1) reste la vraie protection, car la clé a pu être copiée.
3. Déployer en production derrière un serveur WSGI (gunicorn) plutôt que le serveur de développement Flask.
4. Idéalement, valider les paiements par un **webhook Stripe signé** (`checkout.session.completed`) plutôt que par le retour du navigateur.

## Autres faiblesses relevées pendant la correction (hors périmètre des 8)

- **XSS stockée possible** : `dangerouslySetInnerHTML={{__html: room.description}}` dans `front/src/pages/room/Room.tsx:52` et `booking/Booking.tsx:49`. La CSP la limite, mais il faut assainir le HTML (DOMPurify) ou l'afficher en texte.
- **Mots de passe hachés en MD5 sans sel** (`back/api/users/users_models.py`) : passer à `werkzeug.security.generate_password_hash` (scrypt/pbkdf2) ou à bcrypt/argon2.
- `requests` est utilisé par `services/stripe.py` sans figurer dans `requirements.txt` (il est installé via `stripe`).
