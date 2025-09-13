# Commandes et exemples — Tokens, DAOs, admin, DB (développement)

Ce document liste toutes les commandes et exemples utiles pour : créer un token, lister/filtrer/tri les DAOs, vérifier les connexions, effectuer des opérations admin (reset), et commandes système utiles pour le développement local.

Règles générales

- Les appels API protégés nécessitent un header Authorization: Bearer <TOKEN> (sauf endpoint de reset en développement).
- Le frontend en développement fait toujours un fetch frais pour `/api/dao`.

Prérequis

- Serveur dev démarré : `pnpm install` puis `pnpm dev`
- Frontend : http://localhost:8080
- Backend API : http://localhost:3001/api/

1. Auth — créer un token (login)

- Curl (login → récupère token dans la réponse JSON) :

  curl -s -X POST http://localhost:3001/api/auth/login \
   -H "Content-Type: application/json" \
   -d '{"email":"admin@2snd.fr","password":"admin123"}'

  Réponse attendue :
  {
  "user": { "id": "1", "email": "admin@2snd.fr", "role": "admin" },
  "token": "<JWT_TOKEN>"
  }

- Exemple fetch (console navigateur) :

  fetch('/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email:'admin@2snd.fr', password:'admin123' }) })
  .then(r=>r.json()).then(console.log).catch(console.error)

- Générer un JWT manuellement (node) — utile pour scripts ou tests (NE JAMAIS COMMITTER JWT_SECRET) :

  node -e "console.log(require('jsonwebtoken').sign({ id:'1', email:'admin@2snd.fr', role:'admin' }, process.env.JWT_SECRET, { expiresIn:'24h', issuer:'dao-management', audience:'dao-app' }))"

2. Endpoints principaux (auth & DAO)

- GET /api/health
  - Méthode : GET
  - Usage : vérifie que le serveur répond (200 OK)
  - Exemple : curl http://localhost:3001/api/health

- GET /api/boot
  - Méthode : GET
  - Usage : récupère le bootId courant (utilisé pour invalider le localStorage côté client)
  - Exemple : curl http://localhost:3001/api/boot

- POST /api/auth/login
  - Méthode : POST
  - Usage : authentification, renvoie token

- POST /api/auth/logout
  - Méthode : POST (Authorization requise)

- GET /api/auth/me
  - Méthode : GET (Authorization requise)
  - Récupère l'utilisateur courant

- GET /api/dao
  - Méthode : GET (Authorization requise en flow normal)
  - Usage : renvoie la liste des DAOs
  - Note : côté serveur, si MongoDB est utilisé la liste est retournée triée par updatedAt desc (DaoModel.find().sort({ updatedAt: -1 })). En développement, le frontend force un fetch frais.
  - Exemple : curl -H "Authorization: Bearer <TOKEN>" http://localhost:3001/api/dao

- GET /api/dao/:id
  - Méthode : GET (Authorization requise)
  - Exemple : curl -H "Authorization: Bearer <TOKEN>" http://localhost:3001/api/dao/12345

- GET /api/dao/next-number
  - Méthode : GET (Authorization requise)
  - Usage : génère le prochain numéro DAO (DAO-YYYY-XXX)

- POST /api/dao
  - Méthode : POST (Authorization + admin requis)
  - Body : objet DAO (numeroListe, objetDossier, reference, autoriteContractante, dateDepot, equipe, tasks)
  - Exemple (curl) :

    curl -X POST http://localhost:3001/api/dao \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <TOKEN>" \
     -d '{"numeroListe":"DAO-2025-999","objetDossier":"Exemple","reference":"REF-1","autoriteContractante":"Mairie","dateDepot":"2025-09-10","equipe":[{"id":"1","name":"Marie Dubois","role":"chef_equipe"}] }'

- PUT /api/dao/:id
  - Méthode : PUT (Authorization + requireDaoLeaderOrAdmin middleware)
  - Body : champs partiels à mettre à jour

- DELETE /api/dao/:id
  - Méthode : DELETE (Authorization + admin)

3. Admin runtime — reset et opérations globales

- POST /api/admin/reset-app
  - Méthode : POST
  - Body: { rotateBootId?: boolean, seedDaos?: boolean }
  - En développement (NODE_ENV !== 'production') l'endpoint autorise un reset sans token pour faciliter le debug local.
  - En production il requiert un JWT admin dans Authorization: Bearer <TOKEN>.
  - Action : clear DAOs (DaoService.clearAll() ou fallback in-memory), NotificationService.clearAll(), réinitialise users/sessions et renvoie le nouveau bootId si rotateBootId=true.
  - Exemple rapide (console navigateur) :

    fetch('/api/admin/reset-app', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ rotateBootId:true, seedDaos:false }) }).then(r=>r.json()).then(console.log)

4. Accès et tri / filtrage

- Tri côté serveur :
  - Par défaut, quand la DB est utilisée, la liste est triée par `updatedAt` (desc) sur le serveur.
  - Le serveur expose maintenant des query params pour trier/filtrer/paginer `/api/dao`.

- Query params supportés on GET /api/dao:
  - search: text search across numeroListe, objetDossier, reference, autoriteContractante
  - autorite: exact match on autoriteContractante
  - dateFrom: ISO date or yyyy-mm-dd (inclusive) to filter `dateDepot` >= dateFrom
  - dateTo: ISO date or yyyy-mm-dd (inclusive) to filter `dateDepot` <= dateTo
  - sort: field name to sort by (default: updatedAt)
  - order: asc or desc
  - page: 1-based page number
  - pageSize: items per page (max 100)

- Filtrage côté frontend :
  - The client still applies filters locally; use server-side filtering for large datasets or pagination.

5. Vérifier les connexions et l'état de la DB

- Vérifier que le serveur backend est opérationnel :
  curl http://localhost:3001/api/health

- Vérifier bootId (pour forcer purge client) :
  curl http://localhost:3001/api/boot

- Logs backend (sur votre machine) : surveiller les messages concernant MongoDB (ECONNREFUSED) — le service bascule en in-memory s'il ne parvient pas à se connecter.

- Si MongoDB est utilisée et que vous voulez inspecter la collection `daos` :

  # Avec mongosh

  mongosh "<MONGODB_URI>"
  use <dbName>
  db.daos.find().sort({ updatedAt: -1 }).pretty()

  # Supprimer toutes les DAOs (ATTENTION — destructif)

  db.daos.deleteMany({})

6. Commandes locales / Dev helpers

- Démarrer :
  pnpm install
  pnpm dev

- Forcer nettoyage localStorage (console navigateur) :

  for (let i = localStorage.length - 1; i >= 0; i--) {
  const k = localStorage.key(i);
  if (k && /(dao|DAO|cache|notification)/i.test(k)) localStorage.removeItem(k);
  }
  location.reload();

- Raccourci depuis l'app (dev) : Ctrl+Shift+C — implémenté dans `frontend/pages/Index.tsx` pour invalider le cache et recharger.

7. Vérifications post-opérations

- Après POST /api/admin/reset-app, vérifier :
  - GET /api/boot -> bootId a changé
  - GET /api/dao -> retourne [] (ou nombre attendu)
  - Logs backend: messages "🧹 Cleared DAOs" ou "Cleared DAOs via in-memory daoStorage fallback"

8. Liste d'API complète (raccourci)

- GET /api/health
- GET /api/boot
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/auth/me
- GET /api/auth/users (admin)
- POST /api/auth/users (admin)
- GET /api/dao
- GET /api/dao/next-number
- GET /api/dao/:id
- POST /api/dao (admin)
- PUT /api/dao/:id
- DELETE /api/dao/:id
- POST /api/comments/\* (comment routes)
- POST /api/admin/reset-app (dev: unauth, prod: admin token)

9. Exemples curl rapides

- Lister DAOs (avec token) :
  curl -H "Authorization: Bearer <TOKEN>" "http://localhost:3001/api/dao?search=ami&autorite=Mairie&page=1&pageSize=10&sort=updatedAt&order=desc"

- Reset app (dev, sans token) :
  curl -X POST -H "Content-Type: application/json" -d '{"rotateBootId":true,"seedDaos":false}' http://localhost:3001/api/admin/reset-app

- Générer next DAO number :
  curl -H "Authorization: Bearer <TOKEN>" http://localhost:3001/api/dao/next-number

- Lister sessions actives (dev: sans token, prod: requiert token admin) :
  curl http://localhost:3001/api/admin/sessions

- Révoquer un token (POST) :
  curl -X POST -H "Content-Type: application/json" -d '{"token":"<TOKEN_TO_REVOKE>"}' http://localhost:3001/api/admin/revoke-session

10. SMTP / Email configuration (variables d'environnement)

Le projet peut envoyer des notifications par email. Configurez ces variables avant d'utiliser l'envoi d'emails :

- SMTP_HOST — hôte du serveur SMTP
- SMTP_PORT — port SMTP (ex: 465 ou 587)
- SMTP_SECURE — true/false (TLS)
- SMTP_USER — login SMTP
- SMTP_PASS — mot de passe SMTP
- SMTP_FROM — adresse "from" utilisée pour les emails (ex: noreply@example.com)
- MAIL_DOMAIN — (optionnel) domaine utilisé pour les templates / DKIM

Exemple local (exportez avant de démarrer) :

export SMTP_HOST="smtp.example.com"
export SMTP_PORT=465
export SMTP_SECURE=true
export SMTP_USER="mailer@example.com"
export SMTP_PASS="supersecret"
export SMTP_FROM="noreply@example.com"

11. Besoin d'autres commandes ?

Si vous souhaitez :

- Ajouter des query params serveur pour tri/filtre sur `/api/dao`, je peux implémenter `?sort=...&autorite=...&search=...` côté backend.
- Ajouter un endpoint admin pour « lister les sessions actives » ou pour gérer les utilisateurs, je peux l'ajouter aussi.

Dites-moi quelles commandes supplémentaires vous voulez (ex.: export CSV, pagination, query-server filtering) et je les ajoute à cette doc et implémente l'API correspondante.
