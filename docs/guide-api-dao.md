# Guide API DAO (local) — dictionnaire de requêtes

Ce document récapitule comment lancer le projet en local et toutes les requêtes utiles (avec exemples) pour lister les DAO, filtrer par jour et afficher les noms/"locations" (autorités contractantes).

## Démarrer en local

- Lancer client + serveur: `pnpm dev`
- (Option) Backend seul: `pnpm run dev:backend`
- (Option) Frontend seul: `pnpm run dev:frontend`

Identifiants de test (depuis le backend):

- Admin: `admin@2snd.fr` / `admin123`
- Utilisateurs: `marie.dubois@2snd.fr` / `marie123`, `pierre.martin@2snd.fr` / `pierre123`

## Authentification

1. Obtenir un token (login):

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@2snd.fr","password":"admin123"}'
```

Réponse: `{ token, user: {...} }`

2. Utiliser le token:

```bash
TOKEN="<COLLER_TOKEN_ICI>"
# Exemple: lister tous les DAO
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dao
```

## Endpoints principaux

- Santé: `GET /api/health`
- Ping: `GET /api/ping`

DAO

- `GET /api/dao` — Liste tous les DAO
- `GET /api/dao/:id` — Récupère un DAO par ID
- `GET /api/dao/next-number` — Prochaine référence disponible
- `POST /api/dao` — Crée un DAO (admin)
- `PUT /api/dao/:id` — Met à jour un DAO (chef d’équipe/admin)
- `DELETE /api/dao/:id` — Supprime un DAO (admin)

Tâches (sous /api/dao)

- `POST /:daoId/tasks` — Ajouter une tâche
- `PUT /:daoId/tasks/:taskId` — Mettre à jour une tâche (progress/comment/applicable/assignedTo)
- `PUT /:daoId/tasks/:taskId/name` — Renommer une tâche
- `PUT /:daoId/tasks/reorder` — Réordonner les tâches
- `DELETE /:daoId/tasks/:taskId` — Supprimer une tâche

Commentaires

- `GET /api/comments/dao/:daoId` — Tous les commentaires d’un DAO
- `GET /api/comments/dao/:daoId/task/:taskId` — Commentaires d’une tâche
- `POST /api/comments` — Ajouter un commentaire
- `PUT /api/comments/:id` — Modifier
- `DELETE /api/comments/:id` — Supprimer
- `GET /api/comments/recent` — Récents

Auth

- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- Gestion utilisateurs: `GET/POST/PUT/DELETE /api/auth/users*`, `PUT /api/auth/profile`, `POST /api/auth/forgot-password`, `POST /api/auth/verify-reset-token`, `POST /api/auth/reset-password`

## Recettes utiles

Lister tous les DAO (avec token):

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dao | jq
```

DAO par jour (filtrer localement par dateDepot):

- Par date exacte (YYYY-MM-DD):

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dao \
| jq '[.[] | select(.dateDepot == "2025-01-15")]'
```

- Par jour du mois (ex: le 15, peu importe le mois/année):

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dao \
| jq '[.[] | select((.dateDepot | split("-")[2]) == "15")]'
```

Noms des DAO (numeroListe) et "locations" (autorité contractante), avec date:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dao \
| jq '[.[] | {id, numeroListe, autoriteContractante, dateDepot}]'
```

Rechercher par nom (numeroListe contenant une sous-chaîne):

```bash
QUERY="DAO-2025";
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/dao \
| jq --arg q "$QUERY" '[.[] | select(.numeroListe | test($q))]'
```

Créer un DAO (admin):

```bash
curl -s -X POST http://localhost:8080/api/dao \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "numeroListe":"DAO-2025-001",
    "objetDossier":"Fourniture X",
    "reference":"AO-2025-XYZ",
    "autoriteContractante":"Mairie de Lyon",
    "dateDepot":"2025-01-20",
    "equipe":[{"id":"2","name":"Marie Dubois","role":"chef_equipe"}]
  }'
```

Mettre à jour une tâche d’un DAO:

```bash
curl -s -X PUT http://localhost:8080/api/dao/<DAO_ID>/tasks/<TASK_ID> \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"progress": 60, "comment":"En cours", "isApplicable": true, "assignedTo": "2"}'
```

Réordonner les tâches:

```bash
curl -s -X PUT http://localhost:8080/api/dao/<DAO_ID>/tasks/reorder \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"taskIds": [3,1,2,4]}'
```

## Notes

- Le backend actuel ne filtre pas encore côté serveur par date; on filtre côté client (exemples `jq` ci-dessus). Si besoin, on pourra ajouter `GET /api/dao?date=YYYY-MM-DD`.
- Toutes les routes protégées requièrent `Authorization: Bearer <token>`.
