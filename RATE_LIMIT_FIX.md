# 🔧 Correction des Erreurs 429 - Rate Limiting

## ❌ Problème Identifié

L'erreur **HTTP 429 "Too Many Requests"** se produisait lors des tentatives de connexion car le rate limiting était configuré de manière trop restrictive :

- **Limite Auth**: Seulement 10 tentatives par 15 minutes
- **Pas de différenciation** développement/production
- **Pas d'outils de débogage** pour diagnostiquer

## ✅ Corrections Apportées

### 1. **Rate Limiting Adaptatif**

```typescript
// Avant
max: 10, // Trop restrictif

// Après
max: process.env.NODE_ENV === "production" ? 20 : 100, // Adapté à l'environnement
```

### 2. **Opérations Sensibles Plus Permissives**

```typescript
// backend-express/middleware/auth.ts
const MAX_ATTEMPTS = process.env.NODE_ENV === "production" ? 5 : 20;
const WINDOW_MS = process.env.NODE_ENV === "production" ? 60 * 1000 : 30 * 1000;
```

### 3. **Système de Débogage Complet**

- **Utilitaire de diagnostic**: `rate-limit-debug.ts`
- **Route de débogage**: `GET /api/debug/rate-limits`
- **Logging automatique** des erreurs 429
- **Boutons de débogage** sur la page de login

### 4. **Gestion d'Erreurs Améliorée**

```typescript
// frontend/services/authService.ts
if (response.status === 429) {
  const resetTime = rateLimitReset
    ? new Date(parseInt(rateLimitReset) * 1000).toLocaleTimeString()
    : "dans quelques minutes";

  throw new Error(
    `Trop de tentatives de connexion. Veuillez réessayer ${resetTime}.`,
  );
}
```

## 🚀 Nouvelles Fonctionnalités

### Mode Développement

- **100 tentatives** de connexion par 15 minutes
- **Boutons de débogage** sur la page de login
- **Logs détaillés** des rate limits
- **Route de diagnostic** `/api/debug/rate-limits`

### Mode Production

- **20 tentatives** de connexion par 15 minutes (sécurisé mais raisonnable)
- **Logs de sécurité** pour audit
- **Messages d'erreur** informatifs pour les utilisateurs

## 🔍 Outils de Débogage

### 1. **Page de Login (Dev uniquement)**

- **🧹 Clear Auth**: Vide les données d'authentification
- **🔍 Check Rate Limits**: Affiche le statut des rate limits

### 2. **API de Diagnostic**

```bash
# Vérifier le statut des rate limits
curl http://localhost:3001/api/debug/rate-limits
```

Retourne :

```json
{
  "currentIP": "127.0.0.1",
  "isNearLimit": false,
  "userRateLimits": [...],
  "allRateLimits": [...],
  "tips": [...]
}
```

### 3. **Logs Automatiques**

Chaque erreur 429 génère un log détaillé :

```
🚨 RATE LIMIT HIT:
  IP: 127.0.0.1
  User: admin@2snd.fr
  Endpoint: POST /api/auth/login
  Time: 2024-01-20T14:18:43.000Z
  Headers: {...}
  Reset Time: 2024-01-20T14:33:43.000Z
  Time Until Reset: 900s

💡 Solutions:
  1. Wait for the rate limit to reset
  2. Use different IP/user for testing
  3. Adjust rate limit config in development
  4. Clear rate limit cache (if implemented)
```

## 📊 Nouvelles Limites

| Environnement   | Auth Attempts | Time Window | Sensitive Ops | Window |
| --------------- | ------------- | ----------- | ------------- | ------ |
| **Development** | 100           | 15 min      | 20            | 30 sec |
| **Production**  | 20            | 15 min      | 5             | 60 sec |

## 🛡️ Sécurité Maintenue

Même avec les limites plus permissives en développement :

- ✅ **Protection DDoS** maintenue
- ✅ **Brute force** protection active
- ✅ **Audit logging** complet
- ✅ **Headers de sécurité** préservés

## 🔄 Test de la Correction

1. **Redémarrer le serveur** (automatique)
2. **Tenter une connexion** normale
3. **Utiliser les outils de débogage** si nécessaire
4. **Vérifier les logs** pour confirmation

## 📝 Notes pour la Production

⚠️ **Important** : En production, assurez-vous que :

- `NODE_ENV=production` est défini
- Les limites sont appropriées pour votre charge
- Le monitoring des rate limits est en place
- Les alertes sont configurées pour les abus
