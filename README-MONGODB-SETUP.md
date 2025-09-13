# Configuration du Backend MongoDB avec Service Email

## 🎯 Basculement vers MongoDB

Le backend MongoDB est maintenant configuré avec le service d'email pour la réinitialisation de mot de passe.

### 1. Démarrer MongoDB (requis)

```bash
# Option 1: MongoDB local
brew services start mongodb/brew/mongodb-community
# ou
sudo systemctl start mongod

# Option 2: MongoDB Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### 2. Configuration Email Gmail

Éditez `backend-mongodb/.env` :

```env
# Remplacez ces valeurs par vos paramètres Gmail
SMTP_USER=votre-email@gmail.com
SMTP_PASS=votre-app-password-gmail
```

**Pour obtenir un App Password Gmail :**
1. Allez dans votre compte Google → Sécurité
2. Activez l'authentification à 2 facteurs
3. Générez un "App Password" pour l'application
4. Utilisez ce mot de passe (16 caractères) dans `SMTP_PASS`

### 3. Démarrer le Backend MongoDB

```bash
# Option 1: Script automatique
./switch-backend.sh mongodb

# Option 2: Manuel
cd backend-mongodb
pnpm dev
```

### 4. Démarrer le Frontend

```bash
# Dans un autre terminal
pnpm dev:frontend
```

## 🔧 Fonctionnalités Email

### Service d'Email Configuré
- ✅ Réinitialisation de mot de passe par email
- ✅ Templates HTML avec design 2SND
- ✅ Codes à 6 chiffres valides 15 minutes
- ✅ Logs détaillés pour debug

### Test de Réinitialisation
1. Allez sur `/forgot-password`
2. Entrez votre email (ex: fontoncredo@gmail.com)
3. Vérifiez votre boîte email ou les logs du serveur
4. Utilisez le code de 6 chiffres reçu

## 🗄️ Données de Test

Le backend créé automatiquement ces utilisateurs :

```
Admin: admin@2snd.fr / admin123
User: marie.dubois@2snd.fr / marie123
User: pierre.martin@2snd.fr / pierre123
User: fontoncredo@gmail.com / W@l7t8WkaCYm
```

## 🚨 Dépannage

### Email non reçu ?
1. Vérifiez les logs du serveur pour le code
2. Vérifiez vos spams/courrier indésirable
3. Confirmez la configuration Gmail App Password

### Erreur de connexion MongoDB ?
```bash
# Vérifier le statut
brew services list | grep mongodb
# ou
sudo systemctl status mongod
```

### Port déjà utilisé ?
```bash
# Tuer le processus sur le port 5000
lsof -ti:5000 | xargs kill -9
```

## 🔄 Retour vers Express

Pour revenir au backend Express :

```bash
./switch-backend.sh express
```

> ⚠️ **Note**: Le backend Express n'a pas de service email configuré. Les codes apparaîtront uniquement dans les logs.
