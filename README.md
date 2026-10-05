# 🛡️ Sentinel-X Backend API

Backend API pour le système de détection d'intrusion **Sentinel-X**.  
Expose une API REST + WebSocket pour l'ingestion, la consultation et le suivi en temps réel des alertes de sécurité.

---

## 📋 Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| **API REST** | CRUD complet sur les alertes (création, lecture, filtres, pagination) |
| **WebSocket (Socket.io)** | Push temps réel vers le Dashboard frontend |
| **Validation** | Schéma strict pour les alertes entrantes |
| **Statistiques** | Agrégation par sévérité, source, statut |
| **Health Check** | Endpoint `/api/health` pour monitoring |
| **Arrêt gracieux** | Gestion SIGTERM/SIGINT pour déploiements zero-downtime |

---

## 🚀 Démarrage rapide en local (Node.js)

### Prérequis
- **Node.js ≥ 20** (LTS recommandé)
- **npm ≥ 9**

### Installation
```bash
cd backend-api
npm ci
```

### Variables d'environnement
```bash
cp env.development.template .env
# Éditer .env si nécessaire
```

### Développement (avec hot-reload)
```bash
npm run dev
# → API sur http://localhost:3000
# → Debug inspector sur port 9229
```

### Production
```bash
npm start
```

---

## 🐳 Lancement via Docker (Backend seul, sans frontend, sans docker-compose)

Le backend peut être exécuté de manière 100% autonome via Docker, sans frontend et sans recourir à `docker-compose`.

### 1. Construction de l'image Docker

⚠️ **Attention au dossier d'exécution** :

- **Si vous êtes à la racine du projet (`Sentinel-X-G4`)** :
  ```powershell
  # Spécifier le chemin du Dockerfile et le contexte backend-api
  docker build -f backend-api/Dockerfile -t sentinel-x-backend backend-api
  ```
- **Si vous êtes déjà dans le dossier `backend-api`** (`cd backend-api`) :
  ```powershell
  docker build -t sentinel-x-backend .
  ```

---

### 2. Démarrage du conteneur en mode autonome (sans frontend)

Comme vous n'avez pas de frontend, on autorise toutes les origines avec `FRONTEND_URL="*"` (ou en l'omettant car c'est la valeur par défaut de l'API) :

#### Sous Windows PowerShell :
```powershell
docker run -d `
  --name sentinel-x-backend `
  -p 3000:3000 `
  -e NODE_ENV=production `
  -e PORT=3000 `
  -e FRONTEND_URL="*" `
  sentinel-x-backend
```

#### Sous Linux / macOS / Git Bash :
```bash
docker run -d \
  --name sentinel-x-backend \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e PORT=3000 \
  -e FRONTEND_URL="*" \
  sentinel-x-backend
```

> **Avec fichier `.env`** : Si vous préférez utiliser votre fichier `.env` :
> ```powershell
> docker run -d --name sentinel-x-backend -p 3000:3000 --env-file backend-api/.env sentinel-x-backend
> ```

---

### 3. Mode Développement avec hot-reload (`Dockerfile.dev`)

Si vous modifiez le code et souhaitez que le conteneur recharge automatiquement sans reconstruire l'image :

- **Build de l'image dev** (depuis `Sentinel-X-G4`) :
  ```powershell
  docker build -f backend-api/Dockerfile.dev -t sentinel-x-backend:dev backend-api
  ```
- **Lancement avec volume monté (PowerShell)** :
  ```powershell
  docker run -it --rm `
    --name sentinel-x-backend-dev `
    -p 3000:3000 `
    -p 9229:9229 `
    -v "${PWD}/backend-api:/app" `
    -v /app/node_modules `
    -e NODE_ENV=development `
    sentinel-x-backend:dev
  ```

---

### 3. Commandes utiles de gestion du conteneur

```bash
# Vérifier l'état du conteneur et le healthcheck
docker ps

# Suivre les logs en direct
docker logs -f sentinel-x-backend

# Tester le point de terminaison de santé
curl http://localhost:3000/api/health

# Arrêter et supprimer le conteneur
docker stop sentinel-x-backend
docker rm sentinel-x-backend
```

### 4. Variables d'environnement Docker supportées

| Variable | Défaut | Description |
|----------|--------|-------------|
| `NODE_ENV` | `production` | Environnement d'exécution (`production` ou `development`) |
| `PORT` | `3000` | Port d'écoute HTTP et WebSocket |
| `FRONTEND_URL` | `*` | Origine autorisée pour CORS (ex: `http://localhost:5173`) |
| `LOG_LEVEL` | `info` | Niveau de verbosité des logs |

---

## 📡 API Endpoints

### Health Check
```http
GET /api/health
```
```json
{
  "status": "OK",
  "message": "Backend API Sentinel-X Opérationnel",
  "timestamp": "2025-01-15T10:30:00.000Z",
  "uptime": 3600,
  "alertsCount": 42
}
```

### Alertes

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/v1/alerts` | Créer une alerte |
| `GET` | `/api/v1/alerts` | Lister (filtres, pagination) |
| `GET` | `/api/v1/alerts/:id` | Détail d'une alerte |
| `PATCH` | `/api/v1/alerts/:id/acknowledge` | Acquitter une alerte |

#### Créer une alerte
```http
POST /api/v1/alerts
Content-Type: application/json

{
  "title": "Tentative SSH brute-force",
  "severity": "high",
  "source": "fail2ban",
  "description": "5 échecs de connexion SSH depuis 192.168.1.50",
  "metadata": { "ip": "192.168.1.50", "port": 22, "attempts": 5 }
}
```

**Sévérités acceptées** : `low`, `medium`, `high`, `critical`

#### Filtres de liste (GET `/api/v1/alerts`)
| Paramètre | Type | Exemple |
|-----------|------|---------|
| `severity` | string (csv) | `?severity=high,critical` |
| `source` | string | `?source=firewall` |
| `since` | ISO 8601 | `?since=2025-01-01T00:00:00Z` |
| `search` | string | `?search=brute-force` |
| `page` | integer | `?page=2` |
| `limit` | integer (1-100) | `?limit=20` |

### Statistiques
```http
GET /api/v1/stats
```
```json
{
  "status": "success",
  "data": {
    "total": 150,
    "bySeverity": { "critical": 5, "high": 23, "medium": 67, "low": 55 },
    "acknowledged": 42,
    "unacknowledged": 108,
    "bySource": { "firewall": 60, "fail2ban": 45, "suricata": 45 }
  }
}
```

---

## 🔌 WebSocket (Temps réel)

### Connexion
```javascript
const socket = io('http://localhost:3000');
```

### Événements émis par le serveur

| Événement | Payload | Description |
|-----------|---------|-------------|
| `init_alerts` | `Alert[]` | 50 dernières alertes à la connexion |
| `new_alert` | `Alert` | Nouvelle alerte créée |
| `alert_low` | `Alert` | Alerte sévérité low |
| `alert_medium` | `Alert` | Alerte sévérité medium |
| `alert_high` | `Alert` | Alerte sévérité high |
| `alert_critical` | `Alert` | Alerte sévérité critical |
| `alert_acknowledged` | `Alert` | Alerte acquittée |
| `stats_update` | `Stats` | Réponse à `request_stats` |

### Événements côté client

| Événement | Description |
|-----------|-------------|
| `request_stats` | Demander les stats actuelles |

---

## 📦 Structure du projet

```
backend-api/
├── server.js              # Point d'entrée principal
├── Dockerfile             # Image production multi-stage
├── Dockerfile.dev         # Image développement (hot-reload)
├── .dockerignore          # Exclusions build Docker
├── package.json           # Dépendances & scripts
├── env.development.template   # Template variables dev
├── env.production.template    # Template variables prod
├── .gitignore             # Exclusions Git
└── README.md              # Ce fichier
```

---

## 🛠️ Scripts disponibles

| Commande | Description |
|----------|-------------|
| `npm start` | Démarre en production |
| `npm run dev` | Démarre avec nodemon + inspect |
| `npm run lint` | Vérifie le code (ESLint) |
| `npm run lint:fix` | Corrige automatiquement |

---

## 🔒 Sécurité

- **Utilisateur non-root** dans le container (UID 1001)
- **CORS configurable** via `FRONTEND_URL`
- **Validation stricte** des payloads entrants
- **Rate limiting** recommandé en production (reverse proxy)
- **Secrets** via variables d'environnement uniquement

---

## 📊 Monitoring

| Endpoint | Usage |
|----------|-------|
| `GET /api/health` | Liveness/Readiness probe (K8s, Docker, LB) |
| `GET /api/v1/stats` | Métriques métier pour Grafana/Datadog |

---

## 🤝 Contribution

1. Fork le repo
2. Créez une branche (`git checkout -b feature/ma-fonctionnalite`)
3. Committez (`git commit -m 'feat: ajouter ...'`)
4. Push (`git push origin feature/ma-fonctionnalite`)
5. Ouvrez une Pull Request

---

## 📄 Licence

ISC - Voir le fichier [LICENSE](../LICENSE) à la racine du projet.