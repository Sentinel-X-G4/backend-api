# 🛡️ Sentinel-X Backend API

Backend API pour le système de détection d'intrusion **Sentinel-X**.  
Expose une API REST + WebSocket pour l'ingestion, la consultation et le suivi en temps réel des alertes de sécurité.

---

## 📋 Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| **API REST** | CRUD complet sur les alertes (création, lecture, filtres, pagination) |
| **WebSocket (Socket.io)** | Push temps réel vers le Dashboard frontend |
| **Validation** | Schéma strict whitelisté pour les alertes entrantes |
| **Auth ingestion** | `X-API-Key` obligatoire sur `POST /api/v1/alerts` (fail-closed en prod) |
| **Rate limiting** | Limites globales + dédiée à l'ingestion → `429` + en-têtes `RateLimit` |
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
| `API_KEY` | — | **Obligatoire en prod** : clé d'ingestion envoyée en `X-API-Key` |
| `TRUST_PROXY` | `1` | Saux de reverse proxy de confiance pour la vraie IP cliente (`false` pour désactiver) |
| `RATE_LIMIT_WINDOW_MS` | `900000` | Fenêtre du rate limit global (15 min) |
| `RATE_LIMIT_MAX_REQUESTS` | `600` (prod) | Requêtes max par fenêtre (health check exempt) |
| `RATE_LIMIT_INGEST_MAX_REQUESTS` | `60` | POST `/api/v1/alerts` max par minute |

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
| `POST` | `/api/v1/alerts` | Créer une alerte (header `X-API-Key` requis) |
| `GET` | `/api/v1/alerts` | Lister (filtres, pagination) |
| `GET` | `/api/v1/alerts/:id` | Détail d'une alerte |
| `PATCH` | `/api/v1/alerts/:id/acknowledge` | Acquitter une alerte |

#### Créer une alerte (appelant : Backend IoT / Broker MQTT)
```http
POST /api/v1/alerts
Content-Type: application/json
X-API-Key: <votre-api-key>

{
  "title": "Tentative SSH brute-force",
  "severity": "high",
  "source": "fail2ban",
  "description": "5 échecs de connexion SSH depuis 192.168.1.50",
  "metadata": { "ip": "192.168.1.50", "port": 22, "attempts": 5 }
}
```

> **Erreurs possibles** : `401` sans mauvaise API key · `400` payload invalide ·
> `413` payload > 100 Ko · `429` rate limit · `503` `API_KEY` non configurée (prod).
> Les champs `metadata` acceptent uniquement des valeurs scalaires (string ≤ 512 car, number, boolean, null).

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

| Protection | Implémentation |
|------------|----------------|
| **Auth ingestion** | `X-API-Key` comparée en temps constant (`crypto.timingSafeEqual`) ; fail-closed en production si absente |
| **Rate limiting** | Global (hors health) + ingestion 60/min, en-têtes `RateLimit` standardisés, `429` JSON |
| **CSRF** | Double-submit cookie (`XSRF-TOKEN` + header `X-CSRF-Token`) sur toutes les routes v1 sauf l'ingestion M2M |
| **Validation stricte** | Whitelist de champs (anti mass-assignment), limites de taille, `metadata` scalaire, blocage `__proto__`/`constructor`/`prototype` |
| **Headers** | `helmet` (CSP, HSTS, nosniff...), `X-Powered-By` désactivé |
| **CORS** | Whitelist d'origines stricte (`FRONTEND_URL`), rejet → `403` |
| **Payloads** | Body limité à 100 Ko (`413`), `urlencoded` désactivé (JSON uniquement) |
| **Logs** | CR/LF neutralisés (anti log-injection) |
| **WebSocket** | `maxHttpBufferSize` 10 Ko, origines restreintes par le CORS |
| **Proxy** | `TRUST_PROXY` pour la vraie IP client derrière le reverse proxy |
| **Container** | Utilisateur non-root (UID 1001), dépendances auditées (`npm audit` : 0 vulnérabilité prod) |
| **Secrets** | Variables d'environnement uniquement, `.env` jamais commité |

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