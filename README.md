# Sentinel-X Backend API

Backend API pour le système de surveillance SENTINEL-X. Expose une API REST + WebSocket pour l'ingestion, la consultation et le suivi en temps réel des alertes de sécurité.

## Points clés

- **Base de données** (`db.js`) : l'API ne se connecte pas à MQTT. Le service de détection
  (`backend-iot-alerts`) écoute le broker et écrit alertes et états d'appareils dans PostgreSQL ;
  l'API les lit, acquitte les alertes et relaie le temps réel (`LISTEN/NOTIFY`) en WebSocket.
- **Authentification** : toute l'API (`/api/v1/*` et WebSocket) exige `API_KEY` en `Authorization: Bearer <clé>`
  (WebSocket : `io({ auth: { token } })`). Seul `GET /api/health` est public.
- **Health check** : `GET /api/health` pour la supervision du conteneur.
- **WebSocket** : push temps réel vers le frontend (Dashboard).

## Léquipe

- **Backend API** (backend-api/) : toi.
- **Backend IoT / Broker MQTT (Mosquitto)** : Baptiste.
- **Reverse Proxy (Défenseur réseau)** : Baptiste, Charles.
- **Frontend (Dashboard + Grafana)** : Aurel ou Hugo.

## Pour lancer en local

```bash
cd backend-api
npm ci
# la configuration vient du .env de main/ (make init), le backend n'a pas de .env propre ;
# DATABASE_URL doit pointer vers une base accessible (dans la pile, sentinel-db n'est pas exposée)
npm run dev
```

Le serveur démarre sur http://localhost:3000.

## Pour lancer avec Docker (backend seul, sans frontend)

Depuis la racine du projet :

```bash
docker build -f backend-api/Dockerfile -t sentinel-x-backend backend-api
docker run -d --name sentinel-x-backend -p 3000:3000 -e NODE_ENV=production -e FRONTEND_URL="http://localhost:5173" -e API_KEY="$(openssl rand -hex 32)" -e DATABASE_URL="postgresql://user:pass@hote:5432/sentinel" sentinel-x-backend
```

Depuis `backend-api/` :

```bash
docker build -t sentinel-x-backend .
docker run -d --name sentinel-x-backend -p 3000:3000 --env-file ../../.env sentinel-x-backend
```

Pour arrêter et supprimer : `docker stop sentinel-x-backend && docker rm sentinel-x-backend`.

## Base de données

`DATABASE_URL` est obligatoire (l'API refuse de démarrer sans). Le schéma est créé par
`sentinel-x-g4/infra/postgres/init/` ; l'API ne crée aucune table.

| Source | Usage |
|---|---|
| `public.alerts` | `GET /api/v1/alerts`, `/alerts/:id`, `/stats`, acquittement (`PATCH`) |
| `detection.predictions` | dernier état de chaque appareil : `GET /api/v1/devices` |
| `NOTIFY sentinel_alerts` (id) | WebSocket `new_alert` |
| `NOTIFY sentinel_devices` (device_id) | WebSocket `device_status` |

## Points d'intégration

- Le service de détection et l'ESP passent par **MQTT** ; seul le service de détection y est abonné.
- Il n'y a pas d'ingestion HTTP : les alertes arrivent par la base.
- Sans `API_KEY` (32 caractères minimum), l'API refuse de démarrer en production.
- Le health check est accessible à `GET /api/health` pour le reverse proxy et la supervision.
- WebSocket : chemin socket.io par défaut (`/socket.io/`), relayé au backend par le reverse proxy.
  Il hérite du CORS : `FRONTEND_URL` doit contenir l'origine exacte du dashboard.
- Historique persistant en base (survit aux redémarrages de l'API).

## Variables d'environnement (`.env` de `main/`, voir `main/.env.example`)

| Variable | Rôle |
|---|---|
| `PORT` | port HTTP (3000 ; 5678 dans la pile Sentinel-X, attendu par le reverse proxy) |
| `FRONTEND_URL` | origine(s) autorisée(s), séparées par des virgules. Pas de joker : `*` n'est **pas** interprété |
| `API_KEY` | clé unique REST + WebSocket, obligatoire en production |
| `DATABASE_URL` | `postgresql://user:pass@sentinel-db:5432/sentinel`, obligatoire |

Dans la pile Sentinel-X, ces variables viennent du `.env` de `main/` (voir `docker-compose.yml`) ; le backend n'a pas de `.env` propre. `npm run dev` charge `../../.env`.

## Sécurité

Clé d'API obligatoire (comparée en temps constant, refus de démarrer en production si absente), frein au brute-force sur les 401, rate limiting, body limité à 10 Ko, CORS restreint, headers sécurisés (helmet), logs anti log-injection, WebSocket limité à 10 Ko, conteneur non-root.

## Scripts

| Commande | Description |
|----------|-------------|
| `npm start` | Production |
| `npm run dev` | Développement avec hot-reload |
| `npm run lint` | Validation du code |
| `npm run lint:fix` | Correction automatique |

## Licence

ISC
