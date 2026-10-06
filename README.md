# Sentinel-X Backend API

Backend API pour le système de surveillance SENTINEL-X. Expose une API REST + WebSocket pour l'ingestion, la consultation et le suivi en temps réel des alertes de sécurité.

## Points clés

- **POST /api/v1/alerts** : point d'entrée pour le Backend IoT (MQTT) d'ingérer des alertes. Requiert le header `X-API-Key`.
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
cp .env.example .env
npm run dev
```

Le serveur démarre sur http://localhost:3000.

## Pour lancer avec Docker (backend seul, sans frontend)

Depuis la racine du projet :

```bash
docker build -f backend-api/Dockerfile -t sentinel-x-backend backend-api
docker run -d --name sentinel-x-backend -p 3000:3000 -e NODE_ENV=production -e PORT=3000 -e FRONTEND_URL="*" -e API_KEY="<votre-cle-secrete>" sentinel-x-backend
```

Depuis `backend-api/` :

```bash
docker build -t sentinel-x-backend .
docker run -d --name sentinel-x-backend -p 3000:3000 --env-file .env sentinel-x-backend
```

Pour arrêter et supprimer : `docker stop sentinel-x-backend && docker rm sentinel-x-backend`.

## Points d'intégration

- Le Backend IoT doit appeler `POST /api/v1/alerts` avec `X-API-Key` pour envoyer une alerte.
- Le health check est accessible à `GET /api/health` pour le reverse proxy et la supervision.
- Le WebSocket hérite du CORS : si le backend est derrière un reverse proxy, le `FRONTEND_URL` doit correspondre à l'origine frontend.
- Il n'y a pas encore de persistance : l'historique est en mémoire (perdu au redémarrage).

## Variables d'environnement (voir .env.example)

La seule variable vraiment nécessaire maintenant est `API_KEY` (en production, obligatoire pour l'ingestion). Les autres variables sont pour plus tard : PostgreSQL, MQTT, Redis, JWT.

## Sécurité

La surface d'attaque est réduite : validation stricte des payloads (whitelist de champs, limites de taille, blocage des clés dangereuses), auth ingestion par `X-API-Key` comparée en temps constant (fail-closed en prod si absente), rate limiting, body limité à 100 Ko, CORS restreint, headers sécurisés (helmet, X-Powered-By désactivé), logs anti log-injection, WebSocket limité à 10 Ko, conteneur non-root.

## Scripts

| Commande | Description |
|----------|-------------|
| `npm start` | Production |
| `npm run dev` | Développement avec hot-reload |
| `npm run lint` | Validation du code |
| `npm run lint:fix` | Correction automatique |

## Licence

ISC
