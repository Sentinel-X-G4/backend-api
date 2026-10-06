# Sentinel-X Backend API

Backend API pour le système de surveillance SENTINEL-X. Expose une API REST + WebSocket pour l'ingestion, la consultation et le suivi en temps réel des alertes de sécurité.

## Points clés

- **Pont MQTT** (`mqtt-bridge.js`) : abonné en MQTTS aux résultats du service de détection et aux
  alertes de l'ESP ; c'est le chemin normal des alertes dans la pile Sentinel-X.
- **POST /api/v1/alerts** : ingestion HTTP d'une alerte (outils, intégrations). Requiert le header `X-API-Key`.
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
docker run -d --name sentinel-x-backend -p 3000:3000 -e NODE_ENV=production -e PORT=3000 -e FRONTEND_URL="http://localhost:5173" -e API_KEY="<votre-cle-secrete>" sentinel-x-backend
```

Depuis `backend-api/` :

```bash
docker build -t sentinel-x-backend .
docker run -d --name sentinel-x-backend -p 3000:3000 --env-file .env sentinel-x-backend
```

Pour arrêter et supprimer : `docker stop sentinel-x-backend && docker rm sentinel-x-backend`.

## Pont MQTT

Actif dès que `MQTT_URL` est défini (sinon l'API tourne seule, sans MQTT). Compte `iot-backend`
dans la pile Sentinel-X (droits : `sentinel-x-g4/infra/mosquitto/config/acl`).

| Topic | Effet |
|---|---|
| `sentinelx/+/detection` | résultat du service de détection : état de l'appareil (`GET /api/v1/devices`, WebSocket `device_status`) et alerte créée à l'**activation** de `feu`, `fuite_gaz` ou `presence` |
| `sentinelx/+/alert` | alerte brute de l'ESP, ex. `{"type":"pir","value":true}` |

Les alertes reçues en MQTT suivent le même chemin que celles du POST (stockage, `new_alert` en
WebSocket), sans passer par la validation HTTP.

## Points d'intégration

- Le service de détection et l'ESP passent par **MQTT**, pas par `POST /api/v1/alerts`.
- `POST /api/v1/alerts` demande `X-API-Key` : sans `API_KEY` configurée, il répond 503 en production.
- Écritures du dashboard (`PATCH`…) : jeton CSRF à lire sur `GET /api/v1/csrf-token`, à renvoyer
  dans le header `X-CSRF-Token` (avec le cookie `XSRF-TOKEN`).
- Le health check est accessible à `GET /api/health` pour le reverse proxy et la supervision.
- WebSocket : chemin socket.io par défaut (`/socket.io/`), relayé au backend par le reverse proxy.
  Il hérite du CORS : `FRONTEND_URL` doit contenir l'origine exacte du dashboard.
- Il n'y a pas encore de persistance : l'historique est en mémoire (perdu au redémarrage).

## Variables d'environnement (voir .env.example)

| Variable | Rôle |
|---|---|
| `PORT` | port HTTP (3000 ; 5678 dans la pile Sentinel-X, attendu par le reverse proxy) |
| `FRONTEND_URL` | origine(s) autorisée(s), séparées par des virgules. Pas de joker : `*` n'est **pas** interprété |
| `API_KEY` | clé de `POST /api/v1/alerts`, obligatoire en production |
| `MQTT_URL`, `MQTT_USERNAME`, `MQTT_PASSWORD`, `MQTT_CA_FILE` | pont MQTT (vide = désactivé) |
| `TRUST_PROXY`, `RATE_LIMIT_*` | reverse proxy et limites de débit |

PostgreSQL, Redis et JWT sont pour plus tard.

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
