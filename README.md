# Sentinel-X Backend API

Backend API pour le système de surveillance SENTINEL-X. Expose une API REST pour la consultation, l'acquittement et le suivi en direct des alertes de sécurité (le dashboard interroge l'API à intervalle régulier : pas de WebSocket).

## Points clés

- **Base de données** (`db.js`) : l'API ne se connecte pas à MQTT. Le service de détection
  (`backend-iot-alerts`), seul à parler aux capteurs et à la caméra, écoute le broker et écrit
  alertes et états d'appareils dans PostgreSQL ; l'API les lit et acquitte les alertes. Elle n'a ni
  WebSocket ni connexion permanente à la base.
- **Seule porte du frontend** : base de données et API du service de détection (santé,
  entraînement, commandes ESP) ne sont exposées au dashboard que par cette API.
- **Authentification** : toute l'API (`/api/v1/*`) exige un jeton de session (utilisateurs du
  dashboard, `POST /api/v1/auth/login` ou `/auth/face`) ou `API_KEY` (services) en `Authorization: Bearer <jeton>`
  Seuls `GET /api/health` et la connexion sont publics.
- **Rôles** (`users.role`) : `superadmin`, `admin`, `user` (le défaut `viewer` de la base vaut `user`).
  Le compte est relu en base à chaque requête : suppression ou changement de rôle immédiats.
- **Health check** : `GET /api/health` pour la supervision du conteneur.
- **Direct** : le dashboard redemande `GET /api/v1/overview` (alertes récentes, états des appareils, stats et identité caméra en une seule réponse) et `/camera/snapshot` toutes les 0,5 s, soit 4 requêtes par seconde et par onglet.

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
# DATABASE_URL doit pointer vers une base accessible (dans la pile, la base database n'est pas exposée)
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
le dépôt `database` (`db/init/`) ; l'API ne crée aucune table.

| Source | Usage |
|---|---|
| `public.alerts` | `GET /api/v1/alerts`, `/alerts/:id`, `/stats`, acquittement (`PATCH`) |
| `detection.predictions` | dernier état de chaque appareil : `GET /api/v1/devices` |
| `detection.camera_state` | dernier état de la caméra (identité, visages vus) : `GET /api/v1/camera`, `camera` de `/overview` ; `null` / 503 si aucun état depuis 30 s |

## Rôles et droits

| Fonction | user | admin | superadmin |
|---|:-:|:-:|:-:|
| Supervision : alertes, stats, appareils, caméra (identité + flux vidéo) | ✓ | ✓ | ✓ |
| Mon compte : `GET /auth/me`, `PATCH /auth/password` | ✓ | ✓ | ✓ |
| Connexion faciale `POST /auth/face` | ✓ | ✓ | ✓ |
| Acquitter une alerte (aussi avec `API_KEY`) | | ✓ | ✓ |
| Visages autorisés `/faces` | | ✓ | ✓ |
| Comptes `/users` (`GET`, `POST`, `PATCH /:id`, `DELETE /:id`) | | comptes `user` | tous |
| Santé du service de détection `GET /iot/health` | | ✓ | ✓ |
| Commandes ESP `POST /devices/:id/{alert,buzzer,led,screen,reset}` (aussi avec `API_KEY`) | | ✓ | ✓ |
| Entraînement : `/iot/recording`, `/iot/recording/start\|stop`, `POST /iot/reload-model` | | | ✓ |

Personne ne modifie ni ne supprime son propre compte par `/users` (seulement son mot de passe par
`/auth/password`) : il reste donc toujours au moins un superadmin. Premier démarrage : le compte
`ADMIN_USERNAME` / `ADMIN_PASSWORD` est créé superadmin ; sur une base sans superadmin, il est promu.

**Connexion faciale** : `POST /api/v1/auth/face { username }` ouvre une session si, en 2,5 s au plus,
la caméra voit 3 images avec **un seul** visage, reconnu sous le nom du compte. En cas d'échec, le
message dit si aucun visage, plusieurs visages ou un autre visage a été vu (sans jamais le nommer).
Un compte peut n'avoir **aucun mot de passe** (`POST /users` sans `password`) : il ne se connecte que
par visage et peut en définir un ensuite (`PATCH /auth/password` sans `currentPassword`) ; interdit
pour un superadmin. `hasPassword` dans les comptes renvoyés indique lequel des deux cas. Un visage nommé comme un compte ne peut donc
être ajouté ou supprimé que par ce compte ou par quelqu'un qui le gère (un admin ne peut pas enregistrer
son visage sous le nom d'un superadmin).
`GET /api/v1/auth/face/stream` (public, sans session) : le flux annoté de la caméra Sentinel pour la page
de connexion, comme `/camera/stream` ; 2 aperçus simultanés au plus, 120 ouvertures par IP / 15 min.

## Service de détection (backend-iot-alerts)

Relayé vers son API (`iot.js`, `http://sentinel-detection:8000` par le réseau `sentinel-data`,
`DETECTION_API_URL` pour changer). Service injoignable → 503.

| Route | Rôle |
|---|---|
| `GET /api/v1/iot/health` | santé : MQTT, base, modèle, dernière mesure par appareil |
| `GET /api/v1/iot/recording` | sessions d'enregistrement en cours |
| `POST /api/v1/iot/recording/start` | `{ device_id, label, notes? }`, label : `aucune`, `presence`, `fuite_gaz`, `feu` (combinables avec `+`) |
| `POST /api/v1/iot/recording/stop` | `{ device_id? }` (toutes si absent) |
| `POST /api/v1/iot/reload-model` | recharge le modèle (`DETECTION_ADMIN_TOKEN` si le service en exige un) |

## Commandes vers les ESP

Relayées au service de détection (`iot.js` → `POST /devices/{device_id}/…`, jeton
`DETECTION_ADMIN_TOKEN`), seul client MQTT des appareils : il publie sur `sentinelx/{device_id}/cmd`
(QoS 1) et attend l'acquittement de l'ESP sur `sentinelx/{device_id}/ack` (même `id`, 5 s max).
Validation faite ici (messages clairs pour le dashboard) puis refaite par le service. L'ESP ne déclenche aucune alerte seul (pas
de seuil local) : son alarme ne se déclenche que par `POST …/alert`. `auto` = la sortie suit cette
alerte. Alerte et modes forcés restent actifs jusqu'au `reset` ou au redémarrage de l'ESP.

| Route | Corps |
|---|---|
| `POST /api/v1/devices/:id/alert` | `{ "state": "on" \| "off" }` : buzzer + LED rouge + « ALERT » à l'écran (sorties en `auto`) |
| `POST /api/v1/devices/:id/buzzer` | `{ "state": "on" \| "off" \| "auto" }` (`off` rend l'alerte silencieuse) |
| `POST /api/v1/devices/:id/led` | `{ "state": "red" \| "green" \| "both" \| "off" \| "auto" }` |
| `POST /api/v1/devices/:id/screen` | `{ "state": "auto" \| "off" }` ou `{ "state": "message", "text": "…" }` (100 caractères max, accents retirés) |
| `POST /api/v1/devices/:id/reset` | aucun : alerte arrêtée, tout revient en `auto` |

Réponse : `200 { status: "success", data: { command, state: { alert, buzzer, led, screen } } }` (état
après la commande). Erreurs : `400` corps ou `device_id` invalide, `422` refusée par l'ESP, `502` jeton
admin du service erroné, `503` service de détection ou broker injoignable, `504` aucun acquittement
(ESP hors ligne).

```bash
curl -X POST https://dashboard.sentinel.lan/api/v1/devices/esp01/screen \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"state":"message","text":"Evacuation salle B"}'
```

Message MQTT publié par le service de détection : `{"id": "<uuid>", "command": "alert" | "buzzer" | "led" | "screen" | "reset", "state"?, "text"?}` ;
acquittement : `{"id", "command", "ok", "error"?, "state": {"alert", "buzzer", "led", "screen"}}`
(firmware : `software/src/main.cpp`, `handleCommand`).

**Dashboard (à construire)** : contrôles réservés aux admins ; bouton principal « Déclencher
l'alerte » (`alert`, avec confirmation), « Tout réinitialiser » (`reset`) bien visible ;
confirmation avant de couper le buzzer. L'état des sorties n'est connu qu'au
retour d'une commande (pas encore en base).

## Caméra : reconnaissance faciale

L'identité courante vient de la base : la caméra la publie en MQTT, le service de détection
l'enregistre (`detection.camera_state`, à chaque changement et au moins toutes les 10 s).
Visages autorisés, image et connexion faciale sont relayés vers l'API interne du détecteur
(`human-detection-ia`, réseau Docker `sentinel-vision`, clé partagée `VISION_API_KEY`) : la
connexion faciale lit l'image en cours, jamais un état en base qui pourrait dater. Le dashboard ne
parle qu'au backend, avec la même clé que le reste.

| Route | Rôle |
|---|---|
| `GET /api/v1/camera` | identité courante (base) : `identity` = `none` (personne) \| `authorized` (personne autorisée) \| `unknown` (inconnu), `person`, `names` (autorisés reconnus), `faces` (visages vus : `name` ou `null`), `device_id`, `ts`, `updated_at`. 503 si aucun état depuis 30 s (caméra hors ligne) |
| `GET /api/v1/faces` | visages autorisés : `[{ id, name, created_at }]` |
| `POST /api/v1/faces` | `{ "name": "Alice" }` → 201. Le détecteur prend le visage sur l'image courante de la caméra Sentinel : le backend ne reçoit aucune image. 422 s'il n'y a pas exactement un visage exploitable (≥ 40 px) |
| `GET /api/v1/faces/:id/image` | vignette JPEG du visage (à charger en `fetch` + Bearer, pas en `<img src>`) |
| `DELETE /api/v1/faces/:id` | supprime le visage |
| `GET /api/v1/camera/snapshot` | dernière image JPEG annotée de la webcam (détecteur, port 8089 ; `VISION_PREVIEW_URL` pour changer). Le dashboard la redemande chaque seconde |

Plusieurs captures sous le même `name` améliorent la reconnaissance (lumière, angle, lunettes).
Détecteur injoignable → 503 ; clé partagée erronée → 502.

## Points d'intégration

- Le service de détection et l'ESP passent par **MQTT** ; seul le service de détection y est connecté
  (mesures, caméra, commandes vers les ESP). L'API lui parle en HTTP (`iot.js`).
- Il n'y a pas d'ingestion HTTP : les alertes arrivent par la base.
- Sans `API_KEY` (32 caractères minimum), l'API refuse de démarrer en production.
- Le health check est accessible à `GET /api/health` pour le reverse proxy et la supervision.
- CORS : `FRONTEND_URL` doit contenir l'origine exacte du dashboard.
- Historique persistant en base (survit aux redémarrages de l'API).

## Variables d'environnement (`.env` de `main/`, voir `main/.env.example`)

| Variable | Rôle |
|---|---|
| `PORT` | port HTTP (3000 ; 5678 dans la pile Sentinel-X, attendu par le reverse proxy) |
| `FRONTEND_URL` | origine(s) autorisée(s), séparées par des virgules. Pas de joker : `*` n'est **pas** interprété |
| `API_KEY` | clé des services, obligatoire en production |
| `DATABASE_URL` | `postgresql://user:pass@db:5432/sentinel`, obligatoire |
| `VISION_API_URL` | API interne du détecteur caméra (`http://sentinel-human-detection:8090`) ; absente = routes caméra en 503 |
| `VISION_API_KEY` | clé partagée avec le détecteur (`make vision-api-key` dans `main/`) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | compte superadmin initial (voir Rôles et droits) |
| `DETECTION_ADMIN_TOKEN` | jeton des routes d'action du service de détection (commandes ESP, rechargement du modèle) ; `make detection-admin-token` dans `main/` |
| `DETECTION_API_URL`, `VISION_PREVIEW_URL` | facultatives : les valeurs par défaut conviennent à la pile Docker ; à définir pour `npm run dev` hors Docker (`http://localhost:8000`, `http://localhost:8089`) |

Dans la pile Sentinel-X, ces variables viennent du `.env` de `main/` (voir le `docker-compose.yml` de `main`, seul compose du projet) ; le backend n'a pas de `.env` propre. `npm run dev` charge `../../.env`.

## Sécurité

Clé d'API obligatoire (comparée en temps constant, refus de démarrer en production si absente), frein au brute-force sur les 401, rate limiting (600 requêtes par minute et par IP), body limité à 10 Ko, CORS restreint, headers sécurisés (helmet), logs anti log-injection, conteneur non-root.

## Scripts

| Commande | Description |
|----------|-------------|
| `npm start` | Production |
| `npm run dev` | Développement avec hot-reload |
| `npm run lint` | Validation du code |
| `npm run lint:fix` | Correction automatique |

## Licence

ISC
