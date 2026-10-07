const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { createStore } = require('./db');
const { hashPassword, verifyPassword, createSessions } = require('./auth');
const { createVision } = require('./vision');
const { createIot } = require('./iot');

const isProduction = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173').split(',').map(u => u.trim()).filter(Boolean);

// Une seule clé protège toute l'API (REST + WebSocket). En production elle est obligatoire
// et doit être générée : openssl rand -hex 32
if (isProduction && (!API_KEY || API_KEY.length < 32)) {
    console.error('[SÉCURITÉ] API_KEY absente ou trop courte (32 caractères minimum) : arrêt');
    process.exit(1);
}
if (!API_KEY) {
    console.warn('[SÉCURITÉ] API_KEY absente : API ouverte (développement uniquement)');
}

// Toutes les données viennent de la base (écrite par le service de détection)
if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL absente : arrêt');
    process.exit(1);
}

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest();
const isAuthorized = (token) =>
    !API_KEY || (typeof token === 'string' && crypto.timingSafeEqual(sha256(token), sha256(API_KEY)));

const app = express();

// Un seul reverse proxy (nginx) devant l'API : nécessaire pour l'IP réelle du client (rate limit, logs)
app.set('trust proxy', 1);
app.disable('x-powered-by');

const store = createStore(process.env.DATABASE_URL);
const sessions = createSessions(API_KEY);
// Rôles du dashboard :
//   superadmin  tout : comptes admin, entraînement et modèle de l'IA de détection
//   admin       acquittement des alertes, visages autorisés, comptes « user », santé du service IoT
//   user        supervision (états, courbes, caméra, alertes) en lecture seule
const ROLES = ['superadmin', 'admin', 'user'];

// Premier démarrage : crée le compte superadmin depuis ADMIN_USERNAME / ADMIN_PASSWORD si aucun
// compte n'existe. Base créée avant les rôles actuels (aucun superadmin) : ADMIN_USERNAME est promu.
(async () => {
    const username = process.env.ADMIN_USERNAME || 'admin';
    try {
        const users = await store.listUsers();
        if (users.length === 0 && process.env.ADMIN_PASSWORD) {
            await store.createUser(username, hashPassword(process.env.ADMIN_PASSWORD), 'superadmin');
            console.log(`Compte superadmin initial créé : ${sanitizeForLog(username)}`);
        } else if (!users.some((u) => u.role === 'superadmin')) {
            const account = users.find((u) => u.username === username);
            if (account) {
                await store.updateUser(account.id, { role: 'superadmin' });
                console.log(`Aucun superadmin : ${sanitizeForLog(username)} promu superadmin`);
            }
        }
    } catch (err) {
        console.error('❌ Création du compte superadmin impossible:', sanitizeForLog(err.message));
    }
})();
// Reconnaissance faciale : API interne du détecteur caméra (facultative)
const vision = createVision(process.env.VISION_API_URL, process.env.VISION_API_KEY, process.env.VISION_PREVIEW_URL || undefined);
// Service de détection (backend-iot-alerts) : même réseau Docker que la base (sentinel-data)
const iot = createIot(process.env.DETECTION_API_URL || 'http://sentinel-detection:8000', process.env.DETECTION_ADMIN_TOKEN);
if (!vision.enabled) {
    console.warn('VISION_API_URL absente : routes /api/v1/faces et /api/v1/camera indisponibles');
}

const tooMany = (req, res) => res.status(429).json({ status: 'error', message: 'Trop de requêtes. Réessayez plus tard.' });
const limiterOptions = { standardHeaders: 'draft-8', legacyHeaders: false, handler: tooMany };

app.use(helmet());
app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Health check (sonde Docker) : public, sans donnée métier
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'OK', uptime: process.uptime() });
});

// 10 requêtes/s par IP (comme nginx) : le dashboard interroge l'API en continu (voir frontend live.jsx)
app.use(rateLimit({ ...limiterOptions, windowMs: 60 * 1000, limit: 600 }));
// Seul l'ajout d'un visage transporte une image : son corps est lu après l'authentification
const isFaceUpload = (req) => req.method === 'POST' && req.path === '/api/v1/faces';
const smallJson = express.json({ limit: '10kb' });
app.use((req, res, next) => (isFaceUpload(req) ? next() : smallJson(req, res, next)));

// Nettoyage avant logging (anti log-injection : CR/LF/tab -> espace)
const sanitizeForLog = (value) => String(value).replace(/[\r\n\t]+/g, ' ').slice(0, 300);

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${sanitizeForLog(req.path)}`);
    next();
});

// Frein au brute-force : seules les réponses en échec (401) comptent
const authFailureLimiter = rateLimit({
    ...limiterOptions,
    windowMs: 15 * 60 * 1000,
    limit: 20,
    skipSuccessfulRequests: true,
    requestWasSuccessful: (req, res) => res.statusCode !== 401
});

const relay = (res, { status, json }) => res.status(status).json(json);
const publicAccount = (user) => ({ id: user.id, username: user.username, role: user.role });
const sessionResponse = (res, user) => {
    const account = publicAccount(user);
    res.status(200).json({ status: 'success', data: { token: sessions.issue(account), user: account } });
};
const FACE_LOGIN_REFUSED = { status: 'error', message: 'Visage non reconnu pour ce compte' };

// Connexion : publique (frein au brute-force via authFailureLimiter), renvoie un jeton de session
app.post('/api/v1/auth/login', authFailureLimiter, async (req, res) => {
    const { username, password } = req.body || {};
    const user = typeof username === 'string' && typeof password === 'string' ? await store.getUser(username) : null;
    if (!user || !verifyPassword(password, user.password_hash)) {
        return res.status(401).json({ status: 'error', message: 'Identifiant ou mot de passe incorrect' });
    }
    sessionResponse(res, user);
});

// Connexion par reconnaissance faciale : l'identifiant doit correspondre au SEUL visage que la
// caméra voit à cet instant (visage enregistré sous le nom du compte). Les superadmins gardent
// le mot de passe obligatoire.
app.post('/api/v1/auth/face', authFailureLimiter, async (req, res) => {
    const { username } = req.body || {};
    const user = typeof username === 'string' ? await store.getUser(username) : null;
    if (!user || user.role === 'superadmin') {
        return res.status(401).json(FACE_LOGIN_REFUSED);
    }
    const camera = await vision.status();
    if (camera.status !== 200) {
        return relay(res, camera);
    }
    const faces = camera.json.data.faces || [];
    if (faces.length !== 1 || faces[0].name !== user.username) {
        return res.status(401).json(FACE_LOGIN_REFUSED);
    }
    console.log(`Connexion par visage : ${sanitizeForLog(user.username)}`);
    sessionResponse(res, user);
});

// Jeton de session -> compte relu en base : un compte supprimé ou dont le rôle change est
// pris en compte immédiatement, sans attendre l'expiration du jeton
const accountFromToken = async (token) => {
    const session = sessions.verify(token);
    const user = session && await store.getUser(session.username);
    return user ? publicAccount(user) : null;
};

// Accès : clé API (services) ou jeton de session (utilisateurs du dashboard)
app.use('/api/v1', authFailureLimiter, async (req, res, next) => {
    const [scheme, token] = (req.headers.authorization || '').split(' ');
    if (scheme === 'Bearer') {
        const user = await accountFromToken(token);
        if (user) {
            req.user = user;
            return next();
        }
        if (isAuthorized(token)) {
            req.service = true;
            return next();
        }
    }
    console.warn(`[SÉCURITÉ] Accès refusé (ip=${req.ip})`);
    res.status(401).json({ status: 'error', message: 'Authentification requise' });
});

// Droits par route : allow('admin', 'superadmin') ; 'service' = appel avec la clé API
const allow = (...roles) => (req, res, next) =>
    (req.user && roles.includes(req.user.role)) || (req.service && roles.includes('service'))
        ? next()
        : res.status(403).json({ status: 'error', message: 'Droits insuffisants' });
const ADMINS = ['admin', 'superadmin'];

// Un admin ne gère que les comptes « user » ; un superadmin gère tout le monde
const canManage = (actor, target) => actor.role === 'superadmin' || (actor.role === 'admin' && target.role === 'user');
const assignableRoles = (actor) => (actor.role === 'superadmin' ? ROLES : ['user']);
const roleRefused = (actor) => ({ status: 'error', message: `Rôle non autorisé (${assignableRoles(actor).join(', ')})` });

const validPassword = (password) => typeof password === 'string' && password.length >= 8 && password.length <= 200;
const PASSWORD_ERROR = { status: 'error', message: 'Mot de passe : 8 à 200 caractères' };

// Mon compte : identité et rôle à jour (le dashboard adapte ses menus), changement de mot de passe
app.get('/api/v1/auth/me', allow(...ROLES), (req, res) => {
    res.status(200).json({ status: 'success', data: req.user });
});

app.patch('/api/v1/auth/password', allow(...ROLES), async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const user = await store.getUser(req.user.username);
    if (typeof currentPassword !== 'string' || !verifyPassword(currentPassword, user.password_hash)) {
        return res.status(400).json({ status: 'error', message: 'Mot de passe actuel incorrect' });
    }
    if (!validPassword(newPassword)) {
        return res.status(400).json(PASSWORD_ERROR);
    }
    await store.updateUser(user.id, { passwordHash: hashPassword(newPassword) });
    res.status(200).json({ status: 'success', message: 'Mot de passe modifié' });
});

// Comptes : un admin gère les comptes « user », un superadmin tous les comptes
app.get('/api/v1/users', allow(...ADMINS), async (req, res) => {
    res.status(200).json({ status: 'success', data: await store.listUsers() });
});

app.post('/api/v1/users', allow(...ADMINS), async (req, res) => {
    const { username, password, role } = req.body || {};
    if (typeof username !== 'string' || !/^[\w.@-]{3,50}$/.test(username)) {
        return res.status(400).json({ status: 'error', message: 'Identifiant invalide (3 à 50 caractères : lettres, chiffres, . _ @ -)' });
    }
    if (!validPassword(password)) {
        return res.status(400).json(PASSWORD_ERROR);
    }
    if (!assignableRoles(req.user).includes(role)) {
        return res.status(403).json(roleRefused(req.user));
    }
    const user = await store.createUser(username, hashPassword(password), role);
    if (!user) {
        return res.status(409).json({ status: 'error', message: 'Cet identifiant existe déjà' });
    }
    console.log(`Compte créé : ${sanitizeForLog(user.username)} (${user.role}) par ${sanitizeForLog(req.user.username)}`);
    res.status(201).json({ status: 'success', data: user });
});

// Cible d'une modification : existe, n'est pas soi-même et est gérable par l'acteur. Personne ne
// pouvant se rétrograder ni se supprimer, il reste toujours au moins un superadmin.
const loadTarget = async (req, res, next) => {
    const target = /^\d{1,9}$/.test(req.params.id) ? await store.getUserById(Number(req.params.id)) : null;
    if (!target) {
        return res.status(404).json({ status: 'error', message: 'Compte non trouvé' });
    }
    if (target.id === req.user.id) {
        return res.status(403).json({ status: 'error', message: 'Modifiez votre propre compte depuis « Mon compte »' });
    }
    if (!canManage(req.user, target)) {
        return res.status(403).json({ status: 'error', message: 'Droits insuffisants sur ce compte' });
    }
    req.target = target;
    next();
};

// { role?, password? } : changement de rôle ou réinitialisation du mot de passe
app.patch('/api/v1/users/:id', allow(...ADMINS), loadTarget, async (req, res) => {
    const { role, password } = req.body || {};
    if (role !== undefined && !assignableRoles(req.user).includes(role)) {
        return res.status(403).json(roleRefused(req.user));
    }
    if (password !== undefined && !validPassword(password)) {
        return res.status(400).json(PASSWORD_ERROR);
    }
    const user = await store.updateUser(req.target.id, { role, passwordHash: password && hashPassword(password) });
    console.log(`Compte modifié : ${sanitizeForLog(user.username)} (${user.role}) par ${sanitizeForLog(req.user.username)}`);
    res.status(200).json({ status: 'success', data: user });
});

app.delete('/api/v1/users/:id', allow(...ADMINS), loadTarget, async (req, res) => {
    await store.deleteUser(req.target.id);
    console.log(`Compte supprimé : ${sanitizeForLog(req.target.username)} par ${sanitizeForLog(req.user.username)}`);
    res.status(200).json({ status: 'success', message: 'Compte supprimé' });
});

// Un paramètre répété (?a=1&a=2) arrive sous forme de tableau : on ne garde que les chaînes
const queryString = (value) => (typeof value === 'string' ? value : '');

app.get('/api/v1/alerts', async (req, res) => {
    const since = new Date(queryString(req.query.since));
    const filters = {
        severities: queryString(req.query.severity).split(',').filter(Boolean),
        source: queryString(req.query.source).toLowerCase(),
        search: queryString(req.query.search).toLowerCase(),
        since: isNaN(since.getTime()) ? null : since
    };

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const { data, total } = await store.listAlerts(filters, { offset: (page - 1) * limit, limit });

    res.status(200).json({
        status: 'success',
        data,
        pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
});

app.get('/api/v1/alerts/:id', async (req, res) => {
    const alert = await store.getAlert(req.params.id);
    if (!alert) {
        return res.status(404).json({ status: 'error', message: 'Alerte non trouvée' });
    }
    res.status(200).json({ status: 'success', data: alert });
});

app.patch('/api/v1/alerts/:id/acknowledge', allow(...ADMINS, 'service'), async (req, res) => {
    // Utilisateur connecté : son identifiant fait foi ; service (clé API) : champ facultatif
    const acknowledgedBy = req.user ? req.user.username : (req.body || {}).acknowledgedBy;
    if (acknowledgedBy !== undefined && (typeof acknowledgedBy !== 'string' || acknowledgedBy.trim().length === 0 || acknowledgedBy.trim().length > 100)) {
        return res.status(400).json({
            status: 'error',
            message: 'Le champ "acknowledgedBy" doit être une chaîne de 1 à 100 caractères'
        });
    }

    const alert = await store.acknowledgeAlert(req.params.id, acknowledgedBy ? acknowledgedBy.trim() : 'unknown');
    if (!alert) {
        return res.status(404).json({ status: 'error', message: 'Alerte non trouvée' });
    }

    res.status(200).json({ status: 'success', message: 'Alerte acquittée', data: alert });
});

// --- Caméra : reconnaissance faciale (relayée vers le détecteur) ------------------------
// Identité courante : none (personne) | authorized (personne autorisée) | unknown (inconnu)
const FACE_ID = /^[0-9a-f]{32}$/;
const checkFaceId = (req, res, next) =>
    FACE_ID.test(req.params.id) ? next() : res.status(404).json({ status: 'error', message: 'Visage non trouvé' });

app.get('/api/v1/camera', async (req, res) => relay(res, await vision.status()));

// Image courante de la webcam (annotée par l'IA) : le dashboard la redemande régulièrement
app.get('/api/v1/camera/snapshot', async (req, res) => {
    const result = await vision.snapshot();
    if (!result.image) {
        return relay(res, result);
    }
    res.status(200).type('image/jpeg').set('Cache-Control', 'private, no-store').send(result.image);
});

// Un visage enregistré sous le nom d'un compte sert à la connexion faciale de ce compte :
// on ne l'ajoute ou ne le supprime que pour soi-même ou pour un compte qu'on gère
const mayEditFace = async (actor, name) => {
    const account = await store.getUser(name);
    return !account || account.id === actor.id || canManage(actor, account);
};
const FACE_FORBIDDEN = { status: 'error', message: 'Ce visage est lié à un compte que vous ne gérez pas' };

app.get('/api/v1/faces', allow(...ADMINS), async (req, res) => relay(res, await vision.listFaces()));

// { name, image? } : image en base64 (ou data URL), JPEG ou PNG. Sans image, le visage est
// pris sur l'image courante de la caméra.
app.post('/api/v1/faces', allow(...ADMINS), express.json({ limit: '8mb' }), async (req, res) => {
    const { name, image } = req.body || {};
    if (typeof name !== 'string' || name.trim().length === 0 || name.trim().length > 64) {
        return res.status(400).json({ status: 'error', message: 'Le champ "name" doit être une chaîne de 1 à 64 caractères' });
    }
    if (image !== undefined && (typeof image !== 'string' || image.length === 0)) {
        return res.status(400).json({ status: 'error', message: 'Le champ "image" doit être une image encodée en base64' });
    }
    if (!await mayEditFace(req.user, name.trim())) {
        return res.status(403).json(FACE_FORBIDDEN);
    }
    const result = await vision.addFace(name.trim(), image);
    if (result.status === 201) {
        console.log(`Visage autorisé ajouté : ${sanitizeForLog(result.json.data.name)}`);
    }
    relay(res, result);
});

app.get('/api/v1/faces/:id/image', allow(...ADMINS), checkFaceId, async (req, res) => {
    const result = await vision.faceImage(req.params.id);
    if (!result.image) {
        return relay(res, result);
    }
    res.status(200).type('image/jpeg').set('Cache-Control', 'private, no-store').send(result.image);
});

app.delete('/api/v1/faces/:id', allow(...ADMINS), checkFaceId, async (req, res) => {
    const faces = await vision.listFaces();
    if (faces.status !== 200) {
        return relay(res, faces);
    }
    const face = faces.json.data.find((f) => f.id === req.params.id);
    if (!face) {
        return res.status(404).json({ status: 'error', message: 'Visage non trouvé' });
    }
    if (!await mayEditFace(req.user, face.name)) {
        return res.status(403).json(FACE_FORBIDDEN);
    }
    const result = await vision.deleteFace(req.params.id);
    if (result.status === 200) {
        console.log(`Visage autorisé supprimé : ${req.params.id}`);
    }
    relay(res, result);
});

// États des appareils (dernier résultat du service de détection)
app.get('/api/v1/devices', async (req, res) => {
    res.status(200).json({ status: 'success', data: await store.devices() });
});

// Tout ce que le dashboard affiche en direct, en une seule requête (alertes récentes, états des
// appareils, stats, identité caméra) : il l'interroge toutes les 0,5 s sans saturer la limite de débit
app.get('/api/v1/overview', async (req, res) => {
    const [alerts, devices, stats, camera] = await Promise.all([
        store.listAlerts({ severities: [], source: '', search: '', since: null }, { offset: 0, limit: 50 }),
        store.devices(),
        store.stats(),
        vision.status()
    ]);
    res.status(200).json({
        status: 'success',
        data: { alerts: alerts.data, devices, stats, camera: camera.status === 200 ? camera.json.data : null }
    });
});

app.get('/api/v1/stats', async (req, res) => {
    res.status(200).json({ status: 'success', data: await store.stats() });
});

// --- Service de détection (backend-iot-alerts) : relayé vers son API ---------------------
// Santé : MQTT, base, modèle, dernière mesure par appareil
app.get('/api/v1/iot/health', allow(...ADMINS), async (req, res) => relay(res, await iot.health()));

// Sessions d'enregistrement étiquetées : jeu d'entraînement du modèle
const RECORDING_LABEL = /^(aucune|presence|fuite_gaz|feu)(\+(presence|fuite_gaz|feu))*$/;
app.get('/api/v1/iot/recording', allow('superadmin'), async (req, res) => relay(res, await iot.recordings()));

app.post('/api/v1/iot/recording/start', allow('superadmin'), async (req, res) => {
    const { device_id: deviceId, label, notes } = req.body || {};
    if (typeof deviceId !== 'string' || !/^[\w.-]{1,64}$/.test(deviceId)) {
        return res.status(400).json({ status: 'error', message: 'device_id invalide' });
    }
    if (typeof label !== 'string' || !RECORDING_LABEL.test(label)) {
        return res.status(400).json({ status: 'error', message: 'label : aucune, presence, fuite_gaz, feu (combinables avec +)' });
    }
    if (notes !== undefined && (typeof notes !== 'string' || notes.length > 500)) {
        return res.status(400).json({ status: 'error', message: 'notes : 500 caractères maximum' });
    }
    relay(res, await iot.startRecording(deviceId, label, notes));
});

app.post('/api/v1/iot/recording/stop', allow('superadmin'), async (req, res) => {
    const { device_id: deviceId } = req.body || {};
    if (deviceId !== undefined && (typeof deviceId !== 'string' || !/^[\w.-]{1,64}$/.test(deviceId))) {
        return res.status(400).json({ status: 'error', message: 'device_id invalide' });
    }
    relay(res, await iot.stopRecording(deviceId));
});

app.post('/api/v1/iot/reload-model', allow('superadmin'), async (req, res) => {
    const result = await iot.reloadModel();
    if (result.status === 200) {
        console.log(`Modèle de détection rechargé par ${sanitizeForLog(req.user.username)}`);
    }
    relay(res, result);
});

app.use((req, res) => {
    res.status(404).json({ status: 'error', message: 'Route non trouvée' });
});

app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') {
        return res.status(413).json({ status: 'error', message: 'Payload trop volumineux' });
    }
    if (err instanceof SyntaxError && err.status === 400) {
        return res.status(400).json({ status: 'error', message: 'JSON invalide dans le corps de la requête' });
    }
    console.error('Erreur serveur:', sanitizeForLog(err.message || err));
    res.status(500).json({ status: 'error', message: 'Erreur interne du serveur' });
});

const gracefulShutdown = (signal) => {
    console.log(`Signal ${signal} reçu, arrêt en cours...`);
    server.close(() => store.close().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10000).unref();
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('uncaughtException', (err) => {
    console.error('Exception non capturée:', err);
    process.exit(1);
});
process.on('unhandledRejection', (reason) => {
    console.error('Promesse rejetée non gérée:', reason);
});

const server = app.listen(PORT, () => {
    console.log(`API Sentinel-X en écoute sur le port ${PORT}`);
});
