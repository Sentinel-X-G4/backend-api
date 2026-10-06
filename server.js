const express = require('express');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');
const helmet = require('helmet');
const { Server } = require('socket.io');
const { rateLimit } = require('express-rate-limit');
const { startMqttBridge } = require('./mqtt-bridge');

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

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest();
const isAuthorized = (token) =>
    !API_KEY || (typeof token === 'string' && crypto.timingSafeEqual(sha256(token), sha256(API_KEY)));

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: allowedOrigins, methods: ['GET', 'POST'] },
    maxHttpBufferSize: 10000
});

// Un seul reverse proxy (nginx) devant l'API : nécessaire pour l'IP réelle du client (rate limit, logs)
app.set('trust proxy', 1);
app.disable('x-powered-by');

const alertsStore = [];
const MAX_ALERTS = 1000;
// Dernier résultat du service de détection par appareil (reçu en MQTT)
const devicesState = new Map();

const tooMany = (req, res) => res.status(429).json({ status: 'error', message: 'Trop de requêtes. Réessayez plus tard.' });
const limiterOptions = { standardHeaders: 'draft-8', legacyHeaders: false, handler: tooMany };

app.use(helmet());
app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Health check (sonde Docker) : public, sans donnée métier
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'OK', uptime: process.uptime() });
});

app.use(rateLimit({ ...limiterOptions, windowMs: 15 * 60 * 1000, limit: 600 }));
app.use(express.json({ limit: '10kb' }));

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

app.use('/api/v1', authFailureLimiter, (req, res, next) => {
    const [scheme, token] = (req.headers.authorization || '').split(' ');
    if (scheme === 'Bearer' && isAuthorized(token)) {
        return next();
    }
    console.warn(`[SÉCURITÉ] Accès refusé (ip=${req.ip})`);
    res.status(401).json({ status: 'error', message: 'Authentification requise' });
});

// Création, stockage et diffusion d'une alerte (appelée par le pont MQTT, données déjà bornées)
function ingestAlert({ title, severity, source, description = '', metadata = {} }) {
    const newAlert = {
        id: crypto.randomUUID(),
        title: String(title).slice(0, 200),
        severity,
        source: String(source).slice(0, 100),
        description: String(description).slice(0, 2000),
        metadata,
        timestamp: new Date().toISOString(),
        acknowledged: false
    };

    alertsStore.unshift(newAlert);
    if (alertsStore.length > MAX_ALERTS) {
        alertsStore.pop();
    }

    console.log(`Nouvelle alerte [${newAlert.severity.toUpperCase()}] :`, sanitizeForLog(newAlert.title));
    io.emit('new_alert', newAlert);
    return newAlert;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const computeStats = () => {
    const stats = {
        total: alertsStore.length,
        acknowledged: 0,
        unacknowledged: 0,
        bySeverity: Object.fromEntries(SEVERITIES.map(s => [s, 0])),
        bySource: {}
    };
    for (const alert of alertsStore) {
        stats[alert.acknowledged ? 'acknowledged' : 'unacknowledged']++;
        stats.bySeverity[alert.severity]++;
        stats.bySource[alert.source] = (stats.bySource[alert.source] || 0) + 1;
    }
    return stats;
};

// Un paramètre répété (?a=1&a=2) arrive sous forme de tableau : on ne garde que les chaînes
const queryString = (value) => (typeof value === 'string' ? value : '');

app.get('/api/v1/alerts', (req, res) => {
    const severities = queryString(req.query.severity).split(',').filter(Boolean);
    const source = queryString(req.query.source).toLowerCase();
    const search = queryString(req.query.search).toLowerCase();
    const since = new Date(queryString(req.query.since));

    const filtered = alertsStore.filter(a =>
        (severities.length === 0 || severities.includes(a.severity)) &&
        (!source || a.source.toLowerCase().includes(source)) &&
        (isNaN(since.getTime()) || new Date(a.timestamp) >= since) &&
        (!search || [a.title, a.description, a.source].some(f => f.toLowerCase().includes(search)))
    );

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));

    res.status(200).json({
        status: 'success',
        data: filtered.slice((page - 1) * limit, page * limit),
        pagination: { page, limit, total: filtered.length, totalPages: Math.ceil(filtered.length / limit) }
    });
});

app.get('/api/v1/alerts/:id', (req, res) => {
    const alert = alertsStore.find(a => a.id === req.params.id);
    if (!alert) {
        return res.status(404).json({ status: 'error', message: 'Alerte non trouvée' });
    }
    res.status(200).json({ status: 'success', data: alert });
});

app.patch('/api/v1/alerts/:id/acknowledge', (req, res) => {
    const alert = alertsStore.find(a => a.id === req.params.id);
    if (!alert) {
        return res.status(404).json({ status: 'error', message: 'Alerte non trouvée' });
    }

    const { acknowledgedBy } = req.body || {};
    if (acknowledgedBy !== undefined && (typeof acknowledgedBy !== 'string' || acknowledgedBy.trim().length === 0 || acknowledgedBy.trim().length > 100)) {
        return res.status(400).json({
            status: 'error',
            message: 'Le champ "acknowledgedBy" doit être une chaîne de 1 à 100 caractères'
        });
    }

    alert.acknowledged = true;
    alert.acknowledgedAt = new Date().toISOString();
    alert.acknowledgedBy = acknowledgedBy ? acknowledgedBy.trim() : 'unknown';

    io.emit('alert_acknowledged', alert);
    res.status(200).json({ status: 'success', message: 'Alerte acquittée', data: alert });
});

// États des appareils (dernier résultat de détection reçu en MQTT)
app.get('/api/v1/devices', (req, res) => {
    res.status(200).json({ status: 'success', data: Object.fromEntries(devicesState) });
});

app.get('/api/v1/stats', (req, res) => {
    res.status(200).json({ status: 'success', data: computeStats() });
});

// WebSocket : même clé que l'API REST, passée par le client (io({ auth: { token } }))
io.use((socket, next) => {
    if (isAuthorized(socket.handshake.auth?.token)) {
        return next();
    }
    console.warn(`[SÉCURITÉ] WebSocket refusé (ip=${socket.handshake.address})`);
    next(new Error('Authentification requise'));
});

io.on('connection', (socket) => {
    console.log(`Client WebSocket connecté: ${socket.id}`);
    socket.emit('init_alerts', alertsStore.slice(0, 50));
    socket.emit('init_devices', Object.fromEntries(devicesState));

    socket.on('disconnect', (reason) => {
        console.log(`Client WebSocket déconnecté: ${socket.id} (${reason})`);
    });
});

app.use((req, res) => {
    res.status(404).json({ status: 'error', message: 'Route non trouvée' });
});

app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') {
        return res.status(413).json({ status: 'error', message: 'Payload trop volumineux (max 10 Ko)' });
    }
    if (err instanceof SyntaxError && err.status === 400) {
        return res.status(400).json({ status: 'error', message: 'JSON invalide dans le corps de la requête' });
    }
    console.error('Erreur serveur:', sanitizeForLog(err.message || err));
    res.status(500).json({ status: 'error', message: 'Erreur interne du serveur' });
});

// Pont MQTT (alertes du service de détection et de l'ESP)
const mqttClient = startMqttBridge({ ingestAlert, io, devices: devicesState });

const gracefulShutdown = (signal) => {
    console.log(`Signal ${signal} reçu, arrêt en cours...`);
    if (mqttClient) mqttClient.end();
    io.close();
    server.close(() => process.exit(0));
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

server.listen(PORT, () => {
    console.log(`API Sentinel-X en écoute sur le port ${PORT}`);
});
