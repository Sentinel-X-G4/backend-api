const express = require('express');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');
const helmet = require('helmet');
const { Server } = require('socket.io');
const { rateLimit } = require('express-rate-limit');
const { createStore } = require('./db');

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
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: allowedOrigins, methods: ['GET', 'POST'] },
    maxHttpBufferSize: 10000
});

// Un seul reverse proxy (nginx) devant l'API : nécessaire pour l'IP réelle du client (rate limit, logs)
app.set('trust proxy', 1);
app.disable('x-powered-by');

const store = createStore(process.env.DATABASE_URL);

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

app.patch('/api/v1/alerts/:id/acknowledge', async (req, res) => {
    const { acknowledgedBy } = req.body || {};
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

    io.emit('alert_acknowledged', alert);
    res.status(200).json({ status: 'success', message: 'Alerte acquittée', data: alert });
});

// États des appareils (dernier résultat du service de détection)
app.get('/api/v1/devices', async (req, res) => {
    res.status(200).json({ status: 'success', data: await store.devices() });
});

app.get('/api/v1/stats', async (req, res) => {
    res.status(200).json({ status: 'success', data: await store.stats() });
});

// WebSocket : même clé que l'API REST, passée par le client (io({ auth: { token } }))
io.use((socket, next) => {
    if (isAuthorized(socket.handshake.auth?.token)) {
        return next();
    }
    console.warn(`[SÉCURITÉ] WebSocket refusé (ip=${socket.handshake.address})`);
    next(new Error('Authentification requise'));
});

io.on('connection', async (socket) => {
    console.log(`Client WebSocket connecté: ${socket.id}`);
    try {
        socket.emit('init_alerts', await store.recentAlerts(50));
        socket.emit('init_devices', await store.devices());
    } catch (err) {
        console.error('❌ État initial indisponible:', sanitizeForLog(err.message));
    }

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

// Temps réel : nouvelles alertes et états d'appareils écrits en base par le service de détection
const stopListening = store.listen({
    onAlert: (alert) => {
        console.log(`Nouvelle alerte [${alert.severity.toUpperCase()}] :`, sanitizeForLog(alert.title));
        io.emit('new_alert', alert);
    },
    onDevice: (device) => io.emit('device_status', device)
});

const gracefulShutdown = (signal) => {
    console.log(`Signal ${signal} reçu, arrêt en cours...`);
    io.close();
    server.close(() => Promise.all([stopListening(), store.close()]).finally(() => process.exit(0)));
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
