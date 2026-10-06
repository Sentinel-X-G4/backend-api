const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

dotenv.config();

const isProduction = process.env.NODE_ENV === 'production';

const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173').split(',').map(u => u.trim()).filter(Boolean);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ['GET', 'POST', 'PATCH'],
        credentials: true
    },
    // Durcissement WS : 10 Ko max par message entrant (les clients n'envoient
    // que des événements légers type request_stats)
    maxHttpBufferSize: 10000
});

const PORT = process.env.PORT || 3000;

const trustProxyEnv = process.env.TRUST_PROXY;
let trustProxy = 1;
if (trustProxyEnv === 'false') {
    trustProxy = false;
} else if (trustProxyEnv !== undefined && trustProxyEnv !== 'true') {
    trustProxy = /^\d+$/.test(trustProxyEnv) ? Number(trustProxyEnv) : trustProxyEnv;
}
app.set('trust proxy', trustProxy);

// Ne pas exposer la version de framework (fuite d'information)
app.disable('x-powered-by');

// Stockage en mémoire des alertes (remplacer par une DB en production)
const alertsStore = [];
const MAX_ALERTS = 1000;

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", ...allowedOrigins, "ws:", "wss:"]
        }
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error(`Origine CORS non autorisée : ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

const rateLimitWindowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000;
const globalRateMax = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || (isProduction ? 600 : 1000);
const ingestRateMax = parseInt(process.env.RATE_LIMIT_INGEST_MAX_REQUESTS, 10) || 60;

const rateLimitHandler = (req, res) => {
    res.status(429).json({ status: 'error', message: 'Trop de requêtes. Réessayez plus tard.' });
};

const globalLimiter = rateLimit({
    windowMs: rateLimitWindowMs,
    limit: globalRateMax,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skip: (req) => req.path === '/api/health',
    handler: rateLimitHandler
});

const ingestLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: ingestRateMax,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: rateLimitHandler
});

app.use(globalLimiter);
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));

const setSecureCookie = (res, name, value, options = {}) => {
    res.cookie(name, value, {
        httpOnly: options.httpOnly ?? true,
        secure: isProduction,
        sameSite: isProduction ? 'strict' : 'lax',
        maxAge: options.maxAge || 24 * 60 * 60 * 1000,
        path: '/',
        ...options
    });
};

app.get('/api/v1/csrf-token', (req, res) => {
    let csrfToken = req.cookies['XSRF-TOKEN'];
    if (!csrfToken) {
        csrfToken = crypto.randomBytes(32).toString('hex');
        setSecureCookie(res, 'XSRF-TOKEN', csrfToken, { httpOnly: false });
    }
    res.status(200).json({ status: 'success', csrfToken });
});const timingSafeEquals = (a, b) => {
    const bufA = Buffer.from(String(a), 'utf8');
    const bufB = Buffer.from(String(b), 'utf8');
    if (bufA.length !== bufB.length) {
        return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
};

const verifyCsrfToken = (req, res, next) => {
    if (req.method === 'POST' && req.path === '/alerts') {
        return next();
    }

    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    const apiKey = req.headers['x-api-key'];
    if (apiKey && process.env.API_KEY && timingSafeEquals(apiKey, process.env.API_KEY)) {
        return next();
    }

    const cookieToken = req.cookies['XSRF-TOKEN'];
    const headerToken = req.headers['x-csrf-token'];

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
        return res.status(403).json({
            status: 'error',
            message: 'Token CSRF manquant ou invalide. Requête rejetée.'
        });
    }

    next();
};

app.use('/api/v1', verifyCsrfToken);

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${String(req.path).replace(/[\r\n]+/g, '')}`);
    next();
});

app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        message: 'Backend API Sentinel-X Opérationnel',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        alertsCount: alertsStore.length
    });
});

// Nettoyage des chaînes avant logging (anti log-injection : CR/LF -> espace)
const sanitizeForLog = (value) => String(value).replace(/[\r\n\t]+/g, ' ').slice(0, 300);

// Clés interdites : pollution de prototype / accès protégé
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Validation stricte d'une alerte :
// - whitelist de champs (anti mass-assignment : acknowledged, id, timestamp...)
// - limites de taille sur chaque champ
// - metadata : objet plat à valeurs scalaires uniquement (anti injection / pollution de prototype)
function validateAlert(alert) {
    const errors = [];

    if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
        errors.push('Le corps de la requête doit être un objet JSON');
        return errors;
    }

    const allowedFields = ['title', 'severity', 'source', 'description', 'metadata'];
    const unknownFields = Object.keys(alert).filter((key) => !allowedFields.includes(key));
    if (unknownFields.length > 0) {
        errors.push(`Champs non autorisés : ${unknownFields.join(', ')}`);
    }

    if (!alert.title || typeof alert.title !== 'string' || alert.title.trim().length === 0) {
        errors.push('Le champ "title" est requis et doit être une chaîne non vide');
    } else if (alert.title.length > 200) {
        errors.push('Le champ "title" ne peut pas dépasser 200 caractères');
    }

    if (!alert.severity || !['low', 'medium', 'high', 'critical'].includes(alert.severity)) {
        errors.push('Le champ "severity" est requis et doit être: low, medium, high ou critical');
    }

    if (!alert.source || typeof alert.source !== 'string' || alert.source.trim().length === 0) {
        errors.push('Le champ "source" est requis et doit être une chaîne non vide');
    } else if (alert.source.length > 100) {
        errors.push('Le champ "source" ne peut pas dépasser 100 caractères');
    }

    if (alert.description !== undefined && alert.description !== null) {
        if (typeof alert.description !== 'string') {
            errors.push('Le champ "description" doit être une chaîne de caractères');
        } else if (alert.description.length > 2000) {
            errors.push('Le champ "description" ne peut pas dépasser 2000 caractères');
        }
    }

    if (alert.metadata !== undefined && alert.metadata !== null) {
        if (typeof alert.metadata !== 'object' || Array.isArray(alert.metadata)) {
            errors.push('Le champ "metadata" doit être un objet JSON');
        } else {
            const keys = Object.keys(alert.metadata);
            if (keys.length > 10) {
                errors.push('Le champ "metadata" ne peut pas contenir plus de 10 clés');
            }
            for (const key of keys) {
                if (DANGEROUS_KEYS.has(key)) {
                    errors.push(`Clé interdite dans "metadata" : ${sanitizeForLog(key)}`);
                    continue;
                }
                if (!/^[A-Za-z0-9_.-]{1,64}$/.test(key)) {
                    errors.push(`Clé invalide dans "metadata" : ${sanitizeForLog(key)}`);
                    continue;
                }
                const value = alert.metadata[key];
                const isScalar = value === null || ['string', 'number', 'boolean'].includes(typeof value);
                if (!isScalar) {
                    errors.push(`La valeur de "metadata.${key}" doit être un scalaire (string, number, boolean ou null)`);
                } else if (typeof value === 'string' && value.length > 512) {
                    errors.push(`La valeur de "metadata.${key}" ne peut pas dépasser 512 caractères`);
                } else if (typeof value === 'number' && !Number.isFinite(value)) {
                    errors.push(`La valeur de "metadata.${key}" doit être un nombre fini`);
                }
            }
        }
    }

    return errors;
}

const requireApiKey = (req, res, next) => {
    const provided = req.headers['x-api-key'];
    const expected = process.env.API_KEY;

    if (!expected) {
        if (isProduction) {
            console.error('[SÉCURITÉ] API_KEY absente : ingestion refusée (fail-closed)');
            return res.status(503).json({
                status: 'error',
                message: 'Service d\'ingestion non configuré'
            });
        }
        console.warn('[SÉCURITÉ] API_KEY absente : ingestion ouverte (mode développement uniquement)');
        return next();
    }

    if (!provided || !timingSafeEquals(provided, expected)) {
        console.warn(`[SÉCURITÉ] Ingestion refusée : API key invalide (ip=${req.ip}, ua=${sanitizeForLog(req.headers['user-agent'] || '-')})`);
        return res.status(401).json({
            status: 'error',
            message: 'API key manquante ou invalide'
        });
    }

    next();
};

app.post('/api/v1/alerts', ingestLimiter, requireApiKey, (req, res) => {
    const alertPayload = req.body;

    const validationErrors = validateAlert(alertPayload);
    if (validationErrors.length > 0) {
        console.warn('Alerte invalide reçue:', validationErrors.map(sanitizeForLog));
        return res.status(400).json({
            status: 'error',
            message: 'Données d\'alerte invalides',
            errors: validationErrors
        });
    }

    const newAlert = {
        id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        title: alertPayload.title.trim(),
        severity: alertPayload.severity,
        source: alertPayload.source.trim(),
        description: alertPayload.description?.trim() || '',
        metadata: alertPayload.metadata || {},
        timestamp: new Date().toISOString(),
        acknowledged: false
    };

    alertsStore.unshift(newAlert);
    if (alertsStore.length > MAX_ALERTS) {
        alertsStore.pop();
    }

    console.log(`Nouvelle alerte [${newAlert.severity.toUpperCase()}] :`, sanitizeForLog(newAlert.title));

    io.emit('new_alert', newAlert);
    io.emit(`alert_${newAlert.severity}`, newAlert);

    res.status(201).json({
        status: 'success',
        message: 'Alerte ingérée', 
        alert: newAlert
    });
});

app.get('/api/v1/alerts', (req, res) => {
    try {
        let filteredAlerts = [...alertsStore];

        if (req.query.severity) {
            const severities = req.query.severity.split(',');
            filteredAlerts = filteredAlerts.filter(a => severities.includes(a.severity));
        }

        if (req.query.source) {
            filteredAlerts = filteredAlerts.filter(a =>
                a.source.toLowerCase().includes(req.query.source.toLowerCase())
            );
        }

        if (req.query.since) {
            const sinceDate = new Date(req.query.since);
            if (!isNaN(sinceDate.getTime())) {
                filteredAlerts = filteredAlerts.filter(a => new Date(a.timestamp) >= sinceDate);
            }
        }

        if (req.query.search) {
            const searchTerm = req.query.search.toLowerCase();
            filteredAlerts = filteredAlerts.filter(a =>
                a.title.toLowerCase().includes(searchTerm) ||
                a.description.toLowerCase().includes(searchTerm) ||
                a.source.toLowerCase().includes(searchTerm)
            );
        }

        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;

        const paginatedAlerts = filteredAlerts.slice(startIndex, endIndex);

        res.status(200).json({
            status: 'success',
            data: paginatedAlerts,
            pagination: {
                page,
                limit,
                total: filteredAlerts.length,
                totalPages: Math.ceil(filteredAlerts.length / limit)
            }
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des alertes:', error);
        res.status(500).json({ status: 'error', message: 'Erreur interne du serveur' });
    }
});

app.get('/api/v1/alerts/:id', (req, res) => {
    const alert = alertsStore.find(a => a.id === req.params.id);

    if (!alert) {
        return res.status(404).json({ status: 'error', message: 'Alerte non trouvée' });
    }

    res.status(200).json({ status: 'success', data: alert });
});

app.patch('/api/v1/alerts/:id/acknowledge', (req, res) => {
    const alertIndex = alertsStore.findIndex(a => a.id === req.params.id);

    if (alertIndex === -1) {
        return res.status(404).json({ status: 'error', message: 'Alerte non trouvée' });
    }

    const { acknowledgedBy } = req.body || {};
    if (acknowledgedBy !== undefined && (typeof acknowledgedBy !== 'string' || acknowledgedBy.trim().length === 0 || acknowledgedBy.trim().length > 100)) {
        return res.status(400).json({
            status: 'error',
            message: 'Le champ "acknowledgedBy" doit être une chaîne de 1 à 100 caractères'
        });
    }

    alertsStore[alertIndex].acknowledged = true;
    alertsStore[alertIndex].acknowledgedAt = new Date().toISOString();
    alertsStore[alertIndex].acknowledgedBy = acknowledgedBy ? acknowledgedBy.trim() : 'unknown';

    io.emit('alert_acknowledged', alertsStore[alertIndex]);

    res.status(200).json({
        status: 'success',
        message: 'Alerte acquittée',
        data: alertsStore[alertIndex]
    });
});

app.get('/api/v1/stats', (req, res) => {
    const stats = {
        total: alertsStore.length,
        bySeverity: {
            critical: alertsStore.filter(a => a.severity === 'critical').length,
            high: alertsStore.filter(a => a.severity === 'high').length,
            medium: alertsStore.filter(a => a.severity === 'medium').length,
            low: alertsStore.filter(a => a.severity === 'low').length
        },
        acknowledged: alertsStore.filter(a => a.acknowledged).length,
        unacknowledged: alertsStore.filter(a => !a.acknowledged).length,
        bySource: {}
    };

    alertsStore.forEach(alert => {
        stats.bySource[alert.source] = (stats.bySource[alert.source] || 0) + 1;
    });

    res.status(200).json({ status: 'success', data: stats });
});

io.on('connection', (socket) => {
    console.log(`Client WebSocket connecté: ${socket.id}`);

    socket.emit('init_alerts', alertsStore.slice(0, 50));

    socket.on('request_stats', () => {
        const stats = {
            total: alertsStore.length,
            bySeverity: {
                critical: alertsStore.filter(a => a.severity === 'critical').length,
                high: alertsStore.filter(a => a.severity === 'high').length,
                medium: alertsStore.filter(a => a.severity === 'medium').length,
                low: alertsStore.filter(a => a.severity === 'low').length
            }
        };
        socket.emit('stats_update', stats);
    });

    socket.on('disconnect', (reason) => {
        console.log(`Client WebSocket déconnecté: ${socket.id} (${reason})`);
    });

    socket.on('error', (error) => {
        console.error(`Erreur WebSocket ${socket.id}:`, error);
    });
});

app.use((req, res) => {
    res.status(404).json({ status: 'error', message: `Route ${req.method} ${req.path} non trouvée` });
});

app.use((err, req, res, next) => {
    if (err && typeof err.message === 'string' && err.message.startsWith('Origine CORS non autorisée')) {
        return res.status(403).json({ status: 'error', message: 'Origine non autorisée' });
    }

    if (err && err.type === 'entity.too.large') {
        return res.status(413).json({ status: 'error', message: 'Payload trop voluméux (max 100 Ko)' });
    }

    console.error('Erreur serveur:', sanitizeForLog(err && err.message ? err.message : err));

    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ status: 'error', message: 'JSON invalide dans le corps de la requête' });
    }

    res.status(500).json({
        status: 'error',
        message: 'Erreur interne du serveur',
        ...(process.env.NODE_ENV === 'development' && { details: err.message })
    });
});

const gracefulShutdown = (signal) => {
    console.log(`Signal ${signal} reçu, arrêt en cours...`);
    io.close(() => {
        console.log('Connexions WebSocket fermées');
    });
    server.close(() => {
        console.log('Serveur HTTP fermé');
        process.exit(0);
    });
    setTimeout(() => {
        console.error('Arrêt forcé après timeout');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
    console.error('Exception non capturée:', err);
    gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, _promise) => {
    console.error('Promesse rejetée non gérée:', reason);
});

server.listen(PORT, () => {
    console.log(`Serveur HTTP: http://localhost:${PORT}`);
    console.log(`WebSocket: ws://localhost:${PORT}`);
    console.log(`Health check: GET /api/health`);
    console.log(`Alertes: POST /api/v1/alerts`);
    console.log(`Stats: GET /api/v1/stats`);
});

