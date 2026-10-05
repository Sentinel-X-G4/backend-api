const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');

// Chargement des variables d'environnement
dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL || '*',
        methods: ['GET', 'POST']
    }
});

const PORT = process.env.PORT || 3000;

// Stockage en mémoire des alertes (remplacer par une DB en production)
const alertsStore = [];
const MAX_ALERTS = 1000;

// Middlewares
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Logger de requêtes simple
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// Route de diagnostic simple
app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        message: 'Backend API Sentinel-X Opérationnel',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        alertsCount: alertsStore.length
    });
});

// Validation d'une alerte
function validateAlert(alert) {
    const errors = [];
    
    if (!alert) {
        errors.push('Corps de la requête manquant');
        return errors;
    }
    
    if (!alert.title || typeof alert.title !== 'string' || alert.title.trim().length === 0) {
        errors.push('Le champ "title" est requis et doit être une chaîne non vide');
    }
    
    if (!alert.severity || !['low', 'medium', 'high', 'critical'].includes(alert.severity)) {
        errors.push('Le champ "severity" est requis et doit être: low, medium, high ou critical');
    }
    
    if (!alert.source || typeof alert.source !== 'string' || alert.source.trim().length === 0) {
        errors.push('Le champ "source" est requis et doit être une chaîne non vide');
    }
    
    if (alert.description && typeof alert.description !== 'string') {
        errors.push('Le champ "description" doit être une chaîne de caractères');
    }
    
    if (alert.metadata && typeof alert.metadata !== 'object') {
        errors.push('Le champ "metadata" doit être un objet');
    }
    
    return errors;
}

// Endpoint pour recevoir les alertes
app.post('/api/v1/alerts', (req, res) => {
    const alertPayload = req.body;
    
    // Validation
    const validationErrors = validateAlert(alertPayload);
    if (validationErrors.length > 0) {
        console.warn('❌ Alerte invalide reçue:', validationErrors);
        return res.status(400).json({
            status: 'error',
            message: 'Données d\'alerte invalides',
            errors: validationErrors
        });
    }
    
    // Création de l'alerte enrichie
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
    
    // Stockage (avec limite pour éviter les fuites mémoire)
    alertsStore.unshift(newAlert);
    if (alertsStore.length > MAX_ALERTS) {
        alertsStore.pop();
    }
    
    console.log(`🚨 Nouvelle alerte [${newAlert.severity.toUpperCase()}] :`, newAlert.title);
    
    // Émission WebSocket vers tous les clients connectés
    io.emit('new_alert', newAlert);
    
    // Émission spécifique selon la sévérité
    io.emit(`alert_${newAlert.severity}`, newAlert);
    
    res.status(201).json({ 
        status: 'success', 
        message: 'Alerte ingérée avec succès par l\'API',
        alert: newAlert
    });
});

// Endpoint pour récupérer les alertes (avec filtres)
app.get('/api/v1/alerts', (req, res) => {
    try {
        let filteredAlerts = [...alertsStore];
        
        // Filtre par sévérité
        if (req.query.severity) {
            const severities = req.query.severity.split(',');
            filteredAlerts = filteredAlerts.filter(a => severities.includes(a.severity));
        }
        
        // Filtre par source
        if (req.query.source) {
            filteredAlerts = filteredAlerts.filter(a => 
                a.source.toLowerCase().includes(req.query.source.toLowerCase())
            );
        }
        
        // Filtre par date (depuis)
        if (req.query.since) {
            const sinceDate = new Date(req.query.since);
            if (!isNaN(sinceDate.getTime())) {
                filteredAlerts = filteredAlerts.filter(a => new Date(a.timestamp) >= sinceDate);
            }
        }
        
        // Recherche textuelle
        if (req.query.search) {
            const searchTerm = req.query.search.toLowerCase();
            filteredAlerts = filteredAlerts.filter(a => 
                a.title.toLowerCase().includes(searchTerm) ||
                a.description.toLowerCase().includes(searchTerm) ||
                a.source.toLowerCase().includes(searchTerm)
            );
        }
        
        // Pagination
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
        res.status(500).json({
            status: 'error',
            message: 'Erreur interne du serveur'
        });
    }
});

// Endpoint pour récupérer une alerte spécifique
app.get('/api/v1/alerts/:id', (req, res) => {
    const alert = alertsStore.find(a => a.id === req.params.id);
    
    if (!alert) {
        return res.status(404).json({
            status: 'error',
            message: 'Alerte non trouvée'
        });
    }
    
    res.status(200).json({
        status: 'success',
        data: alert
    });
});

// Endpoint pour acquitter une alerte
app.patch('/api/v1/alerts/:id/acknowledge', (req, res) => {
    const alertIndex = alertsStore.findIndex(a => a.id === req.params.id);
    
    if (alertIndex === -1) {
        return res.status(404).json({
            status: 'error',
            message: 'Alerte non trouvée'
        });
    }
    
    alertsStore[alertIndex].acknowledged = true;
    alertsStore[alertIndex].acknowledgedAt = new Date().toISOString();
    alertsStore[alertIndex].acknowledgedBy = req.body.acknowledgedBy || 'unknown';
    
    // Émission WebSocket de la mise à jour
    io.emit('alert_acknowledged', alertsStore[alertIndex]);
    
    res.status(200).json({
        status: 'success',
        message: 'Alerte acquittée',
        data: alertsStore[alertIndex]
    });
});

// Endpoint pour les statistiques
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
    
    // Compter par source
    alertsStore.forEach(alert => {
        stats.bySource[alert.source] = (stats.bySource[alert.source] || 0) + 1;
    });
    
    res.status(200).json({
        status: 'success',
        data: stats
    });
});

// Gestion des connexions WebSocket
io.on('connection', (socket) => {
    console.log(`🔌 Client WebSocket connecté: ${socket.id}`);
    
    // Envoi des alertes récentes à la connexion
    socket.emit('init_alerts', alertsStore.slice(0, 50));
    
    // Demande de statistiques
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
        console.log(`🔌 Client WebSocket déconnecté: ${socket.id} (${reason})`);
    });
    
    socket.on('error', (error) => {
        console.error(`❌ Erreur WebSocket ${socket.id}:`, error);
    });
});

// Middleware de gestion d'erreurs 404
app.use((req, res) => {
    res.status(404).json({
        status: 'error',
        message: `Route ${req.method} ${req.path} non trouvée`
    });
});

// Middleware de gestion d'erreurs global
app.use((err, req, res, next) => {
    console.error('❌ Erreur serveur:', err);
    
    // Erreur de parsing JSON
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({
            status: 'error',
            message: 'JSON invalide dans le corps de la requête'
        });
    }
    
    res.status(500).json({
        status: 'error',
        message: 'Erreur interne du serveur',
        ...(process.env.NODE_ENV === 'development' && { details: err.message })
    });
});

// Gestion propre de l'arrêt
const gracefulShutdown = (signal) => {
    console.log(`\n📴 Signal ${signal} reçu, arrêt en cours...`);
    
    // Fermer les connexions WebSocket
    io.close(() => {
        console.log('🔌 Connexions WebSocket fermées');
    });
    
    // Fermer le serveur HTTP
    server.close(() => {
        console.log('🌐 Serveur HTTP fermé');
        process.exit(0);
    });
    
    // Forcer l'arrêt après 10 secondes
    setTimeout(() => {
        console.error('⏱️ Arrêt forcé après timeout');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Gestion des erreurs non capturées
process.on('uncaughtException', (err) => {
    console.error('❌ Exception non capturée:', err);
    gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Promesse rejetée non gérée:', reason);
});

// Lancement du serveur
server.listen(PORT, () => {
    console.log(`\n╔══════════════════════════════════════════╗`);
    console.log(`║  🛡️  Sentinel-X Backend API v1.0.0      ║`);
    console.log(`╠══════════════════════════════════════════╣`);
    console.log(`║  🌐 Serveur HTTP:  http://localhost:${PORT}    ║`);
    console.log(`║  🔌 WebSocket:     ws://localhost:${PORT}    ║`);
    console.log(`║  📡 Health check:  GET /api/health      ║`);
    console.log(`║  🚨 Alertes:       POST /api/v1/alerts  ║`);
    console.log(`║  📊 Stats:         GET /api/v1/stats    ║`);
    console.log(`╚══════════════════════════════════════════╝\n`);
});
