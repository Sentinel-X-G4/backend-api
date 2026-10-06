// ============================================
// Pont MQTT -> API : alertes et états des appareils Sentinel-X
// ============================================
// S'abonne (MQTTS + compte iot-backend) à :
//   sentinelx/+/detection : résultats du service de détection (statut, alertes, métriques)
//   sentinelx/+/alert     : alertes brutes de l'ESP, ex. {"type":"pir","value":true}
// Une alerte n'est créée qu'à l'activation (pas à chaque heartbeat). Chaque résultat
// de détection est aussi diffusé tel quel en WebSocket (événement "device_status").
// Désactivé si MQTT_URL n'est pas défini (lancement autonome de l'API).

const fs = require('fs');
const mqtt = require('mqtt');

const DETECTION_TOPIC = 'sentinelx/+/detection';
const ESP_ALERT_TOPIC = 'sentinelx/+/alert';

const DEVICE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const SEVERITY = { feu: 'critical', fuite_gaz: 'critical', presence: 'high' };
const TITLES = { feu: 'Incendie détecté', fuite_gaz: 'Fuite de gaz détectée', presence: 'Présence détectée' };

function startMqttBridge({ ingestAlert, io, devices }) {
    const url = process.env.MQTT_URL;
    if (!url) {
        console.warn('⚠️  MQTT_URL non défini : pont MQTT désactivé');
        return null;
    }

    const client = mqtt.connect(url, {
        username: process.env.MQTT_USERNAME,
        password: process.env.MQTT_PASSWORD,
        ca: process.env.MQTT_CA_FILE ? fs.readFileSync(process.env.MQTT_CA_FILE) : undefined,
        rejectUnauthorized: true,
        clientId: `backend-api-${process.pid}`,
        reconnectPeriod: 2000
    });

    client.on('connect', () => {
        console.log(`📡 MQTT connecté (${url})`);
        client.subscribe([DETECTION_TOPIC, ESP_ALERT_TOPIC], { qos: 1 }, (err) => {
            if (err) console.error('❌ Abonnement MQTT refusé:', err.message);
        });
    });
    client.on('error', (err) => console.error('❌ MQTT:', err.message));
    client.on('offline', () => console.warn('⚠️  MQTT hors ligne, reconnexion...'));

    client.on('message', (topic, message) => {
        const [, deviceId, kind] = topic.split('/');
        let payload;
        try {
            payload = JSON.parse(message.toString());
        } catch {
            console.warn(`❌ JSON invalide sur ${topic}`);
            return;
        }
        if (!DEVICE_ID.test(deviceId) || !payload || typeof payload !== 'object' || Array.isArray(payload)) {
            console.warn(`❌ Message ignoré sur ${topic}`);
            return;
        }
        if (kind === 'detection') onDetection(deviceId, payload);
        else if (kind === 'alert') onEspAlert(deviceId, payload);
    });

    function onDetection(deviceId, payload) {
        const previous = devices.get(deviceId);
        devices.set(deviceId, payload);
        io.emit('device_status', payload);

        const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
        const wasActive = new Set((previous?.alerts || []).filter(a => a.active).map(a => a.type));
        for (const alert of alerts) {
            if (!alert || !alert.active || typeof alert.type !== 'string' || wasActive.has(alert.type)) continue;
            const confidence = Number.isFinite(alert.confidence) ? Math.round(alert.confidence * 100) : '?';
            ingestAlert({
                title: `${TITLES[alert.type] || alert.type} (${deviceId})`,
                severity: SEVERITY[alert.type] || 'medium',
                source: `detection-service/${deviceId}`,
                description: `Confiance ${confidence} %, origine : ${alert.source === 'rule' ? 'règle de sécurité' : 'modèle'}`,
                metadata: { device_id: deviceId, type: alert.type, since: alert.since,
                            model_version: payload.model_version, metrics: payload.metrics }
            });
        }
    }

    function onEspAlert(deviceId, payload) {
        if (typeof payload.type !== 'string' || !payload.type || payload.value === false) return;
        ingestAlert({
            title: `Alerte capteur ${payload.type} (${deviceId})`,
            severity: 'medium',
            source: `esp/${deviceId}`,
            // Champs choisis un par un : le contenu du message ne doit pas écraser device_id
            metadata: { device_id: deviceId, type: payload.type.slice(0, 64), value: typeof payload.value === 'object' ? null : payload.value }
        });
    }

    return client;
}

module.exports = { startMqttBridge };
