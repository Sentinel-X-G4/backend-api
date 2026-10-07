// Client de l'API du service de détection (backend-iot-alerts, port 8000) : santé du service,
// sessions d'enregistrement étiquetées (jeu d'entraînement de l'IA), rechargement du modèle et
// commandes vers les ESP. Le service de détection est le seul à parler MQTT aux appareils ;
// joignable par le réseau Docker sentinel-data, le dashboard passe toujours par ce backend.

const TIMEOUT_MS = 5000;
// Le service attend l'acquittement de l'ESP (5 s) avant de répondre
const COMMAND_TIMEOUT_MS = 10000;

const createIot = (baseUrl, adminToken) => {
    const enabled = Boolean(baseUrl);

    const call = async (path, { method = 'GET', body, admin = false, timeoutMs = TIMEOUT_MS } = {}) => {
        if (!enabled) {
            return { status: 503, json: { status: 'error', message: 'Service de détection non configuré (DETECTION_API_URL)' } };
        }
        let res;
        try {
            res = await fetch(baseUrl + path, {
                method,
                headers: {
                    ...(body && { 'Content-Type': 'application/json' }),
                    ...(admin && adminToken && { Authorization: `Bearer ${adminToken}` })
                },
                body: body && JSON.stringify(body),
                signal: AbortSignal.timeout(timeoutMs)
            });
        } catch {
            return { status: 503, json: { status: 'error', message: 'Service de détection injoignable' } };
        }
        const json = await res.json().catch(() => null);
        if (!res.ok) {
            // FastAPI : { detail } ; 401 = jeton admin mal configuré, pas une erreur du client
            const detail = typeof json?.detail === 'string' ? json.detail : `Erreur ${res.status} du service de détection`;
            return { status: res.status === 401 ? 502 : res.status, json: { status: 'error', message: detail } };
        }
        return { status: res.status, json: { status: 'success', data: json } };
    };

    return {
        enabled,
        health: () => call('/health'),
        recordings: () => call('/recording'),
        startRecording: (deviceId, label, notes) =>
            call('/recording/start', { method: 'POST', body: { device_id: deviceId, label, ...(notes && { notes }) } }),
        stopRecording: (deviceId) => call('/recording/stop', { method: 'POST', body: deviceId ? { device_id: deviceId } : {} }),
        reloadModel: () => call('/admin/reload-model', { method: 'POST', admin: true }),
        // name : alert | buzzer | led | screen | reset ; data = { command, state: { alert, buzzer, led, screen } }
        command: (deviceId, name, body) => call(`/devices/${encodeURIComponent(deviceId)}/${name}`,
            { method: 'POST', body: body || {}, admin: true, timeoutMs: COMMAND_TIMEOUT_MS })
    };
};

module.exports = { createIot };
