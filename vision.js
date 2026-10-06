// Client de l'API interne du détecteur (human-detection-ia, port 8090) : visages autorisés
// et état d'identité de la caméra. Le détecteur n'est joignable que depuis le réseau Docker
// sentinel-vision ; le dashboard passe toujours par ce backend (même clé, même rate limit).

const TIMEOUT_MS = 10000;

const createVision = (baseUrl, apiKey) => {
    const enabled = Boolean(baseUrl);

    const call = async (path, { method = 'GET', body } = {}) => {
        if (!enabled) {
            return { status: 503, json: { status: 'error', message: 'Reconnaissance faciale non configurée (VISION_API_URL)' } };
        }
        let res;
        try {
            res = await fetch(baseUrl + path, {
                method,
                headers: {
                    ...(body && { 'Content-Type': 'application/json' }),
                    ...(apiKey && { Authorization: `Bearer ${apiKey}` })
                },
                body: body && JSON.stringify(body),
                signal: AbortSignal.timeout(TIMEOUT_MS)
            });
        } catch {
            return { status: 503, json: { status: 'error', message: 'Détecteur caméra injoignable' } };
        }
        if ((res.headers.get('content-type') || '').startsWith('image/')) {
            return { status: res.status, image: Buffer.from(await res.arrayBuffer()) };
        }
        const json = await res.json().catch(() => ({ status: 'error', message: 'Réponse invalide du détecteur' }));
        // 401 du détecteur = clé partagée mal configurée : pas une erreur d'authentification du client
        return { status: res.status === 401 ? 502 : res.status, json };
    };

    // Relaie les changements d'identité (none / authorized / unknown) en temps réel
    const watch = (onChange, intervalMs = 1000) => {
        if (!enabled) {
            return () => {};
        }
        let last = null;
        const timer = setInterval(async () => {
            const { status, json } = await call('/status');
            if (status !== 200) {
                return;
            }
            const { identity, names } = json.data;
            const key = JSON.stringify([identity, names]);
            if (key !== last) {
                last = key;
                onChange(json.data);
            }
        }, intervalMs);
        timer.unref();
        return () => clearInterval(timer);
    };

    return {
        enabled,
        status: () => call('/status'),
        listFaces: () => call('/faces'),
        addFace: (name, image) => call('/faces', { method: 'POST', body: { name, ...(image && { image }) } }),
        faceImage: (id) => call(`/faces/${id}/image`),
        deleteFace: (id) => call(`/faces/${id}`, { method: 'DELETE' }),
        watch
    };
};

module.exports = { createVision };
