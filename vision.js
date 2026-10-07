// Client de l'API interne du détecteur (human-detection-ia, port 8090) : visages autorisés
// et état d'identité de la caméra. Le détecteur n'est joignable que depuis le réseau Docker
// sentinel-vision ; le dashboard passe toujours par ce backend (même clé, même rate limit).

const TIMEOUT_MS = 10000;
// Image annotée du détecteur (port 8089, réseau sentinel-vision) : VISION_PREVIEW_URL,
// sinon même hôte que l'API interne sur le port 8089
const previewFrom = (baseUrl) => {
    try {
        const url = new URL(baseUrl);
        url.port = '8089';
        return url.origin;
    } catch {
        return null;
    }
};

const createVision = (baseUrl, apiKey, previewUrl = baseUrl && previewFrom(baseUrl)) => {
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

    // Dernière image de la webcam (JPEG)
    const snapshot = async () => {
        if (!previewUrl) {
            return { status: 503, json: { status: 'error', message: 'Flux caméra non configuré (VISION_API_URL)' } };
        }
        try {
            const res = await fetch(`${previewUrl}/snapshot`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
            if (!res.ok) {
                return { status: 503, json: { status: 'error', message: 'Aucune image de la caméra pour le moment' } };
            }
            return { status: 200, image: Buffer.from(await res.arrayBuffer()) };
        } catch {
            return { status: 503, json: { status: 'error', message: 'Détecteur caméra injoignable' } };
        }
    };

    return {
        enabled,
        status: () => call('/status'),
        listFaces: () => call('/faces'),
        addFace: (name, image) => call('/faces', { method: 'POST', body: { name, ...(image && { image }) } }),
        faceImage: (id) => call(`/faces/${id}/image`),
        deleteFace: (id) => call(`/faces/${id}`, { method: 'DELETE' }),
        snapshot
    };
};

module.exports = { createVision };
