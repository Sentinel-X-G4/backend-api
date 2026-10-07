// Client de l'API interne du détecteur (human-detection-ia, port 8090) : visages autorisés
// et état d'identité de la caméra. Le détecteur n'est joignable que depuis le réseau Docker
// sentinel-vision ; le dashboard passe toujours par ce backend (même clé, même rate limit).

const TIMEOUT_MS = 10000;
const MAX_FRAME_BYTES = 2 * 1024 * 1024;

// Flux annoté du détecteur (MJPEG, port 8089, réseau sentinel-vision) : VISION_PREVIEW_URL,
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

// Découpe un flux multipart/x-mixed-replace en images JPEG (chaque partie porte Content-Length)
async function readMjpeg(body, onFrame, signal) {
    const reader = body.getReader();
    let buffer = Buffer.alloc(0);
    while (!signal.aborted) {
        const { done, value } = await reader.read();
        if (done) return;
        buffer = Buffer.concat([buffer, Buffer.from(value)]);
        for (;;) {
            const headerEnd = buffer.indexOf('\r\n\r\n');
            if (headerEnd < 0) break;
            const match = /Content-Length:\s*(\d+)/i.exec(buffer.subarray(0, headerEnd).toString('latin1'));
            if (!match) {
                buffer = buffer.subarray(headerEnd + 4);
                continue;
            }
            const length = Number(match[1]);
            if (length > MAX_FRAME_BYTES) throw new Error('image trop volumineuse');
            const start = headerEnd + 4;
            if (buffer.length < start + length) break;
            onFrame(Buffer.from(buffer.subarray(start, start + length)));
            buffer = buffer.subarray(start + length);
        }
        if (buffer.length > MAX_FRAME_BYTES * 2) buffer = Buffer.alloc(0);
    }
}

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

    // Image en direct de la webcam : un seul flux ouvert vers le détecteur tant que quelqu'un
    // regarde, images limitées à maxFps, reconnexion avec backoff. Renvoie la fonction d'arrêt.
    const stream = (onFrame, maxFps = 8) => {
        if (!previewUrl) {
            return () => {};
        }
        const controller = new AbortController();
        const minGap = 1000 / maxFps;
        let lastSent = 0;
        let delay = 1000;
        const run = async () => {
            while (!controller.signal.aborted) {
                try {
                    const res = await fetch(`${previewUrl}/stream`, { signal: controller.signal });
                    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
                    delay = 1000;
                    await readMjpeg(res.body, (jpeg) => {
                        const now = Date.now();
                        if (now - lastSent >= minGap) {
                            lastSent = now;
                            onFrame(jpeg);
                        }
                    }, controller.signal);
                } catch {
                    // flux coupé ou détecteur absent : on réessaie
                }
                if (controller.signal.aborted) return;
                await new Promise((resolve) => setTimeout(resolve, delay).unref());
                delay = Math.min(delay * 2, 15000);
            }
        };
        run();
        return () => controller.abort();
    };

    return {
        enabled,
        streaming: Boolean(previewUrl),
        stream,
        status: () => call('/status'),
        listFaces: () => call('/faces'),
        addFace: (name, image) => call('/faces', { method: 'POST', body: { name, ...(image && { image }) } }),
        faceImage: (id) => call(`/faces/${id}/image`),
        deleteFace: (id) => call(`/faces/${id}`, { method: 'DELETE' }),
        watch
    };
};

module.exports = { createVision };
