// Mots de passe (scrypt) et jetons de session signés (HMAC-SHA256), sans dépendance externe.
const crypto = require('crypto');

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
// Compte sans mot de passe (connexion par visage uniquement) : valeur qu'aucun mot de passe ne vérifie
const NO_PASSWORD = 'none';

function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(password, salt, 64);
    return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
    const [scheme, saltHex, hashHex] = String(stored).split('$');
    if (scheme !== 'scrypt' || !saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
}

// secret : dérivé de l'API_KEY (stable entre redémarrages) ou aléatoire en dev sans clé
function createSessions(secret) {
    const key = crypto.createHash('sha256').update(`sentinel-session:${secret || crypto.randomBytes(32).toString('hex')}`).digest();
    const sign = (body) => crypto.createHmac('sha256', key).update(body).digest('base64url');

    return {
        issue(user) {
            const body = Buffer.from(JSON.stringify({ u: user.username, r: user.role, exp: Date.now() + SESSION_TTL_MS })).toString('base64url');
            return `${body}.${sign(body)}`;
        },
        // -> { username, role } ou null
        verify(token) {
            if (typeof token !== 'string') return null;
            const [body, signature] = token.split('.');
            if (!body || !signature) return null;
            const expected = Buffer.from(sign(body));
            const received = Buffer.from(signature);
            if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) return null;
            try {
                const { u, r, exp } = JSON.parse(Buffer.from(body, 'base64url').toString());
                return exp > Date.now() ? { username: u, role: r } : null;
            } catch {
                return null;
            }
        }
    };
}

module.exports = { NO_PASSWORD, hashPassword, verifyPassword, createSessions };
