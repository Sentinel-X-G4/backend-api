// ============================================
// Accès à la base Sentinel-X (dépôt database : PostgreSQL / TimescaleDB)
// ============================================
// L'API ne parle pas à MQTT : le service de détection (backend-iot-alerts) écoute le broker
// et écrit en base ; l'API lit, acquitte, et relaie le temps réel en WebSocket.
//   public.alerts          alertes (écrites par le service de détection)
//   detection.predictions  dernier état de chaque appareil
//   users                  comptes du dashboard (superadmin, admin, user)
// Temps réel : triggers NOTIFY de database (db/init/03_notify.sql), canaux
// « sentinel_alerts » (payload = id) et « sentinel_devices » (payload = device_id).
// Le schéma est créé par database (db/init/) : l'API ne crée aucune table.

const { Client, Pool } = require('pg');

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CHANNELS = { alerts: 'sentinel_alerts', devices: 'sentinel_devices' };

const ALERT_COLUMNS = 'id, time, source, severity, title, description, metadata, acknowledged, acknowledged_at, acknowledged_by';
const DEVICE_COLUMNS = 'device_id, window_end, status, device_state, reason, alerts, metrics, model_version';

const toAlert = (row) => ({
    id: row.id,
    title: row.title,
    severity: row.severity,
    source: row.source,
    description: row.description,
    metadata: row.metadata,
    timestamp: row.time.toISOString(),
    acknowledged: row.acknowledged,
    ...(row.acknowledged_at && { acknowledgedAt: row.acknowledged_at.toISOString() }),
    ...(row.acknowledged_by && { acknowledgedBy: row.acknowledged_by })
});

// Même forme que le résultat publié par le service de détection (docs/BACKEND_CONTRACT.md)
const toDevice = (row) => ({
    device_id: row.device_id,
    timestamp: row.window_end.toISOString(),
    status: row.status,
    device_state: row.device_state,
    reason: row.reason,
    alerts: row.alerts,
    metrics: row.metrics,
    model_version: row.model_version
});

const USER_COLUMNS = 'id, username, role';
const toUser = (row) => ({ id: row.id, username: row.username, role: row.role === 'viewer' ? 'user' : row.role });

// Filtres de GET /api/v1/alerts : sous-chaînes insensibles à la casse, sans motif LIKE
function whereClause({ severities, source, search, since }) {
    const params = [];
    const conds = [];
    const p = (value) => { params.push(value); return `$${params.length}`; };
    if (severities.length) conds.push(`severity = ANY(${p(severities)})`);
    if (source) conds.push(`strpos(lower(source), ${p(source)}) > 0`);
    if (since) conds.push(`time >= ${p(since)}`);
    if (search) {
        const s = p(search);
        conds.push(`(strpos(lower(title), ${s}) > 0 OR strpos(lower(description), ${s}) > 0 OR strpos(lower(source), ${s}) > 0)`);
    }
    return { where: conds.length ? `WHERE ${conds.join(' AND ')}` : '', params };
}

function createStore(connectionString) {
    const pool = new Pool({ connectionString, max: 5 });
    pool.on('error', (err) => console.error('❌ PostgreSQL:', err.message));

    const getAlert = async (id) => {
        if (!UUID.test(id)) return null;
        const { rows } = await pool.query(`SELECT ${ALERT_COLUMNS} FROM alerts WHERE id = $1`, [id]);
        return rows[0] ? toAlert(rows[0]) : null;
    };

    const getDevice = async (deviceId) => {
        const { rows } = await pool.query(
            `SELECT ${DEVICE_COLUMNS} FROM detection.predictions WHERE device_id = $1 ORDER BY window_end DESC LIMIT 1`,
            [deviceId]
        );
        return rows[0] ? toDevice(rows[0]) : null;
    };

    // Connexion dédiée au LISTEN, rouverte avec backoff si la base redémarre.
    // Les notifications émises pendant une coupure sont perdues : le client se resynchronise en REST.
    function listen({ onAlert, onDevice }) {
        let client = null;
        let stopped = false;
        let delay = 1000;

        const handle = async ({ channel, payload }) => {
            try {
                const item = channel === CHANNELS.alerts ? await getAlert(payload) : await getDevice(payload);
                if (!item) return;
                (channel === CHANNELS.alerts ? onAlert : onDevice)(item);
            } catch (err) {
                console.error(`❌ Notification ${channel} non traitée:`, err.message);
            }
        };

        const connect = async () => {
            if (stopped) return;
            client = new Client({ connectionString });
            client.on('notification', handle);
            client.on('error', (err) => console.error('❌ PostgreSQL (LISTEN):', err.message));
            client.on('end', () => {
                if (stopped) return;
                console.warn(`⚠️  LISTEN interrompu, reconnexion dans ${delay / 1000} s`);
                setTimeout(connect, delay);
                delay = Math.min(delay * 2, 30000);
            });
            try {
                await client.connect();
                await client.query(`LISTEN ${CHANNELS.alerts}; LISTEN ${CHANNELS.devices}`);
                delay = 1000;
                console.log('🗄️  Base connectée : écoute des alertes et des états d\'appareils');
            } catch (err) {
                console.error('❌ Connexion LISTEN impossible:', err.message);
                client.end().catch(() => {});
            }
        };

        connect();
        return () => {
            stopped = true;
            return client ? client.end().catch(() => {}) : Promise.resolve();
        };
    }

    return {
        async listAlerts(filters, { offset, limit }) {
            const { where, params } = whereClause(filters);
            const [rows, count] = await Promise.all([
                pool.query(`SELECT ${ALERT_COLUMNS} FROM alerts ${where} ORDER BY time DESC
                            LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, limit, offset]),
                pool.query(`SELECT count(*)::int AS total FROM alerts ${where}`, params)
            ]);
            return { data: rows.rows.map(toAlert), total: count.rows[0].total };
        },
        getAlert,
        async acknowledgeAlert(id, by) {
            if (!UUID.test(id)) return null;
            const { rows } = await pool.query(
                `UPDATE alerts SET acknowledged = true, acknowledged_at = now(), acknowledged_by = $2
                 WHERE id = $1 RETURNING ${ALERT_COLUMNS}`,
                [id, by]
            );
            return rows[0] ? toAlert(rows[0]) : null;
        },
        async recentAlerts(n) {
            const { rows } = await pool.query(`SELECT ${ALERT_COLUMNS} FROM alerts ORDER BY time DESC LIMIT $1`, [n]);
            return rows.map(toAlert);
        },
        async stats() {
            const { rows } = await pool.query(
                `SELECT severity, source, count(*)::int AS n, count(*) FILTER (WHERE acknowledged)::int AS acked
                 FROM alerts GROUP BY severity, source`
            );
            const stats = {
                total: 0,
                acknowledged: 0,
                unacknowledged: 0,
                bySeverity: Object.fromEntries(SEVERITIES.map(s => [s, 0])),
                bySource: {}
            };
            for (const { severity, source, n, acked } of rows) {
                stats.total += n;
                stats.acknowledged += acked;
                stats.unacknowledged += n - acked;
                stats.bySeverity[severity] += n;
                stats.bySource[source] = (stats.bySource[source] || 0) + n;
            }
            return stats;
        },
        // Dernier état connu de chaque appareil : { device_id: résultat }
        async devices() {
            const { rows } = await pool.query(
                `SELECT DISTINCT ON (device_id) ${DEVICE_COLUMNS} FROM detection.predictions
                 ORDER BY device_id, window_end DESC`
            );
            return Object.fromEntries(rows.map(r => [r.device_id, toDevice(r)]));
        },
        // Comptes du dashboard (table users). Le rôle par défaut de la base (« viewer ») vaut « user ».
        async getUser(username) {
            const { rows } = await pool.query(`SELECT ${USER_COLUMNS}, password_hash FROM users WHERE username = $1`, [username]);
            return rows[0] ? { ...toUser(rows[0]), password_hash: rows[0].password_hash } : null;
        },
        async getUserById(id) {
            const { rows } = await pool.query(`SELECT ${USER_COLUMNS} FROM users WHERE id = $1`, [id]);
            return rows[0] ? toUser(rows[0]) : null;
        },
        async listUsers() {
            const { rows } = await pool.query(`SELECT ${USER_COLUMNS} FROM users ORDER BY id`);
            return rows.map(toUser);
        },
        async countUsers() {
            const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
            return rows[0].n;
        },
        // -> { id, username, role } ou null si l'identifiant existe déjà
        async createUser(username, passwordHash, role) {
            const { rows } = await pool.query(
                `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)
                 ON CONFLICT (username) DO NOTHING RETURNING ${USER_COLUMNS}`,
                [username, passwordHash, role]
            );
            return rows[0] ? toUser(rows[0]) : null;
        },
        // changes : { role?, passwordHash? } -> compte mis à jour ou null
        async updateUser(id, { role, passwordHash }) {
            const { rows } = await pool.query(
                `UPDATE users SET role = COALESCE($2, role), password_hash = COALESCE($3, password_hash)
                 WHERE id = $1 RETURNING ${USER_COLUMNS}`,
                [id, role ?? null, passwordHash ?? null]
            );
            return rows[0] ? toUser(rows[0]) : null;
        },
        async deleteUser(id) {
            const { rowCount } = await pool.query('DELETE FROM users WHERE id = $1', [id]);
            return rowCount > 0;
        },
        async ping() {
            await pool.query('SELECT 1');
        },
        listen,
        close: () => pool.end()
    };
}

module.exports = { createStore };
