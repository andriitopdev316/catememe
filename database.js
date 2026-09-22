const {Pool} = require('pg');

const connectionString = process.env.DATABASE_URL;
const pool = new Pool({connectionString, max: 5});

async function initialize() {
  if (!connectionString) throw new Error('DATABASE_URL is required. Attach Railway Postgres to this service.');
  await pool.query(`CREATE TABLE IF NOT EXISTS visitors (id TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS invites (code TEXT PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS ip_intelligence (ip TEXT PRIMARY KEY, data JSONB NOT NULL, expires_at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS tracking_rate_limits (ip TEXT NOT NULL, bucket TEXT NOT NULL, window_started_at TIMESTAMPTZ NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (ip, bucket));`);
}
async function getVisitor(id) {
  const result = await pool.query('SELECT data FROM visitors WHERE id = $1', [id]);
  return result.rows[0]?.data || null;
}
async function saveVisitor(visitor) {
  await pool.query('INSERT INTO visitors (id, data, updated_at) VALUES ($1, $2::jsonb, NOW()) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()', [visitor.id, JSON.stringify(visitor)]);
}
async function listVisitors() {
  const result = await pool.query('SELECT data FROM visitors ORDER BY updated_at DESC');
  return result.rows.map(row => row.data);
}
async function deleteVisitor(id) {
  await pool.query('DELETE FROM visitors WHERE id = $1', [id]);
}
async function listInvites() {
  const result = await pool.query('SELECT data FROM invites ORDER BY created_at DESC');
  return result.rows.map(row => row.data);
}
async function getInvite(code) {
  const result = await pool.query('SELECT data FROM invites WHERE code = $1', [code]);
  return result.rows[0]?.data || null;
}
async function createInvite(invite) {
  await pool.query('INSERT INTO invites (code, data) VALUES ($1, $2::jsonb)', [invite.code, JSON.stringify(invite)]);
}
async function getNetwork(ip) {
  const result = await pool.query('SELECT data FROM ip_intelligence WHERE ip = $1 AND expires_at > NOW()', [ip]);
  return result.rows[0]?.data || null;
}
async function cacheNetwork(ip, data, ttlMs) {
  await pool.query(`INSERT INTO ip_intelligence (ip, data, expires_at) VALUES ($1, $2::jsonb, NOW() + ($3 * INTERVAL '1 millisecond'))
    ON CONFLICT (ip) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at`, [ip, JSON.stringify(data), ttlMs]);
}
async function allow(ip, bucket, limit, windowMs) {
  const result = await pool.query(`INSERT INTO tracking_rate_limits (ip, bucket, window_started_at, count) VALUES ($1, $2, NOW(), 1)
    ON CONFLICT (ip, bucket) DO UPDATE SET
      count = CASE WHEN tracking_rate_limits.window_started_at < NOW() - ($4 * INTERVAL '1 millisecond') THEN 1 ELSE tracking_rate_limits.count + 1 END,
      window_started_at = CASE WHEN tracking_rate_limits.window_started_at < NOW() - ($4 * INTERVAL '1 millisecond') THEN NOW() ELSE tracking_rate_limits.window_started_at END
    RETURNING count`, [ip, bucket, limit, windowMs]);
  return result.rows[0].count <= limit;
}

module.exports = {initialize, getVisitor, saveVisitor, listVisitors, deleteVisitor, listInvites, getInvite, createInvite, getNetwork, cacheNetwork, allow};
