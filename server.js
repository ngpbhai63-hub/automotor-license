import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const required = ['DATABASE_URL', 'ADMIN_SECRET', 'LICENSE_JWT_SECRET'];
for (const key of required) if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false } });
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use('/admin', express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '16kb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));
const hash = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const makeKey = () => `AM-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
const adminOnly = (req, res, next) => {
  const supplied = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const a = Buffer.from(supplied); const b = Buffer.from(process.env.ADMIN_SECRET);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Admin authentication required' });
  next();
};
async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS licenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), key_hash TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'issued' CHECK (status IN ('issued','active','revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), activated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ, device_id TEXT, label TEXT
  )`);
}
app.get('/health', (_req, res) => res.json({ ok: true, service: 'automotor-license-api' }));
app.post('/api/license/activate', async (req, res) => {
  const key = String(req.body?.key || '').trim().toUpperCase();
  const deviceId = String(req.body?.deviceId || '').trim();
  if (!/^AM-[A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{8}$/.test(key) || !/^[a-zA-Z0-9-]{20,100}$/.test(deviceId)) return res.status(400).json({ error: 'Invalid license key or device ID' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const q = await client.query('SELECT * FROM licenses WHERE key_hash=$1 FOR UPDATE', [hash(key)]);
    if (!q.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'License key not found' }); }
    const row = q.rows[0];
    if (row.status === 'revoked') { await client.query('ROLLBACK'); return res.status(403).json({ error: 'License revoked' }); }
    if (row.status === 'active' && row.device_id !== deviceId) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'This license is already bound to another device. Contact admin for a device reset.' }); }
    let activatedAt = row.activated_at; let expiresAt = row.expires_at;
    if (row.status === 'issued') {
      activatedAt = new Date(); expiresAt = new Date(activatedAt.getTime() + 30 * 24 * 60 * 60 * 1000);
      await client.query(`UPDATE licenses SET status='active', device_id=$2, activated_at=$3, expires_at=$4 WHERE id=$1`, [row.id, deviceId, activatedAt, expiresAt]);
    }
    if (new Date(expiresAt) <= new Date()) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'License expired' }); }
    await client.query('COMMIT');
    const token = jwt.sign({ sub: row.id, deviceId, exp: Math.floor(new Date(expiresAt).getTime()/1000) }, process.env.LICENSE_JWT_SECRET, { issuer: 'automotor-license-api', audience: 'automotor-extension' });
    res.json({ ok: true, token, expiresAt: new Date(expiresAt).toISOString(), status: 'active' });
  } catch (e) { await client.query('ROLLBACK').catch(()=>{}); console.error(e); res.status(500).json({ error: 'License service error' }); }
  finally { client.release(); }
});
app.post('/api/license/verify', async (req, res) => {
  const token = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const deviceId = String(req.body?.deviceId || '');
  try {
    const claims = jwt.verify(token, process.env.LICENSE_JWT_SECRET, { issuer: 'automotor-license-api', audience: 'automotor-extension' });
    if (claims.deviceId !== deviceId) return res.status(403).json({ ok: false, error: 'Device mismatch' });
    const q = await pool.query(`SELECT status, device_id, expires_at FROM licenses WHERE id=$1`, [claims.sub]);
    if (!q.rowCount) return res.status(403).json({ ok: false, error: 'License not found' });
    const row = q.rows[0];
    if (row.status !== 'active' || row.device_id !== deviceId || new Date(row.expires_at) <= new Date()) return res.status(403).json({ ok: false, error: 'License expired, revoked, or device mismatch' });
    res.json({ ok: true, status: 'active', expiresAt: new Date(row.expires_at).toISOString() });
  } catch { res.status(401).json({ ok: false, error: 'License token invalid or expired' }); }
});
app.post('/api/admin/licenses', adminOnly, async (req, res) => {
  const count = Math.max(1, Math.min(100, Number.parseInt(req.body?.count ?? '1', 10) || 1));
  const label = String(req.body?.label || '').slice(0, 120) || null;
  const keys = [];
  for (let i=0;i<count;i++) {
    const key = makeKey();
    await pool.query('INSERT INTO licenses(key_hash,label) VALUES($1,$2)', [hash(key), label]);
    keys.push(key);
  }
  res.status(201).json({ keys, note: 'Copy these keys now. Only their hashes are stored.' });
});
app.get('/api/admin/licenses', adminOnly, async (_req, res) => {
  const q = await pool.query('SELECT id,status,created_at,activated_at,expires_at,device_id,label FROM licenses ORDER BY created_at DESC LIMIT 500');
  res.json({ licenses: q.rows });
});
app.post('/api/admin/licenses/:id/revoke', adminOnly, async (req, res) => {
  const q = await pool.query(`UPDATE licenses SET status='revoked' WHERE id=$1 RETURNING id,status`, [req.params.id]);
  if (!q.rowCount) return res.status(404).json({ error: 'License not found' });
  res.json({ ok: true, license: q.rows[0] });
});
app.post('/api/admin/licenses/:id/renew', adminOnly, async (req, res) => {
  const q = await pool.query(`UPDATE licenses SET status='active', activated_at=now(), expires_at=now()+interval '30 days' WHERE id=$1 AND status <> 'revoked' RETURNING id,status,expires_at`, [req.params.id]);
  if (!q.rowCount) return res.status(404).json({ error: 'License not found or revoked' });
  res.json({ ok: true, license: q.rows[0], note: 'Renewed for 30 days from now. Device binding is preserved.' });
});
app.post('/api/admin/licenses/:id/reset-device', adminOnly, async (req, res) => {
  const q = await pool.query(`UPDATE licenses SET status='issued', device_id=NULL, activated_at=NULL, expires_at=NULL WHERE id=$1 AND status <> 'revoked' RETURNING id,status`, [req.params.id]);
  if (!q.rowCount) return res.status(404).json({ error: 'License not found or revoked' });
  res.json({ ok: true, license: q.rows[0], note: 'Next activation binds this key to the new device and starts a fresh 30-day period.' });
});
const port = Number(process.env.PORT || 10000);
init().then(() => app.listen(port, () => console.log(`AutoMotor License API listening on ${port}`))).catch(e => { console.error(e); process.exit(1); });
