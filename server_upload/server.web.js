const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { hashPassword, verifyPassword } = require('./auth');

function loadEnv() {
  const p = path.join(__dirname, '.env');
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const i = t.indexOf('=');
    if (i > 0 && !process.env[t.slice(0, i)]) process.env[t.slice(0, i)] = t.slice(i + 1);
  }
}
loadEnv();

const PORT = Number(process.env.PORT || 3847);
const HOST = process.env.HOST || '0.0.0.0';
const TTL = Number(process.env.SESSION_TTL_HOURS || 12) * 3600000;
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || 'true').toLowerCase() === 'true';
const ROOT = __dirname;
const DATA_ROOT = process.env.PC_CHEAK_DATA_DIR || path.join(ROOT, 'data');
const REPORTS = path.join(DATA_ROOT, 'reports');
const USERS = path.join(DATA_ROOT, 'users.json');
const KEYS = path.join(DATA_ROOT, 'activation-keys.json');
fs.mkdirSync(REPORTS, { recursive: true });

function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2)); }
function readUsers() { return readJson(USERS, []); }
function writeUsers(x) { writeJson(USERS, x); }
function readKeys() { return readJson(KEYS, []); }
function writeKeys(x) { writeJson(KEYS, x); }

if (!fs.existsSync(KEYS)) writeKeys([]);
if (!fs.existsSync(USERS)) {
  const username = String(process.env.ADMIN_USERNAME || 'admin').trim();
  const password = String(process.env.ADMIN_PASSWORD || '');
  if (!password || password.length < 10) {
    console.error('ADMIN_PASSWORD must be set and contain at least 10 characters on first startup.');
    process.exit(1);
  }
  writeUsers([{ id: crypto.randomUUID(), username, passwordHash: hashPassword(password), role: 'admin', active: true, createdAt: new Date().toISOString() }]);
}

const allowedOrigins = String(process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '12mb' }));

// GitHub Pages and the API are separate origins, so the staff UI needs CORS + credentials.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (allowedOrigins.includes('*') || allowedOrigins.includes(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Pc-Cheak-Key, X-Agent-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/health', (_req, res) => res.json({ ok: true, service: 'pc-cheak-api', version: '2.0.0' }));

const cookie = (req, name) => {
  const h = req.headers.cookie || '';
  const m = h.split(';').map(x => x.trim()).find(x => x.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
};
const sessions = new Map();
function sessionUser(req) {
  const token = cookie(req, 'pc_cheak_session');
  const session = token && sessions.get(token);
  if (!session || Date.now() - session.at > TTL) { if (token) sessions.delete(token); return null; }
  const user = readUsers().find(x => x.id === session.userId);
  return user && user.active ? user : null;
}
function requireAuth(req, res, next) { const user = sessionUser(req); if (!user) return res.status(401).json({ error: 'Staff login required' }); req.user = user; next(); }
function requireRole(...roles) { return (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Insufficient permissions' }); }
function saveReport(report) {
  if (!report || !/^[A-Za-z0-9._-]{1,120}$/.test(String(report.id || ''))) throw new Error('Invalid report id');
  fs.writeFileSync(path.join(REPORTS, `${report.id}.json`), JSON.stringify(report, null, 2));
}
function validActivationKey(value) {
  const key = String(value || '').trim().toUpperCase();
  return readKeys().find(x => x.key === key && x.active && !x.used);
}

app.get('/api/player/status', (req, res) => {
  const key = String(req.headers['x-pc-cheak-key'] || req.query.key || '').trim().toUpperCase();
  const k = validActivationKey(key);
  res.json({ authorized: !!k, key: k?.key || null });
});
app.post('/api/player/activate', (req, res) => {
  const key = String(req.body?.key || '').trim().toUpperCase();
  const k = validActivationKey(key);
  if (!k) return res.status(403).json({ error: 'Invalid or already used activation key' });
  res.json({ ok: true, key: k.key, label: k.label });
});

// The Windows desktop client scans locally and sends the finished consent report here.
app.post('/api/player/submit', (req, res) => {
  const keyValue = String(req.headers['x-pc-cheak-key'] || '').trim().toUpperCase();
  const keys = readKeys();
  const key = keys.find(x => x.key === keyValue && x.active && !x.used);
  const report = req.body;
  if (!key) return res.status(403).json({ error: 'Invalid or already used activation key' });
  if (!report || !report.scan || !report.consent?.given) return res.status(400).json({ error: 'Invalid consent report' });
  key.used = true; key.usedAt = new Date().toISOString(); key.reportCount = (key.reportCount || 0) + 1;
  writeKeys(keys); saveReport(report);
  res.json({ ok: true, id: report.id });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = readUsers().find(x => x.username === String(username || '') && x.active);
  if (!user || !verifyPassword(password || '', user.passwordHash)) return res.status(403).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, at: Date.now() });
  const parts = [`pc_cheak_session=${encodeURIComponent(token)}`, 'Path=/', 'HttpOnly', 'SameSite=None', `Max-Age=${Math.floor(TTL / 1000)}`];
  if (COOKIE_SECURE) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
});
app.post('/api/auth/logout', (req, res) => {
  const token = cookie(req, 'pc_cheak_session'); if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'pc_cheak_session=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure'); res.json({ ok: true });
});
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: { id: req.user.id, username: req.user.username, role: req.user.role } }));

app.get('/api/staff/keys', requireAuth, requireRole('admin', 'reviewer'), (_req, res) => res.json({ keys: readKeys().map(k => ({ key: k.key, label: k.label, used: !!k.used, active: k.active, createdAt: k.createdAt, usedAt: k.usedAt || null })) }));
app.post('/api/staff/keys', requireAuth, requireRole('admin', 'reviewer'), (req, res) => {
  const keys = readKeys(); const key = 'PC-' + crypto.randomBytes(4).toString('hex').toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const item = { key, label: String(req.body?.label || '').slice(0, 100), active: true, used: false, createdAt: new Date().toISOString() };
  keys.push(item); writeKeys(keys); res.json({ ok: true, key: item.key, label: item.label });
});
app.get('/api/staff/reports', requireAuth, requireRole('admin', 'reviewer', 'viewer'), (_req, res) => {
  const reports = fs.readdirSync(REPORTS).filter(f => f.endsWith('.json')).map(f => {
    try { const r = JSON.parse(fs.readFileSync(path.join(REPORTS, f), 'utf8')); return { id: r.id, createdAt: r.createdAt, playerName: r.consent?.playerName || '', discord: r.consent?.discord || '', computer: r.scan?.computer || '', user: r.scan?.user || '', risk: r.risk, score: r.score ?? 0, flagCount: (r.flags || []).length }; }
    catch { return null; }
  }).filter(Boolean).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  res.json({ reports });
});
app.get('/api/staff/reports/:id', requireAuth, requireRole('admin', 'reviewer', 'viewer'), (req, res) => {
  const file = path.join(REPORTS, `${path.basename(req.params.id)}.json`);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Report not found' });
  res.json(JSON.parse(fs.readFileSync(file, 'utf8')));
});
app.post('/api/staff/import', requireAuth, requireRole('admin', 'reviewer'), (req, res) => {
  const r = req.body; if (!r || !r.id || !r.scan || !r.consent?.given) return res.status(400).json({ error: 'Not a valid consent report.' });
  saveReport(r); res.json({ ok: true, id: r.id });
});
app.get('/api/staff/users', requireAuth, requireRole('admin'), (_req, res) => res.json({ users: readUsers().map(u => ({ id: u.id, username: u.username, role: u.role, active: u.active, createdAt: u.createdAt })) }));
app.post('/api/staff/users', requireAuth, requireRole('admin'), (req, res) => {
  const { username, password, role = 'viewer' } = req.body || {};
  if (!username || String(password || '').length < 10 || !['admin', 'reviewer', 'viewer'].includes(role)) return res.status(400).json({ error: 'Username, password (10+ chars), and valid role are required' });
  const users = readUsers(); if (users.some(u => u.username === username)) return res.status(409).json({ error: 'Username already exists' });
  const user = { id: crypto.randomUUID(), username: String(username).slice(0, 50), passwordHash: hashPassword(password), role, active: true, createdAt: new Date().toISOString() };
  users.push(user); writeUsers(users); res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role, active: true } });
});
app.patch('/api/staff/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const users = readUsers(), user = users.find(x => x.id === req.params.id); if (!user) return res.status(404).json({ error: 'User not found' });
  if (req.body.role && ['admin', 'reviewer', 'viewer'].includes(req.body.role)) user.role = req.body.role;
  if (typeof req.body.active === 'boolean') user.active = req.body.active;
  if (req.body.password) { if (String(req.body.password).length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters' }); user.passwordHash = hashPassword(req.body.password); }
  writeUsers(users); res.json({ ok: true });
});
app.delete('/api/staff/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account' });
  const users = readUsers(), next = users.filter(u => u.id !== req.params.id); if (next.length === users.length) return res.status(404).json({ error: 'User not found' });
  writeUsers(next); res.json({ ok: true });
});
app.get('/api/player/report/:id', requireAuth, requireRole('admin', 'reviewer', 'viewer'), (req, res) => {
  const file = path.join(REPORTS, `${path.basename(req.params.id)}.json`); if (!fs.existsSync(file)) return res.status(404).json({ error: 'Report not found' });
  res.download(file, path.basename(file));
});

const server = app.listen(PORT, HOST, () => console.log(`Pc-Cheak API listening on http://${HOST}:${PORT}`));
module.exports = { app, server };
