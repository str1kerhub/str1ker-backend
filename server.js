// language: JavaScript, file: server.js, runtime: Node 20+
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-secret');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const DB_FILE = './keys.json';
const PENDING_FILE = './pending.json';
const RATE_FILE = './rate.json';
const PROF_FILE = './profiles.json';

let DB = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE)) : {};
let PENDING = fs.existsSync(PENDING_FILE) ? JSON.parse(fs.readFileSync(PENDING_FILE)) : {};
let RATE = fs.existsSync(RATE_FILE) ? JSON.parse(fs.readFileSync(RATE_FILE)) : {};
let PROFILES = fs.existsSync(PROF_FILE) ? JSON.parse(fs.readFileSync(PROF_FILE)) : {};

function saveDB() { fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2)); }
function savePending() { fs.writeFileSync(PENDING_FILE, JSON.stringify(PENDING, null, 2)); }
function saveRate() { fs.writeFileSync(RATE_FILE, JSON.stringify(RATE, null, 2)); }
function saveProfiles() { fs.writeFileSync(PROF_FILE, JSON.stringify(PROFILES, null, 2)); }

function normIP(raw) {
  if (!raw) return null;
  let ip = String(raw).trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip.includes(',')) ip = ip.split(',')[0].trim();
  return ip;
}

function getIP(req) {
  return normIP(req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress);
}

function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let key = 'STR1KER';
  for (let g = 0; g < 4; g++) {
    key += '-';
    for (let i = 0; i < 4; i++) key += chars[crypto.randomInt(0, chars.length)];
  }
  return key;
}

function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

function rateLimit(ip, bucket, max, windowMs) {
  const key = `${ip}:${bucket}`;
  const now = Date.now();
  const r = RATE[key];
  if (!r || now > r.resetAt) {
    RATE[key] = { count: 1, resetAt: now + windowMs };
    return true;
  }
  if (r.count >= max) return false;
  r.count++;
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN AUTH
// ═══════════════════════════════════════════════════════════════════════════

function requireAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret']
    || (req.body && (req.body.admin_secret || req.body.secret));

  const realSecret = process.env.ADMIN_SECRET || 'change-me';

  if (secret !== realSecret) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// ═══ /register ═══
app.post('/register', (req, res) => {
  const ip = getIP(req);
  const puid = (req.body.puid || '').toString();

  if (!ip) return res.status(400).json({ error: 'no_ip' });
  if (!puid || !/^\d{10,20}$/.test(puid)) return res.status(400).json({ error: 'bad_puid' });

  if (!rateLimit(ip, 'register', 6, 60_000)) {
    console.log(`[Register] rate limited ip=${ip}`);
    return res.status(429).json({ error: 'rate_limited' });
  }

  const token = generateToken();
  PENDING[ip] = { puid, token, since: Date.now(), used: false };
  savePending();

  console.log(`[Register] ip=${ip} puid=${puid} token=${token.slice(0,8)}...`);
  res.json({ ok: true, token });
});

// ═══ postback ═══
function handlePostback(req, res) {
  const p = { ...req.query, ...req.body };
  const ip = normIP(p.ip || p.IP || getIP(req));
  const click_id = p.click_id || p.CLICK_ID || null;
  const signature = p.signature || p.sig || null;

  if (!ip) return res.status(400).send('missing ip');

  const SECRET = process.env.POSTBACK_SECRET;
  if (SECRET && signature) {
    const expected = crypto.createHmac('sha256', SECRET)
      .update(String(click_id || '') + ip)
      .digest('hex');
    if (signature !== expected) {
      console.log(`[Postback] bad signature ip=${ip}`);
      return res.status(403).send('bad signature');
    }
  }

  const pend = PENDING[ip];
  const now = Date.now();

  if (!pend || (now - pend.since) > 5 * 60 * 1000) {
    console.log(`[Postback] ip=${ip} sem register ativo`);
    return res.status(200).send('no pending match');
  }
  if (pend.used) {
    console.log(`[Postback] ip=${ip} token já usado`);
    return res.status(200).send('already used');
  }

  const puid = pend.puid;

  const existing = Object.entries(DB).find(([k, v]) => v.puid === puid && Date.now() < v.expires);
  if (existing) {
    pend.used = true; savePending();
    console.log(`[Postback] ${puid} já tem key ativa`);
    return res.send('OK - already has key');
  }

  const key = generateKey();
  DB[key] = {
    puid: String(puid),
    ip,
    tier: 'free',
    expires: Date.now() + 12 * 60 * 60 * 1000,
    created: Date.now(),
    click_id,
  };
  saveDB();

  pend.used = true;
  savePending();

  console.log(`[Postback] ip=${ip} puid=${puid} click=${click_id} → key ${key}`);

  const wurl = process.env.DISCORD_WEBHOOK;
  if (wurl) {
    fetch(wurl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: 'Nova key gerada (LootLabs)',
          color: 0x3b82f6,
          fields: [
            { name: 'Key', value: '`' + key + '`' },
            { name: 'PUID', value: '`' + puid + '`', inline: true },
            { name: 'IP', value: '`' + ip + '`', inline: true },
          ],
          timestamp: new Date().toISOString(),
        }],
      }),
    }).catch(() => {});
  }

  res.send('OK');
}

app.get('/postback/lootlabs', handlePostback);
app.post('/postback/lootlabs', handlePostback);

// ═══ /get-key-by-ip ═══
app.get('/get-key-by-ip', (req, res) => {
  const ip = getIP(req);
  const token = (req.query.token || '').toString();

  if (!ip) return res.json({ found: false });
  if (!token) return res.json({ found: false, error: 'no_token' });

  if (!rateLimit(ip, 'poll', 200, 60_000)) {
    return res.status(429).json({ found: false, error: 'rate_limited' });
  }

  const pend = PENDING[ip];
  if (!pend || pend.token !== token) {
    return res.json({ found: false, error: 'bad_token' });
  }

  const entry = Object.entries(DB).find(([k, v]) => v.ip === ip && Date.now() < v.expires);
  if (!entry) return res.json({ found: false });

  const [key, data] = entry;
  res.json({ found: true, key, expires: data.expires });
});

// ═══ /get-key/:puid ═══
app.get('/get-key/:puid', (req, res) => {
  const { puid } = req.params;
  const entry = Object.entries(DB).find(([k, v]) => v.puid === puid);
  if (!entry) return res.json({ found: false });
  const [key, data] = entry;
  if (Date.now() > data.expires) return res.json({ found: false, reason: 'expired' });
  res.json({ found: true, key, expires: data.expires });
});

// ═══ /validate ═══
app.post('/validate', (req, res) => {
  const { key, puid, username } = req.body;
  if (!key) return res.json({ valid: false, reason: 'no_key' });
  const data = DB[key];
  if (!data) return res.json({ valid: false, reason: 'not_found' });
  if (Date.now() > data.expires) return res.json({ valid: false, reason: 'expired' });

  if (!data.usedBy && puid) {
    data.usedBy = puid;
    data.usedByUsername = username || null;
    data.firstUsedAt = Date.now();
    saveDB();
  }

  res.json({
    valid: true,
    tier: data.tier,
    expires: data.expires,
    remaining_h: Math.floor((data.expires - Date.now()) / 3600000),
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════

app.post('/admin/create', requireAdmin, (req, res) => {
  const body = req.body || {};
  const count = Math.min(Math.max(parseInt(body.count) || 1, 1), 50);

  let durationH = 24;
  if (typeof body.hours === 'number' && body.hours > 0) {
    durationH = body.hours;
  } else if (typeof body.days === 'number' && body.days > 0) {
    durationH = body.days * 24;
  }

  const tier = body.tier || 'premium';
  const now = Date.now();
  const out = [];

  for (let i = 0; i < count; i++) {
    const key = generateKey();
    DB[key] = {
      puid: null,
      tier,
      expires: now + durationH * 3600 * 1000,
      created: now,
      admin: true,
    };
    out.push(key);
  }
  saveDB();

  console.log(`[Admin] ${count} key(s) geradas · ${durationH}h · tier=${tier}`);

  const wurl = process.env.DISCORD_WEBHOOK;
  if (wurl) {
    fetch(wurl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: 'Nova(s) key(s) geradas (Admin)',
          color: 0x3b82f6,
          fields: [
            { name: 'Quantidade', value: String(count), inline: true },
            { name: 'Duração', value: durationH + 'h', inline: true },
            { name: 'Tier', value: tier, inline: true },
            { name: 'Keys', value: '```' + out.join('\n') + '```' },
          ],
          timestamp: new Date().toISOString(),
        }],
      }),
    }).catch(() => {});
  }

  res.json({ ok: true, keys: out, expiresInHours: durationH, tier });
});

app.get('/admin/keys', requireAdmin, (req, res) => {
  const now = Date.now();
  const list = Object.entries(DB).map(([key, v]) => ({
    key,
    createdAt: v.created,
    expiresAt: v.expires,
    expired: v.expires < now,
    tier: v.tier || 'free',
    used: !!v.usedBy,
    usedBy: v.usedBy || null,
    usedByUsername: v.usedByUsername || null,
    admin: !!v.admin,
  }));
  list.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ ok: true, total: list.length, keys: list });
});

app.post('/admin/revoke', requireAdmin, (req, res) => {
  const { key } = req.body || {};
  if (!key || !DB[key]) return res.status(404).json({ error: 'not_found' });
  delete DB[key];
  saveDB();
  console.log(`[Admin] key revogada: ${key}`);
  res.json({ ok: true });
});

app.get('/admin/stats', requireAdmin, (req, res) => {
  const now = Date.now();
  let active = 0, expired = 0, used = 0;
  for (const k of Object.values(DB)) {
    if (k.expires < now) expired++;
    else active++;
    if (k.usedBy) used++;
  }
  res.json({
    ok: true,
    total: Object.keys(DB).length,
    active,
    expired,
    used,
    pending: Object.keys(PENDING).length,
    profiles: Object.keys(PROFILES).length,
  });
});

app.post('/admin/killswitch', requireAdmin, (req, res) => {
  const enable = req.body && req.body.enable === true;
  process.env.KILLSWITCH = enable ? 'false' : 'true';
  res.json({ ok: true, enabled: process.env.KILLSWITCH !== 'true' });
});

// ═══ /status ═══
app.get('/status', (req, res) => {
  res.json({ enabled: process.env.KILLSWITCH !== 'true' });
});

// ═══ /version ═══
app.get('/version', (req, res) => {
  res.json({
    version: 4,
    url: 'https://raw.githubusercontent.com/str1kerhub/str1ker1/main/str1ker_pvp.lua',
  });
});

// ═══ /log ═══
const logBucket = new Map();
app.post('/log', (req, res) => {
  const { event, data, user } = req.body || {};
  const ip = getIP(req) || 'unknown';
  const now = Date.now();

  const recent = (logBucket.get(ip) || []).filter(t => now - t < 60_000);
  if (recent.length > 30) return res.status(429).json({ ok: false });
  recent.push(now);
  logBucket.set(ip, recent);

  const wurl = process.env.DISCORD_WEBHOOK;
  if (wurl) {
    fetch(wurl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: 'Str1ker · ' + (event || 'event'),
          color: 0x3b82f6,
          fields: [
            { name: 'User', value: '`' + (user || '?') + '`', inline: true },
            { name: 'IP', value: '`' + ip + '`', inline: true },
            { name: 'Data', value: '```' + JSON.stringify(data || {}).slice(0, 900) + '```' },
          ],
          timestamp: new Date().toISOString(),
        }],
      }),
    }).catch(() => {});
  }

  res.json({ ok: true });
});

// ═══ /profiles ═══
app.post('/profiles/:puid', (req, res) => {
  const { puid } = req.params;
  const { name, data } = req.body;
  if (!puid || !name || !data) return res.status(400).json({ error: 'missing' });
  if (!/^[a-zA-Z0-9_\- ]{1,32}$/.test(name)) return res.status(400).json({ error: 'bad_name' });
  if (!PROFILES[puid]) PROFILES[puid] = {};
  PROFILES[puid][name] = { data, updated: Date.now() };
  saveProfiles();
  console.log(`[Profiles] ${puid} saved "${name}"`);
  res.json({ ok: true });
});

app.get('/profiles/:puid', (req, res) => {
  const { puid } = req.params;
  const list = PROFILES[puid] || {};
  const out = Object.entries(list).map(([name, v]) => ({ name, updated: v.updated }));
  out.sort((a, b) => b.updated - a.updated);
  res.json({ profiles: out });
});

app.get('/profiles/:puid/:name', (req, res) => {
  const { puid, name } = req.params;
  const p = PROFILES[puid] && PROFILES[puid][name];
  if (!p) return res.status(404).json({ error: 'not_found' });
  res.json({ name, data: p.data, updated: p.updated });
});

app.delete('/profiles/:puid/:name', (req, res) => {
  const { puid, name } = req.params;
  if (PROFILES[puid]) {
    delete PROFILES[puid][name];
    saveProfiles();
    console.log(`[Profiles] ${puid} deleted "${name}"`);
  }
  res.json({ ok: true });
});

// ═══ health ═══
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    keys: Object.keys(DB).length,
    pending: Object.keys(PENDING).length,
    profiles: Object.keys(PROFILES).length,
  });
});

setInterval(() => {
  const now = Date.now();
  let cp = false, cr = false;
  for (const [ip, p] of Object.entries(PENDING)) {
    if (now - p.since > 10 * 60 * 1000) { delete PENDING[ip]; cp = true; }
  }
  for (const [k, r] of Object.entries(RATE)) {
    if (now > r.resetAt) { delete RATE[k]; cr = true; }
  }
  if (cp) savePending();
  if (cr) saveRate();
}, 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Str1ker backend rodando na porta ${PORT}`));
