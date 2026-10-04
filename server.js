// language: JavaScript, file: server.js, runtime: Node 20+
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

app.set('trust proxy', true);   // ← essa linha

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS manual
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const DB_FILE = './keys.json';
let DB = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE)) : {};

// IPs que pediram key nos últimos 5 min
const PENDING_FILE = './pending.json';
let PENDING = fs.existsSync(PENDING_FILE) ? JSON.parse(fs.readFileSync(PENDING_FILE)) : {};

function saveDB() { fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2)); }
function savePending() { fs.writeFileSync(PENDING_FILE, JSON.stringify(PENDING, null, 2)); }

function generateKey() {
  const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `STR1KER-${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
}

// normaliza IP (remove IPv6 prefix, etc)
function normIP(raw) {
  if (!raw) return null;
  let ip = String(raw).trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

// ═══ ENDPOINT 0 — REGISTER (HTML chama antes de abrir LootLabs) ═══
app.post('/register', (req, res) => {
  const ip = normIP(req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress);
  const puid = (req.body.puid || '').toString();

  if (!ip) return res.status(400).json({ error: 'no_ip' });

  PENDING[ip] = {
    puid: puid || null,
    since: Date.now(),
  };
  savePending();

  console.log(`[Register] ip=${ip} puid=${puid || 'none'}`);
  res.json({ ok: true, ip });
});

// ═══ POSTBACK ═══
function handlePostback(req, res) {
  const p = { ...req.query, ...req.body };
  const ip = normIP(p.ip || p.IP || req.ip);
  const click_id = p.click_id || p.CLICK_ID || null;

  if (!ip) return res.status(400).send('missing ip');

  // acha um pending desse IP nos últimos 5 min
  const pend = PENDING[ip];
  const now = Date.now();

  if (!pend || (now - pend.since) > 5 * 60 * 1000) {
    console.log(`[Postback] ip=${ip} sem register ativo — descartado`);
    return res.status(200).send('no pending match');
  }

  const puid = pend.puid || ip;

  // evita gerar duplicado
  const existing = Object.entries(DB).find(([k, v]) => v.puid === puid && Date.now() < v.expires);
  if (existing) {
    console.log(`[Postback] ${puid} já tem key ativa`);
    delete PENDING[ip]; savePending();
    return res.send('OK - already has key');
  }

  const key = generateKey();
  DB[key] = {
    puid: String(puid),
    ip: ip,
    tier: 'free',
    expires: Date.now() + 12 * 60 * 60 * 1000,
    created: Date.now(),
    click_id: click_id,
  };
  saveDB();
  delete PENDING[ip];
  savePending();

  console.log(`[Postback] ip=${ip} puid=${puid} click=${click_id} → key ${key}`);
  res.send('OK');
}

app.get('/postback/lootlabs', handlePostback);
app.post('/postback/lootlabs', handlePostback);

// ═══ GET KEY BY PUID ═══
app.get('/get-key/:puid', (req, res) => {
  const { puid } = req.params;
  const entry = Object.entries(DB).find(([k, v]) => v.puid === puid);
  if (!entry) return res.json({ found: false });
  const [key, data] = entry;
  if (Date.now() > data.expires) return res.json({ found: false, reason: 'expired' });
  res.json({ found: true, key, expires: data.expires });
});

// ═══ GET KEY BY IP (fallback — HTML consulta pelo próprio IP) ═══
app.get('/get-key-by-ip', (req, res) => {
  const ip = normIP(req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress);
  if (!ip) return res.json({ found: false });

  const entry = Object.entries(DB).find(([k, v]) => v.ip === ip && Date.now() < v.expires);
  if (!entry) return res.json({ found: false });

  const [key, data] = entry;
  res.json({ found: true, key, expires: data.expires });
});

// ═══ VALIDATE ═══
app.post('/validate', (req, res) => {
  const { key } = req.body;
  if (!key) return res.json({ valid: false, reason: 'no_key' });
  const data = DB[key];
  if (!data) return res.json({ valid: false, reason: 'not_found' });
  if (Date.now() > data.expires) return res.json({ valid: false, reason: 'expired' });
  res.json({
    valid: true,
    tier: data.tier,
    expires: data.expires,
    remaining_h: Math.floor((data.expires - Date.now()) / 3600000),
  });
});

// ═══ ADMIN ═══
app.post('/admin/create', (req, res) => {
  const { admin_secret, tier, days } = req.body;
  if (admin_secret !== (process.env.ADMIN_SECRET || 'change-me')) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const key = generateKey();
  DB[key] = {
    puid: null,
    tier: tier || 'premium',
    expires: Date.now() + (days || 30) * 24 * 60 * 60 * 1000,
    created: Date.now(),
  };
  saveDB();
  res.json({ key, tier, expires_in_days: days || 30 });
});

// ═══ HEALTH ═══
app.get('/', (req, res) => {
  res.json({ status: 'ok', keys: Object.keys(DB).length, pending: Object.keys(PENDING).length });
});

// limpa pending antigo a cada minuto
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [ip, p] of Object.entries(PENDING)) {
    if (now - p.since > 10 * 60 * 1000) { delete PENDING[ip]; changed = true; }
  }
  if (changed) savePending();
}, 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Str1ker backend rodando na porta ${PORT}`));
