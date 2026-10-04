const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

app.use(express.json());

const DB_FILE = './keys.json';
let DB = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE)) : {};

function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2));
}

// Gera key no formato STR1KER-XXXX-XXXX
function generateKey() {
  const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `STR1KER-${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
}

// ═══ ENDPOINT 1 — POSTBACK (LootLabs chama quando alguém completa a task) ═══
app.get('/postback/lootlabs', (req, res) => {
  const { puid } = req.query; // puid = UserId do Roblox

  if (!puid) {
    return res.status(400).send('missing puid');
  }

  // Se já existe uma key ativa pra esse puid, não gera outra
  const existing = Object.entries(DB).find(([k, v]) => v.puid === puid && Date.now() < v.expires);
  if (existing) {
    console.log(`[Postback] ${puid} já tem key ativa: ${existing[0]}`);
    return res.send('OK - already has key');
  }

  // Gera key nova
  const key = generateKey();
  DB[key] = {
    puid: puid,
    tier: 'free',
    expires: Date.now() + 12 * 60 * 60 * 1000, // 12 horas
    created: Date.now(),
  };
  saveDB();

  console.log(`[Postback] ${puid} → key ${key}`);
  res.send('OK');
});

// ═══ ENDPOINT 2 — GET KEY BY PUID (cliente pergunta "qual é minha key?") ═══
app.get('/get-key/:puid', (req, res) => {
  const { puid } = req.params;
  const entry = Object.entries(DB).find(([k, v]) => v.puid === puid);

  if (!entry) {
    return res.json({ found: false });
  }

  const [key, data] = entry;
  if (Date.now() > data.expires) {
    return res.json({ found: false, reason: 'expired' });
  }

  res.json({ found: true, key, expires: data.expires });
});

// ═══ ENDPOINT 3 — VALIDATE (cliente valida key) ═══
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

// ═══ ENDPOINT 4 — ADMIN: criar key premium manualmente ═══
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

// ═══ ENDPOINT 5 — HEALTH (só pra testar se tá rodando) ═══
app.get('/', (req, res) => {
  res.json({ status: 'ok', keys_count: Object.keys(DB).length });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Str1ker backend rodando na porta ${PORT}`));
