require('dotenv').config({ path: require('path').join(__dirname, '.env.local') });
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS streamers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE,
      password_hash TEXT,
      payout_phone TEXT
    );
    CREATE TABLE IF NOT EXISTS drawings (
      id TEXT PRIMARY KEY,
      streamer_id TEXT NOT NULL,
      image_data TEXT NOT NULL,
      duration_sec INTEGER NOT NULL DEFAULT 60,
      amount INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at BIGINT NOT NULL,
      shown_until BIGINT
    );
    CREATE TABLE IF NOT EXISTS payout_requests (
      id TEXT PRIMARY KEY,
      streamer_id TEXT NOT NULL,
      amount INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      requested_at BIGINT NOT NULL,
      paid_at BIGINT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      streamer_id TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);
}
const schemaReady = initSchema();

const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';
const SESSION_COOKIE = 'sc_session';

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.get('/', (req, res) => res.redirect('/signup.html'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(async (req, res, next) => {
  await schemaReady;
  next();
});

function genId() {
  return crypto.randomBytes(8).toString('hex');
}

function asyncHandler(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

// --- streamer signup with email + password ---
app.post('/api/streamers', asyncHandler(async (req, res) => {
  const { name, slug, payout_phone, email, password } = req.body;
  if (!name || !slug) return res.status(400).json({ error: 'name and slug required' });
  if (!payout_phone) return res.status(400).json({ error: 'payout_phone required (для ручного перевода по СБП)' });
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'пароль минимум 6 символов' });

  const id = genId();
  const password_hash = bcrypt.hashSync(password, 10);
  try {
    await pool.query(
      'INSERT INTO streamers (id, name, slug, email, password_hash, payout_phone) VALUES ($1, $2, $3, $4, $5, $6)',
      [id, name, slug, email.toLowerCase(), password_hash, payout_phone]
    );
  } catch (e) {
    return res.status(400).json({ error: 'slug или email уже занят' });
  }

  await createSession(res, id);
  res.json({ id, name, slug, dashboardUrl: '/dashboard.html', donateUrl: `/draw.html?slug=${slug}` });
}));

app.post('/api/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM streamers WHERE email = $1', [(email || '').toLowerCase()]);
  const streamer = rows[0];
  if (!streamer || !streamer.password_hash || !bcrypt.compareSync(password || '', streamer.password_hash)) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }
  await createSession(res, streamer.id);
  res.json({ ok: true });
}));

app.post('/api/logout', asyncHandler(async (req, res) => {
  const sid = req.cookies[SESSION_COOKIE];
  if (sid) await pool.query('DELETE FROM sessions WHERE id = $1', [sid]);
  res.clearCookie(SESSION_COOKIE);
  res.json({ ok: true });
}));

async function createSession(res, streamerId) {
  const sid = genId() + genId();
  await pool.query('INSERT INTO sessions (id, streamer_id, created_at) VALUES ($1, $2, $3)', [sid, streamerId, Date.now()]);
  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

async function authStreamer(req, res, next) {
  try {
    const sid = req.cookies[SESSION_COOKIE];
    if (!sid) return res.status(401).json({ error: 'not authenticated' });
    const { rows: sessionRows } = await pool.query('SELECT * FROM sessions WHERE id = $1', [sid]);
    const session = sessionRows[0];
    if (!session) return res.status(401).json({ error: 'not authenticated' });
    const { rows: streamerRows } = await pool.query('SELECT * FROM streamers WHERE id = $1', [session.streamer_id]);
    const streamer = streamerRows[0];
    if (!streamer) return res.status(401).json({ error: 'not authenticated' });
    req.streamer = streamer;
    next();
  } catch (e) {
    next(e);
  }
}

app.get('/api/me', authStreamer, (req, res) => {
  res.json({ id: req.streamer.id, name: req.streamer.name, slug: req.streamer.slug });
});

app.get('/api/streamers/by-slug/:slug', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, slug FROM streamers WHERE slug = $1', [req.params.slug]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
}));

// --- viewer submits a drawing (payment not wired yet, amount is just stored) ---
app.post('/api/drawings', asyncHandler(async (req, res) => {
  const { slug, image_data, duration_sec, amount } = req.body;
  const { rows } = await pool.query('SELECT * FROM streamers WHERE slug = $1', [slug]);
  const streamer = rows[0];
  if (!streamer) return res.status(404).json({ error: 'streamer not found' });
  if (!image_data) return res.status(400).json({ error: 'image_data required' });
  const id = genId();
  await pool.query(
    `INSERT INTO drawings (id, streamer_id, image_data, duration_sec, amount, status, created_at)
     VALUES ($1, $2, $3, $4, $5, 'pending', $6)`,
    [id, streamer.id, image_data, duration_sec || 60, amount || 0, Date.now()]
  );
  res.json({ id, status: 'pending' });
}));

// --- dashboard: list drawings, optionally filtered by status ---
app.get('/api/drawings', authStreamer, asyncHandler(async (req, res) => {
  const status = req.query.status;
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 200);
  const { rows } = status
    ? await pool.query('SELECT * FROM drawings WHERE streamer_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3', [req.streamer.id, status, limit])
    : await pool.query('SELECT * FROM drawings WHERE streamer_id = $1 ORDER BY created_at DESC LIMIT $2', [req.streamer.id, limit]);
  res.json(rows);
}));

app.post('/api/drawings/:id/approve', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM drawings WHERE id = $1 AND streamer_id = $2', [req.params.id, req.streamer.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  await pool.query("UPDATE drawings SET status = 'approved' WHERE id = $1", [rows[0].id]);
  res.json({ ok: true });
}));

app.post('/api/drawings/:id/reject', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM drawings WHERE id = $1 AND streamer_id = $2', [req.params.id, req.streamer.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  await pool.query("UPDATE drawings SET status = 'rejected' WHERE id = $1", [rows[0].id]);
  res.json({ ok: true });
}));

// --- overlay: shows current drawing on stream, picks oldest approved-not-yet-shown ---
app.get('/api/overlay/:slug/current', asyncHandler(async (req, res) => {
  const { rows: streamerRows } = await pool.query('SELECT * FROM streamers WHERE slug = $1', [req.params.slug]);
  const streamer = streamerRows[0];
  if (!streamer) return res.status(404).json({ error: 'not found' });

  const now = Date.now();
  let { rows: activeRows } = await pool.query(
    "SELECT * FROM drawings WHERE streamer_id = $1 AND status = 'showing' AND shown_until > $2",
    [streamer.id, now]
  );
  let active = activeRows[0];

  if (!active) {
    const { rows: nextRows } = await pool.query(
      "SELECT * FROM drawings WHERE streamer_id = $1 AND status = 'approved' ORDER BY created_at ASC LIMIT 1",
      [streamer.id]
    );
    const next = nextRows[0];
    if (next) {
      const shownUntil = now + next.duration_sec * 1000;
      await pool.query("UPDATE drawings SET status = 'showing', shown_until = $1 WHERE id = $2", [shownUntil, next.id]);
      active = { ...next, status: 'showing', shown_until: shownUntil };
    }
  }

  if (!active) return res.json({ drawing: null });
  res.json({
    drawing: {
      id: active.id,
      image_data: active.image_data,
      shown_until: active.shown_until,
    },
  });
}));

// --- balance: earned (all non-rejected drawings) minus already requested/paid ---
async function getBalance(streamerId) {
  const { rows: earnedRows } = await pool.query(
    "SELECT COALESCE(SUM(amount), 0) AS total FROM drawings WHERE streamer_id = $1 AND status != 'rejected'",
    [streamerId]
  );
  const { rows: requestedRows } = await pool.query(
    'SELECT COALESCE(SUM(amount), 0) AS total FROM payout_requests WHERE streamer_id = $1',
    [streamerId]
  );
  return Number(earnedRows[0].total) - Number(requestedRows[0].total);
}

app.get('/api/payout/balance', authStreamer, asyncHandler(async (req, res) => {
  res.json({ balance: await getBalance(req.streamer.id) });
}));

app.get('/api/payout/requests', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM payout_requests WHERE streamer_id = $1 ORDER BY requested_at DESC', [req.streamer.id]);
  res.json(rows);
}));

app.post('/api/payout/requests', authStreamer, asyncHandler(async (req, res) => {
  const balance = await getBalance(req.streamer.id);
  if (balance <= 0) return res.status(400).json({ error: 'Баланс пуст' });
  const id = genId();
  await pool.query(
    "INSERT INTO payout_requests (id, streamer_id, amount, status, requested_at) VALUES ($1, $2, $3, 'pending', $4)",
    [id, req.streamer.id, balance, Date.now()]
  );
  res.json({ id, amount: balance, status: 'pending' });
}));

// --- admin: manual payouts, no automated money movement ---
function authAdmin(req, res, next) {
  const key = req.query.key || req.headers['x-admin-key'];
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'invalid admin key' });
  next();
}

app.get('/api/admin/payout-requests', authAdmin, asyncHandler(async (req, res) => {
  const status = req.query.status || 'pending';
  const { rows } = await pool.query(
    `SELECT pr.*, s.name AS streamer_name, s.slug, s.payout_phone
     FROM payout_requests pr
     JOIN streamers s ON s.id = pr.streamer_id
     WHERE pr.status = $1
     ORDER BY pr.requested_at ASC`,
    [status]
  );
  res.json(rows);
}));

app.post('/api/admin/payout-requests/:id/mark-paid', authAdmin, asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM payout_requests WHERE id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  await pool.query("UPDATE payout_requests SET status = 'paid', paid_at = $1 WHERE id = $2", [Date.now(), rows[0].id]);
  res.json({ ok: true });
}));

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`streamcanvas running on http://localhost:${PORT}`));
}

module.exports = app;
