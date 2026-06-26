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
      platform_fee INTEGER NOT NULL DEFAULT 0,
      streamer_amount INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      payment_id TEXT,
      created_at BIGINT NOT NULL,
      shown_until BIGINT
    );
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS platform_fee INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS streamer_amount INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS payment_id TEXT;
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS caption TEXT;
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS queue_at BIGINT;
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS promo_code TEXT;
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS sound_effect TEXT;
    ALTER TABLE drawings ADD COLUMN IF NOT EXISTS sound_played BOOLEAN NOT NULL DEFAULT false;
    UPDATE drawings SET streamer_amount = amount WHERE streamer_amount = 0 AND amount > 0;
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
    CREATE TABLE IF NOT EXISTS promo_codes (
      id TEXT PRIMARY KEY,
      streamer_id TEXT NOT NULL,
      code TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      used_at BIGINT,
      created_at BIGINT NOT NULL
    );
  `);
}
const schemaReady = initSchema();

const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';
const SESSION_COOKIE = 'sc_session';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const YOOKASSA_SHOP_ID = process.env.YOOKASSA_SHOP_ID;
const YOOKASSA_SECRET_KEY = process.env.YOOKASSA_SECRET_KEY;
const PLATFORM_FEE_RATE = 0.10; // 10% комиссия платформы

const BASE_PRICE = 50; // отправка рисунка
const RATE_PER_SEC = 1; // цена за каждую секунду показа
const MIN_DURATION_SEC = 10;
const MAX_DURATION_SEC = 3600;
const PROMO_DURATION_SEC = 60; // донаты по промокоду всегда показываются ровно 1 минуту
const SOUND_EFFECTS = ['bell', 'horn', 'laser', 'drum'];

function calcAmount(duration_sec) {
  if (!Number.isInteger(duration_sec) || duration_sec < MIN_DURATION_SEC || duration_sec > MAX_DURATION_SEC) {
    return null;
  }
  return BASE_PRICE + duration_sec * RATE_PER_SEC;
}

async function createYookassaPayment({ amount, description, drawingId, slug }) {
  const idempotenceKey = crypto.randomUUID();
  const res = await fetch('https://api.yookassa.ru/v3/payments', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Idempotence-Key': idempotenceKey,
      Authorization: 'Basic ' + Buffer.from(`${YOOKASSA_SHOP_ID}:${YOOKASSA_SECRET_KEY}`).toString('base64'),
    },
    body: JSON.stringify({
      amount: { value: amount.toFixed(2), currency: 'RUB' },
      capture: true,
      confirmation: {
        type: 'redirect',
        return_url: `${BASE_URL}/draw.html?slug=${slug}&payment=done`,
      },
      description,
      metadata: { drawing_id: drawingId },
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`YooKassa Init failed: ${res.status} ${text}`);
  }
  return res.json();
}

async function fetchYookassaPayment(paymentId) {
  const res = await fetch(`https://api.yookassa.ru/v3/payments/${paymentId}`, {
    headers: {
      Authorization: 'Basic ' + Buffer.from(`${YOOKASSA_SHOP_ID}:${YOOKASSA_SECRET_KEY}`).toString('base64'),
    },
  });
  if (!res.ok) throw new Error(`YooKassa fetch payment failed: ${res.status}`);
  return res.json();
}

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

// --- viewer submits a drawing: creates it as awaiting_payment, returns a YooKassa payment URL ---
// `free: true` skips payment entirely — temporary testing path, remove before real launch.
app.post('/api/drawings', asyncHandler(async (req, res) => {
  const { slug, image_data, free, caption, promo_code, sound_effect } = req.body;
  const duration_sec = promo_code ? PROMO_DURATION_SEC : req.body.duration_sec;
  const { rows } = await pool.query('SELECT * FROM streamers WHERE slug = $1', [slug]);
  const streamer = rows[0];
  if (!streamer) return res.status(404).json({ error: 'streamer not found' });
  if (!image_data) return res.status(400).json({ error: 'image_data required' });
  if (!Number.isInteger(duration_sec) || duration_sec < MIN_DURATION_SEC || duration_sec > MAX_DURATION_SEC) {
    return res.status(400).json({ error: 'недопустимая длительность показа' });
  }
  const captionText = (caption || '').slice(0, 20) || null;
  const soundEffect = SOUND_EFFECTS.includes(sound_effect) ? sound_effect : null;

  const id = genId();

  if (promo_code) {
    const code = promo_code.trim().toUpperCase();
    const { rows: promoRows } = await pool.query(
      "SELECT * FROM promo_codes WHERE streamer_id = $1 AND code = $2 AND status = 'active' AND used_at IS NULL",
      [streamer.id, code]
    );
    if (!promoRows[0]) return res.status(400).json({ error: 'Промокод недействителен или уже использован' });

    await pool.query('UPDATE promo_codes SET used_at = $1 WHERE id = $2', [Date.now(), promoRows[0].id]);
    await pool.query(
      `INSERT INTO drawings (id, streamer_id, image_data, duration_sec, amount, platform_fee, streamer_amount, status, caption, promo_code, sound_effect, created_at)
       VALUES ($1, $2, $3, $4, 0, 0, 0, 'pending', $5, $6, $7, $8)`,
      [id, streamer.id, image_data, duration_sec, captionText, code, soundEffect, Date.now()]
    );
    return res.json({ id, status: 'pending', free: true });
  }

  if (free) {
    await pool.query(
      `INSERT INTO drawings (id, streamer_id, image_data, duration_sec, amount, platform_fee, streamer_amount, status, caption, sound_effect, created_at)
       VALUES ($1, $2, $3, $4, 0, 0, 0, 'pending', $5, $6, $7)`,
      [id, streamer.id, image_data, duration_sec, captionText, soundEffect, Date.now()]
    );
    return res.json({ id, status: 'pending', free: true });
  }

  const amount = calcAmount(duration_sec);
  if (amount === null) return res.status(400).json({ error: 'недопустимая длительность показа' });

  if (!YOOKASSA_SHOP_ID || !YOOKASSA_SECRET_KEY) {
    return res.status(503).json({ error: 'Оплата временно не подключена' });
  }

  const platform_fee = Math.round(amount * PLATFORM_FEE_RATE);
  const streamer_amount = amount - platform_fee;

  await pool.query(
    `INSERT INTO drawings (id, streamer_id, image_data, duration_sec, amount, platform_fee, streamer_amount, status, caption, sound_effect, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'awaiting_payment', $8, $9, $10)`,
    [id, streamer.id, image_data, duration_sec, amount, platform_fee, streamer_amount, captionText, soundEffect, Date.now()]
  );

  let payment;
  try {
    payment = await createYookassaPayment({
      amount,
      description: `Донат для ${streamer.name} — рисунок на стриме`,
      drawingId: id,
      slug,
    });
  } catch (e) {
    await pool.query("UPDATE drawings SET status = 'payment_failed' WHERE id = $1", [id]);
    return res.status(502).json({ error: 'Не удалось создать платёж' });
  }

  await pool.query('UPDATE drawings SET payment_id = $1 WHERE id = $2', [payment.id, id]);
  res.json({ id, status: 'awaiting_payment', paymentUrl: payment.confirmation.confirmation_url });
}));

// --- YooKassa webhook: re-fetch payment by id from YooKassa itself to confirm authenticity ---
app.post('/api/payments/yookassa/webhook', asyncHandler(async (req, res) => {
  const paymentId = req.body && req.body.object && req.body.object.id;
  if (!paymentId) return res.status(400).end();

  let payment;
  try {
    payment = await fetchYookassaPayment(paymentId);
  } catch (e) {
    return res.status(502).end();
  }

  if (payment.status === 'succeeded') {
    await pool.query(
      "UPDATE drawings SET status = 'pending' WHERE payment_id = $1 AND status = 'awaiting_payment'",
      [paymentId]
    );
  } else if (payment.status === 'canceled') {
    await pool.query(
      "UPDATE drawings SET status = 'payment_failed' WHERE payment_id = $1 AND status = 'awaiting_payment'",
      [paymentId]
    );
  }

  res.status(200).end();
}));

// --- viewer polls this after returning from YooKassa to know if the drawing was accepted ---
app.get('/api/drawings/:id/status', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT status FROM drawings WHERE id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json({ status: rows[0].status });
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
  await pool.query("UPDATE drawings SET status = 'approved', queue_at = $1 WHERE id = $2", [Date.now(), rows[0].id]);
  res.json({ ok: true });
}));

app.post('/api/drawings/:id/reject', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM drawings WHERE id = $1 AND streamer_id = $2', [req.params.id, req.streamer.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  await pool.query("UPDATE drawings SET status = 'rejected' WHERE id = $1", [rows[0].id]);
  res.json({ ok: true });
}));

// --- streamer manually stops a currently-showing drawing ---
app.post('/api/drawings/:id/stop', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM drawings WHERE id = $1 AND streamer_id = $2 AND status = 'showing'",
    [req.params.id, req.streamer.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  await pool.query("UPDATE drawings SET status = 'shown', shown_until = NULL WHERE id = $1", [rows[0].id]);
  res.json({ ok: true });
}));

// --- streamer re-queues a previously shown drawing to display it again ---
app.post('/api/drawings/:id/replay', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM drawings WHERE id = $1 AND streamer_id = $2 AND status = 'shown'",
    [req.params.id, req.streamer.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  await pool.query("UPDATE drawings SET status = 'approved', queue_at = $1 WHERE id = $2", [Date.now(), rows[0].id]);
  res.json({ ok: true });
}));

// --- overlay: shows current drawing on stream, picks oldest queued approved-not-yet-shown ---
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
    // expire any drawing whose time ran out so it doesn't stay stuck in 'showing'
    await pool.query(
      "UPDATE drawings SET status = 'shown', shown_until = NULL WHERE streamer_id = $1 AND status = 'showing' AND shown_until <= $2",
      [streamer.id, now]
    );
    const { rows: nextRows } = await pool.query(
      "SELECT * FROM drawings WHERE streamer_id = $1 AND status = 'approved' ORDER BY COALESCE(queue_at, created_at) ASC LIMIT 1",
      [streamer.id]
    );
    const next = nextRows[0];
    if (next) {
      const shownUntil = now + next.duration_sec * 1000;
      await pool.query("UPDATE drawings SET status = 'showing', shown_until = $1 WHERE id = $2", [shownUntil, next.id]);
      active = { ...next, status: 'showing', shown_until: shownUntil };
    }
  }

  // atomically claim the next not-yet-played sound from a just-approved donation, so it fires exactly once
  const { rows: soundRows } = await pool.query(
    `UPDATE drawings SET sound_played = true
     WHERE id = (
       SELECT id FROM drawings
       WHERE streamer_id = $1 AND sound_effect IS NOT NULL AND sound_played = false
         AND status NOT IN ('pending', 'rejected', 'awaiting_payment', 'payment_failed')
       ORDER BY COALESCE(queue_at, created_at) ASC
       LIMIT 1
     )
     RETURNING sound_effect`,
    [streamer.id]
  );
  const sound = soundRows[0] ? soundRows[0].sound_effect : null;

  if (!active) return res.json({ drawing: null, sound });
  res.json({
    drawing: {
      id: active.id,
      image_data: active.image_data,
      caption: active.caption,
      shown_until: active.shown_until,
    },
    sound,
  });
}));

// --- balance: streamer's cut of paid drawings (excludes platform fee, rejected, unpaid) ---
async function getBalance(streamerId) {
  const { rows: earnedRows } = await pool.query(
    `SELECT COALESCE(SUM(streamer_amount), 0) AS total FROM drawings
     WHERE streamer_id = $1 AND status NOT IN ('rejected', 'awaiting_payment', 'payment_failed')`,
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

// --- promo codes: streamer-generated, redeemable for one free donation each ---
function genPromoCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

app.get('/api/promo-codes', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM promo_codes WHERE streamer_id = $1 ORDER BY created_at DESC',
    [req.streamer.id]
  );
  res.json(rows);
}));

app.post('/api/promo-codes', authStreamer, asyncHandler(async (req, res) => {
  const count = Math.min(Math.max(parseInt(req.body.count, 10) || 1, 1), 10);
  const created = [];
  for (let i = 0; i < count; i++) {
    const id = genId();
    const code = genPromoCode();
    await pool.query(
      "INSERT INTO promo_codes (id, streamer_id, code, status, created_at) VALUES ($1, $2, $3, 'active', $4)",
      [id, req.streamer.id, code, Date.now()]
    );
    created.push({ id, code, status: 'active' });
  }
  res.json(created);
}));

app.post('/api/promo-codes/:id/toggle', authStreamer, asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM promo_codes WHERE id = $1 AND streamer_id = $2', [req.params.id, req.streamer.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  const newStatus = rows[0].status === 'active' ? 'deactivated' : 'active';
  await pool.query('UPDATE promo_codes SET status = $1 WHERE id = $2', [newStatus, rows[0].id]);
  res.json({ ok: true, status: newStatus });
}));

app.delete('/api/promo-codes/:id', authStreamer, asyncHandler(async (req, res) => {
  await pool.query('DELETE FROM promo_codes WHERE id = $1 AND streamer_id = $2', [req.params.id, req.streamer.id]);
  res.json({ ok: true });
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
