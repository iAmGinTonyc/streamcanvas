const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

const app = express();
const db = new Database(path.join(__dirname, 'db', 'data.db'));

db.exec(`
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
    created_at INTEGER NOT NULL,
    shown_until INTEGER
  );
  CREATE TABLE IF NOT EXISTS payout_requests (
    id TEXT PRIMARY KEY,
    streamer_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at INTEGER NOT NULL,
    paid_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    streamer_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

// columns added after the initial release — ignore "already exists" errors
for (const stmt of [
  'ALTER TABLE streamers ADD COLUMN payout_phone TEXT',
  'ALTER TABLE streamers ADD COLUMN email TEXT',
  'ALTER TABLE streamers ADD COLUMN password_hash TEXT',
]) {
  try { db.exec(stmt); } catch (e) { /* column already exists */ }
}

const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';
const SESSION_COOKIE = 'sc_session';

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function genId() {
  return crypto.randomBytes(8).toString('hex');
}

// --- streamer signup with email + password ---
app.post('/api/streamers', (req, res) => {
  const { name, slug, payout_phone, email, password } = req.body;
  if (!name || !slug) return res.status(400).json({ error: 'name and slug required' });
  if (!payout_phone) return res.status(400).json({ error: 'payout_phone required (для ручного перевода по СБП)' });
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'пароль минимум 6 символов' });

  const id = genId();
  const password_hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare('INSERT INTO streamers (id, name, slug, email, password_hash, payout_phone) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, name, slug, email.toLowerCase(), password_hash, payout_phone);
  } catch (e) {
    return res.status(400).json({ error: 'slug или email уже занят' });
  }

  createSession(res, id);
  res.json({ id, name, slug, dashboardUrl: '/dashboard.html', donateUrl: `/draw.html?slug=${slug}` });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const streamer = db.prepare('SELECT * FROM streamers WHERE email = ?').get((email || '').toLowerCase());
  if (!streamer || !streamer.password_hash || !bcrypt.compareSync(password || '', streamer.password_hash)) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }
  createSession(res, streamer.id);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const sid = req.cookies[SESSION_COOKIE];
  if (sid) db.prepare('DELETE FROM sessions WHERE id = ?').run(sid);
  res.clearCookie(SESSION_COOKIE);
  res.json({ ok: true });
});

function createSession(res, streamerId) {
  const sid = genId() + genId();
  db.prepare('INSERT INTO sessions (id, streamer_id, created_at) VALUES (?, ?, ?)').run(sid, streamerId, Date.now());
  res.cookie(SESSION_COOKIE, sid, { httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000 });
}

function authStreamer(req, res, next) {
  const sid = req.cookies[SESSION_COOKIE];
  const session = sid && db.prepare('SELECT * FROM sessions WHERE id = ?').get(sid);
  const streamer = session && db.prepare('SELECT * FROM streamers WHERE id = ?').get(session.streamer_id);
  if (!streamer) return res.status(401).json({ error: 'not authenticated' });
  req.streamer = streamer;
  next();
}

app.get('/api/me', authStreamer, (req, res) => {
  res.json({ id: req.streamer.id, name: req.streamer.name, slug: req.streamer.slug });
});

app.get('/api/streamers/by-slug/:slug', (req, res) => {
  const streamer = db.prepare('SELECT id, name, slug FROM streamers WHERE slug = ?').get(req.params.slug);
  if (!streamer) return res.status(404).json({ error: 'not found' });
  res.json(streamer);
});

// --- viewer submits a drawing (payment not wired yet, amount is just stored) ---
app.post('/api/drawings', (req, res) => {
  const { slug, image_data, duration_sec, amount } = req.body;
  const streamer = db.prepare('SELECT * FROM streamers WHERE slug = ?').get(slug);
  if (!streamer) return res.status(404).json({ error: 'streamer not found' });
  if (!image_data) return res.status(400).json({ error: 'image_data required' });
  const id = genId();
  db.prepare(`
    INSERT INTO drawings (id, streamer_id, image_data, duration_sec, amount, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?)
  `).run(id, streamer.id, image_data, duration_sec || 60, amount || 0, Date.now());
  res.json({ id, status: 'pending' });
});

// --- dashboard: list drawings, optionally filtered by status ---
app.get('/api/drawings', authStreamer, (req, res) => {
  const status = req.query.status;
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 200);
  const rows = status
    ? db.prepare('SELECT * FROM drawings WHERE streamer_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?')
        .all(req.streamer.id, status, limit)
    : db.prepare('SELECT * FROM drawings WHERE streamer_id = ? ORDER BY created_at DESC LIMIT ?')
        .all(req.streamer.id, limit);
  res.json(rows);
});

app.post('/api/drawings/:id/approve', authStreamer, (req, res) => {
  const drawing = db.prepare('SELECT * FROM drawings WHERE id = ? AND streamer_id = ?').get(req.params.id, req.streamer.id);
  if (!drawing) return res.status(404).json({ error: 'not found' });
  db.prepare("UPDATE drawings SET status = 'approved' WHERE id = ?").run(drawing.id);
  res.json({ ok: true });
});

app.post('/api/drawings/:id/reject', authStreamer, (req, res) => {
  const drawing = db.prepare('SELECT * FROM drawings WHERE id = ? AND streamer_id = ?').get(req.params.id, req.streamer.id);
  if (!drawing) return res.status(404).json({ error: 'not found' });
  db.prepare("UPDATE drawings SET status = 'rejected' WHERE id = ?").run(drawing.id);
  res.json({ ok: true });
});

// --- overlay: shows current drawing on stream, picks oldest approved-not-yet-shown ---
app.get('/api/overlay/:slug/current', (req, res) => {
  const streamer = db.prepare('SELECT * FROM streamers WHERE slug = ?').get(req.params.slug);
  if (!streamer) return res.status(404).json({ error: 'not found' });

  const now = Date.now();
  let active = db.prepare("SELECT * FROM drawings WHERE streamer_id = ? AND status = 'showing' AND shown_until > ?")
    .get(streamer.id, now);

  if (!active) {
    const next = db.prepare("SELECT * FROM drawings WHERE streamer_id = ? AND status = 'approved' ORDER BY created_at ASC LIMIT 1")
      .get(streamer.id);
    if (next) {
      const shownUntil = now + next.duration_sec * 1000;
      db.prepare("UPDATE drawings SET status = 'showing', shown_until = ? WHERE id = ?").run(shownUntil, next.id);
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
});

// --- balance: earned (all non-rejected drawings) minus already requested/paid ---
function getBalance(streamerId) {
  const earned = db.prepare(`
    SELECT COALESCE(SUM(amount), 0) AS total FROM drawings
    WHERE streamer_id = ? AND status != 'rejected'
  `).get(streamerId).total;
  const requested = db.prepare(`
    SELECT COALESCE(SUM(amount), 0) AS total FROM payout_requests
    WHERE streamer_id = ?
  `).get(streamerId).total;
  return earned - requested;
}

app.get('/api/payout/balance', authStreamer, (req, res) => {
  res.json({ balance: getBalance(req.streamer.id) });
});

app.get('/api/payout/requests', authStreamer, (req, res) => {
  const rows = db.prepare('SELECT * FROM payout_requests WHERE streamer_id = ? ORDER BY requested_at DESC')
    .all(req.streamer.id);
  res.json(rows);
});

app.post('/api/payout/requests', authStreamer, (req, res) => {
  const balance = getBalance(req.streamer.id);
  if (balance <= 0) return res.status(400).json({ error: 'Баланс пуст' });
  const id = genId();
  db.prepare(`
    INSERT INTO payout_requests (id, streamer_id, amount, status, requested_at)
    VALUES (?, ?, ?, 'pending', ?)
  `).run(id, req.streamer.id, balance, Date.now());
  res.json({ id, amount: balance, status: 'pending' });
});

// --- admin: manual payouts, no automated money movement ---
function authAdmin(req, res, next) {
  const key = req.query.key || req.headers['x-admin-key'];
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'invalid admin key' });
  next();
}

app.get('/api/admin/payout-requests', authAdmin, (req, res) => {
  const status = req.query.status || 'pending';
  const rows = db.prepare(`
    SELECT pr.*, s.name AS streamer_name, s.slug, s.payout_phone
    FROM payout_requests pr
    JOIN streamers s ON s.id = pr.streamer_id
    WHERE pr.status = ?
    ORDER BY pr.requested_at ASC
  `).all(status);
  res.json(rows);
});

app.post('/api/admin/payout-requests/:id/mark-paid', authAdmin, (req, res) => {
  const reqRow = db.prepare('SELECT * FROM payout_requests WHERE id = ?').get(req.params.id);
  if (!reqRow) return res.status(404).json({ error: 'not found' });
  db.prepare("UPDATE payout_requests SET status = 'paid', paid_at = ? WHERE id = ?").run(Date.now(), reqRow.id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`streamcanvas running on http://localhost:${PORT}`));
