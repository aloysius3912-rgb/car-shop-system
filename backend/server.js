const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();

const ALLOWED_ORIGINS = [
  'https://car-shop-system-zho8.vercel.app',
  'http://localhost:3000',
];

app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: ALLOWED_ORIGINS }
});

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 10000,
      }
    : {
        user: 'postgres',
        host: 'localhost',
        database: 'postgres',
        password: process.env.LOCAL_DB_PASSWORD || 'changeme-local-only',
        port: 5432,
      }
);

// ── Staff accounts + session storage ──
// Auth is per-staff-member: each user has a username, bcrypt password hash,
// and a role ('Admin' or 'Technician'). Sessions live in the DB (survive
// Render cold starts) and carry the staff id + role.
const SESSION_TTL_HOURS = 12;

async function ensureAuthTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('Master', 'Admin', 'Technician')),
      can_add_member BOOLEAN DEFAULT true,
      can_delete_member BOOLEAN DEFAULT false,
      can_add_points BOOLEAN DEFAULT true,
      can_deduct_points BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  // Existing databases were created with a CHECK that only allowed
  // Admin/Technician — rebuild it so 'Master' is accepted.
  await pool.query(`ALTER TABLE staff_users DROP CONSTRAINT IF EXISTS staff_users_role_check;`);
  await pool.query(`ALTER TABLE staff_users ADD CONSTRAINT staff_users_role_check CHECK (role IN ('Master', 'Admin', 'Technician'));`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      staff_id INT REFERENCES staff_users(id) ON DELETE CASCADE,
      role TEXT,
      expires_at TIMESTAMP NOT NULL
    );
  `);
  // Telegram 2FA: chat id per staff member + a pending link code.
  await pool.query(`
    ALTER TABLE staff_users
      ADD COLUMN IF NOT EXISTS telegram_chat_id BIGINT,
      ADD COLUMN IF NOT EXISTS telegram_link_code TEXT,
      ADD COLUMN IF NOT EXISTS require_2fa BOOLEAN DEFAULT false;
  `);
  // Pending logins waiting on a 4-digit PIN (short-lived).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS login_challenges (
      challenge_token TEXT PRIMARY KEY,
      staff_id INT REFERENCES staff_users(id) ON DELETE CASCADE,
      pin_hash TEXT NOT NULL,
      attempts INT DEFAULT 0,
      expires_at TIMESTAMP NOT NULL
    );
  `);
  // Seed default owner accounts on first run (temp password from env or 'changeme-now').
  const count = await pool.query('SELECT COUNT(*) FROM staff_users');
  if (parseInt(count.rows[0].count) === 0) {
    const tempHash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'changeme-now', 12);
    await pool.query(
      `INSERT INTO staff_users (username, password_hash, role) VALUES
       ('aloysius', $1, 'Master'),
       ('kishen', $1, 'Master')`,
      [tempHash]
    );
    console.log('🔑 Seeded default Master accounts: aloysius, kishen (change passwords immediately).');
  }
}
ensureAuthTables().catch(err => console.error('Auth tables setup failed:', err.message));

// ── Physical-vehicle model ──
// A car is a physical thing that outlives its owners. `vehicles` holds the
// physical car (keyed by plate, NEVER deleted); `cars` stays as the ownership
// link (which member owns which vehicle right now); service history hangs off
// vehicle_id so it survives car deletion and member purges. All steps are
// idempotent and safe to run on every boot.
async function ensureVehicleModel() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vehicles (
      vehicle_id SERIAL PRIMARY KEY,
      plate      VARCHAR(50) NOT NULL,
      car_model  VARCHAR(100),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS vehicles_plate_unique ON vehicles (UPPER(plate));`);
  await pool.query(`ALTER TABLE cars ADD COLUMN IF NOT EXISTS vehicle_id INT REFERENCES vehicles(vehicle_id);`);
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS vehicle_id INT REFERENCES vehicles(vehicle_id);`);
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS served_member_name VARCHAR(100);`);

  // Backfill vehicles from every plate we already have on file.
  await pool.query(`
    INSERT INTO vehicles (plate, car_model)
    SELECT DISTINCT ON (UPPER(c.car_plate)) c.car_plate, c.car_model
      FROM cars c
     WHERE c.car_plate IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM vehicles v WHERE UPPER(v.plate) = UPPER(c.car_plate))
     ORDER BY UPPER(c.car_plate), c.car_id;
  `);
  // Link ownership rows to their vehicle.
  await pool.query(`
    UPDATE cars c SET vehicle_id = v.vehicle_id
      FROM vehicles v
     WHERE UPPER(v.plate) = UPPER(c.car_plate) AND c.vehicle_id IS NULL;
  `);
  // Point historical transactions at the vehicle, and snapshot the owner name.
  await pool.query(`
    UPDATE point_transactions t SET vehicle_id = c.vehicle_id
      FROM cars c
     WHERE t.car_id = c.car_id AND t.vehicle_id IS NULL;
  `);
  await pool.query(`
    UPDATE point_transactions t SET served_member_name = m.full_name
      FROM members m
     WHERE t.member_id = m.member_id AND t.served_member_name IS NULL;
  `);
  console.log('Vehicle model ready.');
}
ensureVehicleModel().catch(err => console.error('Vehicle model setup failed:', err.message));

// Find the physical vehicle for a plate, creating it if this plate is new.
// `db` can be the pool or a transaction client.
async function findOrCreateVehicle(db, plate, model) {
  if (!plate) return null;
  const norm = plate.trim().toUpperCase();
  const found = await db.query('SELECT vehicle_id FROM vehicles WHERE UPPER(plate) = $1', [norm]);
  if (found.rows.length) {
    if (model) {
      await db.query(
        'UPDATE vehicles SET car_model = COALESCE(car_model, $2) WHERE vehicle_id = $1',
        [found.rows[0].vehicle_id, model.trim()]
      );
    }
    return found.rows[0].vehicle_id;
  }
  const created = await db.query(
    'INSERT INTO vehicles (plate, car_model) VALUES ($1, $2) RETURNING vehicle_id',
    [norm, model ? model.trim() : null]
  );
  return created.rows[0].vehicle_id;
}

// ── Session helpers ──
async function createSession(staffId, role) {
  const token = crypto.randomUUID() + crypto.randomUUID();
  await pool.query(
    "INSERT INTO sessions (token, staff_id, role, expires_at) VALUES ($1, $2, $3, NOW() + ($4 || ' hours')::interval)",
    [token, staffId, role, String(SESSION_TTL_HOURS)]
  );
  return token;
}

// Returns { id, role, username } if the session is valid, else null.
async function getSessionUser(token) {
  if (!token) return null;
  const result = await pool.query(
    `SELECT s.staff_id AS id, s.role, u.username,
            u.can_add_member, u.can_delete_member, u.can_add_points, u.can_deduct_points
       FROM sessions s JOIN staff_users u ON u.id = s.staff_id
      WHERE s.token = $1 AND s.expires_at > NOW()`,
    [token]
  );
  return result.rows[0] || null;
}

// ── Telegram 2FA helpers ──
// Requires TELEGRAM_BOT_TOKEN env var (from @BotFather). If it's missing,
// 2FA silently degrades: accounts without a linked chat log in as before,
// and linking is disabled.
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const CHALLENGE_TTL_MINUTES = 5;
const CHALLENGE_MAX_ATTEMPTS = 5;

async function sendTelegram(chatId, text) {
  const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Telegram send failed (${res.status}): ${body}`);
  }
}

// ── Role hierarchy ──
// Master (owners) > Admin (shop manager) > Technician (installers).
// Rank comparisons drive who may manage whom.
const ROLE_RANK = { Master: 3, Admin: 2, Technician: 1 };
const VALID_ROLES = ['Master', 'Admin', 'Technician'];
const rank = (role) => ROLE_RANK[role] || 0;

// Can `requester` manage (edit/delete/reset/2FA) the `targetRole` account?
// Masters manage everyone. Admins manage Technicians only.
function canManageRole(requester, targetRole) {
  if (!requester) return false;
  if (requester.role === 'Master') return true;
  return requester.role === 'Admin' && targetRole === 'Technician';
}

// Admins implicitly have every permission; Technicians use their flags.
function can(user, permission) {
  if (!user) return false;
  if (user.role === 'Admin' || user.role === 'Master') return true;
  return user[permission] === true;
}

// Middleware factory: enforce a permission on a route.
function requirePermission(permission) {
  return (req, res, next) => {
    if (!can(req.user, permission)) {
      return res.status(403).json({ error: 'You do not have permission to do that.' });
    }
    next();
  };
}

// Clean out expired sessions + stale 2FA challenges occasionally (every hour)
setInterval(() => {
  pool.query('DELETE FROM sessions WHERE expires_at <= NOW()').catch(() => {});
  pool.query('DELETE FROM login_challenges WHERE expires_at <= NOW()').catch(() => {});
}, 60 * 60 * 1000);

// Auto-purge trashed members older than 30 days (runs hourly + once at startup).
async function purgeOldTrash() {
  try {
    const old = await pool.query(
      "SELECT member_id FROM members WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '30 days'"
    );
    for (const row of old.rows) {
      // Keep the service history: detach it from the member/car being purged
      // (vehicle_id + served_member_name snapshot preserve the physical car's record).
      await pool.query('UPDATE point_transactions SET member_id = NULL, car_id = NULL WHERE member_id = $1', [row.member_id]);
      await pool.query('DELETE FROM cars WHERE member_id = $1', [row.member_id]);
      await pool.query('DELETE FROM members WHERE member_id = $1', [row.member_id]);
    }
    if (old.rows.length) console.log(`🗑️  Auto-purged ${old.rows.length} member(s) older than 30 days.`);
  } catch (err) {
    console.error('Auto-purge failed:', err.message);
  }
}
setInterval(purgeOldTrash, 60 * 60 * 1000);
purgeOldTrash();

// ── Socket.IO authentication ──
io.use(async (socket, next) => {
  try {
    const user = await getSessionUser(socket.handshake.auth?.token);
    if (user) { socket.user = user; return next(); }
    next(new Error('unauthorized'));
  } catch (err) {
    next(new Error('unauthorized'));
  }
});

// ── Rate limiter for /api/login ──
const loginAttempts = new Map();
const LOGIN_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

function loginRateLimiter(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return next();
  }
  if (entry.count >= LOGIN_LIMIT) {
    const minutesLeft = Math.ceil((entry.resetAt - now) / 60000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${minutesLeft} minute(s).` });
  }
  entry.count += 1;
  next();
}

app.post('/api/login', loginRateLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const result = await pool.query(
      'SELECT id, username, password_hash, role, telegram_chat_id, require_2fa FROM staff_users WHERE LOWER(username) = LOWER($1)',
      [username.trim()]
    );
    const user = result.rows[0];
    // Compare against a dummy hash when user not found so response timing
    // doesn't reveal which usernames exist.
    const hash = user?.password_hash || '$2a$12$invalidinvalidinvalidinvaliduuuuuuuuuuuuuuuuuuuuuuuuu';
    const match = await bcrypt.compare(password, hash);
    if (user && match) {
      // ── Telegram 2FA branch ──
      // If this staff member has linked Telegram (and the bot is configured),
      // don't create a session yet: send a 4-digit PIN and return a short-lived
      // challenge token. The session is created in /api/login/verify-2fa.
      if (user.telegram_chat_id && TELEGRAM_BOT_TOKEN) {
        const pin = String(Math.floor(1000 + Math.random() * 9000)); // 1000–9999
        const pinHash = await bcrypt.hash(pin, 8);
        const challengeToken = crypto.randomUUID() + crypto.randomUUID();

        await pool.query(
          `INSERT INTO login_challenges (challenge_token, staff_id, pin_hash, expires_at)
           VALUES ($1, $2, $3, NOW() + ($4 || ' minutes')::interval)`,
          [challengeToken, user.id, pinHash, String(CHALLENGE_TTL_MINUTES)]
        );

        try {
          await sendTelegram(
            user.telegram_chat_id,
            `🔐 Car Shop login PIN: ${pin}\n\nExpires in ${CHALLENGE_TTL_MINUTES} minutes. If this wasn't you, ignore this message and consider changing your password.`
          );
        } catch (tgErr) {
          console.error('POST /api/login telegram error:', tgErr.message);
          await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
          return res.status(502).json({ error: 'Could not send the login PIN to Telegram. Please try again.' });
        }

        return res.json({ requires2fa: true, challengeToken, expiresInMinutes: CHALLENGE_TTL_MINUTES });
      }

      // No Telegram linked → normal single-factor login (unchanged behaviour).
      // If an Admin has flagged this account as requiring 2FA, tell the
      // frontend so it can push the user through linking right away.
      const token = await createSession(user.id, user.role);
      res.json({
        success: true, token, role: user.role, username: user.username,
        expiresInHours: SESSION_TTL_HOURS,
        mustLink2fa: !!user.require_2fa && !!TELEGRAM_BOT_TOKEN,
      });
    } else {
      res.status(401).json({ error: 'Incorrect username or password' });
    }
  } catch (err) {
    console.error('POST /api/login error:', err.message);
    res.status(500).json({ error: 'Login failed. Try again.' });
  }
});

// ── Verify the 4-digit PIN and complete login (public: user isn't logged in yet) ──
app.post('/api/login/verify-2fa', loginRateLimiter, async (req, res) => {
  const { challengeToken, pin } = req.body || {};
  if (!challengeToken || !/^\d{4}$/.test(String(pin || ''))) {
    return res.status(400).json({ error: 'Enter the 4-digit PIN.' });
  }
  try {
    const result = await pool.query(
      `SELECT c.challenge_token, c.staff_id, c.pin_hash, c.attempts, c.expires_at,
              u.role, u.username
         FROM login_challenges c
         JOIN staff_users u ON u.id = c.staff_id
        WHERE c.challenge_token = $1`,
      [challengeToken]
    );
    const ch = result.rows[0];

    if (!ch || new Date(ch.expires_at) <= new Date()) {
      if (ch) await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
      return res.status(401).json({ error: 'PIN expired. Please log in again.', restart: true });
    }
    if (ch.attempts >= CHALLENGE_MAX_ATTEMPTS) {
      await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
      return res.status(401).json({ error: 'Too many wrong PINs. Please log in again.', restart: true });
    }

    const match = await bcrypt.compare(String(pin), ch.pin_hash);
    if (!match) {
      await pool.query(
        'UPDATE login_challenges SET attempts = attempts + 1 WHERE challenge_token = $1',
        [challengeToken]
      );
      const left = CHALLENGE_MAX_ATTEMPTS - (ch.attempts + 1);
      if (left <= 0) {
        await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
        return res.status(401).json({ error: 'Too many wrong PINs. Please log in again.', restart: true });
      }
      return res.status(401).json({ error: `Wrong PIN. ${left} attempt${left !== 1 ? 's' : ''} left.` });
    }

    // Success: burn the challenge, then create a normal session.
    await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]);
    const token = await createSession(ch.staff_id, ch.role);
    res.json({ success: true, token, role: ch.role, username: ch.username, expiresInHours: SESSION_TTL_HOURS });
  } catch (err) {
    console.error('POST /api/login/verify-2fa error:', err.message);
    res.status(500).json({ error: 'Could not verify PIN. Please try again.' });
  }
});

app.use('/api', async (req, res, next) => {
  if (req.path === '/login' || req.path === '/login/verify-2fa') return next();
  try {
    const user = await getSessionUser(req.headers['x-admin-token']);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = user; // { id, role, username } available to every route
    next();
  } catch (err) {
    res.status(500).json({ error: 'Auth check failed' });
  }
});

// ── RBAC: only Admins and Masters may pass ──
function requireAdmin(req, res, next) {
  if (rank(req.user?.role) < ROLE_RANK.Admin) {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// ── RBAC: Masters only (owner-level actions) ──
function requireMaster(req, res, next) {
  if (req.user?.role !== 'Master') {
    return res.status(403).json({ error: 'Master (owner) access required.' });
  }
  next();
}

// ── Health check ──
app.get('/', (req, res) => {
  res.json({ status: 'Car Shop backend is running ✅' });
});

// ── Change password ──
app.post('/api/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 10) {
    return res.status(400).json({ error: 'New password must be at least 10 characters.' });
  }
  try {
    const result = await pool.query('SELECT password_hash FROM staff_users WHERE id = $1', [req.user.id]);
    const match = await bcrypt.compare(currentPassword || '', result.rows[0]?.password_hash || '');
    if (!match) return res.status(401).json({ error: 'Current password is incorrect.' });

    const newHash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE staff_users SET password_hash = $1 WHERE id = $2', [newHash, req.user.id]);
    // Invalidate this user's other sessions, keep them logged in with a fresh one.
    await pool.query('DELETE FROM sessions WHERE staff_id = $1', [req.user.id]);
    const token = await createSession(req.user.id, req.user.role);
    res.json({ success: true, token });
  } catch (err) {
    console.error('POST /api/change-password error:', err.message);
    res.status(500).json({ error: 'Could not change password.' });
  }
});

// ── Who am I (returns my role + permissions so the UI can adapt) ──
app.get('/api/me', (req, res) => {
  const u = req.user;
  res.json({
    id: u.id, username: u.username, role: u.role,
    permissions: {
      can_add_member: can(u, 'can_add_member'),
      can_delete_member: can(u, 'can_delete_member'),
      can_add_points: can(u, 'can_add_points'),
      can_deduct_points: can(u, 'can_deduct_points'),
    },
  });
});

// ── Telegram 2FA linking (any logged-in staff manages their own) ──

// Status: is the bot configured, and is MY account linked?
app.get('/api/telegram/status', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT telegram_chat_id, telegram_link_code, require_2fa FROM staff_users WHERE id = $1',
      [req.user.id]
    );
    const row = result.rows[0] || {};
    res.json({
      botConfigured: !!TELEGRAM_BOT_TOKEN,
      linked: !!row.telegram_chat_id,
      pendingCode: row.telegram_link_code || null,
      required: !!row.require_2fa,
    });
  } catch (err) {
    console.error('GET /api/telegram/status error:', err.message);
    res.status(500).json({ error: 'Could not load Telegram status.' });
  }
});

// Step 1: generate a one-time link code the staff member sends to the bot.
app.post('/api/telegram/link-code', async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) {
    return res.status(400).json({ error: 'Telegram bot is not configured on the server.' });
  }
  try {
    const code = 'CS-' + crypto.randomBytes(3).toString('hex').toUpperCase(); // e.g. CS-A3F91B
    await pool.query('UPDATE staff_users SET telegram_link_code = $1 WHERE id = $2', [code, req.user.id]);
    res.json({ success: true, code });
  } catch (err) {
    console.error('POST /api/telegram/link-code error:', err.message);
    res.status(500).json({ error: 'Could not create link code.' });
  }
});

// Step 2: after the staff member has sent the code to the bot in Telegram,
// they press "Confirm" — we scan recent bot messages for the code and
// capture the sender's chat id.
app.post('/api/telegram/confirm-link', async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) {
    return res.status(400).json({ error: 'Telegram bot is not configured on the server.' });
  }
  try {
    const result = await pool.query(
      'SELECT telegram_link_code FROM staff_users WHERE id = $1',
      [req.user.id]
    );
    const code = result.rows[0]?.telegram_link_code;
    if (!code) return res.status(400).json({ error: 'No pending link code. Generate one first.' });

    const tgRes = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?limit=100`);
    if (!tgRes.ok) throw new Error(`getUpdates ${tgRes.status}`);
    const data = await tgRes.json();

    // Newest first; match the exact code (case-insensitive, trimmed).
    const updates = (data.result || []).slice().reverse();
    const hit = updates.find(u => (u.message?.text || '').trim().toUpperCase() === code.toUpperCase());
    if (!hit) {
      return res.status(404).json({ error: `Code not received yet. In Telegram, send ${code} to the bot, then press Confirm again.` });
    }

    const chatId = hit.message.chat.id;
    await pool.query(
      'UPDATE staff_users SET telegram_chat_id = $1, telegram_link_code = NULL WHERE id = $2',
      [chatId, req.user.id]
    );
    await sendTelegram(chatId, `✅ Telegram linked to Car Shop staff account "${req.user.username}". You'll now receive a 4-digit PIN on every login.`).catch(() => {});
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/telegram/confirm-link error:', err.message);
    res.status(500).json({ error: 'Could not confirm the link. Please try again.' });
  }
});

// Unlink: turns 2FA off for this account (password required, so a stolen
// session token alone can't silently remove 2FA).
app.post('/api/telegram/unlink', async (req, res) => {
  const { password } = req.body || {};
  try {
    const result = await pool.query('SELECT password_hash, telegram_chat_id, require_2fa FROM staff_users WHERE id = $1', [req.user.id]);
    const row = result.rows[0];
    if (!row?.telegram_chat_id) return res.status(400).json({ error: 'Telegram is not linked.' });
    if (row.require_2fa && req.user.role !== 'Master') {
      return res.status(403).json({ error: '2FA is required for your account and cannot be disabled. Ask a Master to remove it.' });
    }
    const match = await bcrypt.compare(password || '', row.password_hash || '');
    if (!match) return res.status(401).json({ error: 'Password is incorrect.' });

    await pool.query(
      'UPDATE staff_users SET telegram_chat_id = NULL, telegram_link_code = NULL WHERE id = $1',
      [req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/telegram/unlink error:', err.message);
    res.status(500).json({ error: 'Could not unlink Telegram.' });
  }
});

// ── Staff management (Admin only) ──
app.get('/api/staff', requireAdmin, async (req, res) => {
  try {
    // Master accounts are invisible to everyone below Master — Admins and
    // Technicians shouldn't even know owner accounts exist.
    const hideMasters = req.user.role !== 'Master' ? "WHERE role <> 'Master'" : '';
    const result = await pool.query(
      `SELECT id, username, role, can_add_member, can_delete_member,
              can_add_points, can_deduct_points, created_at,
              require_2fa, (telegram_chat_id IS NOT NULL) AS telegram_linked
         FROM staff_users ${hideMasters} ORDER BY created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/staff error:', err.message);
    res.status(500).json({ error: 'Could not load staff.' });
  }
});

app.post('/api/staff', requireAdmin, async (req, res) => {
  const { username, password, role, permissions } = req.body;
  if (!username || !username.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (!password || password.length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
  // Only a Master may create Admin or Master accounts. Admins create Technicians.
  if (role !== 'Technician' && req.user.role !== 'Master') {
    return res.status(403).json({ error: 'Only a Master can create Admin or Master accounts.' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const p = permissions || {};
    const result = await pool.query(
      `INSERT INTO staff_users (username, password_hash, role, can_add_member, can_delete_member, can_add_points, can_deduct_points)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, username, role, can_add_member, can_delete_member, can_add_points, can_deduct_points, created_at`,
      [username.trim(), hash, role, !!p.can_add_member, !!p.can_delete_member, !!p.can_add_points, !!p.can_deduct_points]
    );
    res.json({ success: true, staff: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'That username is already taken.' });
    console.error('POST /api/staff error:', err.message);
    res.status(500).json({ error: 'Could not create staff account.' });
  }
});

app.put('/api/staff/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { role, permissions } = req.body;
  const p = permissions || {};
  try {
    if (role && !VALID_ROLES.includes(role)) {
      return res.status(400).json({ error: 'Invalid role.' });
    }
    const targetRes = await pool.query('SELECT role FROM staff_users WHERE id = $1', [id]);
    const targetRole = targetRes.rows[0]?.role;
    if (!targetRole) return res.status(404).json({ error: 'Staff member not found.' });

    // Admins may only manage Technicians; Masters manage everyone.
    if (!canManageRole(req.user, targetRole)) {
      return res.status(403).json({ error: 'You cannot manage that account.' });
    }
    // Promoting to Admin/Master is a Master-only action.
    if (role && role !== 'Technician' && role !== targetRole && req.user.role !== 'Master') {
      return res.status(403).json({ error: 'Only a Master can assign Admin or Master roles.' });
    }
    // Never demote the last Master — that would orphan owner control.
    if (targetRole === 'Master' && role && role !== 'Master') {
      const masters = await pool.query("SELECT COUNT(*) FROM staff_users WHERE role = 'Master'");
      if (parseInt(masters.rows[0].count) <= 1) {
        return res.status(400).json({ error: 'Cannot demote the last Master account.' });
      }
    }

    await pool.query(
      `UPDATE staff_users
          SET role = COALESCE($2, role),
              can_add_member = $3, can_delete_member = $4,
              can_add_points = $5, can_deduct_points = $6
        WHERE id = $1`,
      [id, role || null, !!p.can_add_member, !!p.can_delete_member, !!p.can_add_points, !!p.can_deduct_points]
    );
    // Changing permissions takes effect on their next request via getSessionUser.
    res.json({ success: true });
  } catch (err) {
    console.error('PUT /api/staff error:', err.message);
    res.status(500).json({ error: 'Could not update staff account.' });
  }
});

// ── Guard: the requester must outrank the target account ──
// Loads the target staff row and rejects Admins acting on Admin/Master
// accounts. Attaches req.targetStaff for the route to use.
async function requireManageTarget(req, res, next) {
  try {
    const result = await pool.query('SELECT id, username, role FROM staff_users WHERE id = $1', [req.params.id]);
    const target = result.rows[0];
    if (!target) return res.status(404).json({ error: 'Staff member not found.' });
    if (!canManageRole(req.user, target.role)) {
      return res.status(403).json({ error: 'You cannot manage that account.' });
    }
    req.targetStaff = target;
    next();
  } catch (err) {
    console.error('requireManageTarget error:', err.message);
    res.status(500).json({ error: 'Could not verify staff account.' });
  }
}

// ── Admin: require (or stop requiring) Telegram 2FA for a staff member ──
// "Required" means: once linked they can't unlink themselves, and until
// they link, the app pushes them through setup on every login.
app.post('/api/staff/:id/require-2fa', requireAdmin, requireManageTarget, async (req, res) => {
  const { id } = req.params;
  const { required } = req.body || {};
  try {
    const result = await pool.query(
      'UPDATE staff_users SET require_2fa = $2 WHERE id = $1 RETURNING id',
      [id, !!required]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Staff member not found.' });
    res.json({ success: true, required: !!required });
  } catch (err) {
    console.error('POST /api/staff require-2fa error:', err.message);
    res.status(500).json({ error: 'Could not update 2FA requirement.' });
  }
});

// ── Admin: forcibly remove a staff member's Telegram link ──
// (e.g. they lost their phone / changed Telegram account). Their sessions
// are wiped so the change takes effect immediately.
app.post('/api/staff/:id/unlink-telegram', requireAdmin, requireManageTarget, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'UPDATE staff_users SET telegram_chat_id = NULL, telegram_link_code = NULL WHERE id = $1 RETURNING username',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Staff member not found.' });
    await pool.query('DELETE FROM sessions WHERE staff_id = $1', [id]); // force re-login
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/staff unlink-telegram error:', err.message);
    res.status(500).json({ error: 'Could not unlink Telegram for that account.' });
  }
});

app.post('/api/staff/:id/reset-password', requireAdmin, requireManageTarget, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 10) {
    return res.status(400).json({ error: 'Password must be at least 10 characters.' });
  }
  try {
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE staff_users SET password_hash = $1 WHERE id = $2', [hash, id]);
    await pool.query('DELETE FROM sessions WHERE staff_id = $1', [id]); // force re-login
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/staff reset-password error:', err.message);
    res.status(500).json({ error: 'Could not reset password.' });
  }
});

app.delete('/api/staff/:id', requireAdmin, requireManageTarget, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  try {
    // Don't allow deleting the last Master — owner control must survive.
    if (req.targetStaff.role === 'Master') {
      const masters = await pool.query("SELECT COUNT(*) FROM staff_users WHERE role = 'Master'");
      if (parseInt(masters.rows[0].count) <= 1) {
        return res.status(400).json({ error: 'Cannot delete the last Master account.' });
      }
    }
    await pool.query('DELETE FROM staff_users WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/staff error:', err.message);
    res.status(500).json({ error: 'Could not delete staff account.' });
  }
});

// ── Fetch ALL members with their cars ──
app.get('/api/members', async (req, res) => {
  try {
    const membersResult = await pool.query('SELECT * FROM members WHERE deleted_at IS NULL ORDER BY full_name ASC');
    const carsResult = await pool.query('SELECT * FROM cars ORDER BY car_id ASC');

    // Group cars by member_id
    const carsMap = {};
    for (const car of carsResult.rows) {
      if (!carsMap[car.member_id]) carsMap[car.member_id] = [];
      carsMap[car.member_id].push(car);
    }

    const members = membersResult.rows.map(m => ({
      ...m,
      cars: carsMap[m.member_id] || [],
    }));

    res.json(members);
  } catch (err) {
    console.error('GET /api/members error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Register a new member with their first car ──
app.post('/api/new-member', requirePermission('can_add_member'), async (req, res) => {
  const { fullName, carPlate, carModel } = req.body;
  if (!fullName || !fullName.trim()) {
    return res.status(400).json({ error: 'Full name is required' });
  }
  try {
    // Check for duplicate plate in cars table
    const normalizedPlate = carPlate ? carPlate.trim().toUpperCase() : null;
    if (normalizedPlate) {
      const existing = await pool.query(
        'SELECT cars.car_id, members.full_name FROM cars JOIN members ON cars.member_id = members.member_id WHERE UPPER(cars.car_plate) = $1',
        [normalizedPlate]
      );
      if (existing.rows.length > 0) {
        return res.status(409).json({
          error: `Plate ${normalizedPlate} is already registered to ${existing.rows[0].full_name}`,
        });
      }
    }

    // Insert member
    const memberResult = await pool.query(
      'INSERT INTO members (full_name, total_points, date_joined) VALUES ($1, 0, NOW()) RETURNING *',
      [fullName.trim()]
    );
    const newMember = memberResult.rows[0];

    // Insert first car, linked to its physical vehicle (find-or-create by plate).
    let cars = [];
    if (normalizedPlate || carModel) {
      const vehicleId = await findOrCreateVehicle(pool, normalizedPlate, carModel);
      const carResult = await pool.query(
        'INSERT INTO cars (member_id, car_plate, car_model, vehicle_id) VALUES ($1, $2, $3, $4) RETURNING *',
        [newMember.member_id, normalizedPlate, carModel ? carModel.trim() : null, vehicleId]
      );
      cars = carResult.rows;
    }

    const memberWithCars = { ...newMember, cars };
    io.emit('memberAdded', memberWithCars);
    res.json({ success: true, member: memberWithCars });
  } catch (err) {
    console.error('POST /api/new-member error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Add a car to an existing member ──
app.post('/api/add-car/:memberId', async (req, res) => {
  const { memberId } = req.params;
  const { carPlate, carModel } = req.body;

  try {
    const normalizedPlate = carPlate ? carPlate.trim().toUpperCase() : null;

    // Check for duplicate plate
    if (normalizedPlate) {
      const existing = await pool.query(
        'SELECT cars.car_id, members.full_name FROM cars JOIN members ON cars.member_id = members.member_id WHERE UPPER(cars.car_plate) = $1',
        [normalizedPlate]
      );
      if (existing.rows.length > 0) {
        return res.status(409).json({
          error: `Plate ${normalizedPlate} is already registered to ${existing.rows[0].full_name}`,
        });
      }
    }

    const vehicleId = await findOrCreateVehicle(pool, normalizedPlate, carModel);
    const result = await pool.query(
      'INSERT INTO cars (member_id, car_plate, car_model, vehicle_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [memberId, normalizedPlate, carModel ? carModel.trim() : null, vehicleId]
    );

    const newCar = result.rows[0];
    io.emit('carAdded', { memberId: parseInt(memberId), car: newCar });
    res.json({ success: true, car: newCar });
  } catch (err) {
    console.error('POST /api/add-car error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Delete a car ──
app.delete('/api/delete-car/:carId', async (req, res) => {
  const { carId } = req.params;
  try {
    // Detach this car's transactions from the ownership row before deleting it.
    // vehicle_id still carries the full service history for the physical car,
    // so selling/removing a car never destroys what was installed on it.
    await pool.query('UPDATE point_transactions SET car_id = NULL WHERE car_id = $1', [carId]);
    const result = await pool.query(
      'DELETE FROM cars WHERE car_id = $1 RETURNING member_id',
      [carId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Car not found' });
    }
    io.emit('carDeleted', { carId: parseInt(carId), memberId: result.rows[0].member_id });
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/delete-car error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Add or deduct points ──
app.post('/api/add-points', async (req, res) => {
  const { memberId, points, description, carId } = req.body;
  const numericPoints = parseInt(points, 10) || 0;

  // Enforce add vs deduct permission based on the sign of the points.
  const perm = numericPoints < 0 ? 'can_deduct_points' : 'can_add_points';
  if (!can(req.user, perm)) {
    return res.status(403).json({ error: `You do not have permission to ${numericPoints < 0 ? 'deduct' : 'add'} points.` });
  }

  // car_id only applies to earning (a service done on a specific car).
  // For deductions (redemptions) it stays null.
  const carIdToLog = numericPoints >= 0 && carId ? parseInt(carId, 10) : null;

  // Everything runs on ONE client inside a transaction so the balance
  // update and the history log either both happen or neither does.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Atomic conditional update: the WHERE clause enforces "never below zero"
    // in the same statement as the update, so concurrent requests can't
    // both slip past a separate balance check (no check-then-act race).
    const result = await client.query(
      `UPDATE members
         SET total_points = COALESCE(total_points, 0) + $1
       WHERE member_id = $2
         AND COALESCE(total_points, 0) + $1 >= 0
       RETURNING total_points`,
      [numericPoints, memberId]
    );

    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      // Distinguish "member missing" from "not enough points" for a clear message
      const check = await pool.query(
        'SELECT total_points FROM members WHERE member_id = $1',
        [memberId]
      );
      if (check.rows.length === 0) {
        return res.status(404).json({ error: 'Member not found' });
      }
      const current = check.rows[0].total_points || 0;
      return res.status(400).json({
        error: `Not enough points! Member has ${current} pts, cannot deduct ${Math.abs(numericPoints)} pts.`,
      });
    }

    // Resolve the physical vehicle (durable history spine) and snapshot the
    // owner's name so the record stays meaningful even after a member purge.
    let vehicleIdToLog = null;
    if (carIdToLog) {
      const vq = await client.query('SELECT vehicle_id FROM cars WHERE car_id = $1', [carIdToLog]);
      vehicleIdToLog = vq.rows[0]?.vehicle_id || null;
    }
    const nameQ = await client.query('SELECT full_name FROM members WHERE member_id = $1', [memberId]);
    const servedName = nameQ.rows[0]?.full_name || null;

    const txResult = await client.query(
      `INSERT INTO point_transactions (member_id, points_added, description, staff_id, car_id, vehicle_id, served_member_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING transaction_id, points_added, description, transaction_date, staff_id, car_id`,
      [memberId, numericPoints, description, req.user.id, carIdToLog, vehicleIdToLog, servedName]
    );

    await client.query('COMMIT');

    const newTotal = result.rows[0].total_points;
    io.emit('pointsUpdated', { memberId, newTotal });
    io.emit('transactionAdded', { memberId, transaction: txResult.rows[0] });
    res.json({ success: true, newTotal });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('POST /api/add-points error:', err.message);
    res.status(500).json({ error: 'Could not update points. Please try again.' });
  } finally {
    client.release();
  }
});

// ── Fetch transaction history ──
app.get('/api/transactions/:memberId', async (req, res) => {
  const { memberId } = req.params;
  try {
    const result = await pool.query(
      `SELECT t.transaction_id, t.points_added, t.description, t.transaction_date,
              u.username AS staff_name,
              c.car_plate, c.car_model
         FROM point_transactions t
         LEFT JOIN staff_users u ON u.id = t.staff_id
         LEFT JOIN cars c ON c.car_id = t.car_id
        WHERE t.member_id = $1
        ORDER BY t.transaction_date DESC LIMIT 50`,
      [memberId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/transactions error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Car service history by plate ──
// The whole point of the vehicles table: search a physical plate and see
// every service ever done on it, across all owners and years, even if the
// original owner has been deleted. Any logged-in staff can look this up.
// Returns a flat array of services (newest first); [] if the plate is
// unknown or has no services yet.
app.get('/api/car-history/:plate', async (req, res) => {
  const plate = (req.params.plate || '').trim().toUpperCase();
  if (!plate) return res.status(400).json({ error: 'Plate is required.' });
  try {
    const result = await pool.query(
      `SELECT t.transaction_id, t.transaction_date, t.description, t.points_added,
              u.username AS staff_name,
              t.served_member_name AS owner_at_the_time
         FROM point_transactions t
         JOIN vehicles v ON v.vehicle_id = t.vehicle_id
         LEFT JOIN staff_users u ON u.id = t.staff_id
        WHERE UPPER(v.plate) = $1
        ORDER BY t.transaction_date DESC`,
      [plate]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/car-history error:', err.message);
    res.status(500).json({ error: 'Could not load car history.' });
  }
});

// ── Delete a member ──
// ── Soft delete: move member to the trash bin (reversible for 30 days) ──
app.delete('/api/delete-member/:id', requirePermission('can_delete_member'), async (req, res) => {
  const memberId = req.params.id;
  try {
    await pool.query('UPDATE members SET deleted_at = NOW() WHERE member_id = $1', [memberId]);
    io.emit('memberDeleted', { memberId: parseInt(memberId) });
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/delete-member error:', err.message);
    res.status(500).json({ error: 'Could not delete member.' });
  }
});

// ── Trash bin: list soft-deleted members (with days remaining) ──
app.get('/api/trash', requirePermission('can_delete_member'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*,
              GREATEST(0, 30 - EXTRACT(DAY FROM NOW() - m.deleted_at))::int AS days_left
         FROM members m
        WHERE m.deleted_at IS NOT NULL
        ORDER BY m.deleted_at DESC`
    );
    // attach cars so the trash view can show plates
    const ids = result.rows.map(r => r.member_id);
    let carsMap = {};
    if (ids.length) {
      const cars = await pool.query('SELECT * FROM cars WHERE member_id = ANY($1)', [ids]);
      for (const c of cars.rows) {
        (carsMap[c.member_id] = carsMap[c.member_id] || []).push(c);
      }
    }
    res.json(result.rows.map(m => ({ ...m, cars: carsMap[m.member_id] || [] })));
  } catch (err) {
    console.error('GET /api/trash error:', err.message);
    res.status(500).json({ error: 'Could not load trash.' });
  }
});

// ── Restore a member from the trash ──
app.post('/api/restore-member/:id', requirePermission('can_delete_member'), async (req, res) => {
  const memberId = req.params.id;
  try {
    const result = await pool.query(
      'UPDATE members SET deleted_at = NULL WHERE member_id = $1 AND deleted_at IS NOT NULL RETURNING *',
      [memberId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Member not in trash.' });
    // re-fetch cars so the restored card is complete
    const cars = await pool.query('SELECT * FROM cars WHERE member_id = $1', [memberId]);
    const restored = { ...result.rows[0], cars: cars.rows };
    io.emit('memberAdded', restored); // reappears in everyone's list
    res.json({ success: true, member: restored });
  } catch (err) {
    console.error('POST /api/restore-member error:', err.message);
    res.status(500).json({ error: 'Could not restore member.' });
  }
});

// ── Permanently delete a member (from trash, Admin-gated via permission) ──
app.delete('/api/purge-member/:id', requirePermission('can_delete_member'), async (req, res) => {
  const memberId = req.params.id;
  try {
    // Detach (don't destroy) service history — vehicle_id keeps the physical
    // car's record alive, and served_member_name preserves who it was for.
    await pool.query('UPDATE point_transactions SET member_id = NULL, car_id = NULL WHERE member_id = $1', [memberId]);
    await pool.query('DELETE FROM cars WHERE member_id = $1', [memberId]);
    await pool.query('DELETE FROM members WHERE member_id = $1 AND deleted_at IS NOT NULL', [memberId]);
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/purge-member error:', err.message);
    res.status(500).json({ error: 'Could not permanently delete member.' });
  }
});

const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🗄️  Database: ${process.env.DATABASE_URL ? 'Neon PostgreSQL' : 'Local Docker'}`);
});