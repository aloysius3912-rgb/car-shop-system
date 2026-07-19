const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { z } = require('zod');
// node-cron is optional: if it isn't installed we fall back to a setInterval
// scheduler so the point-expiry job still runs. (Run: npm install node-cron)
let cron = null;
try { cron = require('node-cron'); }
catch { console.warn('node-cron not installed — using setInterval fallback for the daily expiry job. Run: npm install node-cron'); }

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
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  // Migration for existing installs (pre-existing rows get the deploy time,
  // which self-corrects as those 12-hour sessions expire).
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();`);
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
  // Challenges double as password-reset PINs; purpose keeps the two flows
  // strictly separate (a reset PIN can't complete a login and vice versa).
  // pin_verified marks a reset challenge whose PIN has been accepted, gating
  // the set-new-password step.
  await pool.query(`ALTER TABLE login_challenges ADD COLUMN IF NOT EXISTS purpose TEXT DEFAULT 'login';`);
  await pool.query(`ALTER TABLE login_challenges ADD COLUMN IF NOT EXISTS pin_verified BOOLEAN DEFAULT false;`);
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
  // Fraud interceptor: frozen members can't earn or redeem until unfrozen.
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN DEFAULT false;`);
  // Fraud interceptor: a staff account that trips the interceptor is disabled
  // (can't log in or make requests) until a Master re-enables it.
  await pool.query(`ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT false;`);
  // Quarantine review: 'pending' until a Master approves/rejects; NULL = normal tx.
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS quarantine_status TEXT;`);
  // Contact number for reaching the customer.
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS phone VARCHAR(30);`);
  // One-hour typo window: edits keep an audit trail of the original value.
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS original_points INT;`);
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS edited_at TIMESTAMP;`);
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS edited_by INT REFERENCES staff_users(id);`);
  // Full edit trail: one row per edit, so every change is attributable.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS point_edit_log (
      id SERIAL PRIMARY KEY,
      transaction_id INT REFERENCES point_transactions(transaction_id) ON DELETE CASCADE,
      old_points INT NOT NULL,
      new_points INT NOT NULL,
      edited_by INT REFERENCES staff_users(id),
      edited_at TIMESTAMP DEFAULT NOW()
    );
  `);

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
  // Snapshot the serviced car's plate/model onto each transaction so the history
  // keeps its detail even after the car is removed (car_id gets nulled on delete,
  // but the transaction should still show what the points were for). Backfill
  // from the live car if it still exists, else from the durable vehicle record.
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS served_car_plate VARCHAR(30);`);
  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS served_car_model VARCHAR(100);`);
  await pool.query(`
    UPDATE point_transactions t
       SET served_car_plate = COALESCE(c.car_plate, v.plate),
           served_car_model = COALESCE(c.car_model, v.car_model)
      FROM point_transactions base
      LEFT JOIN cars c     ON c.car_id = base.car_id
      LEFT JOIN vehicles v ON v.vehicle_id = base.vehicle_id
     WHERE base.transaction_id = t.transaction_id
       AND t.served_car_plate IS NULL
       AND COALESCE(c.car_plate, v.plate) IS NOT NULL;
  `);
  console.log('Vehicle model ready.');
}
ensureVehicleModel().catch(err => console.error('Vehicle model setup failed:', err.message));

// ── Operational tables: Master audit trail + idempotency keys ──
// system_audit_logs: an append-only record of every sensitive non-point action
//   (member/car/staff deletes, staff changes, settings) — who, what, when.
// idempotency_keys: dedupe accidental double-submits (spotty shop Wi-Fi / double
//   taps). A client sends a per-submission UUID; a repeat within the window is
//   ignored and the first response is replayed.
async function ensureOpsTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS system_audit_logs (
      id          SERIAL PRIMARY KEY,
      staff_id    INT,
      username    TEXT,
      action_type TEXT NOT NULL,
      target_id   TEXT,
      detail      TEXT,
      ip          TEXT,
      created_at  TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS system_audit_logs_created_idx ON system_audit_logs (created_at DESC);`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS idempotency_keys (
      idempotency_key TEXT PRIMARY KEY,
      staff_id        INT,
      route           TEXT,
      status_code     INT,
      response        JSONB,
      created_at      TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Ops tables ready (audit log + idempotency).');
  // The expiry engine records system transactions with no staff_id, so make
  // sure the column allows NULL (harmless no-op if it already does).
  await pool.query(`ALTER TABLE point_transactions ALTER COLUMN staff_id DROP NOT NULL;`)
    .catch(e => console.warn('staff_id nullability check skipped:', e.message));
  // Track who soft-deleted a member (for the /trash_bin oversight command).
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS deleted_by TEXT;`);
  // Backfill deleted_by for members already in the trash, using the newest
  // DELETE_MEMBER audit entry for each (no-op once every row is populated).
  await pool.query(`
    UPDATE members m
       SET deleted_by = a.username
      FROM (
        SELECT DISTINCT ON (target_id) target_id, username
          FROM system_audit_logs
         WHERE action_type = 'DELETE_MEMBER'
         ORDER BY target_id, created_at DESC
      ) a
     WHERE m.member_id::text = a.target_id
       AND m.deleted_at IS NOT NULL
       AND m.deleted_by IS NULL
  `).catch(e => console.warn('deleted_by backfill skipped:', e.message));
}
ensureOpsTables().catch(err => console.error('Ops tables setup failed:', err.message));

// ── Guarantee a member can't hold the same plate twice ──
// The app-level "is this plate taken?" check is check-then-insert, so two
// near-simultaneous adds (double-tap / "Add anyway" fired twice / network
// retry) can both pass it and both insert. A partial unique index makes the DB
// itself reject the second write. First we collapse any duplicates that already
// slipped in, repointing their transactions to the surviving row so no service
// history is lost, then we create the index.
async function ensureCarUniqueness() {
  // 1a) Move transactions off soon-to-be-removed duplicate rows onto the keeper.
  await pool.query(`
    WITH ranked AS (
      SELECT car_id,
             MIN(car_id) OVER (PARTITION BY member_id, UPPER(car_plate)) AS keep_id
        FROM cars
       WHERE car_plate IS NOT NULL
    )
    UPDATE point_transactions t
       SET car_id = r.keep_id
      FROM ranked r
     WHERE t.car_id = r.car_id AND r.car_id <> r.keep_id
  `);
  // 1b) Delete the duplicate rows, keeping the oldest (lowest car_id) per group.
  const del = await pool.query(`
    DELETE FROM cars c
     USING (
       SELECT car_id,
              MIN(car_id) OVER (PARTITION BY member_id, UPPER(car_plate)) AS keep_id
         FROM cars
        WHERE car_plate IS NOT NULL
     ) d
     WHERE c.car_id = d.car_id AND d.car_id <> d.keep_id
  `);
  if (del.rowCount) console.log(`Car de-dupe: removed ${del.rowCount} duplicate car row(s).`);
  // 2) Enforce one plate per member (case-insensitive) from here on.
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS cars_member_plate_uniq
      ON cars (member_id, UPPER(car_plate))
      WHERE car_plate IS NOT NULL
  `);
  console.log('Car uniqueness index ready (one plate per member).');
}
ensureCarUniqueness().catch(err => console.error('Car uniqueness setup failed:', err.message));

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
    `SELECT s.staff_id AS id, s.role, u.username, u.is_disabled,
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

async function sendTelegram(chatId, text, replyMarkup = null) {
  const body = { chat_id: chatId, text };
  if (replyMarkup) body.reply_markup = replyMarkup;
  const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const resBody = await res.text().catch(() => '');
    throw new Error(`Telegram send failed (${res.status}): ${resBody}`);
  }
}

// Acknowledge a button tap (clears the loading spinner on the user's phone).
async function answerTelegramCallback(callbackQueryId, text = '') {
  await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query_id: callbackQueryId, text }),
  }).catch(e => console.error('answerCallbackQuery failed:', e.message));
}

// Rewrite an existing bot message (used to strike the buttons after a decision).
async function editTelegramMessage(chatId, messageId, text) {
  await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/editMessageText`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, message_id: messageId, text }),
  }).catch(e => console.error('editMessageText failed:', e.message));
}

// ── Customer-facing bot ──
const SHOP_NAME = 'Dats Auto';
// Voucher tiers in points (mirror the redeem presets in the app).
const REWARD_TIERS = [
  { points: 50, label: '$5 voucher' },
  { points: 100, label: '$10 voucher' },
  { points: 200, label: '$20 voucher' },
  { points: 500, label: '$50 voucher' },
];

function rewardProgress(balance) {
  const next = REWARD_TIERS.find(t => t.points > balance);
  if (next) return `You are ${next.points - balance} points away from a ${next.label}.`;
  return `You have enough to redeem our top ${REWARD_TIERS[REWARD_TIERS.length - 1].label} — come by any time!`;
}

// ── Shop settings (simple key/value; used for Master-controlled toggles) ──
async function ensureShopSettings() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shop_settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  await pool.query(
    `INSERT INTO shop_settings (key, value) VALUES ('admins_receive_eod_reports', 'false')
     ON CONFLICT (key) DO NOTHING`
  );
}
ensureShopSettings().catch(err => console.error('Shop settings setup failed:', err.message));

async function getSetting(key) {
  const r = await pool.query('SELECT value FROM shop_settings WHERE key = $1', [key]);
  return r.rows[0]?.value ?? null;
}
async function setSetting(key, value) {
  await pool.query(
    `INSERT INTO shop_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [key, String(value)]
  );
}

// Answer a "/points <plate>" query with the current owner's balance + progress.
async function handlePointsQuery(chatId, plateRaw) {
  const plate = (plateRaw || '').trim().toUpperCase();
  if (!plate) {
    await sendTelegram(chatId, `Please include your car plate, e.g.\n/points SBA1234A`);
    return;
  }
  const r = await pool.query(
    `SELECT m.full_name, m.total_points
       FROM cars c
       JOIN members m ON m.member_id = c.member_id AND m.deleted_at IS NULL
      WHERE UPPER(c.car_plate) = $1
      ORDER BY c.car_id DESC LIMIT 1`,
    [plate]
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, `We couldn't find an active membership for plate ${plate}. Please check the plate, or ask our staff to register you at your next visit.`);
    return;
  }
  const { full_name, total_points } = r.rows[0];
  const bal = Number(total_points) || 0;
  await sendTelegram(chatId,
    `Hi ${full_name}! Your car ${plate} has ${bal.toLocaleString()} points available.\n${rewardProgress(bal)}`);
}

// ── Staff bot commands (role-gated) ──

// /lookup <plate> — durable service history of a physical car (all staff).
async function handleLookupCommand(chatId, plateRaw) {
  const plate = (plateRaw || '').trim().toUpperCase();
  if (!plate) { await sendTelegram(chatId, 'Usage: /lookup SBA1234A'); return; }
  const r = await pool.query(
    `SELECT t.transaction_date, t.description, t.points_added,
            t.served_member_name, u.username AS staff_name
       FROM point_transactions t
       JOIN vehicles v ON v.vehicle_id = t.vehicle_id
       LEFT JOIN staff_users u ON u.id = t.staff_id
      WHERE UPPER(v.plate) = $1
      ORDER BY t.transaction_date DESC
      LIMIT 15`,
    [plate]
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, `No service history on record for ${plate}.`);
    return;
  }
  const lines = r.rows.map(t => {
    const d = new Date(t.transaction_date).toLocaleDateString('en-SG', { day: 'numeric', month: 'short', year: 'numeric' });
    const who = t.served_member_name ? ` — ${t.served_member_name}` : '';
    const by = t.staff_name ? ` (by ${t.staff_name})` : '';
    return `• ${d}: ${t.description || 'Service'}${who}${by}`;
  });
  await sendTelegram(chatId, `Service history for ${plate} (latest ${r.rows.length}):\n\n${lines.join('\n')}`);
}

// /customer <name> — profile, balance, cars (Admin and Master only).
async function handleCustomerCommand(chatId, nameRaw) {
  const name = (nameRaw || '').trim();
  if (!name) { await sendTelegram(chatId, 'Usage: /customer David Lim'); return; }
  const r = await pool.query(
    `SELECT m.member_id, m.full_name, m.total_points, m.date_joined, m.phone
       FROM members m
      WHERE m.deleted_at IS NULL AND m.full_name ILIKE '%' || $1 || '%'
      ORDER BY m.full_name ASC
      LIMIT 5`,
    [name]
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, `No active customer matching "${name}".`);
    return;
  }
  const blocks = [];
  for (const m of r.rows) {
    const carsQ = await pool.query(
      'SELECT car_plate, car_model FROM cars WHERE member_id = $1 ORDER BY car_id ASC',
      [m.member_id]
    );
    const cars = carsQ.rows.length
      ? carsQ.rows.map(c => `${(c.car_plate || '(no plate)').toUpperCase()}${c.car_model ? ` (${c.car_model})` : ''}`).join(', ')
      : 'no cars on file';
    const joined = new Date(m.date_joined).toLocaleDateString('en-SG', { day: 'numeric', month: 'short', year: 'numeric' });
    blocks.push(`${m.full_name}\nPoints: ${(Number(m.total_points) || 0).toLocaleString()}\nJoined: ${joined}\nContact: ${m.phone || 'not on file'}\nCars: ${cars}`);
  }
  await sendTelegram(chatId, blocks.join('\n\n———\n\n'));
}

// Shared stats over a window of N days (1 = today only), SG timezone.
async function fetchPeriodStats(days) {
  const stats = await pool.query(`
    WITH win AS (
      SELECT ((NOW() AT TIME ZONE 'Asia/Singapore')::date - ($1::int - 1)) AS start_d
    )
    SELECT
      (SELECT COUNT(DISTINCT t.vehicle_id) FROM point_transactions t, win
        WHERE t.points_added > 0 AND t.vehicle_id IS NOT NULL
          AND (t.transaction_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date >= win.start_d)::int AS cars_serviced,

      (SELECT COALESCE(SUM(t.points_added), 0) FROM point_transactions t, win
        WHERE t.points_added > 0
          AND COALESCE(t.description, '') !~* '(void|reject)'
          AND (t.transaction_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date >= win.start_d)::int AS points_issued,

      (SELECT COALESCE(SUM(-t.points_added), 0) FROM point_transactions t, win
        WHERE t.points_added < 0
          AND COALESCE(t.description, '') !~* '(void|reject|reverse)'
          AND (t.transaction_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date >= win.start_d)::int AS points_redeemed,

      (SELECT COUNT(*) FROM members m, win
        WHERE (m.date_joined AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date >= win.start_d)::int AS new_customers,

      (SELECT COALESCE(SUM(t.points_added), 0) FROM point_transactions t
        JOIN members m ON m.member_id = t.member_id AND m.is_frozen = true, win
        WHERE t.points_added > 0
          AND (t.transaction_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date >= win.start_d)::int AS flagged_points,

      (SELECT COUNT(*) FROM point_transactions t, win
        WHERE COALESCE(t.description, '') ~* '(void|reject|reverse)'
          AND (t.transaction_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date >= win.start_d)::int AS fraudulent_transactions
  `, [days]);
  return stats.rows[0];
}

function formatStatsMessage(title, s) {
  return (
    `${title}\n\n` +
    `Cars serviced: ${s.cars_serviced.toLocaleString()}\n` +
    `Points issued: ${s.points_issued.toLocaleString()}\n` +
    `Points redeemed: ${s.points_redeemed.toLocaleString()}\n` +
    `New customers: ${s.new_customers.toLocaleString()}\n\n` +
    `⚠️ Security & Audits:\n` +
    `Flagged points (frozen): ${s.flagged_points.toLocaleString()}\n` +
    `Rejected/Voided actions: ${s.fraudulent_transactions.toLocaleString()}`
  );
}

// /eod — today's numbers (Admin only when toggled; Master always).
async function handleEodCommand(chatId) {
  const s = await fetchPeriodStats(1);
  const dateLabel = new Date().toLocaleDateString('en-SG', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Singapore' });
  await sendTelegram(chatId, formatStatsMessage(`End-of-Day Report — ${dateLabel}`, s));
}

// /week and /month — same stats over rolling 7- and 30-day windows.
async function handlePeriodCommand(chatId, days, label) {
  const s = await fetchPeriodStats(days);
  await sendTelegram(chatId, formatStatsMessage(`${label} Report — last ${days} days`, s));
}

// /find <partial> — fuzzy plate search for when only part of a plate is known.
async function handleFindCommand(chatId, partialRaw) {
  const partial = (partialRaw || '').trim().toUpperCase();
  if (partial.length < 2) { await sendTelegram(chatId, 'Usage: /find SJL2 (at least 2 characters)'); return; }
  const r = await pool.query(
    `SELECT v.plate, v.car_model,
            m.full_name AS owner,
            (SELECT COUNT(*)::int FROM point_transactions t WHERE t.vehicle_id = v.vehicle_id) AS service_count
       FROM vehicles v
       LEFT JOIN cars c ON c.vehicle_id = v.vehicle_id
       LEFT JOIN members m ON m.member_id = c.member_id AND m.deleted_at IS NULL
      WHERE UPPER(v.plate) LIKE '%' || $1 || '%'
      ORDER BY v.plate ASC
      LIMIT 8`,
    [partial]
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, `No plates matching "${partial}".`);
    return;
  }
  const lines = r.rows.map(v =>
    `• ${v.plate}${v.car_model ? ` (${v.car_model})` : ''} — ${v.owner || 'no active owner'} — ${v.service_count} service${v.service_count !== 1 ? 's' : ''}`);
  await sendTelegram(chatId, `Plates matching "${partial}" (${r.rows.length}):\n\n${lines.join('\n')}\n\nUse /lookup <plate> for full history.`);
}

// /today — cars already serviced today (SG time). Read-only.
// (Renamed from /queue: without a check-in or booking system this is a
// rear-view list of completed work, not a live waiting queue.)
async function handleTodayCommand(chatId) {
  const r = await pool.query(`
    SELECT v.plate, v.car_model,
           MAX(t.transaction_date) AS last_activity,
           COUNT(*)::int AS services_today,
           STRING_AGG(DISTINCT t.served_member_name, ', ') AS owners
      FROM point_transactions t
      JOIN vehicles v ON v.vehicle_id = t.vehicle_id
     WHERE t.points_added > 0
       AND (t.transaction_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date
           = (NOW() AT TIME ZONE 'Asia/Singapore')::date
     GROUP BY v.vehicle_id, v.plate, v.car_model
     ORDER BY MAX(t.transaction_date) DESC`);
  if (r.rows.length === 0) {
    await sendTelegram(chatId, 'No cars serviced yet today.');
    return;
  }
  const lines = r.rows.map(row => {
    const time = new Date(row.last_activity).toLocaleTimeString('en-SG', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Singapore' });
    return `• ${row.plate}${row.car_model ? ` (${row.car_model})` : ''} — ${row.services_today} service${row.services_today !== 1 ? 's' : ''}, last at ${time}${row.owners ? ` — ${row.owners}` : ''}`;
  });
  await sendTelegram(chatId, `Today's serviced vehicles (${r.rows.length}):\n\n${lines.join('\n')}`);
}

// /whois <plate> — quick context on a car before working on it. Read-only.
async function handleWhoisCommand(chatId, plateRaw) {
  const plate = (plateRaw || '').trim().toUpperCase();
  if (!plate) { await sendTelegram(chatId, 'Usage: /whois SBA1234A'); return; }
  const r = await pool.query(
    `SELECT v.plate, v.car_model,
            m.full_name AS owner, m.total_points,
            (SELECT COUNT(*)::int FROM point_transactions t WHERE t.vehicle_id = v.vehicle_id) AS service_count
       FROM vehicles v
       LEFT JOIN cars c ON c.vehicle_id = v.vehicle_id
       LEFT JOIN members m ON m.member_id = c.member_id AND m.deleted_at IS NULL
      WHERE UPPER(v.plate) = $1
      ORDER BY c.car_id DESC NULLS LAST
      LIMIT 1`,
    [plate]
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, `No vehicle on file for ${plate}.`);
    return;
  }
  const row = r.rows[0];
  await sendTelegram(chatId,
    `${row.plate}${row.car_model ? ` — ${row.car_model}` : ''}\n` +
    `Owner: ${row.owner || 'no active owner on file'}` +
    (row.owner ? ` (${(Number(row.total_points) || 0).toLocaleString()} pts)` : '') + `\n` +
    `Services on record: ${row.service_count}`);
}

// /leaderboard — top 5 customers by points. Read-only. Admin+.
async function handleLeaderboardCommand(chatId) {
  const r = await pool.query(
    `SELECT full_name, total_points FROM members
      WHERE deleted_at IS NULL
      ORDER BY total_points DESC NULLS LAST, full_name ASC
      LIMIT 5`);
  if (r.rows.length === 0) { await sendTelegram(chatId, 'No customers on file yet.'); return; }
  const medals = ['1.', '2.', '3.', '4.', '5.'];
  const lines = r.rows.map((m, i) => `${medals[i]} ${m.full_name} — ${(Number(m.total_points) || 0).toLocaleString()} pts`);
  await sendTelegram(chatId, `Top customers by points:\n\n${lines.join('\n')}`);
}

// /tx <plate> — last 3 transactions incl. transaction_id (for voiding on the
// dashboard). Read-only. Admin+.
async function handleTxCommand(chatId, plateRaw) {
  const plate = (plateRaw || '').trim().toUpperCase();
  if (!plate) { await sendTelegram(chatId, 'Usage: /tx SBA1234A'); return; }
  const r = await pool.query(
    `SELECT t.transaction_id, t.transaction_date, t.description, t.points_added,
            u.username AS staff_name
       FROM point_transactions t
       JOIN vehicles v ON v.vehicle_id = t.vehicle_id
       LEFT JOIN staff_users u ON u.id = t.staff_id
      WHERE UPPER(v.plate) = $1
      ORDER BY t.transaction_date DESC
      LIMIT 3`,
    [plate]
  );
  if (r.rows.length === 0) { await sendTelegram(chatId, `No transactions on record for ${plate}.`); return; }
  const lines = r.rows.map(t => {
    const d = new Date(t.transaction_date).toLocaleString('en-SG', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Singapore' });
    const sign = t.points_added >= 0 ? '+' : '';
    return `#${t.transaction_id} · ${d}\n${t.description || 'Service'} · ${sign}${t.points_added} pts${t.staff_name ? ` · by ${t.staff_name}` : ''}`;
  });
  await sendTelegram(chatId, `Last ${r.rows.length} transactions for ${plate}:\n\n${lines.join('\n\n')}`);
}

// /staff — all staff, roles, 2FA link status. Read-only. Master only.
async function handleStaffListCommand(chatId) {
  const r = await pool.query(
    `SELECT username, role, (telegram_chat_id IS NOT NULL) AS linked
       FROM staff_users ORDER BY
       CASE role WHEN 'Master' THEN 0 WHEN 'Admin' THEN 1 ELSE 2 END, username ASC`);
  const lines = r.rows.map(s => `• ${s.username} — ${s.role} — 2FA ${s.linked ? 'linked' : 'NOT linked'}`);
  await sendTelegram(chatId, `Staff (${r.rows.length}):\n\n${lines.join('\n')}`);
}

// /audit <username> — last 10 point actions by that staff member. Master only.
async function handleAuditCommand(chatId, usernameRaw) {
  const username = (usernameRaw || '').trim();
  if (!username) { await sendTelegram(chatId, 'Usage: /audit aloysius'); return; }
  const staffQ = await pool.query('SELECT id, username FROM staff_users WHERE LOWER(username) = LOWER($1)', [username]);
  if (staffQ.rows.length === 0) { await sendTelegram(chatId, `No staff member named "${username}".`); return; }
  const staff = staffQ.rows[0];
  const r = await pool.query(
    `SELECT t.transaction_id, t.transaction_date, t.description, t.points_added,
            t.served_member_name, v.plate
       FROM point_transactions t
       LEFT JOIN vehicles v ON v.vehicle_id = t.vehicle_id
      WHERE t.staff_id = $1
      ORDER BY t.transaction_date DESC
      LIMIT 10`,
    [staff.id]
  );
  if (r.rows.length === 0) { await sendTelegram(chatId, `${staff.username} has no point transactions on record.`); return; }
  const lines = r.rows.map(t => {
    const d = new Date(t.transaction_date).toLocaleString('en-SG', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Singapore' });
    const sign = t.points_added >= 0 ? '+' : '';
    return `#${t.transaction_id} · ${d} · ${sign}${t.points_added} pts · ${t.description || 'Service'}${t.plate ? ` · ${t.plate}` : ''}${t.served_member_name ? ` · ${t.served_member_name}` : ''}`;
  });
  await sendTelegram(chatId, `Last ${r.rows.length} point actions by ${staff.username}:\n\n${lines.join('\n')}`);
}

// /backup — row-count health check. Read-only. Master only.
async function handleBackupCommand(chatId) {
  const r = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM members)::int AS members,
      (SELECT COUNT(*) FROM members WHERE deleted_at IS NULL)::int AS active_members,
      (SELECT COUNT(*) FROM vehicles)::int AS vehicles,
      (SELECT COUNT(*) FROM cars)::int AS ownership_links,
      (SELECT COUNT(*) FROM point_transactions)::int AS transactions,
      (SELECT COUNT(*) FROM staff_users)::int AS staff
  `);
  const s = r.rows[0];
  await sendTelegram(chatId,
    `System health — row counts:\n\n` +
    `Members: ${s.members} (${s.active_members} active)\n` +
    `Vehicles: ${s.vehicles}\n` +
    `Ownership links: ${s.ownership_links}\n` +
    `Transactions: ${s.transactions}\n` +
    `Staff: ${s.staff}`);
}

// /floor_check — who is live on the dashboard right now. Read-only. Master only.
// A "live" staff member is anyone holding an unexpired session token.
async function handleFloorCheckCommand(chatId) {
  const r = await pool.query(
    `SELECT DISTINCT ON (u.id) u.username, u.role, s.created_at
       FROM sessions s
       JOIN staff_users u ON u.id = s.staff_id
      WHERE s.expires_at > NOW()
      ORDER BY u.id, s.created_at DESC`
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, 'No one is currently logged in to the dashboard.');
    return;
  }
  const rank = { Master: 0, Admin: 1, Technician: 2 };
  const rows = r.rows.sort((a, b) => (rank[a.role] ?? 3) - (rank[b.role] ?? 3) || a.username.localeCompare(b.username));
  const sgNow = new Date().toLocaleDateString('en-SG', { timeZone: 'Asia/Singapore' });
  const lines = rows.map(s => {
    const d = new Date(s.created_at);
    const sameDay = d.toLocaleDateString('en-SG', { timeZone: 'Asia/Singapore' }) === sgNow;
    const since = sameDay
      ? d.toLocaleTimeString('en-SG', { hour: 'numeric', minute: '2-digit', timeZone: 'Asia/Singapore' })
      : d.toLocaleString('en-SG', { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit', timeZone: 'Asia/Singapore' });
    return `🟢 ${s.username} (${s.role}) — Active since ${since}`;
  });
  await sendTelegram(chatId, `Live on Dashboard (${rows.length}):\n\n${lines.join('\n')}`);
}

// Format a timestamp as "Today 4:00 PM" / "Yesterday 11:00 AM" / "3 Jul 4:00 PM"
// in Singapore time — used by the auditor commands.
function sgRelativeDateTime(dateStr) {
  const d = new Date(dateStr);
  const opts = { timeZone: 'Asia/Singapore' };
  const now = new Date();
  const dayStr = d.toLocaleDateString('en-SG', opts);
  const todayStr = now.toLocaleDateString('en-SG', opts);
  const yestStr = new Date(now.getTime() - 24 * 3600 * 1000).toLocaleDateString('en-SG', opts);
  const time = d.toLocaleTimeString('en-SG', { hour: 'numeric', minute: '2-digit', timeZone: 'Asia/Singapore' });
  let label;
  if (dayStr === todayStr) label = 'Today';
  else if (dayStr === yestStr) label = 'Yesterday';
  else label = d.toLocaleDateString('en-SG', { day: 'numeric', month: 'short', timeZone: 'Asia/Singapore' });
  return `${label} ${time}`;
}

// /trending — inventory radar: what accessories moved in the last 7 days.
// Groups earning (points_added > 0) descriptions with light fuzzy normalisation
// so "Dashcam Bundle" and "dashcam bundle install" count together. Admin+.
async function handleTrendingCommand(chatId) {
  const r = await pool.query(
    `SELECT description
       FROM point_transactions
      WHERE transaction_date > NOW() - INTERVAL '7 days'
        AND points_added > 0
        AND description IS NOT NULL AND TRIM(description) <> ''`
  );
  // Descriptions that aren't accessories — don't let them pollute the radar.
  const IGNORE = new Set(['manual adjustment', 'adjustment', 'service', 'top up', 'topup']);
  const FILLER = /\b(install(ation|ed|s)?|fitting|fitted|setup|set up|done|service|job|for|the|a|x\d+)\b/g;
  const counts = new Map();  // key -> { label, n }
  for (const row of r.rows) {
    const raw = row.description.trim();
    let key = raw.toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')   // drop punctuation
      .replace(FILLER, ' ')            // strip filler words
      .replace(/\s+/g, ' ')            // collapse spaces
      .trim();
    if (!key || IGNORE.has(key) || key.startsWith('system')) continue;
    const label = key.replace(/\b\w/g, c => c.toUpperCase()); // Title Case
    const cur = counts.get(key) || { label, n: 0 };
    cur.n += 1;
    counts.set(key, cur);
  }
  const top = [...counts.values()].sort((a, b) => b.n - a.n).slice(0, 5);
  if (top.length === 0) {
    await sendTelegram(chatId, '📈 No accessory installs logged in the last 7 days.');
    return;
  }
  const lines = top.map((t, i) => `${i + 1}. ${t.label} (${t.n} install${t.n === 1 ? '' : 's'})`);
  await sendTelegram(chatId, `📈 Top Accessories This Week:\n${lines.join('\n')}`);
}

// /whales — top 3 customers by points SPENT (redeemed) in the last 30 days.
// Excludes system expiry and void/reject/reverse entries. Admin+.
async function handleWhalesCommand(chatId) {
  const r = await pool.query(
    `SELECT m.full_name, SUM(-t.points_added)::int AS spent
       FROM point_transactions t
       JOIN members m ON m.member_id = t.member_id
      WHERE t.transaction_date > NOW() - INTERVAL '30 days'
        AND t.points_added < 0
        AND m.deleted_at IS NULL
        AND COALESCE(t.description,'') NOT ILIKE 'System:%'
        AND COALESCE(t.description,'') NOT ILIKE '%void%'
        AND COALESCE(t.description,'') NOT ILIKE '%reject%'
        AND COALESCE(t.description,'') NOT ILIKE '%reverse%'
      GROUP BY m.member_id, m.full_name
      HAVING SUM(-t.points_added) > 0
      ORDER BY spent DESC
      LIMIT 3`
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, '👑 No point redemptions in the last 30 days yet.');
    return;
  }
  const lines = r.rows.map((m, i) => `${i + 1}. ${m.full_name} — ${(Number(m.spent) || 0).toLocaleString()} pts`);
  await sendTelegram(chatId, `👑 30-Day VIPs:\n${lines.join('\n')}`);
}

// /voided — mistake tracker: transactions in the last 48h whose description
// mentions void/reject/reverse, with who did it and their role. Master only.
async function handleVoidedCommand(chatId) {
  const r = await pool.query(
    `SELECT t.transaction_date, t.description, u.username, u.role
       FROM point_transactions t
       LEFT JOIN staff_users u ON u.id = t.staff_id
      WHERE t.transaction_date > NOW() - INTERVAL '48 hours'
        AND (t.description ILIKE '%void%' OR t.description ILIKE '%reject%' OR t.description ILIKE '%reverse%')
      ORDER BY t.transaction_date DESC
      LIMIT 25`
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, '⚠️ No voided/reversed transactions in the last 48 hours.');
    return;
  }
  const lines = r.rows.map(t => {
    const who = t.username ? `${t.username} (${t.role})` : 'system';
    return `• ${sgRelativeDateTime(t.transaction_date)}: '${t.description}' by ${who}.`;
  });
  await sendTelegram(chatId, `⚠️ Recent Voids:\n${lines.join('\n')}`);
}

// /trash_bin — deletion log: members in 30-day soft-delete, who deleted them,
// and how long until permanent purge. Master only.
async function handleTrashBinCommand(chatId) {
  const r = await pool.query(
    `SELECT full_name, deleted_by,
            GREATEST(0, 30 - EXTRACT(DAY FROM NOW() - deleted_at))::int AS days_left
       FROM members
      WHERE deleted_at IS NOT NULL
      ORDER BY deleted_at ASC`
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, '🗑️ The trash is empty — no accounts pending deletion.');
    return;
  }
  const lines = r.rows.map(m =>
    `• ${m.full_name} (Deleted by ${m.deleted_by || 'unknown'} - ${m.days_left} day${m.days_left === 1 ? '' : 's'} left)`
  );
  await sendTelegram(chatId, `🗑️ Accounts pending permanent deletion:\n${lines.join('\n')}`);
}

// /review — all of today's transactions (SG time) for the Master to eyeball.
// LEFT JOINs staff + members so it still reads well after purges. Master only.
async function handleReviewCommand(chatId) {
  const r = await pool.query(
    `SELECT t.transaction_id, t.transaction_date, t.points_added, t.description,
            COALESCE(m.full_name, t.served_member_name, '—') AS customer_name,
            u.username AS staff_name
       FROM point_transactions t
       LEFT JOIN members m ON m.member_id = t.member_id
       LEFT JOIN staff_users u ON u.id = t.staff_id
      WHERE (t.transaction_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Singapore')::date
            = (NOW() AT TIME ZONE 'Asia/Singapore')::date
      ORDER BY t.transaction_date ASC`
  );
  if (r.rows.length === 0) {
    await sendTelegram(chatId, 'No transactions to review today.');
    return;
  }
  const lines = r.rows.map(t => {
    const time = new Date(t.transaction_date).toLocaleTimeString('en-SG', { hour: 'numeric', minute: '2-digit', timeZone: 'Asia/Singapore' });
    const sign = t.points_added >= 0 ? '+' : '';
    const staff = t.staff_name || 'system';
    return `${time} · #${t.transaction_id} · ${sign}${t.points_added} pts · ${t.customer_name} · by ${staff} · ${t.description || 'Service'}`;
  });
  await sendTelegram(chatId, `📋 Today's Transactions (${r.rows.length}):\n\n${lines.join('\n')}`);
}

// Route a message from a verified staff member, gated by their exact role.
async function handleStaffMessage(chatId, staff, text) {
  const parts = text.trim().split(/\s+/);
  const cmd = (parts[0] || '').toLowerCase().replace(/@.+$/, ''); // strip @BotName
  const arg = parts.slice(1).join(' ');
  const isAdminPlus = staff.role === 'Admin' || staff.role === 'Master';
  const isMaster = staff.role === 'Master';

  switch (cmd) {
    case '/lookup':
      await handleLookupCommand(chatId, arg);
      return;

    case '/today':
      await handleTodayCommand(chatId);
      return;

    case '/queue': // old name — point people at the new one
      await sendTelegram(chatId, 'This command is now /today (it lists cars already serviced today).');
      return;

    case '/whois':
      await handleWhoisCommand(chatId, arg);
      return;

    case '/find':
      await handleFindCommand(chatId, arg);
      return;

    case '/customer':
      if (!isAdminPlus) {
        await sendTelegram(chatId, 'You do not have permission to use /customer.');
        return;
      }
      await handleCustomerCommand(chatId, arg);
      return;

    case '/leaderboard':
      if (!isAdminPlus) {
        await sendTelegram(chatId, 'You do not have permission to use /leaderboard.');
        return;
      }
      await handleLeaderboardCommand(chatId);
      return;

    case '/tx':
      if (!isAdminPlus) {
        await sendTelegram(chatId, 'You do not have permission to use /tx.');
        return;
      }
      await handleTxCommand(chatId, arg);
      return;

    case '/staff':
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /staff.');
        return;
      }
      await handleStaffListCommand(chatId);
      return;

    case '/audit':
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /audit.');
        return;
      }
      await handleAuditCommand(chatId, arg);
      return;

    case '/floor_check':
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /floor_check.');
        return;
      }
      await handleFloorCheckCommand(chatId);
      return;

    case '/backup':
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /backup.');
        return;
      }
      await handleBackupCommand(chatId);
      return;

    case '/eod':
    case '/week':
    case '/month': {
      if (!isAdminPlus) {
        await sendTelegram(chatId, `You do not have permission to use ${cmd}.`);
        return;
      }
      if (!isMaster) {
        const allowed = (await getSetting('admins_receive_eod_reports')) === 'true';
        if (!allowed) {
          await sendTelegram(chatId, 'Reports for Admins are currently disabled by the Master.');
          return;
        }
      }
      if (cmd === '/eod') await handleEodCommand(chatId);
      else if (cmd === '/week') await handlePeriodCommand(chatId, 7, 'Weekly');
      else await handlePeriodCommand(chatId, 30, 'Monthly');
      return;
    }

    case '/toggle_reports': {
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /toggle_reports.');
        return;
      }
      const current = (await getSetting('admins_receive_eod_reports')) === 'true';
      await setSetting('admins_receive_eod_reports', !current);
      await sendTelegram(chatId, `Admin EOD reports are now ${!current ? 'ON' : 'OFF'}.`);
      return;
    }

    case '/trending':
      if (!isAdminPlus) {
        await sendTelegram(chatId, 'You do not have permission to use /trending.');
        return;
      }
      await handleTrendingCommand(chatId);
      return;

    case '/whales':
      if (!isAdminPlus) {
        await sendTelegram(chatId, 'You do not have permission to use /whales.');
        return;
      }
      await handleWhalesCommand(chatId);
      return;

    case '/voided':
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /voided.');
        return;
      }
      await handleVoidedCommand(chatId);
      return;

    case '/review':
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /review.');
        return;
      }
      await handleReviewCommand(chatId);
      return;

    case '/trash_bin':
      if (!isMaster) {
        await sendTelegram(chatId, 'Only the Master can use /trash_bin.');
        return;
      }
      await handleTrashBinCommand(chatId);
      return;

    case '/start':
    case '/help': {
      const lines = [
        `Staff commands (${staff.role}):`,
        '/lookup <plate> — service history of a car',
        '/find <partial> — fuzzy plate search (e.g. /find SJL2)',
        '/today — vehicles serviced today',
        '/whois <plate> — quick owner/car context',
      ];
      if (isAdminPlus) {
        lines.push('/customer <name> — customer profile, points, cars');
        lines.push('/leaderboard — top 5 customers by points');
        lines.push('/tx <plate> — last 3 transactions with IDs');
        lines.push('/trending — top accessories installed this week');
        lines.push('/whales — top 3 spenders (last 30 days)');
        lines.push('/eod, /week, /month — reports' + (isMaster ? '' : ' (if enabled by Master)'));
      }
      if (isMaster) {
        lines.push('/floor_check — who is logged in right now');
        lines.push('/staff — all staff + 2FA status');
        lines.push('/audit <username> — last 10 point actions by a staff member');
        lines.push('/voided — void/reject/reverse entries (last 48h)');
        lines.push('/review — all of today\'s transactions');
        lines.push('/trash_bin — members pending permanent deletion');
        lines.push('/backup — row-count health check');
        lines.push('/toggle_reports — enable/disable Admin EOD reports');
      }
      await sendTelegram(chatId, lines.join('\n'));
      return;
    }

    default:
      await sendTelegram(chatId, `Unrecognised staff command. Send /help to see what you can use.`);
  }
}

// Process one incoming Telegram update (message).
async function processTelegramUpdate(update) {
  // ── Inline button taps (quarantine Approve/Reject) ──
  if (update.callback_query) {
    const cb = update.callback_query;
    const chatId = cb.message?.chat?.id;
    const data = cb.data || '';
    try {
      // Bouncer: only a chat linked to a MASTER may action these buttons.
      const staffQ = await pool.query(
        `SELECT id, username, role FROM staff_users WHERE telegram_chat_id = $1`,
        [chatId]
      );
      const staff = staffQ.rows[0];
      if (!staff || staff.role !== 'Master') {
        await answerTelegramCallback(cb.id, 'Only a Master can decide this.');
        return;
      }

      const m = data.match(/^q:(approve|reject):(\d+)$/);
      if (!m) {
        await answerTelegramCallback(cb.id, 'Unknown action.');
        return;
      }
      const [, action, txId] = m;
      const result = await reviewQuarantinedTransaction(txId, action, staff);

      if (!result.ok) {
        // Usually "already decided" — tell the tapper and strike the buttons.
        await answerTelegramCallback(cb.id, result.error);
        await editTelegramMessage(chatId, cb.message.message_id,
          `${cb.message.text}\n\n— ${result.error}`);
        return;
      }

      const verdict = action === 'approve'
        ? `APPROVED by ${staff.username} — points stand${result.unfrozen ? ', account unfrozen' : ''}.`
        : `REJECTED by ${staff.username} — ${Number(result.pts).toLocaleString()} pts reversed${result.disabledStaff ? `, staff "${result.disabledStaff}" disabled` : ''}${result.unfrozen ? ', account unfrozen' : ''}.`;

      await answerTelegramCallback(cb.id, action === 'approve' ? 'Approved.' : 'Rejected.');
      // Strike the buttons on THIS Master's copy and record the verdict.
      await editTelegramMessage(chatId, cb.message.message_id,
        `${cb.message.text}\n\n— ${verdict}`);
      // Tell the other Masters it's been handled (their buttons will now no-op safely).
      pool.query(
        `SELECT telegram_chat_id FROM staff_users
          WHERE role = 'Master' AND telegram_chat_id IS NOT NULL AND telegram_chat_id <> $1`,
        [chatId]
      ).then(others => {
        for (const o of others.rows) {
          sendTelegram(o.telegram_chat_id, `Quarantined transaction #${txId}: ${verdict}`).catch(() => {});
        }
      }).catch(() => {});
    } catch (e) {
      console.error('Callback handling error:', e.message);
      await answerTelegramCallback(cb.id, 'Something went wrong — try the dashboard.');
    }
    return;
  }

  const msg = update.message;
  if (!msg || !msg.text) return;
  const chatId = msg.chat.id;
  const text = msg.text.trim();

  // 1) Staff 2FA link code — honored regardless of age so linking is reliable.
  const codeMatch = await pool.query(
    'SELECT id, username FROM staff_users WHERE telegram_link_code IS NOT NULL AND UPPER(telegram_link_code) = UPPER($1)',
    [text]
  );
  if (codeMatch.rows.length) {
    const staff = codeMatch.rows[0];
    await pool.query('UPDATE staff_users SET telegram_chat_id = $1, telegram_link_code = NULL WHERE id = $2', [chatId, staff.id]);
    await sendTelegram(chatId, `Telegram linked to ${SHOP_NAME} staff account "${staff.username}". You'll now receive a 4-digit PIN on every login.`).catch(() => {});
    return;
  }

  // 2) Ignore stale command messages so a cold-started server doesn't reply to
  //    an old backlog. (Link codes above are exempt.)
  if (msg.date && (Date.now() / 1000 - msg.date) > 120) return;

  // 3) THE BOUNCER — is this chat_id a currently-linked staff member?
  //    Looked up fresh on EVERY message: the moment a staff account is deleted
  //    or unlinked (telegram_chat_id = NULL), this stops matching and the
  //    sender instantly falls through to customer routing below.
  const staffQ = await pool.query(
    'SELECT id, username, role FROM staff_users WHERE telegram_chat_id = $1',
    [chatId]
  );
  if (staffQ.rows.length) {
    await handleStaffMessage(chatId, staffQ.rows[0], text);
    return;
  }

  // 4) Customer routing.
  const lower = text.toLowerCase();
  if (lower === '/start' || lower === '/help') {
    await sendTelegram(chatId, `Welcome to ${SHOP_NAME}! To check your loyalty points, send:\n\n/points YOURPLATE\n\nExample: /points SBA1234A`);
    return;
  }
  if (lower.startsWith('/points')) {
    // "/points SBA1234A" or "/points@BotName SBA1234A"
    const parts = text.split(/\s+/);
    await handlePointsQuery(chatId, parts[1]);
    return;
  }

  // Gentle fallback in private chats only (avoid replying in groups).
  if (msg.chat.type === 'private') {
    await sendTelegram(chatId, `Send /points YOURPLATE to check your points — e.g. /points SBA1234A`);
  }
}

// ── Single long-polling loop (owns getUpdates for the whole app) ──
let telegramOffset = 0;
let telegramPolling = false;

async function pollTelegram() {
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?timeout=30${telegramOffset ? `&offset=${telegramOffset}` : ''}`;
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      for (const update of (data.result || [])) {
        telegramOffset = Math.max(telegramOffset, update.update_id + 1);
        try { await processTelegramUpdate(update); }
        catch (e) { console.error('Telegram update error:', e.message); }
      }
    } else if (res.status === 409) {
      console.error('Telegram getUpdates 409 (another poller or webhook active) — backing off');
      await new Promise(r => setTimeout(r, 5000));
    } else {
      await new Promise(r => setTimeout(r, 3000));
    }
  } catch (e) {
    console.error('Telegram poll error:', e.message);
    await new Promise(r => setTimeout(r, 5000));
  }
  setTimeout(pollTelegram, 400);
}

async function startTelegramBot() {
  if (!TELEGRAM_BOT_TOKEN || telegramPolling) return;
  telegramPolling = true;
  // Ensure no webhook is set, otherwise getUpdates returns 409.
  try { await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteWebhook`); } catch {}
  console.log('Telegram bot polling started.');
  pollTelegram();
}
startTelegramBot();

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

// ════════════════════════════════════════════════════════════════════════
//  Audit trail helpers
// ════════════════════════════════════════════════════════════════════════
// Record a sensitive action against the acting staff member. Fire-and-forget:
// a logging failure must never break the underlying operation.
async function auditLog(req, actionType, targetId, detail = null) {
  try {
    const ip = req?.headers?.['x-forwarded-for']?.split(',')[0].trim() || req?.ip || null;
    await pool.query(
      `INSERT INTO system_audit_logs (staff_id, username, action_type, target_id, detail, ip)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [req?.user?.id || null, req?.user?.username || null, actionType,
       targetId != null ? String(targetId) : null, detail, ip]
    );
  } catch (e) { console.error('Audit log failed:', e.message); }
}
// System-initiated audit entry (no request context — e.g. the expiry cron).
async function auditSystem(actionType, targetId, detail = null) {
  try {
    await pool.query(
      `INSERT INTO system_audit_logs (staff_id, username, action_type, target_id, detail)
       VALUES (NULL, 'SYSTEM', $1, $2, $3)`,
      [actionType, targetId != null ? String(targetId) : null, detail]
    );
  } catch (e) { console.error('System audit log failed:', e.message); }
}

// ════════════════════════════════════════════════════════════════════════
//  Telegram → all Masters
// ════════════════════════════════════════════════════════════════════════
async function getMasters() {
  const r = await pool.query(
    `SELECT username, telegram_chat_id FROM staff_users
      WHERE role = 'Master' AND telegram_chat_id IS NOT NULL`
  );
  return r.rows;
}
async function notifyMasters(text, replyMarkup = null) {
  if (!TELEGRAM_BOT_TOKEN) return;
  try {
    const masters = await getMasters();
    for (const m of masters) {
      sendTelegram(m.telegram_chat_id, text, replyMarkup)
        .catch(e => console.error('notifyMasters send failed:', e.message));
    }
  } catch (e) { console.error('notifyMasters lookup failed:', e.message); }
}

// ════════════════════════════════════════════════════════════════════════
//  Idempotency keys (double-submit protection)
// ════════════════════════════════════════════════════════════════════════
const IDEMPOTENCY_WINDOW_MS = 10 * 1000; // replay window for an identical key

// Reserve a key before doing the work. Returns:
//   { reserved: true }                          → first time; proceed
//   { replay: true, statusCode, response }      → duplicate; return this instead
async function reserveIdempotencyKey(key, staffId, route) {
  const ins = await pool.query(
    `INSERT INTO idempotency_keys (idempotency_key, staff_id, route)
     VALUES ($1, $2, $3)
     ON CONFLICT (idempotency_key) DO NOTHING
     RETURNING idempotency_key`,
    [key, staffId, route]
  );
  if (ins.rowCount === 1) return { reserved: true };

  // Key already exists — a duplicate submission.
  const ex = await pool.query(
    'SELECT status_code, response, created_at FROM idempotency_keys WHERE idempotency_key = $1',
    [key]
  );
  const row = ex.rows[0];
  const ageMs = row ? Date.now() - new Date(row.created_at).getTime() : Infinity;
  if (row && ageMs <= IDEMPOTENCY_WINDOW_MS) {
    if (row.response) return { replay: true, statusCode: row.status_code || 200, response: row.response };
    // First request is still in flight — tell the duplicate we've got it.
    return {
      replay: true, statusCode: 202,
      response: { success: true, duplicate: true, message: 'Duplicate submission ignored — the first one is still processing.' },
    };
  }
  // Stale key (older than the window): reclaim it for this fresh request.
  await pool.query('DELETE FROM idempotency_keys WHERE idempotency_key = $1', [key]);
  await pool.query(
    `INSERT INTO idempotency_keys (idempotency_key, staff_id, route)
     VALUES ($1, $2, $3) ON CONFLICT (idempotency_key) DO NOTHING`,
    [key, staffId, route]
  );
  return { reserved: true };
}
// Store the final response so a duplicate within the window replays it exactly.
async function finalizeIdempotencyKey(key, statusCode, response) {
  try {
    await pool.query(
      'UPDATE idempotency_keys SET status_code = $2, response = $3 WHERE idempotency_key = $1',
      [key, statusCode, JSON.stringify(response)]
    );
  } catch (e) { console.error('Idempotency finalize failed:', e.message); }
}
// Release a reserved key when the request failed (so a real retry can proceed).
async function releaseIdempotencyKey(key) {
  try { await pool.query('DELETE FROM idempotency_keys WHERE idempotency_key = $1', [key]); }
  catch (e) { console.error('Idempotency release failed:', e.message); }
}
// Housekeeping: drop keys older than an hour (they're well past the window).
setInterval(() => {
  pool.query("DELETE FROM idempotency_keys WHERE created_at < NOW() - INTERVAL '1 hour'").catch(() => {});
}, 60 * 60 * 1000);

// ════════════════════════════════════════════════════════════════════════
//  Point-expiration engine (loyalty-liability cleanup)
// ════════════════════════════════════════════════════════════════════════
// Outstanding loyalty points are a financial liability. Points expire after
// 12 months of ZERO shop activity (any transaction — earn or redeem — counts
// as activity). Runs daily at 02:00 Asia/Singapore.
const EXPIRY_DAYS = 365;
const EXPIRY_WARNING_DAYS = 30; // heads-up window before points lapse

// Clear balances for members inactive > EXPIRY_DAYS, logging each as a
// "System: 12-Month Expiry" transaction so the paper trail stays intact.
async function expireStalePoints() {
  const stale = await pool.query(
    `SELECT m.member_id, m.full_name, m.total_points
       FROM members m
      WHERE m.deleted_at IS NULL
        AND COALESCE(m.is_frozen, false) = false
        AND COALESCE(m.total_points, 0) > 0
        AND COALESCE(
              (SELECT MAX(t.transaction_date) FROM point_transactions t WHERE t.member_id = m.member_id),
              m.date_joined
            ) < NOW() - ($1 || ' days')::interval`,
    [EXPIRY_DAYS]
  );

  let expiredCount = 0, pointsCleared = 0;
  const client = await pool.connect();
  try {
    for (const m of stale.rows) {
      try {
        await client.query('BEGIN');
        // Guard against a concurrent change: only zero it if it's still the
        // exact balance we read (otherwise the member was active meanwhile).
        const upd = await client.query(
          'UPDATE members SET total_points = 0 WHERE member_id = $1 AND total_points = $2 RETURNING member_id',
          [m.member_id, m.total_points]
        );
        if (upd.rowCount === 0) { await client.query('ROLLBACK'); continue; }
        await client.query(
          `INSERT INTO point_transactions (member_id, points_added, description, staff_id, served_member_name)
           VALUES ($1, $2, 'System: 12-Month Expiry', NULL, $3)`,
          [m.member_id, -m.total_points, m.full_name]
        );
        await client.query('COMMIT');
        expiredCount++; pointsCleared += Number(m.total_points) || 0;
        io.emit('pointsUpdated', { memberId: m.member_id, newTotal: 0 });
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        console.error(`Point expiry failed for member ${m.member_id}:`, e.message);
      }
    }
  } finally {
    client.release();
  }

  if (expiredCount) {
    console.log(`Point expiry: cleared ${pointsCleared} pts from ${expiredCount} inactive member(s).`);
    await auditSystem('POINTS_EXPIRED', null, `${expiredCount} member(s), ${pointsCleared} pts cleared (12-month inactivity)`);
    await notifyMasters(
      `Point Expiry — 12-month inactivity\n\n` +
      `Cleared ${pointsCleared.toLocaleString()} pts from ${expiredCount} inactive customer(s). ` +
      `Liability written off your books.`
    );
  } else {
    console.log('Point expiry: no inactive members to clear today.');
  }
  return { expiredCount, pointsCleared };
}

// Marketing save-the-sale list: points lapsing within EXPIRY_WARNING_DAYS.
async function notifyExpiringSoon() {
  if (!TELEGRAM_BOT_TOKEN) return;
  const soon = await pool.query(
    `SELECT m.member_id, m.full_name, m.total_points, m.phone,
            COALESCE(
              (SELECT MAX(t.transaction_date) FROM point_transactions t WHERE t.member_id = m.member_id),
              m.date_joined
            ) AS last_activity
       FROM members m
      WHERE m.deleted_at IS NULL
        AND COALESCE(m.is_frozen, false) = false
        AND COALESCE(m.total_points, 0) > 0
        AND COALESCE(
              (SELECT MAX(t.transaction_date) FROM point_transactions t WHERE t.member_id = m.member_id),
              m.date_joined
            ) BETWEEN NOW() - ($1 || ' days')::interval
                  AND NOW() - (($1 - $2) || ' days')::interval
      ORDER BY last_activity ASC`,
    [EXPIRY_DAYS, EXPIRY_WARNING_DAYS]
  );
  if (soon.rows.length === 0) return;

  const dayMs = 24 * 60 * 60 * 1000;
  const lines = soon.rows.map(r => {
    const expiresOn = new Date(new Date(r.last_activity).getTime() + EXPIRY_DAYS * dayMs);
    const daysLeft = Math.max(0, Math.ceil((expiresOn - Date.now()) / dayMs));
    return `• ${r.full_name} — ${(Number(r.total_points) || 0).toLocaleString()} pts — ` +
           `expires in ${daysLeft}d${r.phone ? ` — ${r.phone}` : ' — no contact on file'}`;
  });
  await notifyMasters(
    `Points expiring within ${EXPIRY_WARNING_DAYS} days (${soon.rows.length}) — reach out to save the sale:\n\n` +
    lines.join('\n')
  );
}

// Scheduler: node-cron if present, else a minute-ticking setInterval fallback.
async function runExpiryJob() {
  try { await expireStalePoints(); await notifyExpiringSoon(); }
  catch (e) { console.error('Expiry job error:', e.message); }
}
function nowInSG() {
  return new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Singapore' }));
}
let lastExpiryRunDay = null;
function startExpiryScheduler() {
  if (cron) {
    cron.schedule('0 2 * * *', runExpiryJob, { timezone: 'Asia/Singapore' });
    console.log('Point-expiry cron scheduled for 02:00 Asia/Singapore.');
  } else {
    setInterval(() => {
      const sg = nowInSG();
      const day = sg.toISOString().slice(0, 10);
      if (sg.getHours() === 2 && sg.getMinutes() === 0 && lastExpiryRunDay !== day) {
        lastExpiryRunDay = day;
        runExpiryJob();
      }
    }, 60 * 1000);
    console.log('Point-expiry scheduler running via setInterval fallback (02:00 SGT).');
  }
}
startExpiryScheduler();

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
      'SELECT id, username, password_hash, role, telegram_chat_id, require_2fa, is_disabled FROM staff_users WHERE LOWER(username) = LOWER($1)',
      [username.trim()]
    );
    const user = result.rows[0];
    // Compare against a dummy hash when user not found so response timing
    // doesn't reveal which usernames exist.
    const hash = user?.password_hash || '$2a$12$invalidinvalidinvalidinvaliduuuuuuuuuuuuuuuuuuuuuuuuu';
    const match = await bcrypt.compare(password, hash);
    if (user && match) {
      // Disabled by the fraud interceptor → refuse login until re-enabled.
      if (user.is_disabled) {
        return res.status(403).json({ error: 'This staff account has been disabled pending review. Contact a Master.' });
      }
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
        WHERE c.challenge_token = $1
          AND COALESCE(c.purpose, 'login') = 'login'`,
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

// ── Forgot password, step 1: request a reset PIN via Telegram (public) ──
// Only works for accounts with Telegram 2FA linked — that link IS the identity
// proof. The response is the same whether or not the username exists, so the
// login page can't be used to probe which staff accounts are real.
app.post('/api/forgot-password', loginRateLimiter, async (req, res) => {
  const { username } = req.body || {};
  const generic = {
    success: true,
    message: 'If that account has Telegram linked, a 4-digit PIN has been sent to it.',
  };
  if (!username || !String(username).trim()) {
    return res.status(400).json({ error: 'Enter your username.' });
  }
  try {
    const result = await pool.query(
      'SELECT id, username, telegram_chat_id, is_disabled FROM staff_users WHERE LOWER(username) = LOWER($1)',
      [String(username).trim()]
    );
    const user = result.rows[0];
    // No account, no Telegram link, disabled, or no bot configured → same
    // generic answer, no PIN. (Disabled accounts must go through a Master.)
    if (!user || !user.telegram_chat_id || user.is_disabled || !TELEGRAM_BOT_TOKEN) {
      return res.json(generic);
    }

    // One live reset at a time per account.
    await pool.query(
      `DELETE FROM login_challenges WHERE staff_id = $1 AND COALESCE(purpose,'login') = 'reset'`,
      [user.id]
    );

    const pin = String(Math.floor(1000 + Math.random() * 9000)); // 1000–9999
    const pinHash = await bcrypt.hash(pin, 8);
    const challengeToken = crypto.randomUUID() + crypto.randomUUID();
    await pool.query(
      `INSERT INTO login_challenges (challenge_token, staff_id, pin_hash, purpose, expires_at)
       VALUES ($1, $2, $3, 'reset', NOW() + ($4 || ' minutes')::interval)`,
      [challengeToken, user.id, pinHash, String(CHALLENGE_TTL_MINUTES)]
    );

    try {
      await sendTelegram(
        user.telegram_chat_id,
        `🔑 Car Shop PASSWORD RESET PIN: ${pin}\n\nSomeone (hopefully you) asked to reset the password for "${user.username}". Expires in ${CHALLENGE_TTL_MINUTES} minutes.\n\nIf this wasn't you, ignore this message — your password is unchanged — and tell a Master.`
      );
    } catch (tgErr) {
      console.error('POST /api/forgot-password telegram error:', tgErr.message);
      await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
      return res.status(502).json({ error: 'Could not send the PIN to Telegram. Please try again.' });
    }

    res.json({ ...generic, challengeToken, expiresInMinutes: CHALLENGE_TTL_MINUTES });
  } catch (err) {
    console.error('POST /api/forgot-password error:', err.message);
    res.status(500).json({ error: 'Could not start the reset. Please try again.' });
  }
});

// Password policy for resets: min 10 chars with at least one uppercase,
// one lowercase, and one special character. Returns null if OK, else the
// specific requirement that failed (so the user knows exactly what to fix).
function passwordPolicyError(pw) {
  const s = String(pw || '');
  if (s.length < 10) return 'Password must be at least 10 characters.';
  if (!/[A-Z]/.test(s)) return 'Password must include at least one uppercase letter.';
  if (!/[a-z]/.test(s)) return 'Password must include at least one lowercase letter.';
  if (!/[^A-Za-z0-9]/.test(s)) return 'Password must include at least one special character (e.g. ! @ # $ %).';
  return null;
}

// ── Forgot password, step 2: verify the PIN only (public) ──
// On success the challenge is marked pin_verified but NOT burned — the user
// then sets the new password in step 3 against the same challenge token.
app.post('/api/forgot-password/verify-pin', loginRateLimiter, async (req, res) => {
  const { challengeToken, pin } = req.body || {};
  if (!challengeToken || !/^\d{4}$/.test(String(pin || ''))) {
    return res.status(400).json({ error: 'Enter the 4-digit PIN.' });
  }
  try {
    const result = await pool.query(
      `SELECT c.challenge_token, c.attempts, c.expires_at, c.pin_hash
         FROM login_challenges c
        WHERE c.challenge_token = $1
          AND COALESCE(c.purpose, 'login') = 'reset'`,
      [challengeToken]
    );
    const ch = result.rows[0];

    if (!ch || new Date(ch.expires_at) <= new Date()) {
      if (ch) await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
      return res.status(401).json({ error: 'PIN expired. Please start the reset again.', restart: true });
    }
    if (ch.attempts >= CHALLENGE_MAX_ATTEMPTS) {
      await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
      return res.status(401).json({ error: 'Too many wrong PINs. Please start the reset again.', restart: true });
    }

    const match = await bcrypt.compare(String(pin), ch.pin_hash);
    if (!match) {
      await pool.query('UPDATE login_challenges SET attempts = attempts + 1 WHERE challenge_token = $1', [challengeToken]);
      const left = CHALLENGE_MAX_ATTEMPTS - (ch.attempts + 1);
      if (left <= 0) {
        await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
        return res.status(401).json({ error: 'Too many wrong PINs. Please start the reset again.', restart: true });
      }
      return res.status(401).json({ error: `Wrong PIN. ${left} attempt${left !== 1 ? 's' : ''} left.` });
    }

    // PIN accepted: unlock the set-password step for this challenge.
    await pool.query('UPDATE login_challenges SET pin_verified = true WHERE challenge_token = $1', [challengeToken]);
    res.json({ success: true, pinVerified: true });
  } catch (err) {
    console.error('POST /api/forgot-password/verify-pin error:', err.message);
    res.status(500).json({ error: 'Could not verify PIN. Please try again.' });
  }
});

// ── Forgot password, step 3: set the new password (public) ──
// Only works on a challenge whose PIN was verified in step 2 and which hasn't
// expired. Burns the challenge, updates the hash, kills all sessions.
app.post('/api/forgot-password/complete', loginRateLimiter, async (req, res) => {
  const { challengeToken, newPassword } = req.body || {};
  if (!challengeToken) return res.status(400).json({ error: 'Missing reset session. Please start again.' });
  const policyErr = passwordPolicyError(newPassword);
  if (policyErr) return res.status(400).json({ error: policyErr });
  try {
    const result = await pool.query(
      `SELECT c.challenge_token, c.staff_id, c.expires_at, c.pin_verified,
              u.username, u.telegram_chat_id
         FROM login_challenges c
         JOIN staff_users u ON u.id = c.staff_id
        WHERE c.challenge_token = $1
          AND COALESCE(c.purpose, 'login') = 'reset'`,
      [challengeToken]
    );
    const ch = result.rows[0];

    if (!ch || new Date(ch.expires_at) <= new Date()) {
      if (ch) await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]).catch(() => {});
      return res.status(401).json({ error: 'Reset session expired. Please start again.', restart: true });
    }
    if (!ch.pin_verified) {
      return res.status(401).json({ error: 'Verify the PIN first.', restart: true });
    }

    // Burn the challenge, set the new password, kill all existing sessions.
    await pool.query('DELETE FROM login_challenges WHERE challenge_token = $1', [challengeToken]);
    const hash = await bcrypt.hash(String(newPassword), 12);
    await pool.query('UPDATE staff_users SET password_hash = $1 WHERE id = $2', [hash, ch.staff_id]);
    await pool.query('DELETE FROM sessions WHERE staff_id = $1', [ch.staff_id]);

    await auditSystem('PASSWORD_RESET_VIA_2FA', ch.staff_id, `"${ch.username}" reset their password via Telegram PIN`);
    sendTelegram(ch.telegram_chat_id, `✅ Your Car Shop password for "${ch.username}" has been changed. If this wasn't you, tell a Master immediately.`).catch(() => {});

    res.json({ success: true, message: 'Password changed. You can now log in with your new password.' });
  } catch (err) {
    console.error('POST /api/forgot-password/complete error:', err.message);
    res.status(500).json({ error: 'Could not reset the password. Please try again.' });
  }
});

// ── Telegram webhook (public: Telegram's servers call this) ──
// Feeds the SAME router as the polling loop. NOT active unless you register
// it with Telegram via setWebhook — and note that setting a webhook DISABLES
// getUpdates polling, so only switch deliberately:
//   https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://car-shop-system.onrender.com/api/telegram-webhook
// (To go back to polling: deleteWebhook — the server also does this on boot.)
app.post('/api/telegram-webhook', async (req, res) => {
  // Always 200 quickly; Telegram retries non-200s aggressively.
  res.sendStatus(200);
  try {
    if (req.body && (req.body.update_id !== undefined)) {
      await processTelegramUpdate(req.body);
    }
  } catch (err) {
    console.error('POST /api/telegram-webhook error:', err.message);
  }
});

app.use('/api', async (req, res, next) => {
  if (req.path === '/login' || req.path === '/login/verify-2fa'
      || req.path === '/forgot-password' || req.path === '/forgot-password/verify-pin'
      || req.path === '/forgot-password/complete') return next();
  try {
    const user = await getSessionUser(req.headers['x-admin-token']);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (user.is_disabled) {
      return res.status(403).json({ error: 'This staff account has been disabled. Contact a Master.' });
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

// ════════════════════════════════════════════════════════════════════════
//  Zod: request-body schemas + a tiny validation middleware
// ════════════════════════════════════════════════════════════════════════
// Define the shape ONCE; the middleware rejects bad payloads with a clean 400
// and hands the route a parsed, normalised req.body — so routes stop repeating
// manual `if (!x) ...` checks.
function validateBody(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body ?? {});
    if (!parsed.success) {
      const msg = parsed.error.issues[0]?.message || 'Invalid request data.';
      return res.status(400).json({ error: msg });
    }
    req.body = parsed.data; // normalised (trimmed, coerced, phone-cleaned)
    next();
  };
}

// Optional free-text that trims and turns '' into null.
const optionalText = z.preprocess(
  (v) => (v == null ? null : String(v).trim()),
  z.string().nullable()
).transform((v) => (v ? v : null));

// Phone: reuses the SG/MY validator so error messages stay specific.
// Accepts missing/empty (→ null) unless you make it required per-route.
const phoneField = z.preprocess(
  (v) => (v == null ? '' : String(v)),
  z.string()
).superRefine((val, ctx) => {
  const r = validatePhoneNumber(val);
  if (!r.ok) ctx.addIssue({ code: z.ZodIssueCode.custom, message: r.error });
}).transform((val) => validatePhoneNumber(val).value);

const newMemberSchema = z.object({
  fullName: z.preprocess(v => (v == null ? '' : String(v).trim()),
    z.string().min(1, 'Full name is required').max(100, 'Full name is too long.')),
  carPlate: optionalText,
  carModel: optionalText,
  phone: phoneField,
});

const addCarSchema = z.object({
  carPlate: optionalText,
  carModel: optionalText,
});

const staffCreateSchema = z.object({
  username: z.preprocess(v => (v == null ? '' : String(v).trim()),
    z.string().min(1, 'Username is required.').max(50)),
  password: z.string({ required_error: 'Password must be at least 10 characters.' })
    .min(10, 'Password must be at least 10 characters.'),
  role: z.enum(['Master', 'Admin', 'Technician'], { errorMap: () => ({ message: 'Invalid role.' }) }),
  permissions: z.object({
    can_add_member: z.boolean().optional(),
    can_delete_member: z.boolean().optional(),
    can_add_points: z.boolean().optional(),
    can_deduct_points: z.boolean().optional(),
  }).partial().optional().default({}),
});

const addPointsSchema = z.object({
  memberId: z.coerce.number({ invalid_type_error: 'A member is required.' })
    .int('A member is required.').positive('A member is required.'),
  points: z.coerce.number({ invalid_type_error: 'Points must be a whole number.' })
    .int('Points must be a whole number.'),
  description: z.preprocess(v => (v == null ? '' : String(v).trim()),
    z.string().max(200, 'Description is too long.')).optional().default(''),
  carId: z.preprocess(
    (v) => (v === '' || v == null ? undefined : v),
    z.coerce.number().int().positive()
  ).optional(),
});

// ── Health check ──
app.get('/', (req, res) => {
  res.json({ status: 'Car Shop backend is running ✅' });
});

// ── Master: read the system audit trail (append-only; newest first) ──
app.get('/api/audit-logs', requireMaster, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const result = await pool.query(
      `SELECT id, staff_id, username, action_type, target_id, detail, ip, created_at
         FROM system_audit_logs
        ORDER BY created_at DESC
        LIMIT $1`,
      [limit]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/audit-logs error:', err.message);
    res.status(500).json({ error: 'Could not load audit logs.' });
  }
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
    // The polling loop links the account automatically as soon as the code
    // message arrives, so here we just check whether that's happened yet.
    const result = await pool.query(
      'SELECT telegram_chat_id, telegram_link_code FROM staff_users WHERE id = $1',
      [req.user.id]
    );
    const row = result.rows[0] || {};
    if (row.telegram_chat_id) return res.json({ success: true });
    return res.status(404).json({
      error: `Not linked yet. In Telegram, send ${row.telegram_link_code || 'your code'} to the bot, then press Confirm again.`,
    });
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
              require_2fa, is_disabled, (telegram_chat_id IS NOT NULL) AS telegram_linked
         FROM staff_users ${hideMasters} ORDER BY created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/staff error:', err.message);
    res.status(500).json({ error: 'Could not load staff.' });
  }
});

app.post('/api/staff', requireAdmin, validateBody(staffCreateSchema), async (req, res) => {
  const { username, password, role, permissions } = req.body; // validated + normalised
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
      [username, hash, role, !!p.can_add_member, !!p.can_delete_member, !!p.can_add_points, !!p.can_deduct_points]
    );
    await auditLog(req, 'CREATE_STAFF', result.rows[0].id, `created ${role} "${username}"`);
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
    await auditLog(req, 'UPDATE_STAFF', id, `role=${role || targetRole}, perms=${JSON.stringify(p)}`);
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
    await auditLog(req, 'SET_STAFF_2FA', id, `require_2fa=${!!required} for "${req.targetStaff.username}"`);
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
    await auditLog(req, 'UNLINK_STAFF_TELEGRAM', id, `unlinked Telegram for "${result.rows[0].username}"`);
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
    await auditLog(req, 'RESET_STAFF_PASSWORD', id, `reset password for "${req.targetStaff.username}"`);
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
    await auditLog(req, 'DELETE_STAFF', id, `deleted ${req.targetStaff.role} "${req.targetStaff.username}"`);
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/staff error:', err.message);
    res.status(500).json({ error: 'Could not delete staff account.' });
  }
});

// ── Fetch ALL members with their cars ──
// ── Members list: paginated + server-side search ──
// Loading every member (and every car in the DB) into one response stops
// scaling past a few hundred customers. The list is now paged: ?page=1&limit=25
// &search=q — search matches name, plate, or model. Cars are fetched only for
// the members on the current page.
app.get('/api/members', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
    const search = String(req.query.search || '').trim();
    const offset = (page - 1) * limit;

    const params = [];
    let where = 'm.deleted_at IS NULL';
    if (search) {
      params.push(`%${search}%`);
      where += ` AND (m.full_name ILIKE $1 OR EXISTS (
                   SELECT 1 FROM cars c
                    WHERE c.member_id = m.member_id
                      AND (c.car_plate ILIKE $1 OR c.car_model ILIKE $1)))`;
    }

    const countQ = await pool.query(`SELECT COUNT(*)::int AS total FROM members m WHERE ${where}`, params);
    const total = countQ.rows[0].total;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    const membersResult = await pool.query(
      `SELECT m.* FROM members m WHERE ${where}
        ORDER BY m.full_name ASC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );

    // Cars for just this page's members.
    const ids = membersResult.rows.map(m => m.member_id);
    const carsMap = {};
    if (ids.length > 0) {
      const carsResult = await pool.query(
        'SELECT * FROM cars WHERE member_id = ANY($1) ORDER BY car_id ASC',
        [ids]
      );
      for (const car of carsResult.rows) {
        (carsMap[car.member_id] ||= []).push(car);
      }
    }

    const members = membersResult.rows.map(m => ({ ...m, cars: carsMap[m.member_id] || [] }));
    res.json({ members, total, page, limit, totalPages });
  } catch (err) {
    console.error('GET /api/members error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Register a new member with their first car ──
// ── Phone validation: Singapore (+65) & Malaysia (+60), no SMS/OTP ──
// Strips spaces/dashes, enforces exact digit lengths. Phone stays OPTIONAL:
// an empty value is allowed (stored as NULL). To make it REQUIRED at
// registration, reject a null phoneCheck.value in the route (see comment there).
function validatePhoneNumber(raw) {
  if (raw === undefined || raw === null) return { ok: true, value: null };
  const cleaned = String(raw).replace(/[\s-]/g, ''); // strip spaces & dashes only
  if (cleaned === '') return { ok: true, value: null };

  let country, core;
  if (cleaned.startsWith('+65')) { country = 'SG'; core = cleaned.slice(3); }
  else if (cleaned.startsWith('+60')) { country = 'MY'; core = cleaned.slice(3); }
  else if (cleaned.startsWith('+')) {
    return { ok: false, error: 'Only Singapore (+65) and Malaysia (+60) numbers are accepted.' };
  } else if (/^[89]/.test(cleaned)) { country = 'SG'; core = cleaned; } // bare SG mobile
  else {
    return { ok: false, error: 'Unrecognised number. Enter a Singapore number starting with 8 or 9, or include a +65 / +60 country code.' };
  }

  if (!/^\d+$/.test(core)) {
    return { ok: false, error: 'Phone number may only contain digits (plus an optional +65 / +60 code, spaces, and dashes).' };
  }
  if (country === 'SG' && core.length !== 8) {
    return { ok: false, error: 'Singapore numbers must be exactly 8 digits (excluding the +65 country code).' };
  }
  if (country === 'MY' && core.length !== 9 && core.length !== 10) {
    return { ok: false, error: 'Malaysia numbers must be 9 or 10 digits after the +60 country code.' };
  }
  return { ok: true, value: cleaned }; // store the cleaned +code form so tel: links work
}

app.post('/api/new-member', requirePermission('can_add_member'), validateBody(newMemberSchema), async (req, res) => {
  // Validated + normalised by Zod: fullName trimmed & non-empty, phone cleaned
  // (or null). To require a phone, add `.min(1)` semantics in phoneField.
  const { fullName, carPlate, carModel, phone } = req.body;
  try {
    // Check for duplicate plate in cars table
    const normalizedPlate = carPlate ? carPlate.toUpperCase() : null;
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
      'INSERT INTO members (full_name, total_points, date_joined, phone) VALUES ($1, 0, NOW(), $2) RETURNING *',
      [fullName, phone]
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
    await auditLog(req, 'CREATE_MEMBER', newMember.member_id, `"${fullName}"${normalizedPlate ? ` · ${normalizedPlate}` : ''}`);
    res.json({ success: true, member: memberWithCars });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'That car plate is already registered. Please check and try again.' });
    }
    console.error('POST /api/new-member error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Add a car to an existing member ──
app.post('/api/add-car/:memberId', validateBody(addCarSchema), async (req, res) => {
  const { memberId } = req.params;
  const { carPlate, carModel } = req.body; // trimmed by Zod (or null)
  const normalizedPlate = carPlate ? carPlate.toUpperCase() : null;

  try {
    // Check for duplicate plate (distinguish "already on THIS member" from
    // "owned by someone else" for a clearer message).
    if (normalizedPlate) {
      const existing = await pool.query(
        'SELECT c.car_id, c.member_id, m.full_name FROM cars c JOIN members m ON c.member_id = m.member_id WHERE UPPER(c.car_plate) = $1',
        [normalizedPlate]
      );
      if (existing.rows.length > 0) {
        const row = existing.rows[0];
        const sameMember = String(row.member_id) === String(memberId);
        return res.status(409).json({
          error: sameMember
            ? `${normalizedPlate} is already on this customer's account.`
            : `Plate ${normalizedPlate} is already registered to ${row.full_name}.`,
        });
      }
    }

    const vehicleId = await findOrCreateVehicle(pool, normalizedPlate, carModel);
    const result = await pool.query(
      'INSERT INTO cars (member_id, car_plate, car_model, vehicle_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [memberId, normalizedPlate, carModel || null, vehicleId]
    );

    const newCar = result.rows[0];
    io.emit('carAdded', { memberId: parseInt(memberId), car: newCar });
    await auditLog(req, 'ADD_CAR', newCar.car_id, `${normalizedPlate || '(no plate)'} → member ${memberId}`);
    res.json({ success: true, car: newCar });
  } catch (err) {
    // 23505 = the unique index caught a duplicate that raced past the check above.
    if (err.code === '23505') {
      return res.status(409).json({ error: `${normalizedPlate || 'That car'} is already on this customer's account.` });
    }
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
    await auditLog(req, 'DELETE_CAR', carId, `car removed from member ${result.rows[0].member_id}`);
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/delete-car error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Add or deduct points ──
// ── Unfreeze a member after fraud-interceptor review ──
// Master-gated deliberately: the interceptor exists to catch compromised
// staff accounts, and the freeze alert goes to Masters — so only a Master
// signs off on releasing it (e.g. the big addition was a legitimate sale).
app.post('/api/members/:id/unfreeze', requireMaster, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'UPDATE members SET is_frozen = false WHERE member_id = $1 RETURNING full_name',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Member not found' });
    console.log(`Member ${id} (${result.rows[0].full_name}) unfrozen by ${req.user.username}.`);
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/members/:id/unfreeze error:', err.message);
    res.status(500).json({ error: 'Could not unfreeze the member. Please try again.' });
  }
});

// ── Re-enable a staff account disabled by the fraud interceptor (Master) ──
app.post('/api/staff/:id/enable', requireMaster, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'UPDATE staff_users SET is_disabled = false WHERE id = $1 RETURNING username',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Staff member not found' });
    console.log(`Staff ${id} (${result.rows[0].username}) re-enabled by ${req.user.username}.`);
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/staff/:id/enable error:', err.message);
    res.status(500).json({ error: 'Could not re-enable the staff account. Please try again.' });
  }
});

// ── Update a member's contact number ──
app.put('/api/members/:id/phone', requirePermission('can_add_member'), async (req, res) => {
  const { id } = req.params;
  const { phone } = req.body || {};
  const phoneCheck = validatePhoneNumber(phone);
  if (!phoneCheck.ok) return res.status(400).json({ error: phoneCheck.error });
  try {
    const result = await pool.query(
      'UPDATE members SET phone = $2 WHERE member_id = $1 RETURNING member_id, phone',
      [id, phoneCheck.value]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Member not found' });
    io.emit('memberPhoneUpdated', { memberId: result.rows[0].member_id, phone: result.rows[0].phone });
    res.json({ success: true, phone: result.rows[0].phone });
  } catch (err) {
    console.error('PUT /api/members/:id/phone error:', err.message);
    res.status(500).json({ error: 'Could not update the contact number.' });
  }
});

// ── One-hour typo window: edit a transaction's points ──
// Rules: within 60 minutes of posting; by the original poster or Admin/Master;
// not on quarantined/reviewed transactions; the member must not be frozen;
// balance can't go below zero; and the new value can't cross the editor's
// role limit (no editing 300 → 3000 to sneak past the quarantine).
const EDIT_WINDOW_MINUTES = 60;

app.put('/api/transactions/:txId', async (req, res) => {
  const { txId } = req.params;
  const newPoints = parseInt(req.body?.points, 10);
  if (!Number.isFinite(newPoints) || newPoints === 0) {
    return res.status(400).json({ error: 'Enter a valid non-zero points value.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const txQ = await client.query(
      `SELECT t.member_id, t.points_added, t.transaction_date, t.staff_id, t.quarantine_status,
              m.is_frozen
         FROM point_transactions t
         JOIN members m ON m.member_id = t.member_id
        WHERE t.transaction_id = $1
        FOR UPDATE OF t, m`,
      [txId]
    );
    if (txQ.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Transaction not found.' });
    }
    const tx = txQ.rows[0];

    // Window check.
    const ageMinutes = (Date.now() - new Date(tx.transaction_date).getTime()) / 60000;
    if (ageMinutes > EDIT_WINDOW_MINUTES) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: `Transactions can only be edited within ${EDIT_WINDOW_MINUTES} minutes of posting. Use a correcting redemption instead.` });
    }

    // Who may edit: the original poster, or Admin/Master.
    const isAdminPlus = req.user.role === 'Admin' || req.user.role === 'Master';
    if (tx.staff_id !== req.user.id && !isAdminPlus) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Only the staff member who posted this (or an Admin/Master) can edit it.' });
    }

    // Sign flips are corrections of intent, not typos — keep it simple.
    if (Math.sign(newPoints) !== Math.sign(tx.points_added)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'An edit cannot change an earn into a redemption (or vice versa).' });
    }

    // Permission by sign, same as posting.
    const perm = newPoints < 0 ? 'can_deduct_points' : 'can_add_points';
    if (!can(req.user, perm)) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: `You do not have permission to ${newPoints < 0 ? 'deduct' : 'add'} points.` });
    }

    // No editing quarantined/reviewed transactions, or frozen members.
    if (tx.quarantine_status) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: 'This transaction is under (or has been through) Master review and cannot be edited.' });
    }
    if (tx.is_frozen) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: 'This account is FROZEN. A Master must unfreeze it first.' });
    }

    // Role-limit guard: an edit can't cross the editor's ceiling.
    const roleLimit = ROLE_POINT_LIMITS[req.user.role] ?? FRAUD_POINT_THRESHOLD;
    if (newPoints >= roleLimit) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: `Edits at/above your ${roleLimit.toLocaleString()}-point limit aren't allowed — ask a Master to post it.` });
    }

    // Apply the delta atomically, never letting the balance drop below zero.
    const delta = newPoints - tx.points_added;
    const upd = await client.query(
      `UPDATE members
          SET total_points = COALESCE(total_points, 0) + $1
        WHERE member_id = $2
          AND COALESCE(total_points, 0) + $1 >= 0
        RETURNING total_points`,
      [delta, tx.member_id]
    );
    if (upd.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'That edit would take the member below zero points.' });
    }

    // Update the record, preserving the original value once (first edit only).
    await client.query(
      `UPDATE point_transactions
          SET points_added = $2,
              original_points = COALESCE(original_points, $3),
              edited_at = NOW(),
              edited_by = $4
        WHERE transaction_id = $1`,
      [txId, newPoints, tx.points_added, req.user.id]
    );
    // Full trail: one log row per edit.
    await client.query(
      `INSERT INTO point_edit_log (transaction_id, old_points, new_points, edited_by)
       VALUES ($1, $2, $3, $4)`,
      [txId, tx.points_added, newPoints, req.user.id]
    );

    await client.query('COMMIT');

    const newTotal = upd.rows[0].total_points;
    io.emit('pointsUpdated', { memberId: tx.member_id, newTotal });
    io.emit('transactionEdited', { memberId: tx.member_id, transactionId: Number(txId), points: newPoints });
    console.log(`Transaction #${txId} edited by ${req.user.username}: ${tx.points_added} → ${newPoints} pts.`);
    res.json({ success: true, newTotal, points: newPoints });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('PUT /api/transactions/:txId error:', err.message);
    res.status(500).json({ error: 'Could not edit the transaction. Please try again.' });
  } finally {
    client.release();
  }
});

// ── Quarantine review (Master): approve keeps the points, reject reverses ──
// them. Both unfreeze the member if no other pending transactions remain.

app.get('/api/members/:id/quarantine', requireMaster, async (req, res) => {
  const { id } = req.params;
  try {
    const r = await pool.query(
      `SELECT t.transaction_id, t.points_added, t.description, t.transaction_date,
              u.username AS staff_name
         FROM point_transactions t
         LEFT JOIN staff_users u ON u.id = t.staff_id
        WHERE t.member_id = $1 AND t.quarantine_status = 'pending'
        ORDER BY t.transaction_date DESC`,
      [id]
    );
    res.json(r.rows);
  } catch (err) {
    console.error('GET /api/members/:id/quarantine error:', err.message);
    res.status(500).json({ error: 'Could not load pending transactions.' });
  }
});

// ── Shared quarantine decision logic ──
// Used by BOTH the dashboard routes and the Telegram inline buttons, so the
// two paths can never drift. `actor` = { id, username } of the deciding Master.
// Returns { ok, error?, unfrozen?, disabledStaff?, newTotal?, pts?, memberName? }.
async function reviewQuarantinedTransaction(txId, action, actor) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (action === 'approve') {
      const txQ = await client.query(
        `UPDATE point_transactions SET quarantine_status = 'approved'
          WHERE transaction_id = $1 AND quarantine_status = 'pending'
          RETURNING member_id, points_added`,
        [txId]
      );
      if (txQ.rows.length === 0) {
        await client.query('ROLLBACK');
        return { ok: false, error: 'No pending transaction with that ID.' };
      }
      const memberId = txQ.rows[0].member_id;
      const nameQ = await client.query('SELECT full_name FROM members WHERE member_id = $1', [memberId]);

      const pending = await client.query(
        `SELECT 1 FROM point_transactions WHERE member_id = $1 AND quarantine_status = 'pending' LIMIT 1`,
        [memberId]
      );
      const unfrozen = pending.rows.length === 0;
      if (unfrozen) {
        await client.query('UPDATE members SET is_frozen = false WHERE member_id = $1', [memberId]);
      }
      await client.query('COMMIT');

      if (unfrozen) io.emit('memberUnfrozen', { memberId });
      console.log(`Quarantine: tx #${txId} APPROVED by ${actor.username}.`);
      return { ok: true, unfrozen, pts: txQ.rows[0].points_added, memberName: nameQ.rows[0]?.full_name || null };
    }

    // action === 'reject'
    const txQ = await client.query(
      `UPDATE point_transactions SET quarantine_status = 'rejected'
        WHERE transaction_id = $1 AND quarantine_status = 'pending'
        RETURNING member_id, points_added, description, staff_id`,
      [txId]
    );
    if (txQ.rows.length === 0) {
      await client.query('ROLLBACK');
      return { ok: false, error: 'No pending transaction with that ID.' };
    }
    const { member_id: memberId, points_added: pts, staff_id: offenderId } = txQ.rows[0];

    // Reverse the points (floor at zero in case some were already redeemed —
    // shouldn't happen while frozen, but belt-and-braces).
    const upd = await client.query(
      `UPDATE members
          SET total_points = GREATEST(COALESCE(total_points, 0) - $1, 0)
        WHERE member_id = $2
        RETURNING total_points, full_name`,
      [pts, memberId]
    );

    // Reversal record so the history explains itself.
    await client.query(
      `INSERT INTO point_transactions (member_id, points_added, description, staff_id, served_member_name)
       VALUES ($1, $2, $3, $4, $5)`,
      [memberId, -pts, `Rejected quarantined transaction #${txId}`, actor.id, upd.rows[0]?.full_name || null]
    );

    // A rejection means the Master judged this transaction illegitimate — so
    // the account that posted it is suspect. Lock it (and boot its sessions)
    // until a Master re-enables it after speaking with the staff member.
    // Never auto-disable a Master, and skip if the poster no longer exists.
    let disabledStaff = null;
    if (offenderId) {
      const offQ = await client.query(
        `UPDATE staff_users SET is_disabled = true
          WHERE id = $1 AND role <> 'Master' AND is_disabled = false
          RETURNING username`,
        [offenderId]
      );
      if (offQ.rows.length) {
        await client.query('DELETE FROM sessions WHERE staff_id = $1', [offenderId]);
        disabledStaff = offQ.rows[0].username;
      }
    }

    const pending = await client.query(
      `SELECT 1 FROM point_transactions WHERE member_id = $1 AND quarantine_status = 'pending' LIMIT 1`,
      [memberId]
    );
    const unfrozen = pending.rows.length === 0;
    if (unfrozen) {
      await client.query('UPDATE members SET is_frozen = false WHERE member_id = $1', [memberId]);
    }
    await client.query('COMMIT');

    const newTotal = upd.rows[0]?.total_points ?? 0;
    io.emit('pointsUpdated', { memberId, newTotal });
    if (unfrozen) io.emit('memberUnfrozen', { memberId });

    // Tell all Masters the account was locked pending a conversation.
    if (disabledStaff) {
      pool.query(
        `SELECT telegram_chat_id FROM staff_users WHERE role = 'Master' AND telegram_chat_id IS NOT NULL`
      ).then(masters => {
        const note =
          `Quarantine follow-up\n\n` +
          `Master "${actor.username}" REJECTED transaction #${txId} (${pts.toLocaleString()} pts reversed).\n\n` +
          `The staff account "${disabledStaff}" that posted it has been DISABLED and logged out. ` +
          `Speak with them, then re-enable the account from Manage Staff if appropriate.`;
        for (const m of masters.rows) {
          sendTelegram(m.telegram_chat_id, note).catch(e => console.error('Reject notice send failed:', e.message));
        }
      }).catch(e => console.error('Reject notice lookup failed:', e.message));
    }

    console.log(`Quarantine: tx #${txId} REJECTED by ${actor.username}; ${pts} pts reversed${disabledStaff ? `; staff "${disabledStaff}" disabled` : ''}.`);
    return { ok: true, unfrozen, disabledStaff, newTotal, pts, memberName: upd.rows[0]?.full_name || null };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(`reviewQuarantinedTransaction(${action}) error:`, err.message);
    return { ok: false, error: `Could not ${action} the transaction.` };
  } finally {
    client.release();
  }
}

app.post('/api/transactions/:txId/approve', requireMaster, async (req, res) => {
  const result = await reviewQuarantinedTransaction(req.params.txId, 'approve', req.user);
  if (!result.ok) return res.status(result.error.includes('No pending') ? 404 : 500).json({ error: result.error });
  res.json({ success: true, unfrozen: result.unfrozen });
});

app.post('/api/transactions/:txId/reject', requireMaster, async (req, res) => {
  const result = await reviewQuarantinedTransaction(req.params.txId, 'reject', req.user);
  if (!result.ok) return res.status(result.error.includes('No pending') ? 404 : 500).json({ error: result.error });
  res.json({ success: true, newTotal: result.newTotal, unfrozen: result.unfrozen, disabledStaff: result.disabledStaff });
});

// ── Void a transaction (Master only): post an exact reversing ledger entry ──
// Unlike editing, a void never mutates the original row — it appends an inverse
// transaction ("VOID of Tx #<id>") so the audit trail stays intact. Everything
// runs in one DB transaction; the original row is locked FOR UPDATE so two
// concurrent voids can't both slip past the double-void check.
app.post('/api/transactions/:id/void', requireMaster, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 3) Fetch the original (row-locked to serialise concurrent voids).
    const origQ = await client.query(
      'SELECT * FROM point_transactions WHERE transaction_id = $1 FOR UPDATE',
      [id]
    );
    if (origQ.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Transaction not found.' });
    }
    const orig = origQ.rows[0];
    const voidDesc = `VOID of Tx #${id}`;

    // 4) Double-void protection — has a reversal for this id already been posted?
    const dup = await client.query(
      'SELECT 1 FROM point_transactions WHERE description = $1 LIMIT 1',
      [voidDesc]
    );
    if (dup.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Transaction #${id} has already been voided.` });
    }

    // A reversal only makes sense against a live member balance.
    if (orig.member_id == null) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This transaction is not linked to a member and cannot be voided.' });
    }

    const reverse = -Number(orig.points_added); // exact inverse

    // 5) Reverse the math; the WHERE clause keeps the balance from going below 0.
    const upd = await client.query(
      `UPDATE members
          SET total_points = COALESCE(total_points, 0) + $1
        WHERE member_id = $2
          AND COALESCE(total_points, 0) + $1 >= 0
        RETURNING total_points`,
      [reverse, orig.member_id]
    );
    if (upd.rows.length === 0) {
      await client.query('ROLLBACK');
      const cur = await pool.query('SELECT total_points FROM members WHERE member_id = $1', [orig.member_id]);
      const bal = Number(cur.rows[0]?.total_points) || 0;
      return res.status(400).json({
        error: `Voiding this transaction would drop the balance below zero (current ${bal} pts, reversal ${reverse} pts). The customer has likely already redeemed these points.`,
      });
    }
    const newTotal = upd.rows[0].total_points;

    // 6) Ledger entry: exact inverse, same member/car/vehicle, current Master as staff.
    const txResult = await client.query(
      `INSERT INTO point_transactions
         (member_id, points_added, description, staff_id, car_id, vehicle_id, served_member_name, served_car_plate, served_car_model)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING transaction_id, points_added, description, transaction_date, staff_id, car_id`,
      [orig.member_id, reverse, voidDesc, req.user.id, orig.car_id, orig.vehicle_id, orig.served_member_name, orig.served_car_plate, orig.served_car_model]
    );
    const tx = txResult.rows[0];

    // 7) Commit, then real-time emits.
    await client.query('COMMIT');
    io.emit('pointsUpdated', { memberId: orig.member_id, newTotal });
    io.emit('transactionAdded', { memberId: orig.member_id, transaction: tx });

    await auditLog(req, 'VOID_TRANSACTION', id, `reversed ${orig.points_added} pts (tx #${id}) → void tx #${tx.transaction_id}`);
    res.json({ success: true, newTotal, voidTransactionId: tx.transaction_id, reversed: reverse });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('POST /api/transactions/:id/void error:', err.message);
    res.status(500).json({ error: 'Could not void the transaction. Please try again.' });
  } finally {
    client.release();
  }
});

// ── Fraud interceptor: per-role single-transaction point ceilings ──
// A staff member posting at/above their role's ceiling doesn't block the sale
// — the points are RECORDED, but the member is quarantined (frozen) pending
// Master review, with the exact transaction_id in the alert for easy voiding.
const FRAUD_POINT_THRESHOLD = 2000; // base (Technician) threshold
const ROLE_POINT_LIMITS = {
  Technician: FRAUD_POINT_THRESHOLD, // 2000
  Admin: 5000,
  Master: Infinity,                  // Masters are never quarantined
};

app.post('/api/add-points', validateBody(addPointsSchema), async (req, res) => {
  const { memberId, points, description, carId } = req.body; // validated by Zod
  const numericPoints = points; // already an integer

  // 1) Authorization: add vs deduct permission based on the sign.
  const perm = numericPoints < 0 ? 'can_deduct_points' : 'can_add_points';
  if (!can(req.user, perm)) {
    return res.status(403).json({ error: `You do not have permission to ${numericPoints < 0 ? 'deduct' : 'add'} points.` });
  }

  // ── Idempotency: ignore an accidental double-submit within the window ──
  // The frontend sends a per-submission UUID in the Idempotency-Key header.
  // If the same key lands twice inside IDEMPOTENCY_WINDOW_MS, we don't add the
  // points again — we replay the first response.
  const idemKey = req.headers['idempotency-key'] || req.headers['x-idempotency-key'] || null;
  if (idemKey) {
    try {
      const guard = await reserveIdempotencyKey(idemKey, req.user.id, 'add-points');
      if (guard.replay) return res.status(guard.statusCode).json(guard.response);
    } catch (e) {
      console.error('Idempotency reserve failed (proceeding without it):', e.message);
    }
  }

  // car_id only applies to earning (a service done on a specific car).
  // For deductions (redemptions) it stays null.
  const carIdToLog = numericPoints >= 0 && carId ? carId : null;

  // Does this addition cross the poster's role ceiling? (Masters: never.)
  const roleLimit = ROLE_POINT_LIMITS[req.user.role] ?? FRAUD_POINT_THRESHOLD;
  const shouldQuarantine = numericPoints >= roleLimit;

  // Everything — freeze check, balance update, history insert, quarantine —
  // runs on ONE client inside a single transaction: all of it happens or
  // none of it does.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 2) Initial freeze check (row-locked so a concurrent request can't race it).
    const memberQ = await client.query(
      'SELECT full_name, is_frozen FROM members WHERE member_id = $1 FOR UPDATE',
      [memberId]
    );
    if (memberQ.rows.length === 0) {
      await client.query('ROLLBACK');
      if (idemKey) await releaseIdempotencyKey(idemKey);
      return res.status(404).json({ error: 'Member not found' });
    }
    const target = memberQ.rows[0];
    if (target.is_frozen) {
      await client.query('ROLLBACK');
      if (idemKey) await releaseIdempotencyKey(idemKey);
      return res.status(422).json({
        error: 'This account is FROZEN. A Master must unfreeze it before any points can be added or redeemed.',
      });
    }

    // 3) Execution: atomic conditional update — the WHERE clause enforces
    // "never below zero" in the same statement, so concurrent requests can't
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
      if (idemKey) await releaseIdempotencyKey(idemKey);
      const check = await pool.query('SELECT total_points FROM members WHERE member_id = $1', [memberId]);
      const current = Number(check.rows[0]?.total_points) || 0;
      return res.status(400).json({
        error: `Not enough points! Member has ${current} pts, cannot deduct ${Math.abs(numericPoints)} pts.`,
      });
    }

    // Resolve the physical vehicle (durable history spine) and snapshot the
    // owner's name + the serviced car's plate/model so the record stays fully
    // meaningful even after the car is removed or the member is purged.
    let vehicleIdToLog = null, servedPlate = null, servedModel = null;
    if (carIdToLog) {
      const vq = await client.query('SELECT vehicle_id, car_plate, car_model FROM cars WHERE car_id = $1', [carIdToLog]);
      vehicleIdToLog = vq.rows[0]?.vehicle_id || null;
      servedPlate = vq.rows[0]?.car_plate || null;
      servedModel = vq.rows[0]?.car_model || null;
    }

    // Logging: the history record, returning the generated transaction_id.
    const txResult = await client.query(
      `INSERT INTO point_transactions (member_id, points_added, description, staff_id, car_id, vehicle_id, served_member_name, served_car_plate, served_car_model)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING transaction_id, points_added, description, transaction_date, staff_id, car_id`,
      [memberId, numericPoints, description, req.user.id, carIdToLog, vehicleIdToLog, target.full_name, servedPlate, servedModel]
    );
    const tx = txResult.rows[0];

    // 4) QUARANTINE INTERCEPTOR — three tripwires, all non-Master only.
    //    The points stand, but the account locks until a Master reviews.
    //
    //  a) Single transaction at/above the poster's role ceiling.
    //  b) VELOCITY (5-min anti-structuring): total added to THIS customer by
    //     this staff member within the last 5 minutes (including this tx)
    //     reaches FRAUD_POINT_THRESHOLD — catches rapid structuring like
    //     1,999 + 1,999 that slips under the single-tx check.
    let quarantineReason = null;
    if (req.user.role !== 'Master') {
      if (shouldQuarantine) {
        quarantineReason = `single transaction of ${numericPoints.toLocaleString()} pts is at/above their ${roleLimit.toLocaleString()}-pt limit`;
      } else if (numericPoints > 0) {
        // (b) Anti-structuring: rapid accumulation to ONE customer inside 5 minutes.
        //     This tx is already inserted, so member_5min includes the current
        //     numericPoints — i.e. it IS "(prior 5-min sum) + numericPoints".
        //     Flat FRAUD_POINT_THRESHOLD so the 2,000 single-tx rule can't be
        //     bypassed by any non-Master role via small repeats (e.g. 1,999 + 1,999).
        const velQ = await client.query(
          `SELECT COALESCE(SUM(points_added), 0)::int AS member_5min
             FROM point_transactions
            WHERE staff_id = $2
              AND member_id = $1
              AND points_added > 0
              AND quarantine_status IS DISTINCT FROM 'rejected'
              AND transaction_date > NOW() - INTERVAL '5 minutes'`,
          [memberId, req.user.id]
        );
        const { member_5min } = velQ.rows[0];
        if (member_5min >= FRAUD_POINT_THRESHOLD) {
          quarantineReason = `Accumulated points over 5 minutes — ${member_5min.toLocaleString()} pts added to this customer within a 5-minute window (limit ${FRAUD_POINT_THRESHOLD.toLocaleString()})`;
        }
      }
    }

    let wasQuarantined = false;
    if (quarantineReason) {
      await client.query('UPDATE members SET is_frozen = true WHERE member_id = $1', [memberId]);
      await client.query(
        `UPDATE point_transactions SET quarantine_status = 'pending' WHERE transaction_id = $1`,
        [tx.transaction_id]
      );
      wasQuarantined = true;
    }

    // 5) Commit, then emits + alerts + response.
    await client.query('COMMIT');

    const newTotal = result.rows[0].total_points;
    io.emit('pointsUpdated', { memberId, newTotal });
    io.emit('transactionAdded', { memberId, transaction: tx });

    if (wasQuarantined) {
      io.emit('memberFrozen', { memberId });

      // Priority alert to every linked Master with the exact transaction id
      // (fire-and-forget; the quarantine stands even if Telegram is down).
      pool.query(
        `SELECT username, telegram_chat_id FROM staff_users
          WHERE role = 'Master' AND telegram_chat_id IS NOT NULL`
      ).then(masters => {
        const alert =
          `SECURITY ALERT — Quarantine Interceptor\n\n` +
          `Staff "${req.user.username}" (${req.user.role}) added ${numericPoints.toLocaleString()} points ` +
          `to customer "${target.full_name}".\n\n` +
          `Tripwire: ${quarantineReason}.\n\n` +
          `Transaction #${tx.transaction_id} was RECORDED and the customer's account is now FROZEN pending review.\n\n` +
          `Decide below, or from the customer's card on the dashboard.`;
        const buttons = {
          inline_keyboard: [[
            { text: `Approve #${tx.transaction_id}`, callback_data: `q:approve:${tx.transaction_id}` },
            { text: `Reject #${tx.transaction_id}`, callback_data: `q:reject:${tx.transaction_id}` },
          ]],
        };
        for (const m of masters.rows) {
          sendTelegram(m.telegram_chat_id, alert, buttons).catch(e => console.error('Quarantine alert send failed:', e.message));
        }
      }).catch(e => console.error('Quarantine alert lookup failed:', e.message));

      console.warn(`QUARANTINE: tx #${tx.transaction_id} — ${numericPoints} pts by "${req.user.username}" (${req.user.role}) to member ${memberId}; ${quarantineReason}; member frozen.`);
      const quarantinePayload = {
        success: true,
        newTotal,
        transactionId: tx.transaction_id,
        quarantined: true,
        warning: `Points recorded (transaction #${tx.transaction_id}), but a fraud tripwire fired (${quarantineReason}) — the customer's account is temporarily locked pending Master approval. Masters have been notified.`,
      };
      if (idemKey) await finalizeIdempotencyKey(idemKey, 201, quarantinePayload);
      return res.status(201).json(quarantinePayload);
    }

    const okPayload = { success: true, newTotal, transactionId: tx.transaction_id };
    if (idemKey) await finalizeIdempotencyKey(idemKey, 200, okPayload);
    res.status(200).json(okPayload);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (idemKey) await releaseIdempotencyKey(idemKey);
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
              t.quarantine_status, t.original_points, t.edited_at,
              u.username AS staff_name,
              COALESCE(t.served_car_plate, c.car_plate, v.plate) AS car_plate,
              COALESCE(t.served_car_model, c.car_model, v.car_model) AS car_model,
              COALESCE((
                SELECT json_agg(json_build_object(
                         'old', el.old_points,
                         'new', el.new_points,
                         'by', eu.username,
                         'at', el.edited_at
                       ) ORDER BY el.edited_at ASC)
                  FROM point_edit_log el
                  LEFT JOIN staff_users eu ON eu.id = el.edited_by
                 WHERE el.transaction_id = t.transaction_id
              ), '[]'::json) AS edits
         FROM point_transactions t
         LEFT JOIN staff_users u ON u.id = t.staff_id
         LEFT JOIN cars c ON c.car_id = t.car_id
         LEFT JOIN vehicles v ON v.vehicle_id = t.vehicle_id
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

// ── Plate precheck (for the registration form) ──
// Tells staff, as they type a plate, whether this physical car has been with
// us before — so a "new" customer's car that we've serviced under a previous
// owner is flagged, and its history carries over. Fails quiet so a lookup
// hiccup never blocks registration.
app.get('/api/plate-precheck/:plate', async (req, res) => {
  const plate = (req.params.plate || '').trim().toUpperCase();
  if (!plate) return res.json({ known: false });
  try {
    const v = await pool.query('SELECT vehicle_id, car_model FROM vehicles WHERE UPPER(plate) = $1', [plate]);
    if (v.rows.length === 0) return res.json({ known: false, plate });
    const vehicleId = v.rows[0].vehicle_id;

    // Is it currently owned by an active member? (would be a duplicate)
    const active = await pool.query(
      `SELECT m.full_name
         FROM cars c
         JOIN members m ON m.member_id = c.member_id AND m.deleted_at IS NULL
        WHERE c.vehicle_id = $1
        ORDER BY c.car_id DESC LIMIT 1`,
      [vehicleId]
    );

    // Service history summary + most recent known owner (snapshot survives purges).
    const hist = await pool.query(
      `SELECT COUNT(*)::int AS cnt,
              MAX(transaction_date) AS last_date,
              (SELECT served_member_name FROM point_transactions
                WHERE vehicle_id = $1 AND served_member_name IS NOT NULL
                ORDER BY transaction_date DESC LIMIT 1) AS last_owner
         FROM point_transactions WHERE vehicle_id = $1`,
      [vehicleId]
    );
    const row = hist.rows[0] || {};

    res.json({
      known: true,
      plate,
      carModel: v.rows[0].car_model || null,
      serviceCount: row.cnt || 0,
      lastServiceDate: row.last_date || null,
      previousOwner: row.last_owner || null,
      activeOwner: active.rows[0]?.full_name || null,
    });
  } catch (err) {
    console.error('GET /api/plate-precheck error:', err.message);
    res.json({ known: false }); // never block the form on a lookup error
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
    await pool.query('UPDATE members SET deleted_at = NOW(), deleted_by = $2 WHERE member_id = $1', [memberId, req.user.username]);
    io.emit('memberDeleted', { memberId: parseInt(memberId) });
    await auditLog(req, 'DELETE_MEMBER', memberId, 'moved to trash (soft delete)');
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
    await auditLog(req, 'RESTORE_MEMBER', memberId, `"${restored.full_name}" restored from trash`);
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
    await auditLog(req, 'PURGE_MEMBER', memberId, 'permanently deleted from trash');
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