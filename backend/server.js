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
      role TEXT NOT NULL CHECK (role IN ('Admin', 'Technician')),
      can_add_member BOOLEAN DEFAULT true,
      can_delete_member BOOLEAN DEFAULT false,
      can_add_points BOOLEAN DEFAULT true,
      can_deduct_points BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      staff_id INT REFERENCES staff_users(id) ON DELETE CASCADE,
      role TEXT,
      expires_at TIMESTAMP NOT NULL
    );
  `);
  // Seed default admins on first run (temp password from env or 'changeme-now').
  const count = await pool.query('SELECT COUNT(*) FROM staff_users');
  if (parseInt(count.rows[0].count) === 0) {
    const tempHash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'changeme-now', 12);
    await pool.query(
      `INSERT INTO staff_users (username, password_hash, role) VALUES
       ('aloysius', $1, 'Admin'),
       ('kishen', $1, 'Admin')`,
      [tempHash]
    );
    console.log('🔑 Seeded default admin accounts: aloysius, kishen (change passwords immediately).');
  }
}
ensureAuthTables().catch(err => console.error('Auth tables setup failed:', err.message));

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

// Admins implicitly have every permission; Technicians use their flags.
function can(user, permission) {
  if (!user) return false;
  if (user.role === 'Admin') return true;
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

// Clean out expired sessions occasionally (every hour)
setInterval(() => {
  pool.query('DELETE FROM sessions WHERE expires_at <= NOW()').catch(() => {});
}, 60 * 60 * 1000);

// Auto-purge trashed members older than 30 days (runs hourly + once at startup).
async function purgeOldTrash() {
  try {
    const old = await pool.query(
      "SELECT member_id FROM members WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '30 days'"
    );
    for (const row of old.rows) {
      await pool.query('DELETE FROM point_transactions WHERE member_id = $1', [row.member_id]);
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
      'SELECT id, username, password_hash, role FROM staff_users WHERE LOWER(username) = LOWER($1)',
      [username.trim()]
    );
    const user = result.rows[0];
    // Compare against a dummy hash when user not found so response timing
    // doesn't reveal which usernames exist.
    const hash = user?.password_hash || '$2a$12$invalidinvalidinvalidinvaliduuuuuuuuuuuuuuuuuuuuuuuuu';
    const match = await bcrypt.compare(password, hash);
    if (user && match) {
      const token = await createSession(user.id, user.role);
      res.json({ success: true, token, role: user.role, username: user.username, expiresInHours: SESSION_TTL_HOURS });
    } else {
      res.status(401).json({ error: 'Incorrect username or password' });
    }
  } catch (err) {
    console.error('POST /api/login error:', err.message);
    res.status(500).json({ error: 'Login failed. Try again.' });
  }
});

app.use('/api', async (req, res, next) => {
  if (req.path === '/login') return next();
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

// ── RBAC: only Admins may pass ──
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin access required.' });
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

// ── Staff management (Admin only) ──
app.get('/api/staff', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, role, can_add_member, can_delete_member,
              can_add_points, can_deduct_points, created_at
         FROM staff_users ORDER BY created_at ASC`
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
  if (!['Admin', 'Technician'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });
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
    if (role && !['Admin', 'Technician'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role.' });
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

app.post('/api/staff/:id/reset-password', requireAdmin, async (req, res) => {
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

app.delete('/api/staff/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  try {
    // Don't allow deleting the last Admin
    const admins = await pool.query("SELECT COUNT(*) FROM staff_users WHERE role = 'Admin'");
    const target = await pool.query('SELECT role FROM staff_users WHERE id = $1', [id]);
    if (target.rows[0]?.role === 'Admin' && parseInt(admins.rows[0].count) <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last Admin account.' });
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

    // Insert first car
    let cars = [];
    if (normalizedPlate || carModel) {
      const carResult = await pool.query(
        'INSERT INTO cars (member_id, car_plate, car_model) VALUES ($1, $2, $3) RETURNING *',
        [newMember.member_id, normalizedPlate, carModel ? carModel.trim() : null]
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

    const result = await pool.query(
      'INSERT INTO cars (member_id, car_plate, car_model) VALUES ($1, $2, $3) RETURNING *',
      [memberId, normalizedPlate, carModel ? carModel.trim() : null]
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

    const txResult = await client.query(
      'INSERT INTO point_transactions (member_id, points_added, description, staff_id, car_id) VALUES ($1, $2, $3, $4, $5) RETURNING transaction_id, points_added, description, transaction_date, staff_id, car_id',
      [memberId, numericPoints, description, req.user.id, carIdToLog]
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
    await pool.query('DELETE FROM point_transactions WHERE member_id = $1', [memberId]);
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