const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();

// ── Allowed frontend origins ──
const ALLOWED_ORIGINS = [
  'https://car-shop-system-zho8.vercel.app',
  'http://localhost:3000', // local development
];

app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.json());

// ── Simple password gate ──
// Set ADMIN_PASSWORD in Render's Environment tab.
// All /api routes (except /api/login and health check) require the
// 'x-admin-token' header to match ADMIN_PASSWORD.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';

// ── Simple rate limiter for /api/login (5 attempts per 15 min per IP) ──
const loginAttempts = new Map(); // ip -> { count, resetAt }
const LOGIN_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

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
    return res.status(429).json({
      error: `Too many attempts. Try again in ${minutesLeft} minute(s).`,
    });
  }

  entry.count += 1;
  next();
}

app.post('/api/login', loginRateLimiter, (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    // Token is just the password itself for simplicity — kept secret via HTTPS
    res.json({ success: true, token: ADMIN_PASSWORD });
  } else {
    res.status(401).json({ error: 'Incorrect password' });
  }
});

app.use('/api', (req, res, next) => {
  if (req.path === '/login') return next();
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

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

// ── Health check
app.get('/', (req, res) => {
  res.json({ status: 'Car Shop backend is running ✅' });
});

// ── Fetch ALL members
app.get('/api/members', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM members ORDER BY full_name ASC');
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/members error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── NEW: Fetch transaction history for a specific member
app.get('/api/transactions/:memberId', async (req, res) => {
  const { memberId } = req.params;
  try {
    const result = await pool.query(
      'SELECT transaction_id, points_added, description, transaction_date FROM point_transactions WHERE member_id = $1 ORDER BY transaction_date DESC LIMIT 50',
      [memberId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/transactions error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Add or deduct points
app.post('/api/add-points', async (req, res) => {
  const { memberId, points, description } = req.body;
  const numericPoints = parseInt(points, 10) || 0;
  try {
    // ── Guard: fetch current points first if this is a deduction ──
    if (numericPoints < 0) {
      const check = await pool.query(
        'SELECT total_points FROM members WHERE member_id = $1',
        [memberId]
      );
      if (check.rows.length === 0) {
        return res.status(404).json({ error: 'Member not found' });
      }
      const current = check.rows[0].total_points || 0;
      if (current + numericPoints < 0) {
        return res.status(400).json({
          error: `Not enough points! Member has ${current} pts, cannot deduct ${Math.abs(numericPoints)} pts.`,
        });
      }
    }

    const result = await pool.query(
      'UPDATE members SET total_points = COALESCE(total_points, 0) + $1 WHERE member_id = $2 RETURNING total_points',
      [numericPoints, memberId]
    );

    const txResult = await pool.query(
      'INSERT INTO point_transactions (member_id, points_added, description) VALUES ($1, $2, $3) RETURNING transaction_id, points_added, description, transaction_date',
      [memberId, numericPoints, description]
    );

    const newTotal = result.rows[0].total_points;
    io.emit('pointsUpdated', { memberId, newTotal });
    io.emit('transactionAdded', { memberId, transaction: txResult.rows[0] });
    res.json({ success: true, newTotal });
  } catch (err) {
    console.error('POST /api/add-points error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Register a new member
app.post('/api/new-member', async (req, res) => {
  const { fullName, carPlate, carModel } = req.body;
  if (!fullName || !fullName.trim()) {
    return res.status(400).json({ error: 'Full name is required' });
  }
  try {
    // ── Check for duplicate car plate (case-insensitive)
    const normalizedPlate = carPlate ? carPlate.trim().toUpperCase() : null;
    if (normalizedPlate) {
      const existing = await pool.query(
        'SELECT member_id, full_name FROM members WHERE UPPER(car_plate) = $1',
        [normalizedPlate]
      );
      if (existing.rows.length > 0) {
        return res.status(409).json({
          error: `Plate ${normalizedPlate} is already registered to ${existing.rows[0].full_name}`,
        });
      }
    }

    const result = await pool.query(
      'INSERT INTO members (full_name, car_plate, car_model, total_points, date_joined) VALUES ($1, $2, $3, 0, NOW()) RETURNING *',
      [
        fullName.trim(),
        normalizedPlate,
        carModel ? carModel.trim() : null,
      ]
    );

    const newMember = result.rows[0];
    io.emit('memberAdded', newMember);
    res.json({ success: true, member: newMember });
  } catch (err) {
    console.error('POST /api/new-member error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Delete a member
app.delete('/api/delete-member/:id', async (req, res) => {
  const memberId = req.params.id;
  try {
    await pool.query('DELETE FROM point_transactions WHERE member_id = $1', [memberId]);
    await pool.query('DELETE FROM members WHERE member_id = $1', [memberId]);
    io.emit('memberDeleted', { memberId: parseInt(memberId, 10) });
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/delete-member error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🗄️  Database: ${process.env.DATABASE_URL ? 'Render PostgreSQL' : 'Local Docker'}`);
});