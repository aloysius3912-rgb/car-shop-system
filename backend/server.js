const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');

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

// ── Password storage ──
const FALLBACK_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';

async function ensureSettingsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  const existing = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash(FALLBACK_PASSWORD, 10);
    await pool.query(
      "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)",
      [hash]
    );
    console.log('🔑 Seeded initial admin password from ADMIN_PASSWORD env var.');
  }
}
ensureSettingsTable().catch(err => console.error('Settings table setup failed:', err.message));

async function getPasswordHash() {
  const result = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  return result.rows[0]?.value || null;
}

async function setPasswordHash(newHash) {
  await pool.query(
    "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
    [newHash]
  );
}

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
  const { password } = req.body;
  try {
    const hash = await getPasswordHash();
    if (!hash) return res.status(500).json({ error: 'Password not set up yet. Try again shortly.' });
    const match = await bcrypt.compare(password || '', hash);
    if (match) {
      res.json({ success: true, token: hash });
    } else {
      res.status(401).json({ error: 'Incorrect password' });
    }
  } catch (err) {
    console.error('POST /api/login error:', err.message);
    res.status(500).json({ error: 'Login failed. Try again.' });
  }
});

app.use('/api', async (req, res, next) => {
  if (req.path === '/login') return next();
  try {
    const hash = await getPasswordHash();
    const token = req.headers['x-admin-token'];
    if (!hash || token !== hash) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: 'Auth check failed' });
  }
});

// ── Health check ──
app.get('/', (req, res) => {
  res.json({ status: 'Car Shop backend is running ✅' });
});

// ── Change password ──
app.post('/api/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters.' });
  }
  try {
    const hash = await getPasswordHash();
    const match = await bcrypt.compare(currentPassword || '', hash);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect.' });
    const newHash = await bcrypt.hash(newPassword, 10);
    await setPasswordHash(newHash);
    res.json({ success: true, token: newHash });
  } catch (err) {
    console.error('POST /api/change-password error:', err.message);
    res.status(500).json({ error: 'Could not change password.' });
  }
});

// ── Fetch ALL members with their cars ──
app.get('/api/members', async (req, res) => {
  try {
    const membersResult = await pool.query('SELECT * FROM members ORDER BY full_name ASC');
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
app.post('/api/new-member', async (req, res) => {
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
  const { memberId, points, description } = req.body;
  const numericPoints = parseInt(points, 10) || 0;
  try {
    // Guard: prevent negative total
    if (numericPoints < 0) {
      const check = await pool.query('SELECT total_points FROM members WHERE member_id = $1', [memberId]);
      if (check.rows.length === 0) return res.status(404).json({ error: 'Member not found' });
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

// ── Fetch transaction history ──
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

// ── Delete a member ──
app.delete('/api/delete-member/:id', async (req, res) => {
  const memberId = req.params.id;
  try {
    await pool.query('DELETE FROM point_transactions WHERE member_id = $1', [memberId]);
    await pool.query('DELETE FROM cars WHERE member_id = $1', [memberId]);
    await pool.query('DELETE FROM members WHERE member_id = $1', [memberId]);
    io.emit('memberDeleted', { memberId: parseInt(memberId) });
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/delete-member error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🗄️  Database: ${process.env.DATABASE_URL ? 'Neon PostgreSQL' : 'Local Docker'}`);
});