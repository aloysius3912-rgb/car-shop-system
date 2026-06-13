const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
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
        password: 'supersecret',
        port: 5432,
      }
);

// ── Health check
app.get('/', (req, res) => {
  res.json({ status: 'Car Shop backend is running ✅' });
});

// ── Debug: check database columns
app.get('/api/debug', async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT column_name FROM information_schema.columns WHERE table_name='members'"
    );
    res.json({ columns: result.rows, db: process.env.DATABASE_URL ? 'Neon' : 'Local' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    const result = await pool.query(
      'INSERT INTO members (full_name, car_plate, car_model, total_points, date_joined) VALUES ($1, $2, $3, 0, NOW()) RETURNING *',
      [
        fullName.trim(),
        carPlate ? carPlate.trim().toUpperCase() : null,
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