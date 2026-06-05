const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'supersecret',
  port: 5432,
});

// Fetch ALL members
app.get('/api/members', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM members ORDER BY member_id ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add or Deduct points and broadcast
app.post('/api/add-points', async (req, res) => {
  const { memberId, points, description } = req.body;
  const numericPoints = parseInt(points, 10) || 0; 

  try {
    const result = await pool.query(
      'UPDATE members SET total_points = COALESCE(total_points, 0) + $1 WHERE member_id = $2 RETURNING total_points',
      [numericPoints, memberId]
    );
    
    await pool.query(
      'INSERT INTO point_transactions (member_id, points_added, description) VALUES ($1, $2, $3)',
      [memberId, numericPoints, description]
    );
    
    const newTotal = result.rows.total_points;
    io.emit('pointsUpdated', { memberId, newTotal });
    res.json({ success: true, newTotal });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Register a brand new member (Now includes Car Plate!)
app.post('/api/new-member', async (req, res) => {
  const { fullName, carPlate } = req.body; 
  try {
    const result = await pool.query(
      'INSERT INTO members (full_name, car_plate, total_points) VALUES ($1, $2, 0) RETURNING *',
      [fullName, carPlate]
    );
    const newMember = result.rows;
    io.emit('memberAdded', newMember);
    res.json({ success: true, member: newMember });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a member safely
app.delete('/api/delete-member/:id', async (req, res) => {
  const memberId = req.params.id;
  try {
    // Clean up transaction history first
    await pool.query('DELETE FROM point_transactions WHERE member_id = $1', [memberId]);
    // Then delete the member
    await pool.query('DELETE FROM members WHERE member_id = $1', [memberId]);
    
    io.emit('memberDeleted', { memberId: parseInt(memberId, 10) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

server.listen(5001, () => {
  console.log('✅ Master Backend Server is running on port 5001');
});