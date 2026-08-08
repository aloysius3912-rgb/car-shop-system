// Behavioural test for the point-expiry engine + preview, run against an
// in-memory Postgres. Exercises the REAL SQL from server.js.
// Run with:  TEST_DATABASE_URL=postgres://user:pass@host/db  node test-expiry.js
// Point it at a SCRATCH database — it drops and recreates its own tables.
// Never run this against production: it will DROP members/point_transactions.
const { Pool } = require('pg');

const EXPIRY_DAYS = 365; // keep in sync with server.js
const pool = process.env.TEST_DATABASE_URL
  ? new Pool({ connectionString: process.env.TEST_DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : new Pool({ host: process.env.PGHOST || '/tmp', port: Number(process.env.PGPORT) || 5433, user: process.env.PGUSER || 'pg', database: process.env.PGDATABASE || 'postgres' });

// Minimal schema mirroring the real one.
async function setup() {
  await pool.query(`DROP TABLE IF EXISTS point_transactions; DROP TABLE IF EXISTS members;`);
  await pool.query(`
    CREATE TABLE members (
      member_id SERIAL PRIMARY KEY,
      full_name TEXT,
      total_points INT DEFAULT 0,
      date_joined TIMESTAMP,
      deleted_at TIMESTAMP,
      is_frozen BOOLEAN DEFAULT false
    );
    CREATE TABLE point_transactions (
      transaction_id SERIAL PRIMARY KEY,
      member_id INT,
      points_added INT,
      description TEXT,
      staff_id INT,
      served_member_name TEXT,
      transaction_date TIMESTAMP DEFAULT NOW()
    );
  `);

  const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();

  // 1: inactive 400d, has points  → SHOULD expire
  await pool.query(`INSERT INTO members (full_name,total_points,date_joined) VALUES ('Stale Sam',1000,$1)`, [daysAgo(500)]);
  await pool.query(`INSERT INTO point_transactions (member_id,points_added,description,transaction_date) VALUES (1,1000,'LED Install',$1)`, [daysAgo(400)]);

  // 2: active 10d ago            → should NOT expire
  await pool.query(`INSERT INTO members (full_name,total_points,date_joined) VALUES ('Active Amy',500,$1)`, [daysAgo(500)]);
  await pool.query(`INSERT INTO point_transactions (member_id,points_added,description,transaction_date) VALUES (2,500,'Dashcam',$1)`, [daysAgo(10)]);

  // 3: inactive 400d but ZERO points → should NOT appear (nothing to clear)
  await pool.query(`INSERT INTO members (full_name,total_points,date_joined) VALUES ('Broke Bob',0,$1)`, [daysAgo(500)]);
  await pool.query(`INSERT INTO point_transactions (member_id,points_added,description,transaction_date) VALUES (3,0,'nil',$1)`, [daysAgo(400)]);

  // 4: inactive 400d but FROZEN  → should NOT expire (under review)
  await pool.query(`INSERT INTO members (full_name,total_points,date_joined,is_frozen) VALUES ('Frozen Fay',900,$1,true)`, [daysAgo(500)]);
  await pool.query(`INSERT INTO point_transactions (member_id,points_added,description,transaction_date) VALUES (4,900,'Mats',$1)`, [daysAgo(400)]);

  // 5: inactive 400d but DELETED → should NOT expire (in trash)
  await pool.query(`INSERT INTO members (full_name,total_points,date_joined,deleted_at) VALUES ('Deleted Dan',700,$1,$2)`, [daysAgo(500), daysAgo(5)]);
  await pool.query(`INSERT INTO point_transactions (member_id,points_added,description,transaction_date) VALUES (5,700,'Film',$1)`, [daysAgo(400)]);

  // 6: NEVER transacted, joined 400d ago, has points → SHOULD expire (falls back to date_joined)
  await pool.query(`INSERT INTO members (full_name,total_points,date_joined) VALUES ('Ghost Gary',300,$1)`, [daysAgo(400)]);

  // 7: boundary — last activity exactly 364d ago → should NOT expire
  await pool.query(`INSERT INTO members (full_name,total_points,date_joined) VALUES ('Edge Eddie',200,$1)`, [daysAgo(500)]);
  await pool.query(`INSERT INTO point_transactions (member_id,points_added,description,transaction_date) VALUES (7,200,'Tint',$1)`, [daysAgo(364)]);
}

// ── The real preview query from server.js ──
async function previewStalePoints() {
  const stale = await pool.query(
    `SELECT m.member_id, m.full_name, m.total_points,
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
            ) < NOW() - ($1 || ' days')::interval
      ORDER BY m.total_points DESC`,
    [EXPIRY_DAYS]
  );
  const pointsAtRisk = stale.rows.reduce((s, r) => s + (Number(r.total_points) || 0), 0);
  return { members: stale.rows, count: stale.rows.length, pointsAtRisk };
}

// ── The real expiry routine from server.js (transaction bits inlined) ──
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
  for (const m of stale.rows) {
    const upd = await pool.query(
      'UPDATE members SET total_points = 0 WHERE member_id = $1 AND total_points = $2 RETURNING member_id',
      [m.member_id, m.total_points]
    );
    if (upd.rows.length === 0) continue;
    await pool.query(
      `INSERT INTO point_transactions (member_id, points_added, description, staff_id, served_member_name)
       VALUES ($1, $2, 'System: 12-Month Expiry', NULL, $3)`,
      [m.member_id, -m.total_points, m.full_name]
    );
    expiredCount++; pointsCleared += Number(m.total_points) || 0;
  }
  return { expiredCount, pointsCleared };
}

let pass = 0, fail = 0;
function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`${ok ? '✓' : '✗'} ${label}` + (ok ? '' : `\n    expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`));
  ok ? pass++ : fail++;
}

(async () => {
  await setup();

  // ── Preview should not change anything ──
  const p1 = await previewStalePoints();
  const names = p1.members.map(m => m.full_name).sort();
  check('preview finds exactly the stale-with-points members', names, ['Ghost Gary', 'Stale Sam']);
  check('preview totals points at risk', p1.pointsAtRisk, 1300);

  const untouched = await pool.query('SELECT SUM(total_points)::int AS s FROM members');
  check('preview changed NO balances', untouched.rows[0].s, 1000 + 500 + 0 + 900 + 700 + 300 + 200);

  // ── Real run ──
  const r = await expireStalePoints();
  check('expired 2 members', r.expiredCount, 2);
  check('cleared 1300 pts', r.pointsCleared, 1300);

  const after = await pool.query('SELECT member_id, full_name, total_points FROM members ORDER BY member_id');
  const bal = {}; after.rows.forEach(m => bal[m.full_name] = m.total_points);
  check('Stale Sam zeroed', bal['Stale Sam'], 0);
  check('Ghost Gary zeroed (no-tx fallback to date_joined)', bal['Ghost Gary'], 0);
  check('Active Amy untouched', bal['Active Amy'], 500);
  check('Frozen Fay untouched (frozen)', bal['Frozen Fay'], 900);
  check('Deleted Dan untouched (in trash)', bal['Deleted Dan'], 700);
  check('Edge Eddie untouched (364d = inside window)', bal['Edge Eddie'], 200);

  // ── Ledger entries written ──
  const led = await pool.query(`SELECT member_id, points_added, served_member_name FROM point_transactions WHERE description = 'System: 12-Month Expiry' ORDER BY member_id`);
  check('two expiry ledger rows written', led.rows.length, 2);
  check('ledger reverses exact balances', led.rows.map(r => r.points_added).sort((a,b)=>a-b), [-1000, -300].sort((a,b)=>a-b));
  check('ledger snapshots the customer name', led.rows.map(r => r.served_member_name).sort(), ['Ghost Gary', 'Stale Sam']);

  // ── Idempotency: a second run must clear nothing ──
  const r2 = await expireStalePoints();
  check('second run is a no-op', [r2.expiredCount, r2.pointsCleared], [0, 0]);
  const p2 = await previewStalePoints();
  check('preview now empty', p2.count, 0);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('TEST ERROR:', e.message); process.exit(1); });
