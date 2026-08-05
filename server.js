/**
 * HBL Cell Inspector — API Server v1.3.0
 * Optimised for Render free tier (512MB RAM)
 * - Photos stored separately (not in main remarks JSON)
 * - Paginated inspection queries
 * - Stripped base64 from list responses
 * - JSON body limit 5MB (was 50MB)
 * - Node --max-old-space-size=400 via start script
 */
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cellinspector_secret_key_2024';

app.use(cors());
// ── CRITICAL: 5MB limit (was 50MB) — base64 photos must be stripped before sending
app.use(express.json({ limit: '5mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,              // max 5 DB connections (free tier limit)
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});
const q = (text, params) => pool.query(text, params);

// ── Strip base64 photos from remarks before returning to client ────────────
// Photos as base64 in remarks can be 1–5MB per record.
// We strip them from list responses — PDF generation reads direct from device.
function stripPhotosFromRemarks(remarksStr) {
  if (!remarksStr) return remarksStr;
  try {
    const d = JSON.parse(remarksStr);
    // Remove base64 arrays — keep local file URIs only
    if (d.fsrPhotosB64) d.fsrPhotosB64 = [];
    return JSON.stringify(d);
  } catch (e) { return remarksStr; }
}

// ── DATABASE INIT ──────────────────────────────────────────────────────────
async function initDatabase() {
  await q(`CREATE TABLE IF NOT EXISTS engineers (
    id SERIAL PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'engineer',
    circle TEXT DEFAULT '',
    permissions JSONB DEFAULT '{}',
    last_login TIMESTAMPTZ,
    app_version TEXT DEFAULT '',
    device_platform TEXT DEFAULT '',
    login_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS inspections (
    id SERIAL PRIMARY KEY,
    cell_id TEXT,
    cell_type TEXT,
    rated_voltage REAL,
    rated_capacity REAL,
    engineer_id TEXT,
    engineer_name TEXT,
    circle TEXT DEFAULT '',
    decision TEXT,
    remarks TEXT,
    photo_uri TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS thresholds (
    id SERIAL PRIMARY KEY,
    float_voltage_min REAL DEFAULT 2.20,
    float_voltage_max REAL DEFAULT 2.30,
    boost_voltage_min REAL DEFAULT 2.28,
    boost_voltage_max REAL DEFAULT 2.38,
    lvbd_min REAL DEFAULT 1.75,
    dod_caution REAL DEFAULT 60,
    dod_deploy_bb REAL DEFAULT 80,
    smps_efficiency REAL DEFAULT 0.90,
    float_tolerance REAL DEFAULT 0.1,
    boost_tolerance REAL DEFAULT 0.1,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS engineer_admin_map (
    id SERIAL PRIMARY KEY,
    engineer_employee_id TEXT NOT NULL,
    admin_employee_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(engineer_employee_id, admin_employee_id)
  )`);

  // Safe migrations (ADD COLUMN IF NOT EXISTS — idempotent)
  const migrations = [
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS app_version TEXT DEFAULT ''`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS device_platform TEXT DEFAULT ''`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS circle TEXT DEFAULT ''`,
    `ALTER TABLE inspections ADD COLUMN IF NOT EXISTS circle TEXT DEFAULT ''`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS smps_efficiency REAL DEFAULT 0.90`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS float_tolerance REAL DEFAULT 0.1`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS boost_tolerance REAL DEFAULT 0.1`,
  ];
  for (const m of migrations) {
    try { await q(m); } catch(e) { /* column may already exist */ }
  }

  // Default thresholds row
  await q(`INSERT INTO thresholds (id) VALUES (1) ON CONFLICT (id) DO NOTHING`);

  // Default superadmin
  const sa = await q(`SELECT id FROM engineers WHERE employee_id='SUPERADMIN'`);
  if (sa.rows.length === 0) {
    const hash = await bcrypt.hash('super123', 10);
    await q(`INSERT INTO engineers (employee_id,name,password,role,circle,permissions)
             VALUES ('SUPERADMIN','Super Admin',$1,'superadmin','ALL','{}')`, [hash]);
  }
  console.log('DB init done');
}

// ── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── LOGIN ───────────────────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  try {
    const { employee_id, password, app_version = '', device_platform = '' } = req.body;
    if (!employee_id || !password)
      return res.status(400).json({ error: 'Employee ID and password required' });

    const r = await q(`SELECT * FROM engineers WHERE employee_id=$1`, [employee_id.trim().toUpperCase()]);
    const eng = r.rows[0];
    if (!eng) return res.status(401).json({ error: 'Employee ID not found' });

    const ok = await bcrypt.compare(password, eng.password);
    if (!ok) return res.status(401).json({ error: 'Incorrect password' });

    // Record login activity
    await q(`UPDATE engineers SET
      last_login=NOW(),
      login_count=COALESCE(login_count,0)+1,
      app_version=$1, device_platform=$2
      WHERE id=$3`, [app_version || '', device_platform || '', eng.id]);

    const token = jwt.sign(
      { id: eng.id, employee_id: eng.employee_id, name: eng.name, role: eng.role, circle: eng.circle || '' },
      JWT_SECRET, { expiresIn: '30d' }
    );
    res.json({
      token,
      engineer: {
        id: eng.id, employee_id: eng.employee_id, name: eng.name,
        role: eng.role, circle: eng.circle || '',
        permissions: eng.permissions || {}
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CHANGE PASSWORD ─────────────────────────────────────────────────────────
app.post('/change-password', verifyToken, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    const r = await q('SELECT password FROM engineers WHERE id=$1', [req.user.id]);
    const eng = r.rows[0];
    if (!eng) return res.status(404).json({ error: 'User not found' });
    const ok = await bcrypt.compare(current_password, eng.password);
    if (!ok) return res.status(401).json({ error: 'Current password incorrect' });
    const hash = await bcrypt.hash(new_password, 10);
    await q('UPDATE engineers SET password=$1 WHERE id=$2', [hash, req.user.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── INSPECTIONS ─────────────────────────────────────────────────────────────
app.post('/inspections', verifyToken, async (req, res) => {
  try {
    const { cell_id, cell_type, rated_voltage, rated_capacity, decision, remarks, photo_uri } = req.body;
    const userCircle = req.user.circle || '';

    // Strip base64 photos from remarks before saving to DB — saves huge amounts of space
    const cleanRemarks = stripPhotosFromRemarks(remarks);

    const r = await q(
      `INSERT INTO inspections (cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id,created_at`,
      [cell_id, cell_type, rated_voltage, rated_capacity,
       req.user.employee_id, req.user.name, userCircle,
       decision, cleanRemarks, photo_uri || null]
    );
    res.json({ success: true, id: r.rows[0].id, created_at: r.rows[0].created_at });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/inspections', verifyToken, async (req, res) => {
  try {
    const { role, employee_id, circle } = req.user;
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 50);
    const offset = (page - 1) * limit;
    let r;

    if (role === 'superadmin') {
      const filterCircle = req.query.circle;
      r = filterCircle && filterCircle !== 'ALL'
        ? await q(`SELECT id,cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri,created_at
                   FROM inspections WHERE circle=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
                   [filterCircle, limit, offset])
        : await q(`SELECT id,cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri,created_at
                   FROM inspections ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
                   [limit, offset]);
    } else if (role === 'admin') {
      const mappedRes = await q(
        'SELECT engineer_employee_id FROM engineer_admin_map WHERE admin_employee_id=$1',
        [employee_id]
      );
      const mapped = mappedRes.rows.map(row => row.engineer_employee_id);

      // Also get engineers from mapped admins' circles
      let allIds = [...mapped];
      if (mapped.length > 0) {
        const adminsRes = await q(
          `SELECT circle FROM engineers WHERE employee_id=ANY($1::text[]) AND role='admin'`,
          [mapped]
        );
        for (const a of adminsRes.rows) {
          if (a.circle) {
            const engRes = await q(
              `SELECT employee_id FROM engineers WHERE circle=$1 AND role='engineer'`, [a.circle]
            );
            allIds = [...allIds, ...engRes.rows.map(r => r.employee_id)];
          }
        }
      }
      allIds = [...new Set(allIds)];

      if (allIds.length > 0) {
        r = await q(
          `SELECT id,cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri,created_at
           FROM inspections WHERE circle=$1 OR engineer_id=ANY($2::text[])
           ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
          [circle || '', allIds, limit, offset]
        );
      } else {
        r = await q(
          `SELECT id,cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri,created_at
           FROM inspections WHERE circle=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
          [circle || '', limit, offset]
        );
      }
    } else {
      // Engineer — own records only
      r = await q(
        `SELECT id,cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri,created_at
         FROM inspections WHERE engineer_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
        [employee_id, limit, offset]
      );
    }

    // Strip base64 photos from list response — saves huge RAM
    const records = r.rows.map(row => ({
      ...row,
      remarks: stripPhotosFromRemarks(row.remarks)
    }));
    res.json(records);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get single inspection WITH photos (for PDF generation — called only when needed)
app.get('/inspections/:id', verifyToken, async (req, res) => {
  try {
    const r = await q('SELECT * FROM inspections WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]); // Full remarks including photos
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/inspections/:id', verifyToken, async (req, res) => {
  try {
    const { decision, remarks } = req.body;
    const cleanRemarks = stripPhotosFromRemarks(remarks);
    await q('UPDATE inspections SET decision=$1,remarks=$2 WHERE id=$3',
      [decision, cleanRemarks, req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/inspections/:id', verifyToken, async (req, res) => {
  try {
    if (!['superadmin', 'admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    await q('DELETE FROM inspections WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Offline sync — batch insert
app.post('/sync', verifyToken, async (req, res) => {
  try {
    const { records } = req.body;
    if (!Array.isArray(records)) return res.status(400).json({ error: 'records array required' });
    const results = [];
    for (const rec of records) {
      try {
        const clean = stripPhotosFromRemarks(rec.remarks);
        const r = await q(
          `INSERT INTO inspections (cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri,created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11::timestamptz,NOW())) RETURNING id`,
          [rec.cell_id, rec.cell_type, rec.rated_voltage, rec.rated_capacity,
           req.user.employee_id, req.user.name, req.user.circle || '',
           rec.decision, clean, rec.photo_uri || null, rec.created_at || null]
        );
        results.push({ offline_id: rec.offline_id, id: r.rows[0].id, success: true });
      } catch (e) {
        results.push({ offline_id: rec.offline_id, success: false, error: e.message });
      }
    }
    res.json({ synced: results.filter(r => r.success).length, results });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── THRESHOLDS ──────────────────────────────────────────────────────────────
app.get('/thresholds', verifyToken, async (req, res) => {
  try {
    const r = await q('SELECT * FROM thresholds WHERE id=1');
    res.json(r.rows[0] || {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/thresholds', verifyToken, async (req, res) => {
  try {
    if (!['superadmin', 'admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    const { float_voltage_min, float_voltage_max, boost_voltage_min, boost_voltage_max,
            lvbd_min, dod_caution, dod_deploy_bb, smps_efficiency, float_tolerance, boost_tolerance } = req.body;
    await q(`UPDATE thresholds SET
      float_voltage_min=$1, float_voltage_max=$2, boost_voltage_min=$3, boost_voltage_max=$4,
      lvbd_min=$5, dod_caution=$6, dod_deploy_bb=$7, smps_efficiency=$8,
      float_tolerance=$9, boost_tolerance=$10, updated_at=NOW() WHERE id=1`,
      [float_voltage_min, float_voltage_max, boost_voltage_min, boost_voltage_max,
       lvbd_min, dod_caution, dod_deploy_bb, smps_efficiency || 0.90,
       float_tolerance || 0.1, boost_tolerance || 0.1]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ENGINEERS ───────────────────────────────────────────────────────────────
app.get('/engineers', verifyToken, async (req, res) => {
  try {
    const { role, circle } = req.user;
    let r;
    if (role === 'superadmin') {
      const fc = req.query.circle;
      r = fc && fc !== 'ALL'
        ? await q(`SELECT id,employee_id,name,role,circle,permissions,created_at,last_login,app_version,device_platform,login_count FROM engineers WHERE circle=$1 ORDER BY role,name`, [fc])
        : await q(`SELECT id,employee_id,name,role,circle,permissions,created_at,last_login,app_version,device_platform,login_count FROM engineers ORDER BY role,name`);
    } else if (role === 'admin') {
      r = await q(`SELECT id,employee_id,name,role,circle,permissions,created_at,last_login,app_version,device_platform,login_count FROM engineers WHERE circle=$1 ORDER BY role,name`, [circle || '']);
    } else {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/engineers', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    const { employee_id, name, password, role, circle, permissions } = req.body;
    if (!employee_id || !name || !password) return res.status(400).json({ error: 'Required fields missing' });
    const hash = await bcrypt.hash(password, 10);
    const assignedCircle = (circle || '').trim().toUpperCase() || req.user.circle || '';
    const r = await q(
      `INSERT INTO engineers (employee_id,name,password,role,circle,permissions) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [employee_id.trim().toUpperCase(), name, hash, role || 'engineer', assignedCircle, JSON.stringify(permissions || {})]
    );
    res.json({ success: true, id: r.rows[0].id });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Employee ID already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/engineers/:id', verifyToken, async (req, res) => {
  try {
    if (!['superadmin', 'admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    const { name, password, role, circle, permissions } = req.body;
    const assignedCircle = (circle || '').trim().toUpperCase() || '';
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await q(`UPDATE engineers SET name=$1,role=$2,circle=$3,permissions=$4,password=$5 WHERE id=$6`,
        [name, role, assignedCircle, JSON.stringify(permissions || {}), hash, req.params.id]);
    } else {
      await q(`UPDATE engineers SET name=$1,role=$2,circle=$3,permissions=$4 WHERE id=$5`,
        [name, role, assignedCircle, JSON.stringify(permissions || {}), req.params.id]);
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/engineers/:id', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    await q('DELETE FROM engineers WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── NOTIFICATIONS ────────────────────────────────────────────────────────────
app.get('/notifications', verifyToken, async (req, res) => {
  try {
    const r = await q('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 20');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/notifications', verifyToken, async (req, res) => {
  try {
    if (!['superadmin', 'admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    const { title, message } = req.body;
    await q('INSERT INTO notifications (title,message,created_by) VALUES ($1,$2,$3)', [title, message, req.user.name]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/notifications/:id', verifyToken, async (req, res) => {
  try {
    await q('DELETE FROM notifications WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ENGINEER-ADMIN MAPPING ────────────────────────────────────────────────────
app.get('/admin-mappings/:admin_id', verifyToken, async (req, res) => {
  try {
    if (!['superadmin', 'admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    const r = await q('SELECT engineer_employee_id FROM engineer_admin_map WHERE admin_employee_id=$1', [req.params.admin_id]);
    res.json(r.rows.map(row => row.engineer_employee_id));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin-mappings/:admin_id', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    const { engineer_ids } = req.body;
    if (!Array.isArray(engineer_ids)) return res.status(400).json({ error: 'engineer_ids array required' });
    await q('DELETE FROM engineer_admin_map WHERE admin_employee_id=$1', [req.params.admin_id]);
    for (const eid of engineer_ids) {
      await q('INSERT INTO engineer_admin_map (engineer_employee_id,admin_employee_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [eid, req.params.admin_id]);
    }
    res.json({ success: true, mapped: engineer_ids.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/my-admin', verifyToken, async (req, res) => {
  try {
    const r = await q(
      `SELECT e.id,e.employee_id,e.name,e.role,e.circle FROM engineer_admin_map m
       JOIN engineers e ON e.employee_id=m.admin_employee_id WHERE m.engineer_employee_id=$1`,
      [req.user.employee_id]
    );
    res.json(r.rows[0] || null);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    status: 'ok',
    message: 'HBL Cell Inspector API — PostgreSQL',
    memory_mb: Math.round(mem.heapUsed / 1024 / 1024),
    uptime_min: Math.round(process.uptime() / 60)
  });
});

// ── START ─────────────────────────────────────────────────────────────────────
initDatabase()
  .then(() => {
    app.listen(PORT, () => console.log(`HBL Cell Inspector API running on port ${PORT}`));
  })
  .catch(e => {
    console.error('DB init failed:', e.code || '', e.message);
    process.exit(1);
  });
