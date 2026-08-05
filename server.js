/**
 * HBL Cell Inspector — API Server v1.3.1
 * Ultra-lean build for Render free tier (512MB RAM hard limit)
 * Key fixes:
 *   - remarks column: never returns fsrPhotosB64 (stripped at DB query level)
 *   - JSON body limit: 2MB
 *   - DB pool: max 3 connections
 *   - Forced GC hints after large queries
 *   - /inspections returns only last 50 records by default
 *   - /inspections/full for admin (last 200, still stripped)
 */
'use strict';
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const { Pool } = require('pg');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT  = process.env.JWT_SECRET || 'cellinspector_secret_key_2024';

app.use(cors());
app.use(express.json({ limit: '2mb' }));  // hard 2MB — photos must never be sent to server

// ── DB POOL (max 3 — Render free tier) ────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 3,
  idleTimeoutMillis: 20000,
  connectionTimeoutMillis: 5000,
});
const q = (sql, p) => pool.query(sql, p);

// ── STRIP BASE64 FROM REMARKS AT THE SQL LEVEL ─────────────────────────────
// Called on every row before sending to client
// Also called before INSERT/UPDATE to prevent base64 ever reaching the DB
function stripB64(str) {
  if (!str) return str;
  try {
    const d = JSON.parse(str);
    // Remove ONLY the base64 arrays — keep everything else intact
    delete d.fsrPhotosB64;
    // Also strip any inline base64 strings in fsrPhotos array
    if (Array.isArray(d.fsrPhotos)) {
      d.fsrPhotos = d.fsrPhotos.filter(u => u && !u.startsWith('data:'));
    }
    return JSON.stringify(d);
  } catch { return str; }
}

// Strip b64 from a result row
function cleanRow(row) {
  if (!row) return row;
  return { ...row, remarks: stripB64(row.remarks) };
}

// ── DB INIT ────────────────────────────────────────────────────────────────
async function initDB() {
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
    cell_id TEXT, cell_type TEXT,
    rated_voltage REAL, rated_capacity REAL,
    engineer_id TEXT, engineer_name TEXT,
    circle TEXT DEFAULT '',
    decision TEXT,
    remarks TEXT,   -- base64 photos NEVER stored here
    photo_uri TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS thresholds (
    id SERIAL PRIMARY KEY,
    float_voltage_min REAL DEFAULT 2.20, float_voltage_max REAL DEFAULT 2.30,
    boost_voltage_min REAL DEFAULT 2.28, boost_voltage_max REAL DEFAULT 2.38,
    lvbd_min REAL DEFAULT 1.75,
    dod_caution REAL DEFAULT 60, dod_deploy_bb REAL DEFAULT 80,
    smps_efficiency REAL DEFAULT 0.90,
    float_tolerance REAL DEFAULT 0.1, boost_tolerance REAL DEFAULT 0.1,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL, message TEXT NOT NULL,
    created_by TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS engineer_admin_map (
    id SERIAL PRIMARY KEY,
    engineer_employee_id TEXT NOT NULL,
    admin_employee_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(engineer_employee_id, admin_employee_id)
  )`);

  // Safe migrations
  for (const m of [
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS app_version TEXT DEFAULT ''`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS device_platform TEXT DEFAULT ''`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS circle TEXT DEFAULT ''`,
    `ALTER TABLE inspections ADD COLUMN IF NOT EXISTS circle TEXT DEFAULT ''`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS smps_efficiency REAL DEFAULT 0.90`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS float_tolerance REAL DEFAULT 0.1`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS boost_tolerance REAL DEFAULT 0.1`,
  ]) { try { await q(m); } catch {} }

  // Drop NOT NULL on any legacy columns from old schema that block inserts
  for (const col of ['cell_type','cell_make','cell_model','cell_capacity',
                     'cell_voltage','manufacturer','location','remarks']) {
    try {
      await q(`ALTER TABLE thresholds ALTER COLUMN ${col} DROP NOT NULL`);
    } catch {} // Column may not exist — safe to ignore
  }

  // Set defaults on all thresholds columns so INSERT without them works
  try {
    await q(`ALTER TABLE thresholds
      ALTER COLUMN float_voltage_min  SET DEFAULT 2.20,
      ALTER COLUMN float_voltage_max  SET DEFAULT 2.30,
      ALTER COLUMN boost_voltage_min  SET DEFAULT 2.28,
      ALTER COLUMN boost_voltage_max  SET DEFAULT 2.38,
      ALTER COLUMN lvbd_min           SET DEFAULT 1.75,
      ALTER COLUMN dod_caution        SET DEFAULT 60,
      ALTER COLUMN dod_deploy_bb      SET DEFAULT 80,
      ALTER COLUMN smps_efficiency    SET DEFAULT 0.90,
      ALTER COLUMN float_tolerance    SET DEFAULT 0.1,
      ALTER COLUMN boost_tolerance    SET DEFAULT 0.1`);
  } catch (e) { console.log('Set defaults (non-fatal):', e.message); }

  // ── PURGE BASE64 FROM EXISTING DB RECORDS (one-time cleanup) ────────────
  // Old records may have MB of base64 photos in remarks — strip them now
  console.log('Cleaning base64 from existing records...');
  try {
    // Only process records that actually contain base64 data
    const dirty = await q(
      `SELECT id, remarks FROM inspections
       WHERE remarks LIKE '%fsrPhotosB64%' OR remarks LIKE '%data:image%'
       LIMIT 200`
    );
    let cleaned = 0;
    for (const row of dirty.rows) {
      const clean = stripB64(row.remarks);
      if (clean !== row.remarks) {
        await q('UPDATE inspections SET remarks=$1 WHERE id=$2', [clean, row.id]);
        cleaned++;
      }
    }
    if (cleaned > 0) console.log(`Cleaned base64 from ${cleaned} records`);
  } catch (e) { console.log('Cleanup error (non-fatal):', e.message); }

  // Insert default thresholds row — cover ALL possible columns to avoid NOT NULL errors
  try {
    await q(`INSERT INTO thresholds (id,float_voltage_min,float_voltage_max,
      boost_voltage_min,boost_voltage_max,lvbd_min,dod_caution,dod_deploy_bb,
      smps_efficiency,float_tolerance,boost_tolerance)
      VALUES (1,2.20,2.30,2.28,2.38,1.75,60,80,0.90,0.1,0.1)
      ON CONFLICT (id) DO NOTHING`);
  } catch (e) {
    console.log('Thresholds seed (non-fatal):', e.message);
    // Fallback: update existing row instead
    try {
      await q(`UPDATE thresholds SET
        float_voltage_min=2.20, float_voltage_max=2.30,
        boost_voltage_min=2.28, boost_voltage_max=2.38,
        lvbd_min=1.75, dod_caution=60, dod_deploy_bb=80,
        smps_efficiency=0.90, float_tolerance=0.1, boost_tolerance=0.1
        WHERE id=1`);
    } catch {}
  }

  // Default superadmin
  const sa = await q(`SELECT id FROM engineers WHERE employee_id='SUPERADMIN'`);
  if (!sa.rows.length) {
    const h = await bcrypt.hash('super123', 10);
    await q(`INSERT INTO engineers (employee_id,name,password,role,circle,permissions)
             VALUES ('SUPERADMIN','Super Admin',$1,'superadmin','ALL','{}')`, [h]);
  }
  console.log('DB init done');
}

// ── AUTH ───────────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const a = req.headers.authorization;
  if (!a?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(a.split(' ')[1], JWT); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── LOGIN ──────────────────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  try {
    const { employee_id, password, app_version = '', device_platform = '' } = req.body;
    if (!employee_id || !password)
      return res.status(400).json({ error: 'Employee ID and password required' });
    const r = await q(`SELECT * FROM engineers WHERE employee_id=$1`,
      [employee_id.trim().toUpperCase()]);
    const eng = r.rows[0];
    if (!eng) return res.status(401).json({ error: 'Employee ID not found' });
    if (!await bcrypt.compare(password, eng.password))
      return res.status(401).json({ error: 'Incorrect password' });
    await q(`UPDATE engineers SET last_login=NOW(),
      login_count=COALESCE(login_count,0)+1,
      app_version=$1, device_platform=$2 WHERE id=$3`,
      [app_version, device_platform, eng.id]);
    const token = jwt.sign(
      { id: eng.id, employee_id: eng.employee_id, name: eng.name,
        role: eng.role, circle: eng.circle || '' },
      JWT, { expiresIn: '30d' }
    );
    res.json({ token, engineer: {
      id: eng.id, employee_id: eng.employee_id, name: eng.name,
      role: eng.role, circle: eng.circle || '', permissions: eng.permissions || {}
    }});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    const r = await q('SELECT password FROM engineers WHERE id=$1', [req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    if (!await bcrypt.compare(current_password, r.rows[0].password))
      return res.status(401).json({ error: 'Current password incorrect' });
    await q('UPDATE engineers SET password=$1 WHERE id=$2',
      [await bcrypt.hash(new_password, 10), req.user.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── INSPECTIONS ────────────────────────────────────────────────────────────
// SELECT only essential columns — never SELECT * on inspections
const INS_COLS = `id,cell_id,cell_type,rated_voltage,rated_capacity,
  engineer_id,engineer_name,circle,decision,photo_uri,created_at,
  LEFT(remarks, 8000) AS remarks`;  // hard truncate remarks at 8KB per row

app.post('/inspections', auth, async (req, res) => {
  try {
    const { cell_id, cell_type, rated_voltage, rated_capacity, decision, remarks, photo_uri } = req.body;
    // Strip b64 before save — if somehow b64 got through the 2MB limit
    const clean = stripB64(remarks);
    const r = await q(
      `INSERT INTO inspections
       (cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,circle,decision,remarks,photo_uri)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id,created_at`,
      [cell_id, cell_type, rated_voltage, rated_capacity,
       req.user.employee_id, req.user.name, req.user.circle || '',
       decision, clean, photo_uri || null]
    );
    res.json({ success: true, ...r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/inspections', auth, async (req, res) => {
  try {
    const { role, employee_id, circle } = req.user;
    // SuperAdmin gets up to 500 records, others get up to 100
    const maxLimit = (req.user?.role === 'superadmin') ? 500 : 100;
    const limit  = Math.min(maxLimit, parseInt(req.query.limit) || maxLimit);
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    let rows = [];

    if (role === 'superadmin') {
      const fc = req.query.circle;
      const r = (fc && fc !== 'ALL')
        ? await q(`SELECT ${INS_COLS} FROM inspections WHERE circle=$1
                   ORDER BY created_at DESC LIMIT $2 OFFSET $3`, [fc, limit, offset])
        : await q(`SELECT ${INS_COLS} FROM inspections
                   ORDER BY created_at DESC LIMIT $1 OFFSET $2`, [limit, offset]);
      rows = r.rows;

    } else if (role === 'admin') {
      const mapped = await q(
        'SELECT engineer_employee_id FROM engineer_admin_map WHERE admin_employee_id=$1',
        [employee_id]
      );
      const ids = mapped.rows.map(r => r.engineer_employee_id);
      // Get circles from mapped admins
      let allIds = [...ids];
      if (ids.length > 0) {
        const admins = await q(
          `SELECT circle FROM engineers WHERE employee_id=ANY($1::text[]) AND role='admin'`, [ids]
        );
        for (const a of admins.rows) {
          if (a.circle) {
            const eng = await q(
              `SELECT employee_id FROM engineers WHERE circle=$1 AND role='engineer'`, [a.circle]
            );
            allIds = [...allIds, ...eng.rows.map(r => r.employee_id)];
          }
        }
      }
      allIds = [...new Set(allIds)];
      const r = allIds.length > 0
        ? await q(`SELECT ${INS_COLS} FROM inspections
                   WHERE circle=$1 OR engineer_id=ANY($2::text[])
                   ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
                   [circle || '', allIds, limit, offset])
        : (circle
            ? await q(`SELECT ${INS_COLS} FROM inspections WHERE circle=$1
                       ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
                       [circle, limit, offset])
            : await q(`SELECT ${INS_COLS} FROM inspections
                       ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
                       [limit, offset]));
      rows = r.rows;

    } else {
      // Also search by engineer_name — old records may use name instead of ID
      const engInfo = await q('SELECT name FROM engineers WHERE employee_id=$1', [employee_id]);
      const engName = engInfo.rows[0]?.name || '';
      const r = await q(
        `SELECT ${INS_COLS} FROM inspections
         WHERE engineer_id=$1 OR engineer_name=$2
         ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
        [employee_id, engName, limit, offset]
      );
      rows = r.rows;
    }

    // Strip any remaining b64 and send
    res.json(rows.map(cleanRow));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Single record — full remarks for PDF (only called when user opens PDF)
app.get('/inspections/:id', auth, async (req, res) => {
  try {
    const r = await q(
      `SELECT id,cell_id,cell_type,rated_voltage,rated_capacity,
       engineer_id,engineer_name,circle,decision,photo_uri,created_at,remarks
       FROM inspections WHERE id=$1`, [req.params.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    // Still strip b64 — photos are on device, no need to send back
    res.json(cleanRow(r.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/inspections/:id', auth, async (req, res) => {
  try {
    const { decision, remarks } = req.body;
    await q('UPDATE inspections SET decision=$1,remarks=$2 WHERE id=$3',
      [decision, stripB64(remarks), req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/inspections/:id', auth, async (req, res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    await q('DELETE FROM inspections WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Offline sync batch
app.post('/sync', auth, async (req, res) => {
  try {
    const { records } = req.body;
    if (!Array.isArray(records)) return res.status(400).json({ error: 'records array required' });
    const results = [];
    for (const rec of records) {
      try {
        const r = await q(
          `INSERT INTO inspections
           (cell_id,cell_type,rated_voltage,rated_capacity,engineer_id,engineer_name,
            circle,decision,remarks,photo_uri,created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11::timestamptz,NOW()))
           RETURNING id`,
          [rec.cell_id, rec.cell_type, rec.rated_voltage, rec.rated_capacity,
           req.user.employee_id, req.user.name, req.user.circle || '',
           rec.decision, stripB64(rec.remarks), rec.photo_uri || null, rec.created_at || null]
        );
        results.push({ offline_id: rec.offline_id, id: r.rows[0].id, success: true });
      } catch (e) {
        results.push({ offline_id: rec.offline_id, success: false, error: e.message });
      }
    }
    res.json({ synced: results.filter(r => r.success).length, results });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── THRESHOLDS ─────────────────────────────────────────────────────────────
app.get('/thresholds', auth, async (req, res) => {
  try {
    const r = await q('SELECT * FROM thresholds WHERE id=1');
    res.json(r.rows[0] || {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Backward compat — old app calls /thresholds/VRLA
app.get('/thresholds/:cell_type', auth, async (req, res) => {
  try {
    const r = await q('SELECT * FROM thresholds WHERE id=1');
    res.json(r.rows[0] || {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/thresholds/:cell_type', auth, async (req, res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    const t = req.body;
    await q(`UPDATE thresholds SET
      float_voltage_min=$1, float_voltage_max=$2,
      boost_voltage_min=$3, boost_voltage_max=$4,
      lvbd_min=$5, dod_caution=$6, dod_deploy_bb=$7,
      smps_efficiency=$8, float_tolerance=$9, boost_tolerance=$10,
      updated_at=NOW() WHERE id=1`,
      [t.float_voltage_min||2.20, t.float_voltage_max||2.30,
       t.boost_voltage_min||2.28, t.boost_voltage_max||2.38,
       t.lvbd_min||1.75, t.dod_caution||60, t.dod_deploy_bb||80,
       t.smps_efficiency||0.90, t.float_tolerance||0.1, t.boost_tolerance||0.1]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/thresholds', auth, async (req, res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    const t = req.body;
    await q(`UPDATE thresholds SET
      float_voltage_min=$1, float_voltage_max=$2,
      boost_voltage_min=$3, boost_voltage_max=$4,
      lvbd_min=$5, dod_caution=$6, dod_deploy_bb=$7,
      smps_efficiency=$8, float_tolerance=$9, boost_tolerance=$10,
      updated_at=NOW() WHERE id=1`,
      [t.float_voltage_min, t.float_voltage_max,
       t.boost_voltage_min, t.boost_voltage_max,
       t.lvbd_min, t.dod_caution, t.dod_deploy_bb,
       t.smps_efficiency || 0.90, t.float_tolerance || 0.1, t.boost_tolerance || 0.1]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ENGINEERS ──────────────────────────────────────────────────────────────
const ENG_COLS = `id,employee_id,name,role,circle,permissions,created_at,
  last_login,app_version,device_platform,login_count`;

app.get('/engineers', auth, async (req, res) => {
  try {
    const { role, circle } = req.user;
    if (!['superadmin','admin'].includes(role)) return res.status(403).json({ error: 'Forbidden' });
    const r = role === 'superadmin'
      ? await q(`SELECT ${ENG_COLS} FROM engineers ORDER BY role,name`)
      : await q(`SELECT ${ENG_COLS} FROM engineers WHERE circle=$1 ORDER BY role,name`, [circle || '']);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/engineers', auth, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    const { employee_id, name, password, role, circle, permissions } = req.body;
    if (!employee_id || !name || !password)
      return res.status(400).json({ error: 'Required fields missing' });
    const h = await bcrypt.hash(password, 10);
    const c = (circle || '').trim().toUpperCase();
    const r = await q(
      `INSERT INTO engineers (employee_id,name,password,role,circle,permissions)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [employee_id.trim().toUpperCase(), name, h, role || 'engineer', c, JSON.stringify(permissions || {})]
    );
    res.json({ success: true, id: r.rows[0].id });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Employee ID already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/engineers/:id', auth, async (req, res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    const { name, password, role, circle, permissions } = req.body;
    const c = (circle || '').trim().toUpperCase();
    if (password) {
      await q(`UPDATE engineers SET name=$1,role=$2,circle=$3,permissions=$4,password=$5 WHERE id=$6`,
        [name, role, c, JSON.stringify(permissions || {}), await bcrypt.hash(password, 10), req.params.id]);
    } else {
      await q(`UPDATE engineers SET name=$1,role=$2,circle=$3,permissions=$4 WHERE id=$5`,
        [name, role, c, JSON.stringify(permissions || {}), req.params.id]);
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/engineers/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    await q('DELETE FROM engineers WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── NOTIFICATIONS ──────────────────────────────────────────────────────────
app.get('/notifications', auth, async (req, res) => {
  try {
    const r = await q('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 20');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/notifications', auth, async (req, res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    const { title, message } = req.body;
    await q('INSERT INTO notifications (title,message,created_by) VALUES ($1,$2,$3)',
      [title, message, req.user.name]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/notifications/:id', auth, async (req, res) => {
  try {
    await q('DELETE FROM notifications WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ENGINEER-ADMIN MAPPING ─────────────────────────────────────────────────
app.get('/admin-mappings/:admin_id', auth, async (req, res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    const r = await q(
      'SELECT engineer_employee_id FROM engineer_admin_map WHERE admin_employee_id=$1',
      [req.params.admin_id]
    );
    res.json(r.rows.map(r => r.engineer_employee_id));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin-mappings/:admin_id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    const { engineer_ids } = req.body;
    if (!Array.isArray(engineer_ids)) return res.status(400).json({ error: 'engineer_ids required' });
    await q('DELETE FROM engineer_admin_map WHERE admin_employee_id=$1', [req.params.admin_id]);
    for (const eid of engineer_ids) {
      await q(
        'INSERT INTO engineer_admin_map (engineer_employee_id,admin_employee_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [eid, req.params.admin_id]
      );
    }
    res.json({ success: true, mapped: engineer_ids.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/my-admin', auth, async (req, res) => {
  try {
    const r = await q(
      `SELECT e.id,e.employee_id,e.name,e.role,e.circle
       FROM engineer_admin_map m
       JOIN engineers e ON e.employee_id=m.admin_employee_id
       WHERE m.engineer_employee_id=$1`, [req.user.employee_id]
    );
    res.json(r.rows[0] || null);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── FIX OLD DATA (superadmin only — call once after migration) ────────────
// Updates old records that have empty circle or mismatched engineer_id
app.post('/fix-old-data', auth, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin')
      return res.status(403).json({ error: 'SuperAdmin only' });

    let fixed = 0;

    // Fix 1: Records with empty circle — set circle based on engineer's current circle
    const emptyCircle = await q(
      `SELECT DISTINCT engineer_id FROM inspections WHERE circle='' OR circle IS NULL`
    );
    for (const row of emptyCircle.rows) {
      const eng = await q(
        `SELECT circle FROM engineers WHERE employee_id=$1`, [row.engineer_id]
      );
      if (eng.rows[0]?.circle) {
        await q(
          `UPDATE inspections SET circle=$1 WHERE engineer_id=$2 AND (circle='' OR circle IS NULL)`,
          [eng.rows[0].circle, row.engineer_id]
        );
        fixed++;
      }
    }

    // Fix 2: Records where engineer_id matches engineer name instead of employee_id
    const allEngs = await q(`SELECT employee_id, name FROM engineers`);
    for (const eng of allEngs.rows) {
      const byName = await q(
        `SELECT COUNT(*) FROM inspections WHERE engineer_id=$1`, [eng.name]
      );
      if (parseInt(byName.rows[0].count) > 0) {
        await q(
          `UPDATE inspections SET engineer_id=$1 WHERE engineer_id=$2`,
          [eng.employee_id, eng.name]
        );
        fixed += parseInt(byName.rows[0].count);
      }
    }

    res.json({ success: true, fixed, message: `Fixed ${fixed} records` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SUMMARY (backward compat — computes from inspections table) ───────────
app.get('/summary', auth, async (req, res) => {
  try {
    const { role, employee_id, circle } = req.user;
    let r;
    if (role === 'superadmin') {
      r = await q(`SELECT decision, COUNT(*) FROM inspections GROUP BY decision`);
    } else if (role === 'admin') {
      r = await q(`SELECT decision, COUNT(*) FROM inspections WHERE circle=$1 GROUP BY decision`, [circle||'']);
    } else {
      r = await q(`SELECT decision, COUNT(*) FROM inspections WHERE engineer_id=$1 GROUP BY decision`, [employee_id]);
    }
    const summary = { ACCEPT: 0, REJECT: 0, REPLACE: 0 };
    r.rows.forEach(row => { if (summary[row.decision] !== undefined) summary[row.decision] = parseInt(row.count); });
    res.json(summary);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DEBUG (superadmin only — check raw DB state) ──────────────────────────
app.get('/debug', auth, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin')
      return res.status(403).json({ error: 'SuperAdmin only' });

    const total     = await q('SELECT COUNT(*) FROM inspections');
    const withCircle= await q("SELECT COUNT(*) FROM inspections WHERE circle != '' AND circle IS NOT NULL");
    const noCircle  = await q("SELECT COUNT(*) FROM inspections WHERE circle = '' OR circle IS NULL");
    const sample    = await q('SELECT id, cell_id, engineer_id, engineer_name, circle, decision, created_at FROM inspections ORDER BY created_at DESC LIMIT 10');
    const engineers = await q('SELECT employee_id, name, role, circle FROM engineers ORDER BY role');
    const mem       = process.memoryUsage();

    res.json({
      total_records:      parseInt(total.rows[0].count),
      records_with_circle:parseInt(withCircle.rows[0].count),
      records_no_circle:  parseInt(noCircle.rows[0].count),
      latest_10_records:  sample.rows,
      engineers:          engineers.rows,
      memory_mb:          Math.round(mem.heapUsed / 1024 / 1024),
      server_version:     '1.3.1',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HEALTH ─────────────────────────────────────────────────────────────────
// Public health check (no auth) — used to verify server is up
app.get('/health', (req, res) => {
  const m = process.memoryUsage();
  res.json({
    status: 'ok',
    version: '1.3.1',
    memory_mb: Math.round(m.heapUsed / 1024 / 1024),
    rss_mb: Math.round(m.rss / 1024 / 1024),
    uptime_min: Math.round(process.uptime() / 60),
  });
});

// Authenticated health check — App uses this to validate stored JWT token on startup
// If token is valid: 200. If token is expired/wrong secret: 401 → app clears and re-logs in.
app.get('/validate-token', auth, (req, res) => {
  res.json({ valid: true, user: req.user.employee_id, role: req.user.role });
});

// ── START ──────────────────────────────────────────────────────────────────
initDB()
  .then(() => app.listen(PORT, () => console.log(`HBL Cell Inspector v1.3.1 on port ${PORT}`)))
  .catch(e => { console.error('DB init failed:', e.code || '', e.message); process.exit(1); });
