const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cellinspector_secret_key_2024';

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ── PostgreSQL connection (Render provides DATABASE_URL) ──────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ── DB helpers ─────────────────────────────────────────────────────
const q = (text, params) => pool.query(text, params);

// ── INIT DATABASE ──────────────────────────────────────────────────
async function initDatabase() {
  await q(`CREATE TABLE IF NOT EXISTS engineers (
    id SERIAL PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'engineer',
    permissions JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS inspections (
    id SERIAL PRIMARY KEY,
    cell_id TEXT NOT NULL,
    cell_type TEXT DEFAULT 'VRLA',
    rated_voltage REAL, rated_capacity REAL,
    voltage REAL DEFAULT 0, capacity REAL DEFAULT 0,
    resistance REAL DEFAULT 0, temperature REAL DEFAULT 0,
    cycles INTEGER DEFAULT 0, earthing BOOLEAN DEFAULT TRUE,
    visual_faults TEXT, decision TEXT, remarks TEXT,
    engineer_id TEXT, engineer_name TEXT, photo_uri TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS thresholds (
    id SERIAL PRIMARY KEY,
    cell_type TEXT UNIQUE NOT NULL,
    volt_accept REAL DEFAULT 90, volt_replace REAL DEFAULT 70,
    cap_accept REAL DEFAULT 80, cap_replace REAL DEFAULT 60,
    res_accept REAL DEFAULT 30, res_replace REAL DEFAULT 50,
    temp_min REAL DEFAULT 15, temp_max REAL DEFAULT 45,
    cycle_accept INTEGER DEFAULT 500, cycle_replace INTEGER DEFAULT 800,
    float_voltage_max REAL DEFAULT 54.4,
    boost_voltage_max REAL DEFAULT 55.6,
    lvbd_min REAL DEFAULT 42,
    dod_caution REAL DEFAULT 80,
    dod_deploy_bb REAL DEFAULT 80,
    float_tolerance REAL DEFAULT 0.1,
    boost_tolerance REAL DEFAULT 0.1,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    title TEXT DEFAULT 'Notice',
    message TEXT NOT NULL,
    sent_by TEXT, sent_by_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  // Seed VRLA threshold
  await q(`INSERT INTO thresholds (cell_type)
    VALUES ('VRLA') ON CONFLICT (cell_type) DO NOTHING`);

  // Seed superadmin
  const existing = await q(`SELECT id FROM engineers WHERE employee_id=$1`, ['SUPERADMIN']);
  if (existing.rows.length === 0) {
    const hashed = bcrypt.hashSync('super123', 10);
    await q(`INSERT INTO engineers (employee_id,name,password,role,permissions) VALUES ($1,$2,$3,$4,$5)`,
      ['SUPERADMIN','Super Admin', hashed, 'superadmin',
        JSON.stringify({
          view_calculated:true, add_users:true, edit_users:true, delete_users:true,
          adjust_thresholds:true, delete_inspections:true, edit_inspections:true,
          send_notifications:true, view_thresholds:true
        })]);
    console.log('SuperAdmin created: SUPERADMIN / super123');
  }

  // Seed admin
  const adminEx = await q(`SELECT id FROM engineers WHERE employee_id=$1`, ['ADMIN001']);
  if (adminEx.rows.length === 0) {
    const hashed = bcrypt.hashSync('admin123', 10);
    await q(`INSERT INTO engineers (employee_id,name,password,role,permissions) VALUES ($1,$2,$3,$4,$5)`,
      ['ADMIN001','Admin', hashed, 'admin',
        JSON.stringify({
          view_calculated:true, add_users:false, edit_users:false, delete_users:false,
          adjust_thresholds:false, delete_inspections:false, edit_inspections:false,
          send_notifications:false, view_thresholds:true
        })]);
    console.log('Admin created: ADMIN001 / admin123');
  }

  console.log('PostgreSQL database initialised');
}

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}

async function getPerms(employee_id) {
  try {
    const r = await q('SELECT permissions FROM engineers WHERE employee_id=$1', [employee_id]);
    return r.rows[0]?.permissions || {};
  } catch (e) { return {}; }
}

// ── LOGIN ──────────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  try {
    const { employee_id, password } = req.body;
    if (!employee_id || !password) return res.status(400).json({ error: 'Fields required' });
    const r = await q('SELECT * FROM engineers WHERE employee_id=$1', [employee_id]);
    const eng = r.rows[0];
    if (!eng) return res.status(401).json({ error: 'Employee ID not found' });
    if (!bcrypt.compareSync(password, eng.password)) return res.status(401).json({ error: 'Incorrect password' });
    const token = jwt.sign(
      { id: eng.id, employee_id: eng.employee_id, name: eng.name, role: eng.role },
      JWT_SECRET, { expiresIn: '30d' }
    );
    res.json({ token, engineer: {
      id: eng.id, employee_id: eng.employee_id,
      name: eng.name, role: eng.role, permissions: eng.permissions || {}
    }});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CHANGE OWN PASSWORD ────────────────────────────────────────────
app.post('/change-password', verifyToken, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) return res.status(400).json({ error: 'Both passwords required' });
    if (new_password.length < 4) return res.status(400).json({ error: 'Password min 4 chars' });
    const r = await q('SELECT * FROM engineers WHERE employee_id=$1', [req.user.employee_id]);
    const eng = r.rows[0];
    if (!bcrypt.compareSync(current_password, eng.password)) return res.status(401).json({ error: 'Current password incorrect' });
    await q('UPDATE engineers SET password=$1 WHERE employee_id=$2', [bcrypt.hashSync(new_password, 10), req.user.employee_id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── RESET PASSWORD (superadmin) ────────────────────────────────────
app.post('/reset-password/:id', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    const { new_password } = req.body;
    if (!new_password || new_password.length < 4) return res.status(400).json({ error: 'Min 4 chars' });
    await q('UPDATE engineers SET password=$1 WHERE id=$2', [bcrypt.hashSync(new_password, 10), req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── INSPECTIONS ────────────────────────────────────────────────────
app.post('/inspections', verifyToken, async (req, res) => {
  try {
    const { cell_id, cell_type, rated_voltage, rated_capacity,
      voltage, capacity, resistance, temperature, cycles,
      earthing, visual_faults, decision, remarks, photo_uri } = req.body;
    if (!cell_id || !decision) return res.status(400).json({ error: 'cell_id and decision required' });
    const r = await q(`INSERT INTO inspections
      (cell_id,cell_type,rated_voltage,rated_capacity,voltage,capacity,resistance,
       temperature,cycles,earthing,visual_faults,decision,remarks,engineer_id,engineer_name,photo_uri)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
      [cell_id, cell_type||'VRLA', rated_voltage, rated_capacity,
       voltage||0, capacity||0, resistance||0, temperature||0, cycles||0,
       earthing||false,
       typeof visual_faults==='string'?visual_faults:JSON.stringify(visual_faults||[]),
       decision, remarks, req.user.employee_id, req.user.name, photo_uri||null]);
    res.json({ success: true, id: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/inspections', verifyToken, async (req, res) => {
  try {
    const isPrivileged = ['superadmin','admin'].includes(req.user.role);
    const r = isPrivileged
      ? await q('SELECT * FROM inspections ORDER BY created_at DESC')
      : await q('SELECT * FROM inspections WHERE engineer_id=$1 ORDER BY created_at DESC', [req.user.employee_id]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/inspections/:id', verifyToken, async (req, res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    if (req.user.role==='engineer' && !perms.edit_inspections)
      return res.status(403).json({ error: 'Edit permission not granted' });
    const { decision, remarks, visual_faults } = req.body;
    await q('UPDATE inspections SET decision=$1,remarks=$2,visual_faults=$3 WHERE id=$4',
      [decision, remarks,
       typeof visual_faults==='string'?visual_faults:JSON.stringify(visual_faults||[]),
       req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/inspections/:id', verifyToken, async (req, res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const allowed = req.user.role==='superadmin' || (req.user.role==='admin' && perms.delete_inspections);
    if (!allowed) return res.status(403).json({ error: 'Permission denied' });
    await q('DELETE FROM inspections WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/summary', verifyToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const isPrivileged = ['superadmin','admin'].includes(req.user.role);
    const r = isPrivileged
      ? await q(`SELECT decision,COUNT(*) as count FROM inspections WHERE DATE(created_at)=$1 GROUP BY decision`, [today])
      : await q(`SELECT decision,COUNT(*) as count FROM inspections WHERE DATE(created_at)=$1 AND engineer_id=$2 GROUP BY decision`, [today, req.user.employee_id]);
    const s = { ACCEPT:0, REJECT:0, REPLACE:0 };
    r.rows.forEach(row => { s[row.decision] = parseInt(row.count); });
    res.json(s);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── THRESHOLDS ─────────────────────────────────────────────────────
app.get('/thresholds/:cell_type', verifyToken, async (req, res) => {
  try {
    const r = await q('SELECT * FROM thresholds WHERE cell_type=$1', [req.params.cell_type]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/thresholds/:cell_type', verifyToken, async (req, res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const canEdit = req.user.role==='superadmin' || (req.user.role==='admin' && perms.adjust_thresholds);
    if (!canEdit) return res.status(403).json({ error: 'Threshold permission not granted' });
    const t = req.body;
    await q(`UPDATE thresholds SET
      volt_accept=$1,volt_replace=$2,cap_accept=$3,cap_replace=$4,
      res_accept=$5,res_replace=$6,temp_min=$7,temp_max=$8,
      cycle_accept=$9,cycle_replace=$10,float_voltage_max=$11,
      boost_voltage_max=$12,lvbd_min=$13,dod_caution=$14,dod_deploy_bb=$15,
      float_tolerance=$16,boost_tolerance=$17,updated_at=NOW()
      WHERE cell_type=$18`,
      [t.volt_accept,t.volt_replace,t.cap_accept,t.cap_replace,
       t.res_accept,t.res_replace,t.temp_min,t.temp_max,
       t.cycle_accept,t.cycle_replace,t.float_voltage_max,
       t.boost_voltage_max,t.lvbd_min,t.dod_caution,t.dod_deploy_bb,
       t.float_tolerance??0.1,t.boost_tolerance??0.1,
       req.params.cell_type]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ENGINEERS ──────────────────────────────────────────────────────
app.get('/engineers', verifyToken, async (req, res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
    const r = await q('SELECT id,employee_id,name,role,permissions,created_at FROM engineers ORDER BY role,name');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/engineers', verifyToken, async (req, res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const isSA = req.user.role==='superadmin', isA = req.user.role==='admin';
    if (!isSA && !isA) return res.status(403).json({ error: 'Access denied' });
    if (isA && !perms.add_users) return res.status(403).json({ error: 'Add user permission not granted' });
    const { employee_id, name, password, role, permissions } = req.body;
    if (!employee_id||!name||!password) return res.status(400).json({ error: 'All fields required' });
    if (role==='superadmin') return res.status(403).json({ error: 'Cannot create superadmin' });
    if (isA && role!=='engineer') return res.status(403).json({ error: 'Admin can only add engineers' });
    const ex = await q('SELECT id FROM engineers WHERE employee_id=$1', [employee_id]);
    if (ex.rows.length) return res.status(400).json({ error: 'Employee ID already exists' });
    await q('INSERT INTO engineers (employee_id,name,password,role,permissions) VALUES ($1,$2,$3,$4,$5)',
      [employee_id, name, bcrypt.hashSync(password,10), role||'engineer', JSON.stringify(permissions||{})]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/engineers/:id', verifyToken, async (req, res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const isSA = req.user.role==='superadmin', isA = req.user.role==='admin';
    if (!isSA && !(isA && perms.edit_users)) return res.status(403).json({ error: 'Edit permission not granted' });
    const { name, password, role, permissions } = req.body;
    if (isA && role==='admin') return res.status(403).json({ error: 'Cannot promote to admin' });
    if (password) {
      await q('UPDATE engineers SET name=$1,role=$2,permissions=$3,password=$4 WHERE id=$5',
        [name, role, JSON.stringify(permissions||{}), bcrypt.hashSync(password,10), req.params.id]);
    } else {
      await q('UPDATE engineers SET name=$1,role=$2,permissions=$3 WHERE id=$4',
        [name, role, JSON.stringify(permissions||{}), req.params.id]);
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/engineers/:id', verifyToken, async (req, res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const isSA = req.user.role==='superadmin', isA = req.user.role==='admin';
    if (!isSA && !(isA && perms.delete_users)) return res.status(403).json({ error: 'Delete permission not granted' });
    const r = await q('SELECT * FROM engineers WHERE id=$1', [req.params.id]);
    const eng = r.rows[0];
    if (!eng) return res.status(404).json({ error: 'Not found' });
    if (eng.role==='superadmin') return res.status(403).json({ error: 'Cannot delete superadmin' });
    if (isA && eng.role==='admin') return res.status(403).json({ error: 'Admin cannot delete admin' });
    await q('DELETE FROM engineers WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── NOTIFICATIONS ──────────────────────────────────────────────────
app.get('/notifications', verifyToken, async (req, res) => {
  try {
    const r = await q('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/notifications', verifyToken, async (req, res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    if (req.user.role!=='superadmin' && !perms.send_notifications)
      return res.status(403).json({ error: 'Notification permission not granted' });
    const { message, title } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });
    await q('INSERT INTO notifications (title,message,sent_by,sent_by_name) VALUES ($1,$2,$3,$4)',
      [title||'Notice', message, req.user.employee_id, req.user.name]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/notifications/:id', verifyToken, async (req, res) => {
  try {
    if (req.user.role!=='superadmin') return res.status(403).json({ error: 'SuperAdmin only' });
    await q('DELETE FROM notifications WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SYNC ───────────────────────────────────────────────────────────
app.post('/sync', verifyToken, async (req, res) => {
  try {
    const { records } = req.body;
    if (!Array.isArray(records)) return res.status(400).json({ error: 'Records array required' });
    for (const r of records) {
      await q(`INSERT INTO inspections
        (cell_id,cell_type,rated_voltage,rated_capacity,voltage,capacity,resistance,
         temperature,cycles,earthing,visual_faults,decision,remarks,engineer_id,engineer_name,photo_uri,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
        [r.cell_id, r.cell_type||'VRLA', r.rated_voltage, r.rated_capacity,
         r.voltage||0, r.capacity||0, r.resistance||0, r.temperature||0, r.cycles||0,
         r.earthing||false,
         typeof r.visual_faults==='string'?r.visual_faults:JSON.stringify(r.visual_faults||[]),
         r.decision, r.remarks, req.user.employee_id, req.user.name,
         r.photo_uri||null, r.created_at||new Date().toISOString()]);
    }
    res.json({ success: true, synced: records.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'CellInspector Server (PostgreSQL) running' });
});

// Start
initDatabase()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Database init failed:', err);
    process.exit(1);
  });
