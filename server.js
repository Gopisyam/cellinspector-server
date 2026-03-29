const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { db, initDatabase } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'cellinspector_secret_key_2024';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
initDatabase();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

initDatabase();

// ✅ ADD HERE
app.get('/', (req, res) => {
  res.send('CellInspector Server is running 🚀');
});

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function getPerms(employee_id) {
  try {
    const row = db.prepare('SELECT permissions FROM engineers WHERE employee_id = ?').get(employee_id);
    return JSON.parse(row?.permissions || '{}');
  } catch (e) { return {}; }
}

// ── LOGIN ──────────────────────────────────────────────
app.post('/login', (req, res) => {
  const { employee_id, password } = req.body;
  if (!employee_id || !password)
    return res.status(400).json({ error: 'Employee ID and password required' });
  const eng = db.prepare('SELECT * FROM engineers WHERE employee_id = ?').get(employee_id);
  if (!eng) return res.status(401).json({ error: 'Employee ID not found' });
  if (!bcrypt.compareSync(password, eng.password))
    return res.status(401).json({ error: 'Incorrect password' });
  const token = jwt.sign(
    { id: eng.id, employee_id: eng.employee_id, name: eng.name, role: eng.role },
    JWT_SECRET, { expiresIn: '30d' }
  );
  let perms = {};
  try { perms = JSON.parse(eng.permissions || '{}'); } catch (e) {}
  res.json({ token, engineer: {
    id: eng.id, employee_id: eng.employee_id,
    name: eng.name, role: eng.role, permissions: perms
  }});
});

// ── INSPECTIONS ────────────────────────────────────────
app.post('/inspections', verifyToken, (req, res) => {
  const { cell_id, cell_type, rated_voltage, rated_capacity,
    voltage, capacity, resistance, temperature, cycles,
    earthing, visual_faults, decision, remarks, photo_uri } = req.body;
  if (!cell_id || !decision)
    return res.status(400).json({ error: 'Cell ID and decision required' });
  const result = db.prepare(`INSERT INTO inspections (
    cell_id,cell_type,rated_voltage,rated_capacity,voltage,capacity,
    resistance,temperature,cycles,earthing,visual_faults,decision,
    remarks,engineer_id,engineer_name,photo_uri
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    cell_id, cell_type||'VRLA', rated_voltage, rated_capacity,
    voltage||0, capacity||0, resistance||0, temperature||0, cycles||0,
    earthing?1:0,
    typeof visual_faults==='string'?visual_faults:JSON.stringify(visual_faults||[]),
    decision, remarks, req.user.employee_id, req.user.name, photo_uri||null
  );
  res.json({ success: true, id: result.lastInsertRowid });
});

app.get('/inspections', verifyToken, (req, res) => {
  const isPrivileged = ['superadmin','admin'].includes(req.user.role);
  const rows = isPrivileged
    ? db.prepare('SELECT * FROM inspections ORDER BY created_at DESC').all()
    : db.prepare('SELECT * FROM inspections WHERE engineer_id=? ORDER BY created_at DESC').all(req.user.employee_id);
  res.json(rows);
});

app.put('/inspections/:id', verifyToken, (req, res) => {
  const perms = getPerms(req.user.employee_id);
  if (req.user.role==='engineer' && !perms.edit_inspections)
    return res.status(403).json({ error: 'Edit permission not granted' });
  const { decision, remarks, visual_faults } = req.body;
  db.prepare('UPDATE inspections SET decision=?,remarks=?,visual_faults=? WHERE id=?')
    .run(decision, remarks,
      typeof visual_faults==='string'?visual_faults:JSON.stringify(visual_faults||[]),
      req.params.id);
  res.json({ success: true });
});

app.delete('/inspections/:id', verifyToken, (req, res) => {
  const perms = getPerms(req.user.employee_id);
  const allowed = req.user.role==='superadmin' || req.user.role==='admin' && perms.delete_inspections;
  if (!allowed) return res.status(403).json({ error: 'Permission denied' });
  db.prepare('DELETE FROM inspections WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

app.get('/summary', verifyToken, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const isPrivileged = ['superadmin','admin'].includes(req.user.role);
  const rows = isPrivileged
    ? db.prepare(`SELECT decision,COUNT(*) as count FROM inspections WHERE date(created_at)=? GROUP BY decision`).all(today)
    : db.prepare(`SELECT decision,COUNT(*) as count FROM inspections WHERE date(created_at)=? AND engineer_id=? GROUP BY decision`).all(today, req.user.employee_id);
  const s = { ACCEPT:0, REJECT:0, REPLACE:0 };
  rows.forEach(r => { s[r.decision]=r.count; });
  res.json(s);
});

// ── THRESHOLDS ─────────────────────────────────────────
app.get('/thresholds/:cell_type', verifyToken, (req, res) => {
  const row = db.prepare('SELECT * FROM thresholds WHERE cell_type=?').get(req.params.cell_type);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

app.put('/thresholds/:cell_type', verifyToken, (req, res) => {
  const perms = getPerms(req.user.employee_id);
  const canEdit = req.user.role==='superadmin' ||
    (req.user.role==='admin' && perms.adjust_thresholds);
  if (!canEdit) return res.status(403).json({ error: 'Threshold permission not granted' });
  const t = req.body;
  db.prepare(`UPDATE thresholds SET
    volt_accept=?,volt_replace=?,cap_accept=?,cap_replace=?,
    res_accept=?,res_replace=?,temp_min=?,temp_max=?,
    cycle_accept=?,cycle_replace=?,float_voltage_max=?,
    boost_voltage_max=?,lvbd_min=?,dod_caution=?,dod_deploy_bb=?,
    updated_at=datetime('now') WHERE cell_type=?`).run(
    t.volt_accept,t.volt_replace,t.cap_accept,t.cap_replace,
    t.res_accept,t.res_replace,t.temp_min,t.temp_max,
    t.cycle_accept,t.cycle_replace,t.float_voltage_max,
    t.boost_voltage_max,t.lvbd_min,t.dod_caution,t.dod_deploy_bb,
    req.params.cell_type);
  res.json({ success: true });
});

// ── ENGINEERS ──────────────────────────────────────────
app.get('/engineers', verifyToken, (req, res) => {
  if (!['superadmin','admin'].includes(req.user.role))
    return res.status(403).json({ error: 'Access denied' });
  const rows = db.prepare('SELECT id,employee_id,name,role,permissions,created_at FROM engineers ORDER BY role,name').all();
  res.json(rows);
});

app.post('/engineers', verifyToken, (req, res) => {
  const perms = getPerms(req.user.employee_id);
  const isSuperAdmin = req.user.role === 'superadmin';
  const isAdmin = req.user.role === 'admin';

  if (!isSuperAdmin && !isAdmin)
    return res.status(403).json({ error: 'Access denied' });
  if (isAdmin && !perms.add_users)
    return res.status(403).json({ error: 'Add user permission not granted' });

  const { employee_id, name, password, role, permissions } = req.body;
  if (!employee_id || !name || !password)
    return res.status(400).json({ error: 'All fields required' });

  // SuperAdmin can add admin or engineer only (not another superadmin)
  if (role === 'superadmin')
    return res.status(403).json({ error: 'Cannot create a superadmin account' });
  // Admin can ONLY add engineers - never admin
  if (isAdmin && role !== 'engineer')
    return res.status(403).json({ error: 'Admin can only add engineers, not admins' });

  const existing = db.prepare('SELECT id FROM engineers WHERE employee_id=?').get(employee_id);
  if (existing) return res.status(400).json({ error: 'Employee ID already exists' });

  const hashed = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO engineers (employee_id,name,password,role,permissions) VALUES (?,?,?,?,?)')
    .run(employee_id, name, hashed, role||'engineer', JSON.stringify(permissions||{}));
  res.json({ success: true });
});

app.put('/engineers/:id', verifyToken, (req, res) => {
  const perms = getPerms(req.user.employee_id);
  const isSuperAdmin = req.user.role === 'superadmin';
  const isAdmin = req.user.role === 'admin';
  if (!isSuperAdmin && !(isAdmin && perms.edit_users))
    return res.status(403).json({ error: 'Edit permission not granted' });
  const { name, password, role, permissions } = req.body;
  if (isAdmin && role === 'admin')
    return res.status(403).json({ error: 'Admin cannot promote to admin role' });
  const payload = [name, role, JSON.stringify(permissions||{})];
  if (password) {
    db.prepare('UPDATE engineers SET name=?,role=?,permissions=?,password=? WHERE id=?')
      .run(...payload, bcrypt.hashSync(password,10), req.params.id);
  } else {
    db.prepare('UPDATE engineers SET name=?,role=?,permissions=? WHERE id=?')
      .run(...payload, req.params.id);
  }
  res.json({ success: true });
});

app.delete('/engineers/:id', verifyToken, (req, res) => {
  const perms = getPerms(req.user.employee_id);
  const isSuperAdmin = req.user.role === 'superadmin';
  const isAdmin = req.user.role === 'admin';
  if (!isSuperAdmin && !(isAdmin && perms.delete_users))
    return res.status(403).json({ error: 'Delete permission not granted' });
  const eng = db.prepare('SELECT * FROM engineers WHERE id=?').get(req.params.id);
  if (!eng) return res.status(404).json({ error: 'Not found' });
  if (eng.role === 'superadmin') return res.status(403).json({ error: 'Cannot delete superadmin' });
  if (isAdmin && eng.role === 'admin') return res.status(403).json({ error: 'Admin cannot delete admin' });
  db.prepare('DELETE FROM engineers WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── NOTIFICATIONS ──────────────────────────────────────
app.get('/notifications', verifyToken, (req, res) => {
  const rows = db.prepare('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50').all();
  res.json(rows);
});

app.post('/notifications', verifyToken, (req, res) => {
  const perms = getPerms(req.user.employee_id);
  const canSend = req.user.role==='superadmin' || perms.send_notifications;
  if (!canSend) return res.status(403).json({ error: 'Notification permission not granted' });
  const { message, title } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  db.prepare('INSERT INTO notifications (title,message,sent_by,sent_by_name) VALUES (?,?,?,?)')
    .run(title||'Notice', message, req.user.employee_id, req.user.name);
  res.json({ success: true });
});

app.delete('/notifications/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Superadmin only' });
  db.prepare('DELETE FROM notifications WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── SYNC ───────────────────────────────────────────────
app.post('/sync', verifyToken, (req, res) => {
  const { records } = req.body;
  if (!Array.isArray(records)) return res.status(400).json({ error: 'Records array required' });
  const insert = db.prepare(`INSERT INTO inspections (
    cell_id,cell_type,rated_voltage,rated_capacity,voltage,capacity,
    resistance,temperature,cycles,earthing,visual_faults,decision,
    remarks,engineer_id,engineer_name,photo_uri,created_at
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const syncMany = db.transaction(recs => {
    recs.forEach(r => insert.run(
      r.cell_id,r.cell_type||'VRLA',r.rated_voltage,r.rated_capacity,
      r.voltage||0,r.capacity||0,r.resistance||0,r.temperature||0,r.cycles||0,
      r.earthing?1:0,
      typeof r.visual_faults==='string'?r.visual_faults:JSON.stringify(r.visual_faults||[]),
      r.decision,r.remarks,req.user.employee_id,req.user.name,
      r.photo_uri||null,r.created_at||new Date().toISOString()
    ));
  });
  syncMany(records);
  res.json({ success: true, synced: records.length });
});

app.get('/health', (req, res) => {
  res.json({ status:'ok', message:'CellInspector Server running' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`CellInspector Server running on port ${PORT}`);
  console.log(`Test: http://localhost:${PORT}/health`);
});
