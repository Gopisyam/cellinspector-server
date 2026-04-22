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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
const q = (text, params) => pool.query(text, params);

// ─────────────────────────────────────────────────────────────
async function initDatabase() {
  // engineers — now includes circle assignment
  await q(`CREATE TABLE IF NOT EXISTS engineers (
    id SERIAL PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'engineer',
    circle TEXT DEFAULT '',
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
    circle TEXT DEFAULT '',
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
    smps_efficiency REAL DEFAULT 0.90,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    title TEXT DEFAULT 'Notice',
    message TEXT NOT NULL,
    sent_by TEXT, sent_by_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  // Safe migrations for existing databases
  const migrations = [
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS float_tolerance REAL DEFAULT 0.1`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS boost_tolerance REAL DEFAULT 0.1`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS smps_efficiency REAL DEFAULT 0.90`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS float_voltage_max REAL DEFAULT 54.4`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS boost_voltage_max REAL DEFAULT 55.6`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS lvbd_min REAL DEFAULT 42`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS dod_caution REAL DEFAULT 80`,
    `ALTER TABLE thresholds ADD COLUMN IF NOT EXISTS dod_deploy_bb REAL DEFAULT 80`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '{}'`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS circle TEXT DEFAULT ''`,
    `ALTER TABLE inspections ADD COLUMN IF NOT EXISTS circle TEXT DEFAULT ''`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS app_version TEXT DEFAULT ''`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS device_platform TEXT DEFAULT ''`,
    `ALTER TABLE engineers ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0`,
    `CREATE TABLE IF NOT EXISTS engineer_admin_map (
      id SERIAL PRIMARY KEY,
      engineer_employee_id TEXT NOT NULL,
      admin_employee_id TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(engineer_employee_id, admin_employee_id)
    )`,
  ];
  for (const sql of migrations) { try { await q(sql); } catch(e) {} }

  await q(`INSERT INTO thresholds (cell_type) VALUES ('VRLA') ON CONFLICT (cell_type) DO NOTHING`);

  const sa = await q(`SELECT id FROM engineers WHERE employee_id=$1`,['SUPERADMIN']);
  if (!sa.rows.length) {
    await q(`INSERT INTO engineers (employee_id,name,password,role,circle,permissions) VALUES ($1,$2,$3,$4,$5,$6)`,
      ['SUPERADMIN','Super Admin',bcrypt.hashSync('super123',10),'superadmin','ALL',
        JSON.stringify({view_calculated:true,add_users:true,edit_users:true,delete_users:true,
          adjust_thresholds:true,delete_inspections:true,edit_inspections:true,
          send_notifications:true,view_thresholds:true,
          download_excel:true,share_pdf:true})]);
    console.log('SuperAdmin created: SUPERADMIN / super123');
  }

  const adm = await q(`SELECT id FROM engineers WHERE employee_id=$1`,['ADMIN001']);
  if (!adm.rows.length) {
    await q(`INSERT INTO engineers (employee_id,name,password,role,circle,permissions) VALUES ($1,$2,$3,$4,$5,$6)`,
      ['ADMIN001','Admin',bcrypt.hashSync('admin123',10),'admin','AP',
        JSON.stringify({view_calculated:true,add_users:false,edit_users:false,delete_users:false,
          adjust_thresholds:false,delete_inspections:false,edit_inspections:false,
          send_notifications:false,view_thresholds:true,
          download_excel:false,share_pdf:true})]);
    console.log('Admin created: ADMIN001 / admin123');
  }
  console.log('Database ready');
}

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}
async function getPerms(employee_id) {
  try {
    const r = await q('SELECT permissions FROM engineers WHERE employee_id=$1',[employee_id]);
    return r.rows[0]?.permissions || {};
  } catch(e) { return {}; }
}
async function getUserCircle(employee_id) {
  try {
    const r = await q('SELECT circle,role FROM engineers WHERE employee_id=$1',[employee_id]);
    return { circle: r.rows[0]?.circle || '', role: r.rows[0]?.role || 'engineer' };
  } catch(e) { return { circle: '', role: 'engineer' }; }
}

// ── LOGIN ─────────────────────────────────────────────────────
app.post('/login', async (req,res) => {
  try {
    const {employee_id,password} = req.body;
    if (!employee_id||!password) return res.status(400).json({error:'Fields required'});
    const r = await q('SELECT * FROM engineers WHERE employee_id=$1',[employee_id]);
    const eng = r.rows[0];
    if (!eng) return res.status(401).json({error:'Employee ID not found'});
    if (!bcrypt.compareSync(password,eng.password)) return res.status(401).json({error:'Incorrect password'});
    const token = jwt.sign(
      {id:eng.id,employee_id:eng.employee_id,name:eng.name,role:eng.role,circle:eng.circle||''},
      JWT_SECRET,{expiresIn:'30d'});
    // Track last login, app version, device info
    const { app_version='', device_platform='' } = req.body;
    await q(`UPDATE engineers SET
      last_login=NOW(),
      login_count=COALESCE(login_count,0)+1,
      app_version=$1,
      device_platform=$2
      WHERE id=$3`,
      [app_version||'', device_platform||'', eng.id]);
    res.json({token, engineer:{
      id:eng.id, employee_id:eng.employee_id, name:eng.name,
      role:eng.role, circle:eng.circle||'', permissions:eng.permissions||{}
    }});
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/change-password', verifyToken, async (req,res) => {
  try {
    const {current_password,new_password} = req.body;
    if (!current_password||!new_password) return res.status(400).json({error:'Both required'});
    if (new_password.length<4) return res.status(400).json({error:'Min 4 chars'});
    const r = await q('SELECT password FROM engineers WHERE employee_id=$1',[req.user.employee_id]);
    if (!bcrypt.compareSync(current_password,r.rows[0].password))
      return res.status(401).json({error:'Current password incorrect'});
    await q('UPDATE engineers SET password=$1 WHERE employee_id=$2',
      [bcrypt.hashSync(new_password,10),req.user.employee_id]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/reset-password/:id', verifyToken, async (req,res) => {
  try {
    if (req.user.role!=='superadmin') return res.status(403).json({error:'SuperAdmin only'});
    const {new_password} = req.body;
    if (!new_password||new_password.length<4) return res.status(400).json({error:'Min 4 chars'});
    await q('UPDATE engineers SET password=$1 WHERE id=$2',
      [bcrypt.hashSync(new_password,10),req.params.id]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

// ── INSPECTIONS ───────────────────────────────────────────────
// Issue 5: engineers see own records, admin sees own circle only, superadmin sees all
app.post('/inspections', verifyToken, async (req,res) => {
  try {
    const {cell_id,cell_type,rated_voltage,rated_capacity,voltage,capacity,
      resistance,temperature,cycles,earthing,visual_faults,decision,remarks,photo_uri} = req.body;
    if (!cell_id||!decision) return res.status(400).json({error:'cell_id and decision required'});
    const userCircle = req.user.circle||'';
    const r = await q(`INSERT INTO inspections
      (cell_id,cell_type,rated_voltage,rated_capacity,voltage,capacity,resistance,
       temperature,cycles,earthing,visual_faults,decision,remarks,engineer_id,engineer_name,photo_uri,circle)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id`,
      [cell_id,cell_type||'VRLA',rated_voltage,rated_capacity,
       voltage||0,capacity||0,resistance||0,temperature||0,cycles||0,earthing||false,
       typeof visual_faults==='string'?visual_faults:JSON.stringify(visual_faults||[]),
       decision,remarks,req.user.employee_id,req.user.name,photo_uri||null,userCircle]);
    res.json({success:true,id:r.rows[0].id});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/inspections', verifyToken, async (req,res) => {
  try {
    const {role,employee_id,circle} = req.user;
    let r;
    if (role==='superadmin') {
      // SuperAdmin sees ALL records; optionally filter by circle query param
      const filterCircle = req.query.circle;
      if (filterCircle) {
        r = await q('SELECT * FROM inspections WHERE circle=$1 ORDER BY created_at DESC',[filterCircle]);
      } else {
        r = await q('SELECT * FROM inspections ORDER BY created_at DESC');
      }
    } else if (role==='admin') {
      // Admin sees records from:
      // 1. Their own circle
      // 2. Directly mapped engineers (by employee_id)
      // 3. Engineers under mapped admins (admin→admin mapping)
      const mappedRes = await q(
        'SELECT engineer_employee_id FROM engineer_admin_map WHERE admin_employee_id=$1',
        [employee_id]
      );
      const directMappedIds = mappedRes.rows.map(row => row.engineer_employee_id);

      // Find any mapped admin IDs, then get their engineers too
      const mappedAdminIds = directMappedIds.filter(async id => {
        const er = await q('SELECT role FROM engineers WHERE employee_id=$1',[id]);
        return er.rows[0]?.role === 'admin';
      });
      // Simpler: get all circles of mapped admins and include those too
      let allMappedIds = [...directMappedIds];
      if (directMappedIds.length > 0) {
        const mappedAdminsRes = await q(
          `SELECT e2.employee_id FROM engineers e2
           WHERE e2.employee_id = ANY($1::text[]) AND e2.role = 'admin'`,
          [directMappedIds]
        );
        for (const adminRow of mappedAdminsRes.rows) {
          // Get all engineers under each mapped admin (same circle)
          const adminInfo = await q('SELECT circle FROM engineers WHERE employee_id=$1',[adminRow.employee_id]);
          if (adminInfo.rows[0]?.circle) {
            const engRes = await q('SELECT employee_id FROM engineers WHERE circle=$1 AND role=$2',[adminInfo.rows[0].circle,'engineer']);
            allMappedIds = [...allMappedIds, ...engRes.rows.map(r=>r.employee_id)];
          }
        }
      }
      allMappedIds = [...new Set(allMappedIds)]; // deduplicate

      if (allMappedIds.length > 0) {
        const placeholders = allMappedIds.map((_,i) => `$${i+2}`).join(',');
        r = await q(
          `SELECT * FROM inspections WHERE circle=$1 OR engineer_id IN (${placeholders}) ORDER BY created_at DESC`,
          [circle||'', ...allMappedIds]
        );
      } else {
        r = await q('SELECT * FROM inspections WHERE circle=$1 ORDER BY created_at DESC',[circle||'']);
      }
    } else {
      // Engineer sees only their own records
      r = await q('SELECT * FROM inspections WHERE engineer_id=$1 ORDER BY created_at DESC',[employee_id]);
    }
    res.json(r.rows);
  } catch(e){res.status(500).json({error:e.message});}
});

app.put('/inspections/:id', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    if (req.user.role==='engineer'&&!perms.edit_inspections)
      return res.status(403).json({error:'Edit permission not granted'});
    const {decision,remarks,visual_faults} = req.body;
    await q('UPDATE inspections SET decision=$1,remarks=$2,visual_faults=$3 WHERE id=$4',
      [decision,remarks,
       typeof visual_faults==='string'?visual_faults:JSON.stringify(visual_faults||[]),
       req.params.id]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

app.delete('/inspections/:id', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const ok = req.user.role==='superadmin'||(req.user.role==='admin'&&perms.delete_inspections);
    if (!ok) return res.status(403).json({error:'Permission denied'});
    await q('DELETE FROM inspections WHERE id=$1',[req.params.id]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/summary', verifyToken, async (req,res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const {role,employee_id,circle} = req.user;
    let r;
    if (role==='superadmin') {
      r = await q(`SELECT decision,COUNT(*) as count FROM inspections WHERE DATE(created_at)=$1 GROUP BY decision`,[today]);
    } else if (role==='admin') {
      r = await q(`SELECT decision,COUNT(*) as count FROM inspections WHERE DATE(created_at)=$1 AND circle=$2 GROUP BY decision`,[today,circle||'']);
    } else {
      r = await q(`SELECT decision,COUNT(*) as count FROM inspections WHERE DATE(created_at)=$1 AND engineer_id=$2 GROUP BY decision`,[today,employee_id]);
    }
    const s={ACCEPT:0,REJECT:0,REPLACE:0};
    r.rows.forEach(row=>{s[row.decision]=parseInt(row.count);});
    res.json(s);
  } catch(e){res.status(500).json({error:e.message});}
});

// Issue 3: Excel export endpoint with date range filter + permission check
app.get('/export/excel', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    if (req.user.role!=='superadmin' && !perms.download_excel)
      return res.status(403).json({error:'Excel download permission not granted'});

    const {from_date, to_date} = req.query;
    if (!from_date||!to_date) return res.status(400).json({error:'from_date and to_date required (YYYY-MM-DD)'});

    const {role,employee_id,circle} = req.user;
    let r;
    if (role==='superadmin') {
      r = await q(`SELECT * FROM inspections WHERE DATE(created_at) BETWEEN $1 AND $2 ORDER BY created_at DESC`,[from_date,to_date]);
    } else if (role==='admin') {
      r = await q(`SELECT * FROM inspections WHERE DATE(created_at) BETWEEN $1 AND $2 AND circle=$3 ORDER BY created_at DESC`,[from_date,to_date,circle||'']);
    } else {
      r = await q(`SELECT * FROM inspections WHERE DATE(created_at) BETWEEN $1 AND $2 AND engineer_id=$3 ORDER BY created_at DESC`,[from_date,to_date,employee_id]);
    }

    // Return raw data — client builds Excel using SheetJS
    res.json({records: r.rows, from_date, to_date, count: r.rows.length});
  } catch(e){res.status(500).json({error:e.message});}
});

// ── THRESHOLDS ────────────────────────────────────────────────
app.get('/thresholds/:cell_type', verifyToken, async (req,res) => {
  try {
    const r = await q('SELECT * FROM thresholds WHERE cell_type=$1',[req.params.cell_type]);
    if (!r.rows[0]) return res.status(404).json({error:'Not found'});
    res.json(r.rows[0]);
  } catch(e){res.status(500).json({error:e.message});}
});

app.put('/thresholds/:cell_type', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const ok = req.user.role==='superadmin'||(req.user.role==='admin'&&perms.adjust_thresholds);
    if (!ok) return res.status(403).json({error:'Threshold permission not granted'});
    const t = req.body;
    await q(`UPDATE thresholds SET
      volt_accept=$1,volt_replace=$2,cap_accept=$3,cap_replace=$4,
      res_accept=$5,res_replace=$6,temp_min=$7,temp_max=$8,
      cycle_accept=$9,cycle_replace=$10,float_voltage_max=$11,
      boost_voltage_max=$12,lvbd_min=$13,dod_caution=$14,dod_deploy_bb=$15,
      float_tolerance=$16,boost_tolerance=$17,smps_efficiency=$18,updated_at=NOW()
      WHERE cell_type=$19`,
      [t.volt_accept,t.volt_replace,t.cap_accept,t.cap_replace,
       t.res_accept,t.res_replace,t.temp_min,t.temp_max,
       t.cycle_accept,t.cycle_replace,t.float_voltage_max,
       t.boost_voltage_max,t.lvbd_min,t.dod_caution,t.dod_deploy_bb,
       t.float_tolerance??0.1,t.boost_tolerance??0.1,t.smps_efficiency??0.90,
       req.params.cell_type]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

// ── ENGINEERS ─────────────────────────────────────────────────
app.get('/engineers', verifyToken, async (req,res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role)) return res.status(403).json({error:'Access denied'});
    let r;
    if (req.user.role==='superadmin') {
      // SuperAdmin sees all engineers, optionally filtered by circle
      const filterCircle = req.query.circle;
      r = filterCircle
        ? await q('SELECT id,employee_id,name,role,circle,permissions,created_at,last_login,app_version,device_platform,login_count FROM engineers WHERE circle=$1 ORDER BY role,name',[filterCircle])
        : await q('SELECT id,employee_id,name,role,circle,permissions,created_at,last_login,app_version,device_platform,login_count FROM engineers ORDER BY role,name');
    } else {
      // Admin sees engineers in their own circle only
      r = await q('SELECT id,employee_id,name,role,circle,permissions,created_at,last_login,app_version,device_platform,login_count FROM engineers WHERE circle=$1 ORDER BY role,name',[req.user.circle||'']);
    }
    res.json(r.rows);
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/engineers', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const isSA=req.user.role==='superadmin', isA=req.user.role==='admin';
    if (!isSA&&!isA) return res.status(403).json({error:'Access denied'});
    if (isA&&!perms.add_users) return res.status(403).json({error:'Add user permission not granted'});
    const {employee_id,name,password,role,circle,permissions}=req.body;
    if (!employee_id||!name||!password) return res.status(400).json({error:'All fields required'});
    if (role==='superadmin') return res.status(403).json({error:'Cannot create superadmin'});
    if (isA&&role!=='engineer') return res.status(403).json({error:'Admin can only add engineers'});
    // Admin can only add engineers to their own circle
    const assignedCircle = isA ? (req.user.circle||'') : (circle||'');
    const ex = await q('SELECT id FROM engineers WHERE employee_id=$1',[employee_id]);
    if (ex.rows.length) return res.status(400).json({error:'Employee ID already exists'});
    await q('INSERT INTO engineers (employee_id,name,password,role,circle,permissions) VALUES ($1,$2,$3,$4,$5,$6)',
      [employee_id,name,bcrypt.hashSync(password,10),role||'engineer',assignedCircle,JSON.stringify(permissions||{})]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

app.put('/engineers/:id', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const isSA=req.user.role==='superadmin', isA=req.user.role==='admin';
    if (!isSA&&!(isA&&perms.edit_users)) return res.status(403).json({error:'Edit permission not granted'});
    const {name,password,role,circle,permissions}=req.body;
    if (isA&&role==='admin') return res.status(403).json({error:'Cannot promote to admin'});
    const assignedCircle = isSA ? (circle||'') : (req.user.circle||'');
    const update = {name, role, circle:assignedCircle, permissions:JSON.stringify(permissions||{})};
    if (password) update.password = bcrypt.hashSync(password,10);
    if (password) {
      await q('UPDATE engineers SET name=$1,role=$2,circle=$3,permissions=$4,password=$5 WHERE id=$6',
        [name,role,assignedCircle,JSON.stringify(permissions||{}),bcrypt.hashSync(password,10),req.params.id]);
    } else {
      await q('UPDATE engineers SET name=$1,role=$2,circle=$3,permissions=$4 WHERE id=$5',
        [name,role,assignedCircle,JSON.stringify(permissions||{}),req.params.id]);
    }
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

app.delete('/engineers/:id', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    const isSA=req.user.role==='superadmin', isA=req.user.role==='admin';
    if (!isSA&&!(isA&&perms.delete_users)) return res.status(403).json({error:'Delete permission not granted'});
    const r = await q('SELECT role FROM engineers WHERE id=$1',[req.params.id]);
    if (!r.rows[0]) return res.status(404).json({error:'Not found'});
    if (r.rows[0].role==='superadmin') return res.status(403).json({error:'Cannot delete superadmin'});
    if (isA&&r.rows[0].role==='admin') return res.status(403).json({error:'Admin cannot delete admin'});
    await q('DELETE FROM engineers WHERE id=$1',[req.params.id]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

// ── NOTIFICATIONS ─────────────────────────────────────────────
app.get('/notifications', verifyToken, async (req,res) => {
  try {
    const r = await q('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50');
    res.json(r.rows);
  } catch(e){res.status(500).json({error:e.message});}
});
app.post('/notifications', verifyToken, async (req,res) => {
  try {
    const perms = await getPerms(req.user.employee_id);
    if (req.user.role!=='superadmin'&&!perms.send_notifications)
      return res.status(403).json({error:'Notification permission not granted'});
    const {message,title}=req.body;
    if (!message) return res.status(400).json({error:'Message required'});
    await q('INSERT INTO notifications (title,message,sent_by,sent_by_name) VALUES ($1,$2,$3,$4)',
      [title||'Notice',message,req.user.employee_id,req.user.name]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});
app.delete('/notifications/:id', verifyToken, async (req,res) => {
  try {
    if (req.user.role!=='superadmin') return res.status(403).json({error:'SuperAdmin only'});
    await q('DELETE FROM notifications WHERE id=$1',[req.params.id]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

// ── SYNC (offline) ────────────────────────────────────────────
app.post('/sync', verifyToken, async (req,res) => {
  try {
    const {records}=req.body;
    if (!Array.isArray(records)) return res.status(400).json({error:'Records array required'});
    const userCircle = req.user.circle||'';
    for (const r of records) {
      await q(`INSERT INTO inspections
        (cell_id,cell_type,rated_voltage,rated_capacity,voltage,capacity,resistance,
         temperature,cycles,earthing,visual_faults,decision,remarks,engineer_id,engineer_name,photo_uri,circle,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
        [r.cell_id,r.cell_type||'VRLA',r.rated_voltage,r.rated_capacity,
         r.voltage||0,r.capacity||0,r.resistance||0,r.temperature||0,r.cycles||0,r.earthing||false,
         typeof r.visual_faults==='string'?r.visual_faults:JSON.stringify(r.visual_faults||[]),
         r.decision,r.remarks,req.user.employee_id,req.user.name,
         r.photo_uri||null,userCircle,r.created_at||new Date().toISOString()]);
    }
    res.json({success:true,synced:records.length});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/health',(req,res)=>res.json({status:'ok',version:'1.2.0',message:'HBL CellInspector — PostgreSQL'}));

initDatabase().then(()=>{
  app.listen(PORT,'0.0.0.0',()=>console.log(`Server running on port ${PORT}`));
}).catch(e=>{ console.error('DB init failed:',e.message); process.exit(1); });// ── ENGINEER-ADMIN MAPPING ────────────────────────────────────────
app.get('/admin-mappings/:admin_id', verifyToken, async (req,res) => {
  try {
    if (!['superadmin','admin'].includes(req.user.role))
      return res.status(403).json({error:'Access denied'});
    // Returns all mapped user IDs (both engineers and admins)
    const r = await q('SELECT engineer_employee_id FROM engineer_admin_map WHERE admin_employee_id=$1',[req.params.admin_id]);
    res.json(r.rows.map(row => row.engineer_employee_id));
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/admin-mappings/:admin_id', verifyToken, async (req,res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({error:'SuperAdmin only'});
    const {engineer_ids} = req.body;
    if (!Array.isArray(engineer_ids)) return res.status(400).json({error:'engineer_ids array required'});
    await q('DELETE FROM engineer_admin_map WHERE admin_employee_id=$1',[req.params.admin_id]);
    for (const eid of engineer_ids) {
      await q('INSERT INTO engineer_admin_map (engineer_employee_id,admin_employee_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',[eid,req.params.admin_id]);
    }
    res.json({success:true, mapped:engineer_ids.length});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/my-admin', verifyToken, async (req,res) => {
  try {
    const r = await q(`SELECT e.id,e.employee_id,e.name,e.role,e.circle FROM engineer_admin_map m JOIN engineers e ON e.employee_id=m.admin_employee_id WHERE m.engineer_employee_id=$1`,[req.user.employee_id]);
    res.json(r.rows[0] || null);
  } catch(e){res.status(500).json({error:e.message});}
});


