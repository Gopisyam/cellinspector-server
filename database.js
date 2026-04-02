const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Database(path.join(__dirname, 'cellinspector.db'));

function initDatabase() {
  db.exec(`CREATE TABLE IF NOT EXISTS engineers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'engineer',
    permissions TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS inspections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cell_id TEXT NOT NULL, cell_type TEXT DEFAULT 'VRLA',
    rated_voltage REAL, rated_capacity REAL,
    voltage REAL DEFAULT 0, capacity REAL DEFAULT 0,
    resistance REAL DEFAULT 0, temperature REAL DEFAULT 0,
    cycles INTEGER DEFAULT 0, earthing INTEGER DEFAULT 1,
    visual_faults TEXT, decision TEXT, remarks TEXT,
    engineer_id TEXT, engineer_name TEXT, photo_uri TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS thresholds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    updated_at TEXT DEFAULT (datetime('now'))
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT DEFAULT 'Notice', message TEXT NOT NULL,
    sent_by TEXT, sent_by_name TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  // Migrations — safe to run on existing DB
  const migrations = [
    `ALTER TABLE engineers ADD COLUMN permissions TEXT DEFAULT '{}'`,
    `ALTER TABLE thresholds ADD COLUMN float_voltage_max REAL DEFAULT 54.4`,
    `ALTER TABLE thresholds ADD COLUMN boost_voltage_max REAL DEFAULT 55.6`,
    `ALTER TABLE thresholds ADD COLUMN lvbd_min REAL DEFAULT 42`,
    `ALTER TABLE thresholds ADD COLUMN dod_caution REAL DEFAULT 80`,
    `ALTER TABLE thresholds ADD COLUMN dod_deploy_bb REAL DEFAULT 80`,
    `ALTER TABLE thresholds ADD COLUMN float_tolerance REAL DEFAULT 0.1`,
    `ALTER TABLE thresholds ADD COLUMN boost_tolerance REAL DEFAULT 0.1`,
  ];
  migrations.forEach(sql => { try { db.exec(sql); } catch(e) {} });

  // Seed VRLA threshold
  if (!db.prepare('SELECT id FROM thresholds WHERE cell_type=?').get('VRLA'))
    db.prepare('INSERT INTO thresholds (cell_type) VALUES (?)').run('VRLA');

  // Seed superadmin
  if (!db.prepare('SELECT id FROM engineers WHERE employee_id=?').get('SUPERADMIN')) {
    db.prepare('INSERT INTO engineers (employee_id,name,password,role,permissions) VALUES (?,?,?,?,?)')
      .run('SUPERADMIN','Super Admin', bcrypt.hashSync('super123',10), 'superadmin',
        JSON.stringify({
          view_calculated:true, add_users:true, edit_users:true, delete_users:true,
          adjust_thresholds:true, delete_inspections:true, edit_inspections:true,
          send_notifications:true, view_thresholds:true
        }));
    console.log('SuperAdmin created: SUPERADMIN / super123');
  }

  // Seed admin
  if (!db.prepare('SELECT id FROM engineers WHERE employee_id=?').get('ADMIN001')) {
    db.prepare('INSERT INTO engineers (employee_id,name,password,role,permissions) VALUES (?,?,?,?,?)')
      .run('ADMIN001','Admin', bcrypt.hashSync('admin123',10), 'admin',
        JSON.stringify({
          view_calculated:true, add_users:false, edit_users:false, delete_users:false,
          adjust_thresholds:false, delete_inspections:false, edit_inspections:false,
          send_notifications:false, view_thresholds:true
        }));
    console.log('Admin created: ADMIN001 / admin123');
  }
}

module.exports = { db, initDatabase };
