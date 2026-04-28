/**
 * VulnLab Database — SQLite with intentionally vulnerable schema
 * and seed data including weak password hashes (MD5) for training.
 */

const Database = require("better-sqlite3");
const path     = require("path");
const fs       = require("fs");
const crypto   = require("crypto");

const DB_PATH = process.env.DB_PATH || path.join("/data", "vulnlab.db");

let db;

function getDB() {
  if (!db) db = new Database(DB_PATH);
  return db;
}

function md5(str) {
  return crypto.createHash("md5").update(str).digest("hex");
}

function initDB() {
  // Ensure /data directory exists
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const db = getDB();

  // ── Users table (intentionally stores MD5 passwords) ────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      email    TEXT,
      role     TEXT DEFAULT 'user',
      bio      TEXT DEFAULT ''
    );
  `);

  // ── Products table (for SQLi labs) ──────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS products (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL,
      description TEXT,
      price       REAL,
      category    TEXT,
      secret      TEXT
    );
  `);

  // ── Comments table (for stored XSS) ─────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS comments (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT,
      content    TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // ── Flags table ──────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS flags (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      flag_name   TEXT UNIQUE,
      flag_value  TEXT,
      description TEXT,
      points      INTEGER DEFAULT 100
    );
  `);

  // ── Solved flags per user ─────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS solved_flags (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      username  TEXT,
      flag_name TEXT,
      solved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(username, flag_name)
    );
  `);

  // ── Seed users (only if table is empty) ──────────────────────────────────
  const userCount = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
  if (userCount === 0) {
    const insert = db.prepare(
      "INSERT INTO users (username, password, email, role, bio) VALUES (?, ?, ?, ?, ?)"
    );

    // INTENTIONAL: MD5 passwords — easy to crack in John/Hashcat
    insert.run("admin",       md5("admin123"),    "admin@vulnlab.local",    "admin", "Administrator account");
    insert.run("alice",       md5("password"),    "alice@vulnlab.local",    "user",  "Hi I'm Alice");
    insert.run("bob",         md5("letmein"),     "bob@vulnlab.local",      "user",  "Bob's account");
    insert.run("charlie",     md5("charlie123"),  "charlie@vulnlab.local",  "user",  "");
    insert.run("secretuser",  md5("s3cr3t!"),     "secret@vulnlab.local",   "admin", "Flag: VULNLAB{SQL_M4ST3R_9f3a}");
  }

  // ── Seed products ─────────────────────────────────────────────────────────
  const prodCount = db.prepare("SELECT COUNT(*) as c FROM products").get().c;
  if (prodCount === 0) {
    const insert = db.prepare(
      "INSERT INTO products (name, description, price, category, secret) VALUES (?, ?, ?, ?, ?)"
    );
    insert.run("Apple Juice",   "Fresh pressed",         2.99, "juice",  "nothing here");
    insert.run("Orange Juice",  "100% natural",          3.49, "juice",  "nothing here");
    insert.run("Green Smoothie","Spinach and banana",    4.99, "smoothie","VULNLAB{UNION_SELECT_4ll_th3_th1ngs}");
    insert.run("Secret Formula","Not for sale",          999,  "secret", "VULNLAB{H1DD3N_PR0DUCT_F0UND}");
    insert.run("Water",         "Plain old water",       0.99, "water",  "nothing here");
  }

  // ── Seed flags ────────────────────────────────────────────────────────────
  const flagCount = db.prepare("SELECT COUNT(*) as c FROM flags").get().c;
  if (flagCount === 0) {
    const insert = db.prepare(
      "INSERT INTO flags (flag_name, flag_value, description, points) VALUES (?, ?, ?, ?)"
    );
    insert.run("xss_reflected",   "VULNLAB{XSS_R3FL3CT3D_G0T_Y0U}", "Trigger a reflected XSS alert", 100);
    insert.run("xss_stored",      "VULNLAB{ST0R3D_XSS_P3RS1STS}",   "Post a stored XSS payload that fires on page load", 200);
    insert.run("xss_dom",         "VULNLAB{D0M_XSS_N0_S3RV3R}",     "Exploit a DOM-based XSS without server involvement", 200);
    insert.run("sqli_login",      "VULNLAB{SQLI_BYP4SS_L0G1N}",     "Bypass login using SQL injection", 100);
    insert.run("sqli_union",      "VULNLAB{UNION_SELECT_4ll_th3_th1ngs}", "Extract product secrets using UNION SELECT", 200);
    insert.run("sqli_blind",      "VULNLAB{BL1ND_SQLI_T1M1NG}",     "Use time-based blind SQLi to dump data", 300);
    insert.run("auth_weak_pass",  "VULNLAB{WK_P4SS_CR4CK3D}",       "Crack a user's MD5 password hash", 150);
    insert.run("auth_jwt",        "VULNLAB{JWT_N0N3_ALG_BYPASS}",   "Exploit JWT 'none' algorithm bypass", 250);
    insert.run("auth_idor",       "VULNLAB{1D0R_PRIV3SC}",          "Access another user's profile via IDOR", 150);
    insert.run("upload_shell",    "VULNLAB{F1L3_UPL04D_RCE}",       "Upload a webshell bypassing extension filters", 300);
    insert.run("upload_traversal","VULNLAB{PATH_TR4V3RS4L_R34D}",   "Read /etc/passwd via path traversal", 250);
    insert.run("csrf_transfer",   "VULNLAB{CSRF_N0_T0K3N_S0RRY}",   "Perform a CSRF attack to change a user's email", 200);
    insert.run("ssrf_internal",   "VULNLAB{SSRF_R34CH3D_1NT3RN4L}", "Use SSRF to reach an internal service", 300);
  }

  console.log("[VulnLab DB] Initialized at", DB_PATH);
}

module.exports = { getDB, initDB };
