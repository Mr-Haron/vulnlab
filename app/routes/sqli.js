/**
 * VulnLab — SQL Injection Lab
 * Challenges:
 *   1. Login bypass     — ' OR '1'='1
 *   2. UNION SELECT     — extract product secrets
 *   3. Blind/time-based — infer data character by character
 *
 * INTENTIONAL: All queries use raw string concatenation — no parameterization.
 */

const express  = require("express");
const router   = express.Router();
const Database = require("better-sqlite3");
const path     = require("path");

// Use the same DB file
const DB_PATH = process.env.DB_PATH || path.join("/data", "vulnlab.db");

const layout = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title} — VulnLab</title>
<style>
  * { box-sizing:border-box; }
  body { background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0; }
  header { background:#161b22;border-bottom:1px solid #30363d;padding:1rem 2rem; }
  header a { color:#58a6ff;text-decoration:none; }
  main { max-width:800px;margin:2rem auto;padding:0 1rem; }
  h2 { color:#58a6ff; }
  .hint { background:#1c2128;border-left:3px solid #d29922;padding:0.75rem 1rem;margin:1rem 0;border-radius:0 6px 6px 0;font-size:0.85rem;color:#e3b341; }
  .error { background:#3d0e0e;border-left:3px solid #f85149;padding:0.75rem 1rem;margin:1rem 0;color:#f85149;font-size:0.85rem;border-radius:0 6px 6px 0; }
  .success { background:#0d2d0d;border-left:3px solid #3fb950;padding:0.75rem 1rem;margin:1rem 0;color:#3fb950;font-size:0.85rem;border-radius:0 6px 6px 0; }
  input { width:100%;padding:0.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:0.3rem;font-family:monospace; }
  button { padding:0.5rem 1.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-top:0.5rem; }
  .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin:1rem 0; }
  table { width:100%;border-collapse:collapse;margin-top:1rem; }
  th,td { border:1px solid #30363d;padding:0.5rem;text-align:left;font-size:0.85rem; }
  th { background:#21262d;color:#79c0ff; }
  code { background:#21262d;padding:0.1rem 0.3rem;border-radius:3px;color:#79c0ff; }
</style>
</head>
<body>
<header><a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; <a href="/sqli">SQLi Lab</a></header>
<main>${body}</main>
</html>`;

// ── Lab index ─────────────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  res.send(layout("SQL Injection Lab", `
    <h2>SQL Injection Lab</h2>
    <p style="color:#8b949e;margin-bottom:1.5rem">
      SQLi allows attackers to interfere with database queries. One of the most critical vulnerability classes (OWASP A03).
    </p>
    <div class="card">
      <h3><a href="/sqli/login" style="color:#58a6ff">Lab 1 — Login Bypass</a> <span style="color:#e3b341;font-size:0.8rem">[100 pts]</span></h3>
      <p style="color:#8b949e">Username field concatenated raw into query. Bypass authentication entirely.</p>
    </div>
    <div class="card">
      <h3><a href="/sqli/search" style="color:#58a6ff">Lab 2 — UNION SELECT</a> <span style="color:#f85149;font-size:0.8rem">[200 pts]</span></h3>
      <p style="color:#8b949e">Product search is vulnerable. Use UNION SELECT to extract data from other tables.</p>
    </div>
    <div class="card">
      <h3><a href="/sqli/blind" style="color:#58a6ff">Lab 3 — Blind / Time-Based</a> <span style="color:#f85149;font-size:0.8rem">[300 pts]</span></h3>
      <p style="color:#8b949e">No visible output. Infer data through true/false conditions or timing (simulate using delay tricks).</p>
    </div>
  `));
});

// ── Lab 1: Login Bypass ───────────────────────────────────────────────────────
router.get("/login", (req, res) => {
  res.send(layout("SQLi Login Bypass", `
    <h2>Lab 1 — Login Bypass</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> The query is: <code>SELECT * FROM users WHERE username='INPUT' AND password='INPUT'</code><br>
      Try username: <code>' OR '1'='1' --</code> (leave password blank)
    </div>
    <form method="POST" action="/sqli/login">
      <label>Username:</label>
      <input type="text" name="username" placeholder="Enter username">
      <label style="margin-top:0.75rem;display:block">Password:</label>
      <input type="password" name="password" placeholder="Enter password">
      <button type="submit">Login</button>
    </form>
    ${req.query.error ? `<div class="error">Login failed. Invalid credentials.</div>` : ""}
  `));
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const db = new Database(DB_PATH);

  // INTENTIONAL VULNERABILITY: raw string concatenation — classic SQLi target
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

  let result = null;
  let sqlError = null;

  try {
    result = db.prepare(query).get();
  } catch (e) {
    sqlError = e.message;
  }

  if (result) {
    res.send(layout("SQLi Login — Success!", `
      <h2>Lab 1 — Login Bypass</h2>
      <div class="success">
        ✅ Logged in as: <strong>${result.username}</strong> (role: ${result.role})<br>
        🚩 Flag: <strong>VULNLAB{SQLI_BYP4SS_L0G1N}</strong>
      </div>
      <div class="card">
        <strong>What happened?</strong><br>
        The query became: <code>SELECT * FROM users WHERE username='' OR '1'='1' --' AND password=''</code><br>
        The <code>--</code> comments out the password check. <code>'1'='1'</code> is always true, so the first user (admin) is returned.
      </div>
      <p><a href="/sqli/login" style="color:#58a6ff">← Try again</a></p>
    `));
  } else {
    let errInfo = sqlError
      ? `<div class="error">SQL Error (verbose — a real site shouldn't show this): <code>${sqlError}</code></div>`
      : "";
    res.send(layout("SQLi Login — Failed", `
      <h2>Lab 1 — Login Bypass</h2>
      <div class="error">Login failed.</div>
      ${errInfo}
      <p><a href="/sqli/login" style="color:#58a6ff">← Try again</a></p>
    `));
  }
});

// ── Lab 2: UNION SELECT ────────────────────────────────────────────────────────
router.get("/search", (req, res) => {
  const q = req.query.q || "";
  let results = [];
  let sqlError = null;

  if (q) {
    const db = new Database(DB_PATH);
    // INTENTIONAL VULNERABILITY
    const query = `SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%' OR category LIKE '%${q}%'`;
    try {
      results = db.prepare(query).all();
    } catch (e) {
      sqlError = e.message;
    }
  }

  const rows = results.map(r => `
    <tr>
      <td>${r.id !== undefined ? r.id : ""}</td>
      <td>${r.name !== undefined ? r.name : ""}</td>
      <td>${r.description !== undefined ? r.description : ""}</td>
      <td>${r.price !== undefined ? r.price : ""}</td>
    </tr>
  `).join("");

  // Flag if results contain passwords or the product secret
  const resultStr = JSON.stringify(results);
  const unionFlagMsg = (resultStr.includes("VULNLAB{") || resultStr.match(/[a-f0-9]{32}/))
    ? `<div style="background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:.5rem 1rem;border-radius:4px;margin:.75rem 0">🚩 Data extracted via UNION! Flag: <strong>VULNLAB{UNION_SELECT_4ll_th3_th1ngs}</strong></div>`
    : "";

  res.send(layout("SQLi UNION SELECT", `
    <h2>Lab 2 — UNION SELECT Data Extraction</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> The query selects 4 columns. Try:<br>
      <code>' UNION SELECT id,username,password,role FROM users --</code><br>
      Then try to find the hidden product with secret flag using:<br>
      <code>' UNION SELECT id,name,secret,price FROM products --</code>
    </div>
    <form method="GET" action="/sqli/search">
      <label>Search products:</label>
      <input type="text" name="q" value="${q.replace(/"/g, "&quot;")}" placeholder="Try: juice">
      <button type="submit">Search</button>
    </form>
    ${sqlError ? `<div class="error">SQL Error: <code>${sqlError}</code></div>` : ""}
    ${unionFlagMsg}
    ${results.length > 0 ? `
      <table>
        <tr><th>ID</th><th>Name</th><th>Description</th><th>Price</th></tr>
        ${rows}
      </table>
    ` : (q ? `<p style="color:#484f58">No results.</p>` : "")}
  `));
});

// ── Lab 3: Blind SQLi ──────────────────────────────────────────────────────────
router.get("/blind", (req, res) => {
  const id = req.query.id || "1";
  const db = new Database(DB_PATH);

  // INTENTIONAL VULNERABILITY — boolean-based blind
  const query = `SELECT id FROM products WHERE id=${id}`;
  let exists = false;
  let sqlError = null;

  try {
    const row = db.prepare(query).get();
    exists = !!row;
  } catch (e) {
    sqlError = e.message;
  }

  const isBlindSuccess = exists && (String(id).includes("SUBSTR") || String(id).includes("AND") || String(id).includes("SELECT"));
  
  res.send(layout("Blind SQLi", `
    <h2>Lab 3 — Blind SQLi (Boolean-Based)</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> The app returns only "Product exists: YES/NO". No data is shown.<br>
      Use boolean conditions to infer data character by character.<br>
      Try: <code>1 AND SUBSTR((SELECT username FROM users WHERE role='admin' LIMIT 1),1,1)='a'</code><br>
      A YES response confirms the first character of the admin username is 'a'.
      Automate this with sqlmap: <code>sqlmap -u "http://localhost:8080/sqli/blind?id=1" --level=3</code>
    </div>
    <form method="GET" action="/sqli/blind">
      <label>Product ID:</label>
      <input type="text" name="id" value="${String(id).replace(/"/g, "&quot;")}" style="width:300px">
      <button type="submit">Check</button>
    </form>
    <div style="margin-top:1.5rem;font-size:1.1rem">
      Product exists: <strong style="color:${exists ? '#3fb950' : '#f85149'}">${exists ? "YES" : "NO"}</strong>
    </div>
    ${isBlindSuccess ? `<div style="background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:.5rem 1rem;border-radius:4px;margin-top:1rem">🚩 Blind SQLi condition evaluated! Flag: <strong>VULNLAB{BL1ND_SQLI_T1M1NG}</strong></div>` : ""}
    ${sqlError ? `<div class="error">SQL Error: <code>${sqlError}</code></div>` : ""}
    <div style="margin-top:1.5rem;color:#484f58;font-size:0.8rem">
      <strong>sqlmap automation:</strong><br>
      <code>sqlmap -u "http://localhost:8080/sqli/blind?id=1" --dbms=sqlite --dump --level=3 --risk=2</code>
    </div>
  `));
});

module.exports = router;
