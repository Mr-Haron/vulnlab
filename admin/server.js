/**
 * VulnLab — Admin / Instructor Panel
 * Features:
 *   - View all users & scores
 *   - Reset individual labs (clear comments, solved flags, uploads)
 *   - View traffic log
 *   - Manage hints
 *   - Broadcast message to trainees
 * Protected by basic password (env ADMIN_PASSWORD)
 * Runs on internal port 4000 — proxied via nginx at /admin/
 */

const express  = require("express");
const Database = require("better-sqlite3");
const fs       = require("fs");
const path     = require("path");

const app  = express();
const PORT = 4000;

const DB_PATH    = process.env.DB_PATH    || path.join("/data", "vulnlab.db");
const LOG_PATH   = process.env.LOG_PATH   || path.join("/data", "traffic.log");
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join("/data", "uploads");
const ADMIN_PASS = process.env.ADMIN_PASSWORD || "admin123";

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Simple cookie-based auth ───────────────────────────────────────────────────
const cookieParser = require ? (() => {
  try { return require("cookie-parser"); } catch { return null; }
})() : null;

// Manual cookie parse (no extra dep needed)
function getCookie(req, name) {
  const cookies = req.headers.cookie || "";
  const match = cookies.split(";").map(c => c.trim()).find(c => c.startsWith(name + "="));
  return match ? match.split("=")[1] : null;
}

function requireAuth(req, res, next) {
  if (getCookie(req, "vadmin") === ADMIN_PASS) return next();
  if (req.path === "/login" || req.path === "/") return next();
  return res.redirect("/admin/login");
}

function css() {
  return `
    * { box-sizing:border-box;margin:0;padding:0; }
    body { background:#0d1117;color:#c9d1d9;font-family:monospace;display:flex;min-height:100vh; }
    nav { width:220px;background:#010409;border-right:1px solid #21262d;padding:1.5rem 1rem;flex-shrink:0;position:sticky;top:0;height:100vh; }
    nav h1 { color:#f85149;font-size:1rem;margin-bottom:.3rem; }
    nav p  { color:#484f58;font-size:.75rem;margin-bottom:1.5rem; }
    nav a  { display:block;color:#8b949e;text-decoration:none;padding:.4rem .6rem;border-radius:4px;margin:.15rem 0;font-size:.85rem; }
    nav a:hover { background:#161b22;color:#c9d1d9; }
    nav a.active { background:#1f2937;color:#58a6ff; }
    main { flex:1;padding:2rem;overflow-y:auto; }
    h2 { color:#58a6ff;margin-bottom:1.5rem;font-size:1.2rem; }
    h3 { color:#79c0ff;margin:1.5rem 0 .75rem; }
    .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin-bottom:1rem; }
    .grid { display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem;margin-bottom:2rem; }
    .stat { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem; }
    .stat .num { font-size:2rem;font-weight:bold;color:#58a6ff; }
    .stat .lbl { color:#8b949e;font-size:.8rem;margin-top:.2rem; }
    table { width:100%;border-collapse:collapse; }
    th,td { border:1px solid #21262d;padding:.5rem .7rem;font-size:.82rem;text-align:left; }
    th { background:#1c2128;color:#79c0ff; }
    tr:hover td { background:#1c2128; }
    input,select { padding:.4rem .7rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;font-family:monospace; }
    .btn     { display:inline-block;padding:.35rem .9rem;background:#1f6feb;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:.82rem;text-decoration:none; }
    .btn-red { background:#6e1a1a;border:1px solid #f85149;color:#f85149; }
    .btn-grn { background:#0d2d0d;border:1px solid #3fb950;color:#3fb950; }
    .btn-org { background:#2d1e00;border:1px solid #d29922;color:#e3b341; }
    .tag-admin { color:#f85149;font-size:.75rem; }
    .tag-user  { color:#79c0ff;font-size:.75rem; }
    .msg-ok  { background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:.6rem 1rem;border-radius:4px;margin-bottom:1rem; }
    .msg-err { background:#3d0e0e;border:1px solid #f85149;color:#f85149;padding:.6rem 1rem;border-radius:4px;margin-bottom:1rem; }
    pre { background:#010409;border:1px solid #21262d;border-radius:6px;padding:1rem;font-size:.75rem;color:#8b949e;overflow-x:auto;max-height:400px;overflow-y:auto; }
  `;
}

function navHtml(active) {
  const links = [
    ["/admin/", "🏠 Dashboard"],
    ["/admin/users", "👥 Users"],
    ["/admin/scores", "🏆 Scores"],
    ["/admin/flags", "🚩 Flags"],
    ["/admin/traffic", "📡 Traffic Log"],
    ["/admin/resets", "🔄 Reset Labs"],
    ["/admin/hints", "💡 Hints"],
    ["/admin/broadcast", "📢 Broadcast"],
  ];
  return `<nav>
    <h1>⚠ VulnLab</h1>
    <p>Admin Panel</p>
    ${links.map(([href, label]) =>
      `<a href="${href}" ${active === href ? 'class="active"' : ""}>${label}</a>`
    ).join("")}
    <hr style="border-color:#21262d;margin:1rem 0">
    <a href="/" style="color:#484f58">← App</a>
    <a href="/admin/logout" style="color:#484f58">Logout</a>
  </nav>`;
}

function page(active, title, content, msg = "", err = "") {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title} — Admin</title>
  <style>${css()}</style></head><body>
  ${navHtml(active)}
  <main>
    ${msg ? `<div class="msg-ok">✅ ${msg}</div>` : ""}
    ${err ? `<div class="msg-err">❌ ${err}</div>` : ""}
    <h2>${title}</h2>
    ${content}
  </main>
  </body></html>`;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.get("/login", (req, res) => {
  if (getCookie(req, "vadmin") === ADMIN_PASS) return res.redirect("/admin/");
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Login</title>
  <style>
    body{background:#0d1117;display:flex;align-items:center;justify-content:center;height:100vh;font-family:monospace;}
    .box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:2rem;width:340px;}
    h2{color:#f85149;margin-bottom:1.5rem;}
    input{width:100%;padding:.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:.3rem;font-size:1rem;}
    button{width:100%;margin-top:1rem;padding:.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:1rem;}
    .err{color:#f85149;font-size:.85rem;margin-top:.5rem;}
  </style></head><body>
  <div class="box">
    <h2>⚠ Admin Login</h2>
    <form method="POST" action="/admin/login">
      <label style="color:#8b949e">Password:</label>
      <input type="password" name="password" autofocus>
      <button type="submit">Login</button>
      ${req.query.err ? `<div class="err">Wrong password.</div>` : ""}
    </form>
  </div></body></html>`);
});

app.post("/login", (req, res) => {
  if (req.body.password === ADMIN_PASS) {
    res.setHeader("Set-Cookie", `vadmin=${ADMIN_PASS};Path=/;HttpOnly`);
    return res.redirect("/admin/");
  }
  res.redirect("/admin/login?err=1");
});

app.get("/logout", (req, res) => {
  res.setHeader("Set-Cookie", "vadmin=;Path=/;Max-Age=0");
  res.redirect("/admin/login");
});

app.use(requireAuth);

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  const db = new Database(DB_PATH);
  const userCount  = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
  const flagCount  = db.prepare("SELECT COUNT(*) as c FROM flags").get().c;
  const solveCount = db.prepare("SELECT COUNT(*) as c FROM solved_flags").get().c;
  const commentCount = db.prepare("SELECT COUNT(*) as c FROM comments").get().c;
  const uploadsCount = fs.existsSync(UPLOAD_DIR) ? fs.readdirSync(UPLOAD_DIR).length : 0;
  const logLines   = fs.existsSync(LOG_PATH)
    ? fs.readFileSync(LOG_PATH, "utf8").split("\n").filter(Boolean).length
    : 0;

  // Top 5 recent solves
  const recentSolves = db.prepare(`
    SELECT sf.username, sf.flag_name, f.points, sf.solved_at
    FROM solved_flags sf JOIN flags f ON f.flag_name=sf.flag_name
    ORDER BY sf.solved_at DESC LIMIT 8
  `).all();

  const solveRows = recentSolves.map(s => `
    <tr>
      <td>${s.username}</td>
      <td style="color:#79c0ff">${s.flag_name}</td>
      <td style="color:#3fb950">+${s.points}</td>
      <td style="color:#484f58;font-size:.75rem">${new Date(s.solved_at).toLocaleString()}</td>
    </tr>
  `).join("");

  res.send(page("/admin/", "Dashboard", `
    <div class="grid">
      <div class="stat"><div class="num">${userCount}</div><div class="lbl">Registered users</div></div>
      <div class="stat"><div class="num">${solveCount}</div><div class="lbl">Flags captured</div></div>
      <div class="stat"><div class="num">${flagCount}</div><div class="lbl">Total flags</div></div>
      <div class="stat"><div class="num">${commentCount}</div><div class="lbl">Stored XSS comments</div></div>
      <div class="stat"><div class="num">${uploadsCount}</div><div class="lbl">Uploaded files</div></div>
      <div class="stat"><div class="num">${logLines}</div><div class="lbl">Logged requests</div></div>
    </div>
    <h3>Recent Flag Captures</h3>
    ${recentSolves.length > 0
      ? `<table><tr><th>User</th><th>Flag</th><th>Pts</th><th>When</th></tr>${solveRows}</table>`
      : `<p style="color:#484f58">No solves yet.</p>`}
  `));
});

// ── Users ──────────────────────────────────────────────────────────────────────
app.get("/users", (req, res) => {
  const db = new Database(DB_PATH);
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.role,
           COALESCE(SUM(f.points),0) as pts,
           COUNT(sf.flag_name) as solves
    FROM users u
    LEFT JOIN solved_flags sf ON sf.username=u.username
    LEFT JOIN flags f ON f.flag_name=sf.flag_name
    GROUP BY u.id ORDER BY pts DESC
  `).all();

  const rows = users.map(u => `
    <tr>
      <td>${u.id}</td>
      <td><strong>${u.username}</strong></td>
      <td style="color:#484f58">${u.email || "—"}</td>
      <td class="tag-${u.role}">${u.role}</td>
      <td style="color:#79c0ff;font-weight:bold">${u.pts}</td>
      <td>${u.solves}</td>
      <td>
        <a href="/admin/users/delete/${u.id}" class="btn btn-red"
           onclick="return confirm('Delete ${u.username}?')">Del</a>
        <a href="/admin/users/reset-score/${u.username}" class="btn btn-org">Reset Score</a>
      </td>
    </tr>
  `).join("");

  res.send(page("/admin/users", "Users", `
    <table>
      <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Points</th><th>Solves</th><th>Actions</th></tr>
      ${rows}
    </table>
    <h3 style="margin-top:2rem">Add User</h3>
    <form method="POST" action="/admin/users/add" style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">
      <input type="text" name="username" placeholder="username" required>
      <input type="password" name="password" placeholder="password" required>
      <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
      <button class="btn" type="submit">Add User</button>
    </form>
  `, req.query.msg, req.query.err));
});

app.post("/users/add", (req, res) => {
  const { username, password, role } = req.body;
  const crypto = require("crypto");
  const md5 = s => crypto.createHash("md5").update(s).digest("hex");
  try {
    const db = new Database(DB_PATH);
    db.prepare("INSERT INTO users (username, password, role) VALUES (?,?,?)").run(username, md5(password), role || "user");
    res.redirect("/admin/users?msg=User+created");
  } catch (e) {
    res.redirect(`/admin/users?err=${encodeURIComponent(e.message)}`);
  }
});

app.get("/users/delete/:id", (req, res) => {
  const db = new Database(DB_PATH);
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
  db.prepare("DELETE FROM solved_flags WHERE username=(SELECT username FROM users WHERE id=?)").run(req.params.id);
  res.redirect("/admin/users?msg=User+deleted");
});

app.get("/users/reset-score/:username", (req, res) => {
  const db = new Database(DB_PATH);
  db.prepare("DELETE FROM solved_flags WHERE username=?").run(req.params.username);
  res.redirect("/admin/users?msg=Score+reset");
});

// ── Scores ────────────────────────────────────────────────────────────────────
app.get("/scores", (req, res) => {
  const db = new Database(DB_PATH);
  const allFlags = db.prepare("SELECT * FROM flags ORDER BY points").all();
  const users = db.prepare(`
    SELECT DISTINCT username FROM solved_flags
  `).all().map(u => u.username);

  // Build matrix
  const solvedMatrix = {};
  users.forEach(u => {
    solvedMatrix[u] = new Set(
      db.prepare("SELECT flag_name FROM solved_flags WHERE username=?").all(u).map(r => r.flag_name)
    );
  });

  const headerCols = allFlags.map(f => `<th title="${f.description}" style="font-size:.7rem;writing-mode:vertical-rl;transform:rotate(180deg);height:100px;white-space:nowrap">${f.flag_name}</th>`).join("");

  const userRows = users.map(u => {
    const total = allFlags.reduce((s, f) => solvedMatrix[u].has(f.flag_name) ? s + f.points : s, 0);
    const cells = allFlags.map(f => `<td style="text-align:center">${solvedMatrix[u].has(f.flag_name) ? "✅" : "·"}</td>`).join("");
    return `<tr><td><strong>${u}</strong></td><td style="color:#79c0ff;font-weight:bold">${total}</td>${cells}</tr>`;
  }).join("");

  res.send(page("/admin/scores", "Score Matrix", `
    <div style="overflow-x:auto">
      <table>
        <tr><th>User</th><th>Total</th>${headerCols}</tr>
        ${userRows || `<tr><td colspan="99" style="color:#484f58">No solves yet.</td></tr>`}
      </table>
    </div>
  `));
});

// ── Flags ──────────────────────────────────────────────────────────────────────
app.get("/flags", (req, res) => {
  const db = new Database(DB_PATH);
  const flags = db.prepare("SELECT * FROM flags ORDER BY points").all();
  const rows = flags.map(f => `
    <tr>
      <td style="color:#3fb950;font-family:monospace">${f.flag_value}</td>
      <td>${f.flag_name}</td>
      <td style="color:#8b949e">${f.description}</td>
      <td style="color:#79c0ff">${f.points}</td>
      <td>${db.prepare("SELECT COUNT(*) as c FROM solved_flags WHERE flag_name=?").get(f.flag_name).c} solvers</td>
    </tr>
  `).join("");

  res.send(page("/admin/flags", "Flags", `
    <table>
      <tr><th>Flag Value</th><th>Name</th><th>Description</th><th>Pts</th><th>Solved By</th></tr>
      ${rows}
    </table>
    <h3>Add Custom Flag</h3>
    <form method="POST" action="/admin/flags/add" style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;max-width:700px">
      <input name="flag_name"  placeholder="my_custom_flag">
      <input name="flag_value" placeholder="VULNLAB{...}">
      <input name="description" placeholder="Description" style="grid-column:1/-1">
      <input name="points" type="number" value="100" placeholder="Points">
      <button class="btn" type="submit">Add Flag</button>
    </form>
  `, req.query.msg));
});

app.post("/flags/add", (req, res) => {
  const { flag_name, flag_value, description, points } = req.body;
  try {
    const db = new Database(DB_PATH);
    db.prepare("INSERT INTO flags (flag_name,flag_value,description,points) VALUES (?,?,?,?)").run(flag_name, flag_value, description, parseInt(points) || 100);
    res.redirect("/admin/flags?msg=Flag+added");
  } catch (e) {
    res.redirect(`/admin/flags?err=${encodeURIComponent(e.message)}`);
  }
});

// ── Traffic log ────────────────────────────────────────────────────────────────
app.get("/traffic", (req, res) => {
  const filter = req.query.filter || "";
  const lines = fs.existsSync(LOG_PATH)
    ? fs.readFileSync(LOG_PATH, "utf8").split("\n").filter(Boolean).slice(-400).reverse()
    : [];

  const entries = lines
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean)
    .filter(e => !filter || JSON.stringify(e).toLowerCase().includes(filter.toLowerCase()))
    .slice(0, 300);

  const methodColor = { GET:"#3fb950", POST:"#e3b341", PUT:"#79c0ff", DELETE:"#f85149" };

  const rows = entries.map(e => `
    <tr>
      <td style="white-space:nowrap;color:#484f58">${(e.ts||"").slice(0,19).replace("T"," ")}</td>
      <td style="color:${methodColor[e.method]||"#c9d1d9"}">${e.method}</td>
      <td>${e.path}</td>
      <td style="color:#484f58">${JSON.stringify(e.query)!=="{}" ? JSON.stringify(e.query) : ""}</td>
      <td style="color:#e3b341">${e.body&&JSON.stringify(e.body)!=="{}" ? JSON.stringify(e.body).slice(0,100) : ""}</td>
      <td style="color:#484f58">${e.ip}</td>
    </tr>
  `).join("");

  res.send(page("/admin/traffic", "Traffic Log", `
    <form method="GET" style="display:flex;gap:.5rem;margin-bottom:1rem">
      <input name="filter" value="${filter}" placeholder="Filter..." style="width:280px">
      <button class="btn" type="submit">Filter</button>
      <a href="/admin/traffic/clear" class="btn btn-red">Clear Log</a>
    </form>
    <p style="color:#484f58;font-size:.8rem;margin-bottom:.5rem">${entries.length} entries shown</p>
    ${entries.length > 0
      ? `<table><tr><th>Time</th><th>Method</th><th>Path</th><th>Query</th><th>Body</th><th>IP</th></tr>${rows}</table>`
      : `<p style="color:#484f58">No entries.</p>`}
  `));
});

app.get("/traffic/clear", (req, res) => {
  fs.writeFileSync(LOG_PATH, "");
  res.redirect("/admin/traffic?msg=Log+cleared");
});

// ── Lab resets ────────────────────────────────────────────────────────────────
app.get("/resets", (req, res) => {
  res.send(page("/admin/resets", "Reset Labs", `
    <p style="color:#8b949e;margin-bottom:1.5rem">Reset individual lab state. Useful between training sessions.</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1rem">

      <div class="card">
        <h3 style="color:#e3b341;margin:0 0 .5rem">XSS — Stored Comments</h3>
        <p style="color:#484f58;font-size:.82rem;margin-bottom:1rem">Delete all comments from the Stored XSS lab.</p>
        <a href="/admin/resets/xss" class="btn btn-red" onclick="return confirm('Reset XSS comments?')">Reset XSS</a>
      </div>

      <div class="card">
        <h3 style="color:#e3b341;margin:0 0 .5rem">Upload Lab — Files</h3>
        <p style="color:#484f58;font-size:.82rem;margin-bottom:1rem">Delete all files from the uploads directory.</p>
        <a href="/admin/resets/uploads" class="btn btn-red" onclick="return confirm('Delete all uploaded files?')">Reset Uploads</a>
      </div>

      <div class="card">
        <h3 style="color:#e3b341;margin:0 0 .5rem">All Scores</h3>
        <p style="color:#484f58;font-size:.82rem;margin-bottom:1rem">Clear ALL solved flags from ALL users.</p>
        <a href="/admin/resets/scores" class="btn btn-red" onclick="return confirm('Wipe all scores?')">Wipe Scores</a>
      </div>

      <div class="card">
        <h3 style="color:#e3b341;margin:0 0 .5rem">Traffic Log</h3>
        <p style="color:#484f58;font-size:.82rem;margin-bottom:1rem">Clear the request traffic log file.</p>
        <a href="/admin/traffic/clear" class="btn btn-red">Clear Log</a>
      </div>

      <div class="card">
        <h3 style="color:#e3b341;margin:0 0 .5rem">Full Lab Reset</h3>
        <p style="color:#484f58;font-size:.82rem;margin-bottom:1rem">Reset everything: comments, uploads, scores, log.</p>
        <a href="/admin/resets/all" class="btn btn-red" onclick="return confirm('FULL RESET? This cannot be undone.')">Full Reset</a>
      </div>

    </div>
  `, req.query.msg));
});

app.get("/resets/xss", (req, res) => {
  const db = new Database(DB_PATH);
  db.prepare("DELETE FROM comments").run();
  res.redirect("/admin/resets?msg=XSS+comments+cleared");
});

app.get("/resets/uploads", (req, res) => {
  if (fs.existsSync(UPLOAD_DIR)) {
    for (const f of fs.readdirSync(UPLOAD_DIR)) {
      fs.unlinkSync(path.join(UPLOAD_DIR, f));
    }
  }
  res.redirect("/admin/resets?msg=Uploads+cleared");
});

app.get("/resets/scores", (req, res) => {
  const db = new Database(DB_PATH);
  db.prepare("DELETE FROM solved_flags").run();
  res.redirect("/admin/resets?msg=All+scores+wiped");
});

app.get("/resets/all", (req, res) => {
  const db = new Database(DB_PATH);
  db.prepare("DELETE FROM comments").run();
  db.prepare("DELETE FROM solved_flags").run();
  if (fs.existsSync(UPLOAD_DIR)) {
    for (const f of fs.readdirSync(UPLOAD_DIR)) {
      try { fs.unlinkSync(path.join(UPLOAD_DIR, f)); } catch {}
    }
  }
  if (fs.existsSync(LOG_PATH)) fs.writeFileSync(LOG_PATH, "");
  res.redirect("/admin/resets?msg=Full+reset+complete");
});

// ── Hints manager ─────────────────────────────────────────────────────────────
const HINTS = {
  "XSS Reflected":  "Try: <script>alert(document.cookie)</script> in the ?q= param",
  "XSS Stored":     "Try: <img src=x onerror=alert(1)> in the comment box",
  "XSS DOM":        "Navigate to /xss/dom#<img src=x onerror=alert(1)>",
  "SQLi Login":     "Username: ' OR '1'='1' --  (leave password blank)",
  "SQLi UNION":     "Try: ' UNION SELECT id,username,password,role FROM users --",
  "SQLi Blind":     "Use sqlmap: sqlmap -u 'http://localhost:8080/sqli/blind?id=1' --dump",
  "Auth Weak Hash": "Paste the MD5 hashes into crackstation.net",
  "Auth JWT":       "Set alg:none, change role to admin, remove signature",
  "Auth IDOR":      "Change the ID number in /auth/profile/1 → /auth/profile/5",
  "File Upload":    "Upload a file named shell.phtml or shell.php5",
  "Path Traversal": "Try ?file=../../etc/passwd in the download param",
  "CSRF":           "Open /csrf/poc while logged in as alice",
  "SSRF":           "POST to /api/fetch with url=http://admin:4000/",
};

app.get("/hints", (req, res) => {
  const rows = Object.entries(HINTS).map(([k, v]) => `
    <tr>
      <td style="color:#79c0ff">${k}</td>
      <td style="color:#8b949e;font-family:monospace;font-size:.8rem">${v}</td>
    </tr>
  `).join("");

  res.send(page("/admin/hints", "Hints Reference", `
    <p style="color:#8b949e;margin-bottom:1rem">Quick reference for instructors. Share selectively with trainees.</p>
    <table>
      <tr><th>Challenge</th><th>Hint</th></tr>
      ${rows}
    </table>
  `));
});

// ── Broadcast ─────────────────────────────────────────────────────────────────
const BROADCASTS = [];

app.get("/broadcast", (req, res) => {
  res.send(page("/admin/broadcast", "Broadcast Message", `
    <p style="color:#8b949e;margin-bottom:1rem">
      Post a message visible at <code style="color:#79c0ff">/notice</code> on the main app.
      Useful to give hints, announce challenge windows, etc.
    </p>
    <form method="POST" action="/admin/broadcast">
      <textarea name="message" rows="4" style="width:100%;padding:.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;font-family:monospace;font-size:.9rem" placeholder="Enter broadcast message..."></textarea>
      <br>
      <button class="btn" type="submit" style="margin-top:.5rem">Post Broadcast</button>
    </form>
    ${BROADCASTS.length > 0 ? `
      <h3>Recent Broadcasts</h3>
      <ul style="color:#8b949e;font-size:.85rem">
        ${BROADCASTS.slice(-10).reverse().map(b => `<li style="margin:.3rem 0">${b}</li>`).join("")}
      </ul>
    ` : ""}
  `, req.query.msg));
});

app.post("/broadcast", (req, res) => {
  const msg = req.body.message || "";
  if (msg.trim()) BROADCASTS.push(`[${new Date().toLocaleTimeString()}] ${msg.trim()}`);
  res.redirect("/admin/broadcast?msg=Broadcast+posted");
});

// Expose broadcasts to main app via JSON
app.get("/api/broadcast", (req, res) => {
  res.json({ messages: BROADCASTS.slice(-5) });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[VulnLab Admin] running on port ${PORT}`);
});

module.exports = app;
