/**
 * VulnLab — Authentication & Authorization Lab
 * Challenges:
 *   1. Weak password storage (MD5) — crack hashes
 *   2. JWT algorithm confusion (none) — forge tokens
 *   3. IDOR — access any user profile by changing ID in URL
 */

const express = require("express");
const router  = express.Router();
const crypto  = require("crypto");
const jwt     = require("jsonwebtoken");
const { getDB } = require("../db/seed");

function md5(str) {
  return crypto.createHash("md5").update(str).digest("hex");
}

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
  .error { background:#3d0e0e;border-left:3px solid #f85149;padding:0.75rem 1rem;margin:1rem 0;color:#f85149;border-radius:0 6px 6px 0; }
  .success { background:#0d2d0d;border-left:3px solid #3fb950;padding:0.75rem 1rem;margin:1rem 0;color:#3fb950;border-radius:0 6px 6px 0; }
  input { width:100%;padding:0.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:0.3rem;font-family:monospace; }
  button { padding:0.5rem 1.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-top:0.5rem; }
  .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin:1rem 0; }
  code { background:#21262d;padding:0.1rem 0.4rem;border-radius:3px;color:#79c0ff;font-size:0.85rem; }
</style>
</head>
<body>
<header><a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; <a href="/auth">Auth Lab</a></header>
<main>${body}</main>
</html>`;

// ── Lab index ─────────────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  res.send(layout("Auth Lab", `
    <h2>Authentication & Authorization Lab</h2>
    <div class="card">
      <h3><a href="/auth/hashes" style="color:#58a6ff">Lab 1 — Weak Password Hashes</a> <span style="color:#e3b341;font-size:0.8rem">[150 pts]</span></h3>
      <p style="color:#8b949e">Retrieve MD5 password hashes and crack them with John the Ripper or CrackStation.</p>
    </div>
    <div class="card">
      <h3><a href="/auth/jwt-demo" style="color:#58a6ff">Lab 2 — JWT Algorithm Confusion</a> <span style="color:#f85149;font-size:0.8rem">[250 pts]</span></h3>
      <p style="color:#8b949e">The JWT verification accepts the 'none' algorithm. Forge a token claiming admin role.</p>
    </div>
    <div class="card">
      <h3><a href="/auth/profile/1" style="color:#58a6ff">Lab 3 — IDOR (Insecure Direct Object Reference)</a> <span style="color:#f85149;font-size:0.8rem">[150 pts]</span></h3>
      <p style="color:#8b949e">User profiles are served at /auth/profile/:id with no authorization check. Browse other users.</p>
    </div>
  `));
});

// ── Register / Login (for session use across labs) ────────────────────────────
router.get("/register", (req, res) => {
  res.send(layout("Register", `
    <h2>Register</h2>
    <form method="POST" action="/auth/register">
      <label>Username:</label>
      <input type="text" name="username">
      <label style="margin-top:0.75rem;display:block">Password:</label>
      <input type="password" name="password">
      <button type="submit">Register</button>
    </form>
    <p style="margin-top:1rem"><a href="/auth/login" style="color:#58a6ff">Already have an account? Login</a></p>
  `));
});

router.post("/register", (req, res) => {
  const { username, password } = req.body;
  const db = getDB();
  try {
    // INTENTIONAL: MD5 password storage
    db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run(username, md5(password));
    req.session.user = { username, role: "user" };
    res.redirect("/");
  } catch (e) {
    res.send(layout("Register Error", `<div class="error">Username already taken.</div><a href="/auth/register" style="color:#58a6ff">← Back</a>`));
  }
});

router.get("/login", (req, res) => {
  res.send(layout("Login", `
    <h2>Login</h2>
    <form method="POST" action="/auth/login">
      <label>Username:</label>
      <input type="text" name="username">
      <label style="margin-top:0.75rem;display:block">Password:</label>
      <input type="password" name="password">
      <button type="submit">Login</button>
    </form>
    ${req.query.error ? `<div class="error">Invalid credentials.</div>` : ""}
    <p style="margin-top:1rem"><a href="/auth/register" style="color:#58a6ff">No account? Register</a></p>
  `));
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const db = getDB();
  const user = db.prepare("SELECT * FROM users WHERE username=? AND password=?").get(username, md5(password));
  if (user) {
    req.session.user = { username: user.username, role: user.role, id: user.id };
    res.redirect("/");
  } else {
    res.redirect("/auth/login?error=1");
  }
});

router.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// ── Lab 1: Weak hashes ────────────────────────────────────────────────────────
router.get("/hashes", (req, res) => {
  const db = getDB();
  // INTENTIONAL: exposes hashes — trainee cracks them
  const users = db.prepare("SELECT id, username, password, role FROM users").all();
  const rows = users.map(u => `
    <tr>
      <td>${u.id}</td>
      <td>${u.username}</td>
      <td style="font-family:monospace;font-size:0.8rem;color:#79c0ff">${u.password}</td>
      <td>${u.role}</td>
    </tr>
  `).join("");

  res.send(layout("Weak Hashes", `
    <h2>Lab 1 — Weak Password Storage</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> All passwords are stored as unsalted MD5 hashes.<br>
      Crack them using: <br>
      • <a href="https://crackstation.net" style="color:#58a6ff" target="_blank">CrackStation.net</a> (online)<br>
      • <code>john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt</code><br>
      • <code>hashcat -m 0 hashes.txt rockyou.txt</code><br>
      Admin hash cracks to get the flag.
    </div>
    <table style="width:100%;border-collapse:collapse;margin-top:1rem">
      <tr style="background:#21262d">
        <th style="border:1px solid #30363d;padding:0.5rem">ID</th>
        <th style="border:1px solid #30363d;padding:0.5rem">Username</th>
        <th style="border:1px solid #30363d;padding:0.5rem">Password (MD5)</th>
        <th style="border:1px solid #30363d;padding:0.5rem">Role</th>
      </tr>
      ${rows}
    </table>
    <div style="margin-top:1rem;color:#484f58;font-size:.8rem">
      Crack <strong>admin</strong>'s hash → password is <code>admin123</code> →
      login at <a href="/auth/login" style="color:#58a6ff">/auth/login</a> →
      🚩 <strong style="color:#3fb950">VULNLAB{WK_P4SS_CR4CK3D}</strong>
    </div>
  `));
});

// ── Lab 2: JWT none algorithm ─────────────────────────────────────────────────
router.get("/jwt-demo", (req, res) => {
  // Issue a legit JWT to the trainee
  const token = jwt.sign({ username: "trainee", role: "user" }, "vulnlab-secret", { expiresIn: "1h" });

  res.send(layout("JWT Lab", `
    <h2>Lab 2 — JWT Algorithm Confusion</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> The server verifies JWTs but accepts <code>alg: none</code> (no signature required).<br>
      1. Decode your token at <a href="https://jwt.io" style="color:#58a6ff" target="_blank">jwt.io</a><br>
      2. Change payload to <code>"role":"admin"</code><br>
      3. Remove the signature and set <code>alg: "none"</code><br>
      4. Send it to <code>/auth/jwt-verify</code> as <code>Authorization: Bearer &lt;forged-token&gt;</code>
    </div>
    <div class="card">
      <strong>Your token (legitimate):</strong><br>
      <code style="word-break:break-all">${token}</code>
    </div>
    <form method="POST" action="/auth/jwt-verify">
      <label>Paste your token (original or forged):</label>
      <input type="text" name="token" placeholder="Paste JWT here">
      <button type="submit">Verify Token</button>
    </form>
    <div style="margin-top:1rem;color:#484f58;font-size:0.8rem">
      <strong>Forge with Python:</strong><br>
      <code>
        import base64, json<br>
        h = base64.b64encode(json.dumps({{"alg":"none","typ":"JWT"}}).encode()).decode().rstrip('=')<br>
        p = base64.b64encode(json.dumps({{"username":"attacker","role":"admin"}}).encode()).decode().rstrip('=')<br>
        print(f"{{h}}.{{p}}.")
      </code>
    </div>
  `));
});

router.post("/jwt-verify", (req, res) => {
  const token = req.body.token || "";
  let decoded = null;
  let error = null;

  try {
    // INTENTIONAL VULNERABILITY: algorithms: ['HS256', 'none'] — accepts unsigned tokens
    decoded = jwt.verify(token, "vulnlab-secret", { algorithms: ["HS256", "none"] });
  } catch (e) {
    // Also try manual decode for 'none' alg
    try {
      const parts = token.split(".");
      const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());
      const header  = JSON.parse(Buffer.from(parts[0], "base64").toString());
      if (header.alg === "none") decoded = payload;
      else error = e.message;
    } catch (e2) {
      error = e.message;
    }
  }

  if (decoded && decoded.role === "admin") {
    res.send(layout("JWT — Admin!", `
      <h2>Lab 2 — JWT Algorithm Confusion</h2>
      <div class="success">
        ✅ Admin access granted via forged JWT!<br>
        🚩 Flag: <strong>VULNLAB{JWT_N0N3_ALG_BYPASS}</strong>
      </div>
      <div class="card">
        Decoded payload: <code>${JSON.stringify(decoded)}</code>
      </div>
    `));
  } else if (decoded) {
    res.send(layout("JWT — Valid but not admin", `
      <h2>Lab 2 — JWT Algorithm Confusion</h2>
      <div class="hint">Token is valid but role is <strong>${decoded.role}</strong>. Forge one with role=admin.</div>
      <p><a href="/auth/jwt-demo" style="color:#58a6ff">← Back</a></p>
    `));
  } else {
    res.send(layout("JWT — Invalid", `
      <h2>Lab 2 — JWT Algorithm Confusion</h2>
      <div class="error">Invalid token: ${error}</div>
      <p><a href="/auth/jwt-demo" style="color:#58a6ff">← Back</a></p>
    `));
  }
});

// ── Lab 3: IDOR ───────────────────────────────────────────────────────────────
router.get("/profile/:id", (req, res) => {
  const db = getDB();
  const id = req.params.id;

  // INTENTIONAL VULNERABILITY: no authorization check — any ID accessible
  const user = db.prepare("SELECT id, username, email, role, bio FROM users WHERE id=?").get(id);

  if (!user) {
    return res.send(layout("IDOR Lab", `<div class="error">User ID ${id} not found.</div><p><a href="/auth/profile/1" style="color:#58a6ff">← Back</a></p>`));
  }

  const isFlag = user.bio && user.bio.includes("VULNLAB{");

  res.send(layout("User Profile — IDOR", `
    <h2>Lab 3 — IDOR: User Profiles</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> There is no authorization check on this endpoint. You can view ANY user's profile by changing the ID in the URL.<br>
      Try: <code>/auth/profile/1</code>, <code>/auth/profile/2</code>, <code>/auth/profile/5</code> …
    </div>
    <div class="card">
      <p><strong>ID:</strong> ${user.id}</p>
      <p><strong>Username:</strong> ${user.username}</p>
      <p><strong>Email:</strong> ${user.email || "(none)"}</p>
      <p><strong>Role:</strong> ${user.role}</p>
      <p><strong>Bio:</strong> ${user.bio || "(empty)"}</p>
      ${isFlag ? `<div style="margin-top:1rem;background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:0.5rem 1rem;border-radius:4px">🚩 Flag found in bio!</div>` : ""}
    </div>
    <div style="display:flex;gap:0.5rem;margin-top:1rem">
      ${id > 1 ? `<a href="/auth/profile/${parseInt(id)-1}" style="background:#21262d;color:#58a6ff;padding:0.4rem 1rem;border-radius:6px;text-decoration:none">← Prev</a>` : ""}
      <a href="/auth/profile/${parseInt(id)+1}" style="background:#21262d;color:#58a6ff;padding:0.4rem 1rem;border-radius:6px;text-decoration:none">Next →</a>
    </div>
  `));
});

module.exports = router;
