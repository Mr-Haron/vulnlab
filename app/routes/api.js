/**
 * VulnLab — API Security Lab
 * Challenges:
 *   1. IDOR via REST API — change userId param to access other accounts
 *   2. SSRF — the /api/fetch endpoint fetches any URL server-side
 */

const express = require("express");
const router  = express.Router();
const http    = require("http");
const https   = require("https");
const { getDB } = require("../db/seed");

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
  input { width:100%;padding:0.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:0.3rem;font-family:monospace; }
  button { padding:0.5rem 1.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-top:0.5rem; }
  .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin:1rem 0; }
  pre { background:#21262d;padding:1rem;border-radius:6px;overflow-x:auto;font-size:0.8rem;color:#79c0ff;margin-top:0.5rem; }
  code { background:#21262d;padding:0.1rem 0.4rem;border-radius:3px;color:#79c0ff; }
</style>
</head>
<body>
<header><a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; <a href="/api">API Lab</a></header>
<main>${body}</main>
</html>`;

// ── Lab index ─────────────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  res.send(layout("API Security Lab", `
    <h2>API Security Lab</h2>
    <div class="card">
      <h3><a href="/api/orders/1" style="color:#58a6ff">Lab 1 — IDOR in REST API</a></h3>
      <p style="color:#8b949e">The orders endpoint exposes data based on user ID in the URL. No authorization enforced.</p>
    </div>
    <div class="card">
      <h3><a href="/api/ssrf-demo" style="color:#58a6ff">Lab 2 — SSRF (Server-Side Request Forgery)</a></h3>
      <p style="color:#8b949e">The /api/fetch endpoint makes HTTP requests server-side without URL validation. Probe internal services.</p>
    </div>
    <hr style="border-color:#30363d;margin:1.5rem 0">
    <h3 style="color:#8b949e">REST API Endpoints (try with Postman or curl)</h3>
    <pre>GET  /api/users        — List all users (no auth)
GET  /api/users/:id    — Get user by ID (IDOR)
GET  /api/orders/:id   — Get order by user ID (IDOR)
POST /api/fetch        — Fetch URL server-side (SSRF)</pre>
  `));
});

// ── Unauthenticated user listing (OWASP A01) ──────────────────────────────────
router.get("/users", (req, res) => {
  const db = getDB();
  // INTENTIONAL: no auth, exposes passwords
  const users = db.prepare("SELECT id, username, email, role, password FROM users").all();
  res.json({ users });
});

router.get("/users/:id", (req, res) => {
  const db = getDB();
  // INTENTIONAL VULNERABILITY: IDOR — no session check
  const user = db.prepare("SELECT id, username, email, role, bio, password FROM users WHERE id=?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user });
});

// ── IDOR — orders by user ID ──────────────────────────────────────────────────
const FAKE_ORDERS = {
  1: { userId: 1, items: ["Apple Juice x2", "Water x1"], total: 6.97, secret: "Admin's order history" },
  2: { userId: 2, items: ["Orange Juice x1"], total: 3.49, secret: "Alice's private notes" },
  3: { userId: 3, items: ["Green Smoothie x2"], total: 9.98, flag: "VULNLAB{1D0R_PRIV3SC}" },
};

router.get("/orders/:id", (req, res) => {
  const id = parseInt(req.params.id);
  // INTENTIONAL VULNERABILITY: no session check
  const order = FAKE_ORDERS[id];
  if (!order) return res.status(404).send(layout("IDOR Lab", `<p style="color:#f85149">Order ${id} not found.</p><a href="/api/orders/1" style="color:#58a6ff">← Back to order 1</a>`));

  const flagMsg = order.flag ? `<div style="background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:0.5rem 1rem;border-radius:4px;margin-top:1rem">🚩 ${order.flag}</div>` : "";

  res.send(layout("IDOR — Order Detail", `
    <h2>Lab 1 — IDOR: Order ${id}</h2>
    <div class="hint">💡 <strong>Hint:</strong> Try <code>/api/orders/1</code>, <code>/api/orders/2</code>, <code>/api/orders/3</code> — no auth check.</div>
    <div class="card">
      <p><strong>User ID:</strong> ${order.userId}</p>
      <p><strong>Items:</strong> ${order.items.join(", ")}</p>
      <p><strong>Total:</strong> $${order.total}</p>
      <p><strong>Notes:</strong> ${order.secret || order.flag || ""}</p>
    </div>
    ${flagMsg}
    <div style="display:flex;gap:0.5rem;margin-top:1rem">
      ${id > 1 ? `<a href="/api/orders/${id-1}" style="background:#21262d;color:#58a6ff;padding:0.4rem 1rem;border-radius:6px;text-decoration:none">← Prev</a>` : ""}
      <a href="/api/orders/${id+1}" style="background:#21262d;color:#58a6ff;padding:0.4rem 1rem;border-radius:6px;text-decoration:none">Next →</a>
    </div>
  `));
});

// ── SSRF demo page ────────────────────────────────────────────────────────────
router.get("/ssrf-demo", (req, res) => {
  res.send(layout("SSRF Lab", `
    <h2>Lab 2 — SSRF (Server-Side Request Forgery)</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> The server fetches any URL you give it. Try:<br>
      • <code>http://localhost:3000/</code> — internal app<br>
      • <code>http://redis:6379/</code> — internal Redis<br>
      • <code>http://169.254.169.254/latest/meta-data/</code> — AWS metadata (if on cloud)<br>
      • <code>http://admin:4000/</code> — internal admin panel
    </div>
    <form method="POST" action="/api/fetch">
      <label>URL to fetch (server-side):</label>
      <input type="text" name="url" placeholder="http://...">
      <button type="submit">Fetch</button>
    </form>
    <div style="margin-top:1rem;color:#484f58;font-size:0.8rem">
      <strong>With curl:</strong> <code>curl -X POST http://localhost:8080/api/fetch -d "url=http://admin:4000/"</code>
    </div>
  `));
});

// ── SSRF endpoint ─────────────────────────────────────────────────────────────
router.post("/fetch", (req, res) => {
  const url = req.body.url || "";

  if (!url) {
    return res.send(layout("SSRF", `<div style="color:#f85149">No URL provided.</div><a href="/api/ssrf-demo" style="color:#58a6ff">← Back</a>`));
  }

  // INTENTIONAL VULNERABILITY: fetches any URL without restriction
  const proto = url.startsWith("https") ? https : http;

  proto.get(url, (resp) => {
    let data = "";
    resp.on("data", chunk => { data += chunk; });
    resp.on("end", () => {
      const isInternal = url.includes("169.254") || url.includes("admin") || url.includes("redis") || url.includes("localhost") || url.includes("127.0.0.1");
      const flagMsg = isInternal
        ? `<div style="background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">🚩 VULNLAB{SSRF_R34CH3D_1NT3RN4L} — Internal service reached!</div>`
        : "";

      res.send(layout("SSRF — Response", `
        <h2>SSRF — Server fetched: ${url}</h2>
        ${flagMsg}
        <div class="card">
          <strong>Status:</strong> ${resp.statusCode}<br>
          <strong>Content-Type:</strong> ${resp.headers["content-type"] || "unknown"}
        </div>
        <strong>Response body:</strong>
        <pre>${data.replace(/</g, "&lt;").substring(0, 3000)}</pre>
        <a href="/api/ssrf-demo" style="color:#58a6ff">← Try another URL</a>
      `));
    });
  }).on("error", (e) => {
    res.send(layout("SSRF — Error", `
      <div style="color:#f85149">Fetch error: ${e.message}</div>
      <a href="/api/ssrf-demo" style="color:#58a6ff">← Back</a>
    `));
  });
});

module.exports = router;
