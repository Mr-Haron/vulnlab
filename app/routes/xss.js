/**
 * VulnLab — XSS Lab
 * Challenges:
 *   1. Reflected XSS — search parameter echoed without sanitization
 *   2. Stored XSS    — comments stored raw, rendered without escaping
 *   3. DOM XSS       — client-side code reads URL hash and injects into DOM
 */

const express  = require("express");
const router   = express.Router();
const { getDB } = require("../db/seed");

const layout = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title} — VulnLab</title>
<style>
  * { box-sizing: border-box; }
  body { background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0; }
  header { background:#161b22;border-bottom:1px solid #30363d;padding:1rem 2rem; }
  header a { color:#58a6ff;text-decoration:none; }
  main { max-width:800px;margin:2rem auto;padding:0 1rem; }
  h2 { color:#58a6ff; }
  .hint { background:#1c2128;border-left:3px solid #d29922;padding:0.75rem 1rem;margin:1rem 0;border-radius:0 6px 6px 0;font-size:0.85rem;color:#e3b341; }
  input,textarea { width:100%;padding:0.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:0.3rem;font-family:monospace; }
  button { padding:0.5rem 1.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-top:0.5rem; }
  .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin:1rem 0; }
  .flag { background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:0.5rem 1rem;border-radius:4px;font-family:monospace;margin:1rem 0; }
  nav a { margin-right:1rem;color:#58a6ff;text-decoration:none; }
</style>
</head>
<body>
<header>
  <a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; <a href="/xss">XSS Lab</a>
</header>
<main>${body}</main>
</html>`;

// ── Lab index ─────────────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  res.send(layout("XSS Lab", `
    <h2>Cross-Site Scripting (XSS) Lab</h2>
    <p style="color:#8b949e;margin-bottom:1.5rem">
      XSS lets attackers inject scripts into pages viewed by other users.
      OWASP ranks it A03:2021 Injection. Complete all three challenges.
    </p>
    <div class="card">
      <h3><a href="/xss/reflected" style="color:#58a6ff">Lab 1 — Reflected XSS</a> <span style="color:#e3b341;font-size:0.8rem">[100 pts]</span></h3>
      <p style="color:#8b949e">A search box echoes your input directly into the HTML. Inject a script.</p>
    </div>
    <div class="card">
      <h3><a href="/xss/stored" style="color:#58a6ff">Lab 2 — Stored XSS</a> <span style="color:#f85149;font-size:0.8rem">[200 pts]</span></h3>
      <p style="color:#8b949e">Comments are saved to the database and rendered for every visitor. Plant a persistent payload.</p>
    </div>
    <div class="card">
      <h3><a href="/xss/dom" style="color:#58a6ff">Lab 3 — DOM-Based XSS</a> <span style="color:#f85149;font-size:0.8rem">[200 pts]</span></h3>
      <p style="color:#8b949e">JavaScript reads the URL hash and writes it to the DOM with innerHTML. No server involved.</p>
    </div>
  `));
});

// ── Lab 1: Reflected XSS ──────────────────────────────────────────────────────
router.get("/reflected", (req, res) => {
  // INTENTIONAL VULNERABILITY: user input echoed raw into HTML
  const query = req.query.q || "";
  res.send(layout("Reflected XSS", `
    <h2>Lab 1 — Reflected XSS</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> The search term is reflected directly in the page.
      Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
    </div>
    <form method="GET" action="/xss/reflected">
      <label>Search products:</label>
      <input type="text" name="q" value="${query}" placeholder="Search...">
      <button type="submit">Search</button>
    </form>
    ${query ? `<p style="margin-top:1rem">Results for: <strong>${query}</strong></p>
    ${(query.includes('<script') || query.includes('onerror') || query.includes('javascript:'))
      ? `<div style="background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:.5rem 1rem;border-radius:4px;margin-top:.75rem">
           🚩 XSS payload detected! Flag: <strong>VULNLAB{XSS_R3FL3CT3D_G0T_Y0U}</strong>
         </div>` : ""}` : ""}
    <div style="margin-top:1rem;color:#484f58;font-size:0.8rem">
      <strong>What to look for:</strong> The URL parameter <code>q</code> is placed inside the HTML without encoding.
      Open DevTools → Network to see your payload sent as a URL parameter.
    </div>
  `));
});

// ── Lab 2: Stored XSS ─────────────────────────────────────────────────────────
router.get("/stored", (req, res) => {
  const db = getDB();
  // INTENTIONAL VULNERABILITY: comments fetched and rendered raw
  const comments = db.prepare("SELECT * FROM comments ORDER BY id DESC LIMIT 20").all();
  const commentHTML = comments.map(c => `
    <div class="card" style="margin-bottom:0.5rem">
      <strong style="color:#79c0ff">${c.username}</strong>
      <span style="color:#484f58;font-size:0.75rem"> — ${c.created_at}</span>
      <p style="margin-top:0.5rem">${c.content}</p>
    </div>
  `).join("");

  res.send(layout("Stored XSS", `
    <h2>Lab 2 — Stored XSS</h2>
    ${req.query.flag ? `<div style="background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:.5rem 1rem;border-radius:4px;margin-bottom:1rem">🚩 Payload stored! Flag: <strong>VULNLAB{ST0R3D_XSS_P3RS1STS}</strong></div>` : ""}
    <div class="hint">
      💡 <strong>Hint:</strong> Comment content is stored and rendered with innerHTML.
      Try posting: <code>&lt;img src=x onerror="alert(document.cookie)"&gt;</code>
    </div>
    <form method="POST" action="/xss/stored">
      <label>Username:</label>
      <input type="text" name="username" placeholder="Your name" value="">
      <label style="margin-top:0.75rem;display:block">Comment:</label>
      <textarea name="content" rows="3" placeholder="Leave a comment..."></textarea>
      <button type="submit">Post Comment</button>
    </form>
    <h3 style="margin-top:2rem;color:#8b949e">Comments:</h3>
    ${commentHTML || '<p style="color:#484f58">No comments yet.</p>'}
  `));
});

router.post("/stored", (req, res) => {
  const { username, content } = req.body;
  if (username && content) {
    const db = getDB();
    // INTENTIONAL VULNERABILITY: no sanitization before storing
    db.prepare("INSERT INTO comments (username, content) VALUES (?, ?)").run(
      username || "anonymous",
      content
    );
    // Flag awarded if a script/event payload is stored
    const isXSS = /<script|onerror|onload|javascript:/i.test(content);
    if (isXSS) {
      return res.redirect("/xss/stored?flag=1");
    }
  }
  res.redirect("/xss/stored");
});

// ── Lab 3: DOM-Based XSS ──────────────────────────────────────────────────────
router.get("/dom", (req, res) => {
  res.send(layout("DOM XSS", `
    <h2>Lab 3 — DOM-Based XSS</h2>
    <div class="hint">
      💡 <strong>Hint:</strong> JavaScript reads <code>location.hash</code> and sets <code>innerHTML</code>.
      Try navigating to: <code>/xss/dom#&lt;img src=x onerror=alert(1)&gt;</code>
    </div>
    <div id="greeting" style="font-size:1.2rem;color:#58a6ff;margin:1rem 0">
      Welcome!
    </div>
    <label>Or enter a name in the URL hash: <code>/xss/dom#YourName</code></label>
    <div style="margin-top:1rem;color:#484f58;font-size:0.8rem">
      <strong>What's happening:</strong> <code>document.getElementById('greeting').innerHTML = location.hash.slice(1)</code> — no sanitization.
    </div>
    <script>
      // INTENTIONAL VULNERABILITY: innerHTML from URL hash
      const hash = location.hash.slice(1);
      if (hash) {
        document.getElementById('greeting').innerHTML = 'Welcome, ' + decodeURIComponent(hash) + '!';
        // Flag reveal if XSS payload detected
        if (/<|onerror|onload|javascript:/i.test(decodeURIComponent(hash))) {
          document.body.insertAdjacentHTML('beforeend',
            '<div style="background:#0d2d0d;border:1px solid #3fb950;color:#3fb950;padding:.5rem 1rem;border-radius:4px;margin:1rem">'+
            '🚩 DOM XSS triggered! Flag: <strong>VULNLAB{D0M_XSS_N0_S3RV3R}</strong></div>');
        }
      }
    </script>
  `));
});

module.exports = router;
