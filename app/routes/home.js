const express = require("express");
const router  = express.Router();
const { getDB } = require("../db/seed");

router.get("/", (req, res) => {
  const user = req.session.user || null;
  let score = 0;
  let solved = [];

  if (user) {
    const db   = getDB();
    const rows = db.prepare("SELECT flag_name FROM solved_flags WHERE username = ?").all(user.username);
    solved     = rows.map(r => r.flag_name);
    const pts  = db.prepare(`
      SELECT COALESCE(SUM(f.points), 0) as total
      FROM solved_flags sf
      JOIN flags f ON f.flag_name = sf.flag_name
      WHERE sf.username = ?
    `).get(user.username);
    score = pts.total;
  }

  res.send(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VulnLab — Security Training Platform</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
  header h1 { color: #58a6ff; font-size: 1.4rem; }
  header .badge { background: #21262d; border: 1px solid #30363d; padding: 0.3rem 0.8rem; border-radius: 6px; font-size: 0.85rem; }
  .warning { background: #3d1a00; border: 1px solid #d29922; color: #e3b341; padding: 0.8rem 2rem; font-size: 0.85rem; text-align: center; }
  main { max-width: 1100px; margin: 0 auto; padding: 2rem; }
  h2 { color: #58a6ff; margin-bottom: 1.5rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.25rem; transition: border-color 0.2s; }
  .card:hover { border-color: #58a6ff; }
  .card h3 { color: #58a6ff; margin-bottom: 0.5rem; font-size: 1rem; }
  .card p { color: #8b949e; font-size: 0.85rem; margin-bottom: 1rem; line-height: 1.5; }
  .tag { display: inline-block; background: #21262d; color: #79c0ff; border: 1px solid #1f6feb; border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.75rem; margin: 0.15rem; }
  .tag.high { color: #f85149; border-color: #f85149; background: #3d0e0e; }
  .tag.med  { color: #e3b341; border-color: #d29922; background: #2d1e00; }
  .btn { display: inline-block; margin-top: 0.5rem; padding: 0.4rem 1rem; background: #21262d; border: 1px solid #30363d; color: #58a6ff; border-radius: 6px; text-decoration: none; font-size: 0.85rem; cursor: pointer; }
  .btn:hover { background: #1f6feb; color: #fff; border-color: #1f6feb; }
  .progress-bar { background: #21262d; border-radius: 4px; height: 6px; margin-top: 0.5rem; }
  .progress-fill { background: #3fb950; height: 100%; border-radius: 4px; }
  .solved-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #3fb950; margin-right: 4px; }
  footer { text-align: center; color: #484f58; font-size: 0.75rem; padding: 2rem; border-top: 1px solid #21262d; margin-top: 3rem; }
</style>
</head>
<body>
<header>
  <h1>⚠ VulnLab</h1>
  <div style="display:flex;gap:1rem;align-items:center">
    ${user
      ? `<span class="badge">👤 ${user.username} &nbsp;|&nbsp; 🏆 ${score} pts</span>
         <a href="/auth/logout" class="btn">Logout</a>`
      : `<a href="/auth/login" class="btn">Login</a> <a href="/auth/register" class="btn">Register</a>`
    }
    <a href="/admin/" class="btn">Admin Panel</a>
  </div>
</header>

<div class="warning">
  ⚠ This application is intentionally vulnerable. For authorised security training only. Do not expose to public networks.
</div>

<main>
  <h2>Security Training Labs</h2>

  <div class="grid">

    <div class="card">
      <h3>${solved.filter(f=>f.startsWith('xss')).length > 0 ? '<span class="solved-dot"></span>' : ''}Cross-Site Scripting (XSS)</h3>
      <p>Inject malicious scripts into web pages. Learn reflected, stored, and DOM-based XSS with real exploits.</p>
      <span class="tag">OWASP A03</span>
      <span class="tag high">High</span>
      <span class="tag">3 challenges</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${Math.round(solved.filter(f=>f.startsWith('xss')).length/3*100)}%"></div></div>
      <br><a href="/xss" class="btn">Enter Lab →</a>
    </div>

    <div class="card">
      <h3>${solved.filter(f=>f.startsWith('sqli')).length > 0 ? '<span class="solved-dot"></span>' : ''}SQL Injection</h3>
      <p>Manipulate database queries to bypass authentication, extract data, and perform blind timing attacks.</p>
      <span class="tag">OWASP A03</span>
      <span class="tag high">Critical</span>
      <span class="tag">3 challenges</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${Math.round(solved.filter(f=>f.startsWith('sqli')).length/3*100)}%"></div></div>
      <br><a href="/sqli" class="btn">Enter Lab →</a>
    </div>

    <div class="card">
      <h3>${solved.filter(f=>f.startsWith('auth')).length > 0 ? '<span class="solved-dot"></span>' : ''}Authentication & Auth Flaws</h3>
      <p>Exploit weak password storage (MD5), JWT algorithm confusion, and Insecure Direct Object References.</p>
      <span class="tag">OWASP A01/A02/A07</span>
      <span class="tag high">High</span>
      <span class="tag">3 challenges</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${Math.round(solved.filter(f=>f.startsWith('auth')).length/3*100)}%"></div></div>
      <br><a href="/auth" class="btn">Enter Lab →</a>
    </div>

    <div class="card">
      <h3>${solved.filter(f=>f.startsWith('upload')).length > 0 ? '<span class="solved-dot"></span>' : ''}File Upload & Path Traversal</h3>
      <p>Bypass file type restrictions to upload a webshell. Use path traversal to read sensitive server files.</p>
      <span class="tag">OWASP A01/A05</span>
      <span class="tag high">Critical</span>
      <span class="tag">2 challenges</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${Math.round(solved.filter(f=>f.startsWith('upload')).length/2*100)}%"></div></div>
      <br><a href="/upload" class="btn">Enter Lab →</a>
    </div>

    <div class="card">
      <h3>${solved.includes('csrf_transfer') ? '<span class="solved-dot"></span>' : ''}CSRF & Broken Access Control</h3>
      <p>Forge cross-site requests against actions with no CSRF tokens. Understand why SameSite cookies matter.</p>
      <span class="tag">OWASP A01/A05</span>
      <span class="tag med">Medium</span>
      <span class="tag">1 challenge</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${solved.includes('csrf_transfer') ? 100 : 0}%"></div></div>
      <br><a href="/csrf" class="btn">Enter Lab →</a>
    </div>

    <div class="card">
      <h3>${solved.includes('ssrf_internal') ? '<span class="solved-dot"></span>' : ''}API Security & SSRF</h3>
      <p>Exploit IDOR in REST APIs and use Server-Side Request Forgery to probe internal services and metadata endpoints.</p>
      <span class="tag">OWASP A01/A10</span>
      <span class="tag high">High</span>
      <span class="tag">2 challenges</span>
      <div class="progress-bar"><div class="progress-fill" style="width:${Math.round((solved.includes('auth_idor') ? 1 : 0) + (solved.includes('ssrf_internal') ? 1 : 0))/2*100}%"></div></div>
      <br><a href="/api" class="btn">Enter Lab →</a>
    </div>

  </div>

  <div style="margin-top:2rem">
    <a href="/flags/leaderboard" class="btn">🏆 Leaderboard</a>
    <a href="/flags/my-flags" class="btn">My Progress</a>
    <a href="/traffic" class="btn">📡 My Traffic Log</a>
  </div>
</main>

<footer>VulnLab — Built for internal security training. Never expose to the internet.</footer>
</body>
</html>`);
});

module.exports = router;
