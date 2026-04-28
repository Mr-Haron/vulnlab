/**
 * VulnLab — Flags & Scoring System
 * Routes:
 *   GET  /flags/submit       — form to submit a captured flag
 *   POST /flags/submit       — validate and record flag
 *   GET  /flags/leaderboard  — top scorers across all users
 *   GET  /flags/my-flags     — personal progress
 */

const express  = require("express");
const router   = express.Router();
const { getDB } = require("../db/seed");

const layout = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title} — VulnLab</title>
<style>
  * { box-sizing:border-box; }
  body { background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0; }
  header { background:#161b22;border-bottom:1px solid #30363d;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center; }
  header a { color:#58a6ff;text-decoration:none; }
  main { max-width:900px;margin:2rem auto;padding:0 1rem; }
  h2 { color:#58a6ff; }
  .hint  { background:#1c2128;border-left:3px solid #d29922;padding:.75rem 1rem;margin:1rem 0;border-radius:0 6px 6px 0;font-size:.85rem;color:#e3b341; }
  .error { background:#3d0e0e;border-left:3px solid #f85149;padding:.75rem 1rem;margin:1rem 0;color:#f85149;border-radius:0 6px 6px 0; }
  .success { background:#0d2d0d;border-left:3px solid #3fb950;padding:.75rem 1rem;margin:1rem 0;color:#3fb950;border-radius:0 6px 6px 0; }
  input { width:100%;padding:.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:.3rem;font-family:monospace;font-size:1rem; }
  button { padding:.5rem 1.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-top:.5rem; }
  .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin:1rem 0; }
  table { width:100%;border-collapse:collapse;margin-top:1rem; }
  th,td { border:1px solid #30363d;padding:.6rem .8rem;text-align:left;font-size:.85rem; }
  th { background:#21262d;color:#79c0ff; }
  tr:hover td { background:#1c2128; }
  .badge-gold   { color:#e3b341; }
  .badge-silver { color:#8b949e; }
  .badge-bronze { color:#d29922; }
  .solved   { color:#3fb950; }
  .unsolved { color:#484f58; }
  .pts { color:#79c0ff;font-weight:bold; }
</style>
</head>
<body>
<header>
  <div><a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; ${title}</div>
  <div style="display:flex;gap:.8rem">
    <a href="/flags/submit">Submit Flag</a>
    <a href="/flags/leaderboard">Leaderboard</a>
    <a href="/flags/my-flags">My Progress</a>
  </div>
</header>
<main>${body}</main>
</html>`;

// ── Submit flag ───────────────────────────────────────────────────────────────
router.get("/submit", (req, res) => {
  const msg = req.query.msg || "";
  const err = req.query.err || "";
  res.send(layout("Submit Flag", `
    <h2>Submit a Captured Flag</h2>
    <p style="color:#8b949e">Found a flag in the format <code style="color:#79c0ff">VULNLAB{...}</code>? Submit it here to earn points.</p>
    ${msg ? `<div class="success">✅ ${msg}</div>` : ""}
    ${err ? `<div class="error">❌ ${err}</div>` : ""}
    <form method="POST" action="/flags/submit">
      <label>Your username:</label>
      <input type="text" name="username" placeholder="alice" value="${req.session.user ? req.session.user.username : ""}">
      <label style="margin-top:.75rem;display:block">Flag value:</label>
      <input type="text" name="flag" placeholder="VULNLAB{...}" autocomplete="off" spellcheck="false">
      <button type="submit">Submit Flag</button>
    </form>
    <div style="margin-top:2rem;color:#484f58;font-size:.8rem">
      Flags are scattered across all labs — in page source, API responses, SQL query results, and server files.
    </div>
  `));
});

router.post("/submit", (req, res) => {
  const { username, flag } = req.body;
  if (!username || !flag) {
    return res.redirect("/flags/submit?err=Username+and+flag+are+required");
  }

  const db = getDB();

  // Find matching flag
  const flagRow = db.prepare("SELECT * FROM flags WHERE flag_value=?").get(flag.trim());
  if (!flagRow) {
    return res.redirect(`/flags/submit?err=Flag+not+recognised.+Keep+hunting!`);
  }

  // Check if already solved
  const existing = db.prepare(
    "SELECT * FROM solved_flags WHERE username=? AND flag_name=?"
  ).get(username, flagRow.flag_name);

  if (existing) {
    return res.redirect(`/flags/submit?err=Already+solved:+${flagRow.flag_name}`);
  }

  // Record it
  db.prepare("INSERT INTO solved_flags (username, flag_name) VALUES (?, ?)").run(username, flagRow.flag_name);

  return res.redirect(
    `/flags/submit?msg=${encodeURIComponent(`+${flagRow.points} pts — ${flagRow.flag_name} (${flagRow.description})`)}`
  );
});

// ── Leaderboard ───────────────────────────────────────────────────────────────
router.get("/leaderboard", (req, res) => {
  const db = getDB();

  const scores = db.prepare(`
    SELECT sf.username,
           COUNT(sf.flag_name)        AS flags_solved,
           COALESCE(SUM(f.points), 0) AS total_points,
           MAX(sf.solved_at)          AS last_solve
    FROM solved_flags sf
    JOIN flags f ON f.flag_name = sf.flag_name
    GROUP BY sf.username
    ORDER BY total_points DESC, flags_solved DESC
    LIMIT 20
  `).all();

  const totalFlags = db.prepare("SELECT COUNT(*) as c FROM flags").get().c;

  const medals = ["🥇", "🥈", "🥉"];
  const rows = scores.map((s, i) => `
    <tr>
      <td>${medals[i] || (i + 1)}</td>
      <td><strong>${s.username}</strong></td>
      <td class="pts">${s.total_points}</td>
      <td>${s.flags_solved} / ${totalFlags}</td>
      <td style="color:#484f58;font-size:.8rem">${new Date(s.last_solve).toLocaleString()}</td>
    </tr>
  `).join("");

  res.send(layout("Leaderboard", `
    <h2>🏆 Leaderboard</h2>
    <p style="color:#8b949e">${totalFlags} total flags · ${scores.length} participants</p>
    ${scores.length === 0
      ? `<div class="hint">No flags submitted yet. <a href="/" style="color:#58a6ff">Start hacking!</a></div>`
      : `<table>
          <tr><th>#</th><th>Player</th><th>Points</th><th>Flags</th><th>Last Solve</th></tr>
          ${rows}
        </table>`
    }
  `));
});

// ── Personal progress ─────────────────────────────────────────────────────────
router.get("/my-flags", (req, res) => {
  const username = req.query.user || (req.session.user ? req.session.user.username : "");
  const db = getDB();

  const allFlags = db.prepare("SELECT * FROM flags ORDER BY points ASC").all();
  const solved   = username
    ? db.prepare("SELECT flag_name, solved_at FROM solved_flags WHERE username=?").all(username)
    : [];

  const solvedSet = new Set(solved.map(s => s.flag_name));
  const solvedMap = Object.fromEntries(solved.map(s => [s.flag_name, s.solved_at]));

  const totalPts = allFlags.reduce((sum, f) => solvedSet.has(f.flag_name) ? sum + f.points : sum, 0);
  const maxPts   = allFlags.reduce((sum, f) => sum + f.points, 0);
  const pct      = maxPts > 0 ? Math.round((totalPts / maxPts) * 100) : 0;

  const rows = allFlags.map(f => `
    <tr>
      <td class="${solvedSet.has(f.flag_name) ? "solved" : "unsolved"}">
        ${solvedSet.has(f.flag_name) ? "✅" : "☐"} ${f.flag_name}
      </td>
      <td style="color:#8b949e;font-size:.8rem">${f.description}</td>
      <td class="pts">${f.points}</td>
      <td style="color:#484f58;font-size:.75rem">
        ${solvedSet.has(f.flag_name) ? new Date(solvedMap[f.flag_name]).toLocaleString() : "—"}
      </td>
    </tr>
  `).join("");

  res.send(layout("My Progress", `
    <h2>My Progress</h2>
    <form method="GET" style="margin-bottom:1.5rem;display:flex;gap:.5rem">
      <input type="text" name="user" value="${username}" placeholder="Enter username" style="max-width:280px">
      <button type="submit">View</button>
    </form>
    ${username ? `
      <div class="card" style="display:flex;gap:2rem;align-items:center">
        <div>
          <div style="font-size:2rem;font-weight:bold;color:#58a6ff">${totalPts}</div>
          <div style="color:#8b949e;font-size:.85rem">points earned</div>
        </div>
        <div>
          <div style="font-size:2rem;font-weight:bold;color:#3fb950">${solvedSet.size}</div>
          <div style="color:#8b949e;font-size:.85rem">of ${allFlags.length} flags</div>
        </div>
        <div style="flex:1">
          <div style="background:#21262d;border-radius:4px;height:10px;overflow:hidden">
            <div style="background:#3fb950;height:100%;width:${pct}%;transition:width .5s"></div>
          </div>
          <div style="color:#8b949e;font-size:.75rem;margin-top:.3rem">${pct}% complete</div>
        </div>
      </div>
      <table>
        <tr><th>Flag</th><th>Description</th><th>Pts</th><th>Solved At</th></tr>
        ${rows}
      </table>
    ` : `<div class="hint">Enter a username above to view progress.</div>`}
  `));
});

// ── Traffic log viewer ────────────────────────────────────────────────────────
module.exports = router;
