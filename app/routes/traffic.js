/**
 * VulnLab — Traffic Log Viewer
 * Lets trainees review every HTTP request they sent during labs.
 * Accessible at /traffic
 */

const express = require("express");
const router  = express.Router();
const fs      = require("fs");
const path    = require("path");
const readline = require("readline");

const LOG_PATH = process.env.LOG_PATH || path.join("/data", "traffic.log");

const layout = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title} — VulnLab</title>
<style>
  * { box-sizing:border-box; }
  body { background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0; }
  header { background:#161b22;border-bottom:1px solid #30363d;padding:1rem 2rem; }
  header a { color:#58a6ff;text-decoration:none; }
  main { max-width:1200px;margin:2rem auto;padding:0 1rem; }
  h2 { color:#58a6ff; }
  table { width:100%;border-collapse:collapse;font-size:.78rem; }
  th,td { border:1px solid #21262d;padding:.4rem .6rem;vertical-align:top;word-break:break-all; }
  th { background:#161b22;color:#79c0ff;position:sticky;top:0; }
  tr:nth-child(even) td { background:#0e1117; }
  tr:hover td { background:#1c2128; }
  .method-GET  { color:#3fb950; }
  .method-POST { color:#e3b341; }
  .method-PUT  { color:#79c0ff; }
  .method-DELETE { color:#f85149; }
  input { padding:.4rem .8rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;font-family:monospace;width:280px; }
  button { padding:.4rem 1rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer; }
  .btn-danger { background:#6e1a1a;border:1px solid #f85149;color:#f85149; }
</style>
</head>
<body>
<header><a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; Traffic Log</header>
<main>${body}</main>
</html>`;

router.get("/", (req, res) => {
  const filter = req.query.filter || "";
  const limit  = parseInt(req.query.limit) || 200;

  if (!fs.existsSync(LOG_PATH)) {
    return res.send(layout("Traffic Log", `<p style="color:#484f58">No traffic logged yet. Start attacking some labs!</p>`));
  }

  // Read last N lines efficiently
  const lines = fs.readFileSync(LOG_PATH, "utf8")
    .split("\n")
    .filter(Boolean)
    .slice(-500)   // max 500 lines loaded
    .reverse();    // newest first

  const entries = lines
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean)
    .filter(e => !filter || JSON.stringify(e).toLowerCase().includes(filter.toLowerCase()))
    .slice(0, limit);

  const rows = entries.map(e => `
    <tr>
      <td style="white-space:nowrap;color:#484f58">${e.ts ? e.ts.replace("T"," ").slice(0,19) : ""}</td>
      <td class="method-${e.method}">${e.method}</td>
      <td>${e.path}</td>
      <td style="color:#484f58">${JSON.stringify(e.query) !== "{}" ? JSON.stringify(e.query) : ""}</td>
      <td style="color:#e3b341">${e.body && JSON.stringify(e.body) !== "{}" ? JSON.stringify(e.body).slice(0,120) : ""}</td>
      <td style="color:#484f58;font-size:.72rem">${e.ip}</td>
    </tr>
  `).join("");

  res.send(layout("Traffic Log", `
    <h2>📡 Request Traffic Log</h2>
    <p style="color:#8b949e;margin-bottom:1rem">Shows the last ${entries.length} requests. Use this to review your attack payloads.</p>
    <form method="GET" style="display:flex;gap:.5rem;margin-bottom:1rem;align-items:center">
      <input type="text" name="filter" value="${filter}" placeholder="Filter by path, body, IP...">
      <select name="limit" style="padding:.4rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px">
        <option value="50"  ${limit===50?"selected":""}>50 rows</option>
        <option value="200" ${limit===200?"selected":""}>200 rows</option>
        <option value="500" ${limit===500?"selected":""}>500 rows</option>
      </select>
      <button type="submit">Filter</button>
      <a href="/traffic/clear" style="padding:.4rem 1rem;background:#1a0a0a;border:1px solid #f85149;color:#f85149;border-radius:4px;text-decoration:none;font-size:.85rem">Clear Log</a>
    </form>
    ${entries.length === 0
      ? `<p style="color:#484f58">No entries match your filter.</p>`
      : `<table>
          <tr><th>Time</th><th>Method</th><th>Path</th><th>Query</th><th>Body</th><th>IP</th></tr>
          ${rows}
        </table>`
    }
  `));
});

router.get("/clear", (req, res) => {
  fs.writeFileSync(LOG_PATH, "");
  res.redirect("/traffic");
});

module.exports = router;
