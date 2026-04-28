/**
 * VulnLab — File Upload & Path Traversal Lab
 * Challenges:
 *   1. Upload a .php / .js shell bypassing weak extension checks
 *   2. Read /etc/passwd via path traversal in the download endpoint
 */

const express  = require("express");
const router   = express.Router();
const multer   = require("multer");
const path     = require("path");
const fs       = require("fs");

const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join("/data", "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// INTENTIONAL: multer with weak extension filter only
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename:    (req, file, cb) => cb(null, Date.now() + "_" + file.originalname)
});

// INTENTIONAL WEAKNESS: only blocks .php, not .php5, .phtml, .js, etc.
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === ".php") {
      return cb(new Error("PHP files not allowed"));
    }
    cb(null, true); // everything else allowed
  }
});

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
  input[type=text],input[type=file] { width:100%;padding:0.5rem;background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;margin-top:0.3rem; }
  button { padding:0.5rem 1.5rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;cursor:pointer;margin-top:0.5rem; }
  .card { background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin:1rem 0; }
  code { background:#21262d;padding:0.1rem 0.4rem;border-radius:3px;color:#79c0ff; }
  pre { background:#21262d;padding:1rem;border-radius:6px;overflow-x:auto;font-size:0.8rem;color:#c9d1d9;margin-top:0.5rem; }
</style>
</head>
<body>
<header><a href="/">⚠ VulnLab</a> &nbsp;›&nbsp; <a href="/upload">Upload Lab</a></header>
<main>${body}</main>
</html>`;

// ── Lab index ─────────────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  // List uploaded files
  const files = fs.existsSync(UPLOAD_DIR) ? fs.readdirSync(UPLOAD_DIR) : [];
  const fileList = files.map(f => `
    <li style="margin:0.25rem 0">
      <a href="/upload/download?file=${encodeURIComponent(f)}" style="color:#58a6ff">${f}</a>
    </li>
  `).join("");

  res.send(layout("Upload Lab", `
    <h2>File Upload & Path Traversal Lab</h2>

    <div class="card">
      <h3 style="color:#58a6ff">Lab 1 — Unrestricted File Upload</h3>
      <div class="hint">
        💡 <strong>Hint:</strong> Only <code>.php</code> is blocked. Try uploading a file named <code>shell.php5</code>
        or <code>shell.pHp</code> or <code>shell.html</code> containing a payload.<br>
        Node.js shell: <code>&lt;!-- exec: require('child_process').exec('id') --&gt;</code><br>
        Or just a file named <code>webshell.js</code> to demonstrate bypass.
      </div>
      <form method="POST" action="/upload/file" enctype="multipart/form-data">
        <label>Choose file to upload:</label>
        <input type="file" name="file">
        <button type="submit">Upload</button>
      </form>
    </div>

    <div class="card">
      <h3 style="color:#58a6ff">Lab 2 — Path Traversal</h3>
      <div class="hint">
        💡 <strong>Hint:</strong> The download endpoint serves files from the uploads directory using the filename parameter.
        Try: <code>/upload/download?file=../../etc/passwd</code>
        or: <code>/upload/download?file=..%2F..%2Fetc%2Fpasswd</code>
      </div>
      <form method="GET" action="/upload/download">
        <label>Filename to read:</label>
        <input type="text" name="file" placeholder="../../etc/passwd">
        <button type="submit">Download / Read</button>
      </form>
    </div>

    ${files.length > 0 ? `
    <div class="card">
      <strong>Uploaded files:</strong>
      <ul style="margin-top:0.5rem;padding-left:1.5rem">${fileList}</ul>
    </div>` : ""}
  `));
});

// ── Upload handler ────────────────────────────────────────────────────────────
router.post("/file", (req, res) => {
  upload.single("file")(req, res, (err) => {
    if (err) {
      return res.send(layout("Upload Error", `
        <div class="error">Upload blocked: ${err.message}</div>
        <a href="/upload" style="color:#58a6ff">← Back</a>
      `));
    }

    if (!req.file) {
      return res.send(layout("Upload Error", `
        <div class="error">No file selected.</div>
        <a href="/upload" style="color:#58a6ff">← Back</a>
      `));
    }

    const ext = path.extname(req.file.originalname).toLowerCase();
    const isDangerous = [".js", ".sh", ".py", ".html", ".phtml", ".php5"].includes(ext);

    res.send(layout("Upload Success", `
      <h2>File Upload Lab</h2>
      <div class="success">
        ✅ File uploaded: <strong>${req.file.filename}</strong><br>
        Size: ${req.file.size} bytes<br>
        ${isDangerous ? `<br>⚠ Dangerous extension <code>${ext}</code> was NOT blocked! 🚩 VULNLAB{F1L3_UPL04D_RCE}` : ""}
      </div>
      <p><a href="/upload/download?file=${encodeURIComponent(req.file.filename)}" style="color:#58a6ff">Download uploaded file</a></p>
      <p><a href="/upload" style="color:#58a6ff">← Back</a></p>
    `));
  });
});

// ── Download / path traversal handler ────────────────────────────────────────
router.get("/download", (req, res) => {
  const filename = req.query.file || "";

  if (!filename) {
    return res.send(layout("Download", `<div class="error">No file specified.</div><a href="/upload" style="color:#58a6ff">← Back</a>`));
  }

  // INTENTIONAL VULNERABILITY: path.join without sanitization allows traversal
  const filePath = path.join(UPLOAD_DIR, filename);

  // Read and return the file content
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      // Try binary read fallback
      fs.readFile(filePath, (err2, buf) => {
        if (err2) {
          return res.send(layout("Download Error", `
            <div class="error">Cannot read file: ${err.message}</div>
            <a href="/upload" style="color:#58a6ff">← Back</a>
          `));
        }
        res.set("Content-Disposition", `attachment; filename="${path.basename(filePath)}"`);
        return res.send(buf);
      });
      return;
    }

    const isTraversal = filename.includes("../") || filename.includes("..%2F") || filename.includes("%2e%2e");
    const isEtcPasswd = filePath.includes("etc/passwd") || filePath.includes("etc\\passwd");

    res.send(layout("File Content", `
      <h2>${path.basename(filePath)}</h2>
      ${isEtcPasswd ? `<div class="success">🚩 Path traversal successful! Flag: <strong>VULNLAB{PATH_TR4V3RS4L_R34D}</strong></div>` : ""}
      ${isTraversal && !isEtcPasswd ? `<div class="hint">⚠ Path traversal detected — you escaped the uploads directory!</div>` : ""}
      <pre>${data.replace(/</g, "&lt;")}</pre>
      <a href="/upload" style="color:#58a6ff">← Back</a>
    `));
  });
});

module.exports = router;
