/**
 * VulnLab Traffic Logger
 * Logs every request (method, path, headers, body, session) to disk.
 * Trainees can review their own attack traffic here.
 */

const fs   = require("fs");
const path = require("path");

const LOG_PATH = process.env.LOG_PATH || path.join("/data", "traffic.log");

function logger(req, res, next) {
  const entry = {
    ts:      new Date().toISOString(),
    ip:      req.ip,
    method:  req.method,
    path:    req.path,
    query:   req.query,
    body:    req.body,
    cookies: req.cookies,
    session: req.session ? { user: req.session.user } : null,
    ua:      req.get("User-Agent")
  };

  const line = JSON.stringify(entry) + "\n";
  fs.appendFile(LOG_PATH, line, () => {}); // non-blocking

  next();
}

module.exports = logger;
