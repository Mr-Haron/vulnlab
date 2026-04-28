/**
 * VulnLab — Intentionally Vulnerable Training Application
 * --------------------------------------------------------
 * WARNING: This application is deliberately insecure.
 * DO NOT deploy on a public network.
 * For security training use only, in an isolated environment.
 */

const express      = require("express");
const bodyParser   = require("body-parser");
const cookieParser = require("cookie-parser");
const session      = require("express-session");
const path         = require("path");
const fs           = require("fs");

const { initDB }   = require("./db/seed");
const logger       = require("./middleware/logger");

// Routes
const homeRoute    = require("./routes/home");
const xssRoute     = require("./routes/xss");
const sqliRoute    = require("./routes/sqli");
const authRoute    = require("./routes/auth");
const apiRoute     = require("./routes/api");
const uploadRoute  = require("./routes/upload");
const csrfRoute    = require("./routes/csrf");
const flagRoute    = require("./routes/flags");
const trafficRoute = require("./routes/traffic");

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// INTENTIONALLY WEAK session config (teaching point)
app.use(session({
  secret: process.env.SESSION_SECRET || "very-weak-secret",
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,  // INTENTIONAL: allows JS access (XSS demo)
    secure: false,    // INTENTIONAL: no HTTPS required
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, "public")));

// Traffic logger (stores all requests to /data/traffic.log)
app.use(logger);

// ── Routes ──────────────────────────────────────────────────────────────────
app.use("/",        homeRoute);
app.use("/xss",     xssRoute);
app.use("/sqli",    sqliRoute);
app.use("/auth",    authRoute);
app.use("/api",     apiRoute);
app.use("/upload",  uploadRoute);
app.use("/csrf",    csrfRoute);
app.use("/flags",   flagRoute);
app.use("/traffic", trafficRoute);

// ── 404 handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).send(`
    <html><body style="font-family:monospace;background:#111;color:#0f0;padding:2rem">
    <h2>404 — Not Found</h2>
    <p>Path: ${req.path}</p>
    <a href="/" style="color:#0f0">← Back to VulnLab</a>
    </body></html>
  `);
});

// ── Boot ─────────────────────────────────────────────────────────────────────
initDB();
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════╗`);
  console.log(`║  VulnLab running on port ${PORT}        ║`);
  console.log(`║  ⚠  INTENTIONALLY VULNERABLE         ║`);
  console.log(`║  DO NOT expose to public internet     ║`);
  console.log(`╚══════════════════════════════════════╝\n`);
});

module.exports = app;
