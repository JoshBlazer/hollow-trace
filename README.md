# Hollow Trace

A desktop forensics tool that scans server logs for attacks in real time. Open a log file or tail a live one, and Hollow Trace parses each line, flags anomalies, and shows them on a log stream, an anomaly radar, and a running threat score.

Built with Tauri 2: a Rust backend does all parsing and detection, and a React + TypeScript frontend displays the results.

## Features

- **Log formats.** The format is detected automatically from the first 20 lines.
  - Apache/Nginx combined access logs.
  - `auth.log`/syslog (RFC 3164).
  - JSON lines. Fields are read from common names such as `timestamp`/`time`/`@timestamp`, `message`/`msg`, `level`/`severity` and `ip`/`remote_addr`/`client_ip`.
- **Open or tail.** Parse a whole file, or watch a file and process new lines as they're written.
- **Detection:**

  | Detector | Flags | Severity |
  |---|---|---|
  | Pattern | SQL injection, shell injection, SSRF/XXE | Critical |
  | Pattern | Path traversal, XSS, known scanners (Nikto, sqlmap, nmap, …) | High |
  | Pattern | Auth failures (`Failed password`, `Invalid user`, …) | Medium |
  | Rate | ≥ 50 4xx responses from one IP within 10 s (brute force or scanning). One alert per burst. | High |
  | Baseline | Response size more than 3σ from the running mean (after 1,000 samples) | Medium |

  Requests are URL-decoded before matching, so encoded payloads like `UNION+SELECT` or `%2e%2e%2f` are caught.

- **Threat score (0–100).** The score has two halves, each capped at 50:
  - the anomaly rate (the percentage of lines flagged);
  - a severity weighting: Critical × 20, High × 10, Medium × 5, Low × 1.
- **Export.** Save detected anomalies to a JSON file.

## Getting started

### Prerequisites

- [Node.js](https://nodejs.org/) 20.19+ (required by Vite 7)
- [Rust](https://rustup.rs/) (stable)
- The [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your OS. On Windows, WebView2 is already included in Windows 11.

### Run in development

```sh
npm install
npm run tauri dev
```

The first build compiles the Rust dependencies and takes several minutes. Later builds are incremental.

### Build a release

```sh
npm run tauri build
```

Installers are written to `src-tauri/target/release/bundle/`. The app icon's source is `app-icon.svg`; after editing it, regenerate every size with `npx tauri icon app-icon.svg`. Release builds are much faster at runtime than `tauri dev`: parsing and detecting 10,000 lines takes about 80 ms.

## Usage

Press **Ctrl+K** (⌘K on macOS) to open the command palette, then choose one of these commands. **Ctrl+O** (⌘O) opens a file directly.

| Command | What it does |
|---|---|
| Open File | Parse an existing log file from start to finish |
| Watch File | Tail a live log file for new entries |
| Export Anomalies | Save detected anomalies to a JSON file |
| Stop Watching | Detach the file watcher |
| Clear Stream | Flush the log buffer and reset stats |

In the log stream, click a row to see the raw line and parsed fields. Rows with a `!` triggered an anomaly. **PAUSE** stops auto-scrolling.

On the radar, a blip's distance from the center shows its severity: Critical on the outer ring, Low near the center. The **Recent** list shows the latest anomalies with their source IP and request.

## Test data

Two scripts generate an Apache access log with injected attacks: SQL injection, path traversal, shell injection, XSS, SSRF, scanner probes and brute-force bursts.

```sh
python generate_logs.py [output] [lines]       # default: test-apache.log, 10000
```

```powershell
.\generate_logs.ps1 -Output test-apache.log -Lines 10000
```

`*.log` files are gitignored.

## Tests

```sh
cd src-tauri
cargo test --lib
```

## Project layout

```
src/                  React frontend
  hooks/              Tauri event subscriptions, log buffer, auto-scroll
  components/         log-stream, sonar (radar), stats, command-palette
  types/hollow.ts     Shared types (mirror of the Rust structs)
  lib/                Typed invoke() wrappers, formatting
src-tauri/src/
  parser/             Apache, auth.log, JSON parsers (pure functions)
  detector/           Pattern, rate and baseline detectors
  watcher/            File load and live tail (dedicated OS thread)
  events.rs           Batched events to the frontend
  scorer.rs           Threat score
```

See [`CLAUDE.md`](CLAUDE.md) for the project's conventions and key design decisions.

## Known issues

- `npm audit` reports 5 high-severity findings in `braces`, which Tailwind CSS v3's file watcher depends on. No patched `braces` release exists, and npm's only fix is upgrading to Tailwind v4, which this project doesn't use. The exposure is build-time only: nothing from this dependency ships in the app.
