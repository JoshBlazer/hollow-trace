# Hollow Trace — Project Instructions

## What This Is
A Tauri 2.0 desktop forensics tool for cybersecurity analysts. Detects anomalies in server logs
in real-time. Rust backend handles all parsing and detection. React frontend is the display layer.

## Tech Stack
- Desktop: Tauri 2.0
- Backend: Rust (stable 1.86)
- Frontend: React 18 + TypeScript
- Styling: Tailwind CSS v3 (NOT v4)
- Font: JetBrains Mono everywhere, no exceptions
- Virtualization: react-window VariableSizeList (not FixedSizeList)
- SVG only for sonar — no D3, no Canvas

## Color Palette (never change)
- Background: #000000
- Primary/text: #00ff41 (neon green)
- Alert/anomaly: #ff0055 (alert red)
- Warning: #ff6600
- Low severity: #ffff00
- Border glow: box-shadow 0 0 4px #00ff41, 0 0 8px #00ff41

## Phase Progress
- [x] Phase 1  — Scaffold (Tauri init, deps, Tailwind, blank window)
- [x] Phase 2  — Rust + TypeScript types
- [x] Phase 3  — Rust parsers (Apache, auth.log, JSON)
- [x] Phase 4  — Ring buffer + anomaly detection
- [x] Phase 5  — File watcher, threat scorer, app state
- [x] Phase 6  — Tauri commands + main.rs
- [x] Phase 7  — React layout + CSS aesthetic
- [x] Phase 8  — Log Stream Panel
- [x] Phase 9  — Sonar Panel
- [x] Phase 10 — Stats Bar
- [x] Phase 11 — Command Palette
- [x] Phase 12 — Integration + error boundaries

## Project Structure
```
hollow-trace/
├── CLAUDE.md
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── postcss.config.cjs
├── index.html
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── index.css
│   ├── types/hollow.ts            <- ALL shared types, mirror of Rust structs
│   ├── hooks/
│   │   ├── useTauriEvents.ts
│   │   ├── useLogBuffer.ts        <- frontend ring buffer, cap 10k entries
│   │   ├── useCommandPalette.ts
│   │   └── useAutoScroll.ts
│   ├── components/
│   │   ├── layout/AppShell.tsx    <- CSS Grid layout
│   │   ├── log-stream/            <- LogStreamPanel, LogRow, LogRowExpanded
│   │   ├── sonar/                 <- SonarPanel, RadarRing, AnomalyBlip, ThreatScore
│   │   ├── stats/                 <- StatsBar, LiveCounter, TopIpList, SeverityBreakdown
│   │   └── command-palette/      <- CommandPalette, CommandItem
│   └── lib/
│       ├── tauri-commands.ts      <- typed invoke() wrappers ONLY
│       └── format.ts
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json
    ├── capabilities/default.json
    └── src/
        ├── main.rs
        ├── lib.rs
        ├── commands.rs
        ├── state.rs
        ├── events.rs              <- batch: 50 entries (live) / 1000 (file load) / 100ms
        ├── ring_buffer.rs         <- VecDeque, 100k cap
        ├── scorer.rs              <- threat score 0-100
        ├── parser/                <- mod, types, apache, auth, json_log
        ├── detector/              <- mod, types, patterns, rate, baseline
        └── watcher/               <- mod, file_watcher (OS thread)
```

## Rust Rules
- All types crossing Tauri boundary: #[derive(serde::Serialize, serde::Deserialize)]
- All structs: #[serde(rename_all = "camelCase")]
- Commands return Result<T, String>
- Never add tokio to Cargo.toml — use tauri::async_runtime::spawn if needed
- Watcher runs on a dedicated OS thread, not async
- parking_lot::RwLock everywhere (fair, no panic poisoning)
- Parsers are pure functions — no I/O, no side effects

## Pinned Crates
```toml
tauri                 = "2.11"
tauri-plugin-dialog   = "2.7"
tauri-plugin-fs       = "2.5"
serde                 = { version = "1.0", features = ["derive"] }
serde_json            = "1.0"
chrono                = { version = "0.4", features = ["serde"] }
regex                 = "1.12"
once_cell             = "1.21"
anyhow                = "1.0"
thiserror             = "2.0"
log                   = "0.4"
parking_lot           = "0.12"
notify-debouncer-mini = "0.7"
```

## React / TypeScript Rules
- src/types/hollow.ts is the single source of truth for types — never define inline
- All Tauri invocations go through src/lib/tauri-commands.ts
- useTauriEvents must call unlisten() in useEffect cleanup
- LogRow must be React.memo
- After toggling row expand: call listRef.current?.resetAfterIndex(index)
- useLogBuffer caps at 10,000 entries — backend is source of truth for export
- Never import D3. Never use Canvas for sonar.

## CSS Rules
- Scanline: body::after, repeating-linear-gradient, pointer-events none, z-index 9999
- Neon border: border 1px solid #00ff41; box-shadow 0 0 4px #00ff41, 0 0 8px #00ff41
- Alert border: same but #ff0055
- animate-ping for sonar pulse (reset after 1500ms)
- animate-blink for pause toggle and command palette cursor
- animate-flicker for threat score >= 75

## What NOT To Do
- Don't use Tailwind v4 syntax
- Don't use notify 9.0 RC — use notify-debouncer-mini 0.7
- Don't add tokio directly to Cargo.toml
- Don't use FixedSizeList — VariableSizeList only
- Don't call invoke() with raw string names
- Don't define types outside hollow.ts
- Don't use D3 or Canvas

## Key Decisions (don't revisit without flagging)
- notify-debouncer-mini not notify RC: stable API, no RC risk
- OS thread for watcher: notify is callback-based, async adds no benefit
- parking_lot not std::sync: fair locking, no poisoning on panic
- Batch events 50/100ms: prevents React re-rendering 10k times/sec. File loads use 1000/100ms: 50-entry batches meant ~200 IPC events + React renders per 10k lines (~60s load)
- VariableSizeList: required for expandable row heights
- serde camelCase: eliminates all manual field name mapping
