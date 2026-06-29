# Windows Defender but Good

A lightweight, non-invasive download scanner for Windows — single `.exe`, no
install, no kernel driver, no admin rights. It sits in the system tray, watches
your Downloads folder, and scans every new file **before you run it**.

> Targets the most common infection vector: downloading a "game" / "crack" /
> "installer" that is actually a trojan. The file is hashed and scanned the
> instant it lands — if it is bad, you get a notification and it is quarantined
> before you can double-click it.

---

## Detection pipeline

Layers run cheap → expensive. **VirusTotal is primary**; local engines run only
when VT can't decide (no key, error, or file VT has never seen).

| # | Engine | What it does |
|---|--------|-------------|
| 1 | **Offline blocklist** | Instant hash lookup — fed by the MalwareBazaar feed |
| 2 | **Verdict cache** | Skip re-checking a hash we've already decided on |
| 3 | **VirusTotal** | Hash-only lookup via API v3 — the file never leaves your machine |
| 4 | **YARA** | Embedded starter rules + your own; a match → quarantined |
| 5 | **Heuristics** | Static PE signals (packed sections, suspicious imports, double extension, high entropy, unsigned). Lower confidence → **suspicious** (warned, not quarantined) |

Works fully offline with no keys — YARA + heuristics run locally. VT and
MalwareBazaar keys add cloud intelligence.

---

## Dashboard

Right-click the tray icon → **Open dashboard**.

- **Settings** — configure API keys, watched folders, thresholds. Hit **Save**
  and the app restarts automatically with the new config.
- **Quarantine** — browse quarantined files, restore any of them to their
  original location.
- **Scan History** — last 200 scans with verdict, engine, and detail.
  Color-coded: red for malicious, orange for suspicious.
- **Status** — snapshot of which engines are active, blocklist size, cache
  count, and watched folders.

---

## Quick start

1. Download or build `wdbg.exe` (see [Build from source](#build-from-source)).
2. Put it somewhere permanent — **not** your Downloads folder.
3. Double-click it. SmartScreen may warn (it's unsigned) — click
   **More info → Run anyway**. A green shield appears in the system tray.
4. Right-click the tray icon → **Open dashboard → Settings**.
   - Paste your [VirusTotal API key](https://www.virustotal.com) (free, profile → API key).
   - Optionally paste a [MalwareBazaar Auth-Key](https://auth.abuse.ch/) for the hash feed.
   - Hit **Save** — the app restarts and picks up the new keys.
5. Right-click → **Start on login** if you want it to run automatically.

### Verify it works

Download the EICAR test file to your Downloads folder:

```
https://www.eicar.org/download/eicar.com
```

It's a harmless industry-standard fake virus (just a text string). You should
get a "threat blocked" notification and see it appear in the Quarantine tab.

---

## Build from source

### Standard build (no CGO required)

```powershell
go build -ldflags "-H windowsgui -s -w" -o wdbg.exe ./cmd/wdbg
```

YARA degrades gracefully to a no-op stub when built without CGO. All other
detection layers (blocklist, cache, VT, heuristics) work at full capability.

### With YARA (CGO + libyara)

Requires [MSYS2](https://www.msys2.org/) on Windows.

```bash
# In the MSYS2 MINGW64 shell:
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-yara mingw-w64-x86_64-pkgconf

# Then from the project root:
CGO_ENABLED=1 go build -ldflags "-H windowsgui -s -w" -tags yara -o wdbg.exe ./cmd/wdbg
```

### Run tests

```powershell
go test ./...
```

---

## Settings reference

Stored at `%APPDATA%\Windows Defender but Good\config.json`.
Editable via the dashboard Settings tab.

| Key | Default | Description |
|-----|---------|-------------|
| `api_key` | — | VirusTotal API key |
| `malwarebazaar_api_key` | — | MalwareBazaar Auth-Key for the hash feed |
| `watched_folders` | Downloads | Folders to monitor for new files |
| `detection_threshold` | `3` | VT engines that must flag a file to call it malicious |
| `heuristic_threshold` | `5` | Score at/above which a file is flagged suspicious |
| `risky_only` | `false` | Only scan executables, scripts, archives, and MOTW files |
| `enable_hash_feed` | `true` | Pull fresh malware hashes from MalwareBazaar |
| `hash_feed_refresh_hours` | `12` | Feed refresh interval |
| `hash_feed_max` | `50000` | Max hashes kept locally (newest retained) |
| `quarantine_dir` | `%APPDATA%\…\quarantine` | Where quarantined files are moved |

---

## YARA rules

Embedded starter rules live in `internal/scan/rules/`. For broader coverage,
drop community rulesets into `%APPDATA%\Windows Defender but Good\rules\` — they
load automatically alongside the built-in ones.

Good sources: [YARA-Forge](https://yarahq.github.io/),
[signature-base](https://github.com/Neo23x0/signature-base).

---

## Project layout

```
cmd/wdbg/           entry point — wires everything, runs the tray loop
internal/config/    config.json schema + %APPDATA% paths
internal/scan/      scanner pipeline, hashing, YARA, heuristics, blocklist, cache
internal/vt/        VirusTotal API v3 client
internal/feed/      MalwareBazaar feed + bounded blocklist store
internal/quarantine/ reversible quarantine + restore ledger
internal/watch/     fsnotify watcher + wait-for-write-complete logic
internal/tray/      system tray + dashboard UI (lxn/walk, Windows only)
internal/autostart/ opt-in HKCU Run-key launch-at-login
.old/               original Python implementation (still runnable)
```

---

## Scope

**In scope:** watch configurable folders, layered detection (blocklist +
MalwareBazaar + VirusTotal + YARA + heuristics), reversible quarantine,
dashboard UI, opt-in start-on-login.

**Out of scope by design:** kernel-level real-time blocking, full-disk
scanning, AMSI hooks — the invasive parts this tool intentionally avoids.

> **Heads up:** This is a lightweight safety net, not a full antivirus
> replacement. It catches the common case well. Keep your system patched.
