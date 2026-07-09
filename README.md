# Aircrak-automation

**Automated wireless security auditing framework with AI-powered password cracking and persistent self-learning.**

Aircrak-automation is a fully automated wireless penetration testing framework that combines traditional aircrack-ng tooling with an adaptive artificial intelligence engine for intelligent password cracking. It automatically discovers networks, analyzes target profiles, captures WPA handshakes and PMKIDs, and executes a multi-phase AI-driven cracking pipeline. All attack outcomes are persisted in a SQLite brain that improves with every run.

---

## Features

### Intelligence & Reconnaissance
- **22 vendor default password databases** — TP-Link, Netgear, Linksys, D-Link, Asus, Huawei, Tenda, Belkin, Zyxel, and 12 ISP routers (BT, Virgin, Sky, Xfinity, AT&T, Orange, SFR, Free, etc.)
- **OUI-based hardware identification** — 25 MAC prefixes mapped to manufacturers for automatic default password lookup
- **SSID pattern classification** — detects router type (default, ISP, enterprise, public, mobile hotspot, personal)
- **Markov chain password generator** — order-3 Markov model trained on real-world WiFi passwords
- **WPS detection** — scans for WPS lock status using `wash`

### Adaptive Attack Pipeline (5 Phases)
| Phase | Priority | Description |
|-------|----------|-------------|
| 1. Defaults & Seeds | 1.0 | Vendor default passwords + user seeds + ISP/OUI/leaked-DB triage, mutated via rules engine |
| 2. Common Passwords | 0.9 | Top 500 most common WiFi passwords + hashcat-style mutations |
| 3. Markov Generation | 0.7 | AI-generated passwords from trained Markov chain model |
| 4. Genetic Evolution | 0.6 | Population-based genetic algorithm with crossover, mutation, elitism |
| 5. Smart Brute-force | 0.4 | Targeted brute force based on SSID pattern and signal strength |

### Dual Capture Engine
- **WPA Handshake** — targeted deauth (per-client) with `aireplay-ng -c`, dynamic 2s polling, `wpaclean` validation
- **Clientless PMKID** — captures PMKID via `hcxdumptool` when no clients are connected
- **Async parallel capture** — both methods run concurrently in threads with auto-shutdown on first success

### Cracking Triage (Priority Seeds)
Before the adaptive pipeline, the engine pre-screens:
1. **Leaked database** — previously cracked passwords (`cracked.json`)
2. **ISP default generators** — 12 ISPs with serial-number extraction (Verizon, Xfinity, Sky, BT, Virgin, etc.)
3. **OUI vendor defaults** — router manufacturer default password lookup

### Persistent Self-Learning Brain
- **SQLite database** (`~/.pegasus_nexus/brain.db`) — survives reboots, improves with every run
- **Session state** — save/resume interrupted attacks
- **Target profiles** — OUI, vendor, channel, signal history, client peak hours
- **Learned weights** — per-SSID-pattern, per-vendor, per-encryption success rates
- **Password patterns** — `[length]_[charset]` frequency tracking
- **Attack log** — full metadata for every attack attempt

### System Health Guardian
- **13 required + 4 optional tool checks** — auto-detects missing tools
- **Auto-install** — `apt-get`/`pacman`/`dnf`/`zypper` detection
- **Interface repair** — verifies and restores monitor mode

### Hardware Optimization
- **BO regulatory domain** — unlocks up to 30 dBm TX power
- **TX power boost** — `iw set txpower fixed 3000` (30 dBm)
- **MAC spoofing** — `macchanger -r` with auto-restore
- **GPU detection** — auto-detects CUDA/OpenCL/Intel GPU via `hashcat -I`
- **Multi-interface roles** — Scout (continuous full-band scanning) + Executioner (dedicated inject/capture)

### Stealth & PMF Bypass
- **PMF detection** — parses beacon RSN for 802.11w Required/Capable; auto-pivots to PMKID-only when deauth is blocked
- **Jittered deauth timers** — random 80-240ms delays between packets to evade WIDS
- **MAC metamorphosis** — rotates interface MAC between target zones
- **Client traffic analysis** — data frame counters pick the highest-traffic client; round-robin after 2 failures

### Smart SNR Filtering
- **Noise floor parsing** — from `iw survey dump`
- **Dynamic exclusion** — targets below SNR 25dB or RSSI -75dBm are blacklisted for 10 minutes
- **Adaptive timeout** — `-30dBm = 5s` / `-50 = 10s` / `-60 = 15s` / `-70 = 30s` / `-80 = 60s`

### Smart Scheduling
- **Client peak-hour learning** — records which hours have the most client activity per BSSID
- **Recurring attack schedule** — auto-schedules uncracked targets with priority + interval
- **Scheduler summary** — shows due targets and next scheduled runs

### Interactive Password Suggestion
For each target, the script shows the top-10 intelligent password guesses (from leaked DB, ISP patterns, vendor defaults) and prompts the user to add their own passwords before cracking begins. User-supplied passwords are tested first.

### Cracking Backends
- **Aircrack-ng** — parallel batch testing with ProcessPoolExecutor
- **Hashcat** — GPU-accelerated dictionary/mask attacks (mode 22000)
- **Wordlist support** — custom wordlist via `--wordlist / -w`, tried before the adaptive pipeline
- **Auto-benchmark** — measures real cracking speed for optimal time allocation

### Automation & Persistence
- **Fully autonomous batch mode** — scan, filter, attack, crack without intervention
- **Persistent monitor mode** — automatic setup/teardown via `airmon-ng`
- **Multi-pass aggregated scanning** — merges scans by BSSID with averaged signal/probability
- **Scan caching and resume** — save/load scan results as JSON
- **Automatic checkpointing** — saves brute-force progress per BSSID
- **Wordlist management** — download rockyou, SecLists, WPA-probable lists

### Reporting
- **HTML reports** — dark-themed dashboard with success/failure breakdowns, credential database, benchmark charts
- **JSON reports** — machine-readable output
- **Performance tracking** — persistent attack history across sessions

---

## Requirements

### System Tools
- `aircrack-ng` suite (airodump-ng, aireplay-ng, aircrack-ng, airmon-ng)
- `hashcat` (optional, for GPU / PMKID cracking)
- `hcxdumptool` + `hcxpcaptool` (from `hcxtools`, for PMKID capture)
- `macchanger` (for MAC spoofing)
- `iw` + `iwconfig` (for wireless configuration)
- `wash` (from `reaver`, for WPS detection)
- `mdk4` (optional, for deauthentication)
- `wpaclean` (optional, for handshake validation)

### Python
- Python 3.9+

---

## Installation

```bash
# Clone the repository
git clone https://github.com/A-ghost-42/Aircrak-automation.git
cd Aircrak-automation

# The framework auto-detects and reports missing system tools at startup.
# Run once to see what's missing:
python3 main.py --list-only -i wlan0
```

---

## Quick Start

```bash
# Show all available options
python3 main.py --help

# Quick scan — list visible networks
python3 main.py --list-only -i wlan0

# Fully automated attack on all visible networks
python3 main.py --batch -i wlan0

# Automated attack with filters
python3 main.py --batch -i wlan0 --min-signal -70 --encryption WPA2

# Interactive mode with custom passwords
python3 main.py -i wlan0

# Use a custom wordlist (tried first before adaptive pipeline)
python3 main.py -i wlan0 -w /usr/share/wordlists/rockyou.txt

# Hardware optimization (BO regdomain, TX power, MAC spoof, GPU)
python3 main.py --batch -i wlan0 --hardware-optimize

# Benchmark cracking speed before attacking
python3 main.py --benchmark --list-only

# Download wordlists
python3 main.py --download-wordlists

# HTML report generation
python3 main.py --batch -i wlan0 --html-report

# Resume from cached scan
python3 main.py --batch -i wlan0 --resume ~/.pegasus_nexus/scans/scan_20250401_120000.json
```

### Interactive Workflow

1. `python3 main.py -i wlan0` — starts in interactive mode
2. Framework scans and displays networks sorted by success probability
3. Select targets by number (e.g., `1, 3, 5`) or use `all`, `top3`, `strong`, `wps`
4. Optionally provide **seed words** (keywords that might be in the password)
5. Script shows **intelligent password guesses** per target — add your own candidates
6. Confirm attack — script captures handshake/PMKID and cracks

---

## CLI Reference

```
operation modes:
  --batch, --auto           Fully automated mode — no prompts
  --list-only               Scan and display networks only, no attack
  --cap-status              Show live monitor interface status

target filtering (batch mode):
  --min-signal dBm          Minimum signal strength (default: -80)
  --max-targets N           Maximum targets to attack (0 = unlimited)
  --encryption {WPA2,WPA,WEP,OPEN}
  --channel N               Only attack this channel
  --wps-only                Only attack WPS-unlocked networks
  --seeds [WORDS ...]       Seed keywords for password mutation

wordlists:
  --download-wordlists      Download rockyou, SecLists, WPA-probable lists
  --list-wordlists          Show available wordlists and exit
  --wordlist, -w PATH       Custom wordlist to try before adaptive pipeline

advanced:
  --timeout SECONDS         Per-target timeout (default: 3600)
  --html-report             Generate HTML visual report
  --benchmark               Benchmark cracking speed before attack
  --hardware-optimize       BO regdomain, TX power boost, MAC spoof, GPU detect
  --no-gpu                  Disable GPU acceleration
  --deauth-count N          Deauth packets per burst (default: 20)
  --handshake-timeout SEC   Handshake capture timeout (default: 180s)
  --cache-scans             Save scan results to JSON cache
  --resume FILE             Resume from cached scan file
  --no-wps                  Skip WPS detection phase
  --skip-confirm            Skip attack confirmation prompt
```

---

## Architecture

```
core/                           # Foundation layer
  bootstrap.py                  System initialization + hardware checks
  config.py                     12-factor config (JSON + env vars)
  error_handler.py              Error codes, severity, recovery actions

intelligence/                   # Reconnaissance & triage
  monitor_manager.py            Monitor mode setup/teardown (airmon-ng)
  network_scanner.py            airodump-ng CSV parsing
  target_analyzer.py            SSID classification + probability scoring
  wps_detector.py               WPS lock status detection (wash)
  password_intelligence.py      Markov chains, router defaults, attack planning
  cracking_triage.py            ISP ESSID rules, OUI defaults, leaked-DB pre-screen
  health_guardian.py            Toolchain health monitor + auto-install

engines/                        # Attack execution
  password_generator.py         Stream generation + mutation rules
  password_tester.py            Parallel/sync aircrack-ng testing
  handshake_capture.py          Deauth + capture + verify (targeted per-client)
  pmkid_capture.py              Clientless PMKID via hcxdumptool (includes AsyncCaptureEngine)
  adaptive_engine.py            5-phase AI attack pipeline
  attack_strategy.py            Strategy selection and planning
  real_attack_engine.py         Full attack orchestration (all 6 modules integrated)
  rules_engine.py               130+ hashcat-compatible mutation rules
  streaming_engine.py           Demo/simulation engine
  stealth_engine.py             ClientTracker + StealthEngine (jittered deauth, MAC rotation)
  pmf_detector.py               802.11w PMF detection, automatic strategy pivot
  snr_engine.py                 Noise floor parsing, SNR filter, adaptive timeout
  multi_interface.py            Scout + Executioner role assignment
  hardware_optimizer.py         BO regdomain, TX power, MAC spoof, GPU detect

learning/                       # Persistent self-learning
  persistence_brain.py          SQLite-backed brain: sessions, targets, weights, patterns, logs
  smart_scheduler.py            Client peak-hour learning, recurring attack schedule
  genetic_engine.py             Genetic algorithm (crossover, mutation, elitism)
  performance_tracker.py        Attack history + pattern analysis
  model_persistence.py          Save/load Markov models, benchmark

tools/                          # External tool wrappers
  aircrack_wrapper.py           aircrack-ng wrapper
  hashcat_wrapper.py            hashcat GPU cracking
  crunch_wrapper.py             crunch wordlist generator
  wordlist_manager.py           Auto-download rockyou, SecLists
  report_generator.py           HTML + JSON report generation

orchestration/                  # Controllers
  main_controller.py            Master orchestrator
  real_attack_controller.py     Real attack cycle
  attack_controller.py          Demo attack cycle
  state_manager.py              Session persistence
```

### Attack Pipeline Flow

```
[Network Scan] -> [Target Analysis] -> [WPS Detection] -> [SNR Filter]
       |
       +--> [PMF Detection] --PMF required--> [PMKID-only capture]
       |
       +--> [Health Check]
       |
       +--> [Multi-Interface Roles]
                |
                v
[Client Traffic Scan] -> [Async Dual Capture]
  |                              |
  |  Handshake + PMKID in        |
  |  parallel threads            |
  |  (auto-shutdown on 1st hit)  |
  |                              |
  +--------+---------------------+
           |
           v
[Cracking Triage]
  |-- Leaked DB pre-screen
  |-- ISP default generator (12 ISPs)
  |-- OUI vendor defaults
  |-- User-suggested passwords (if interactive)
  |-- Wordlist (if --wordlist)
           |
           v
[Adaptive Attack Engine]
  |-- Phase 1: Defaults + Seeds (rules x266)
  |-- Phase 2: Common passwords (rules x266)
  |-- Phase 3: Markov-generated candidates
  |-- Phase 4: Genetic evolution (10 gens)
  |-- Phase 5: Smart brute force (targeted)
           |
           v
[Persistence Brain]     [Report]
  |-- Log attack        |-- HTML dashboard
  |-- Update weights    |-- JSON export
  |-- Track patterns    |-- Performance stats
  |-- Schedule retry    |-- Credential DB
```

---

## Development

```bash
make test        # Run all tests (pytest)
make lint        # Ruff linter
make typecheck   # mypy type checking
make clean       # Remove caches and build artifacts
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is intended for **authorized security testing only**. Unauthorized access to computer networks is illegal. The authors are not responsible for any misuse or damage caused by this tool. Always obtain explicit written permission before testing any network you do not own.
