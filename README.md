# Aircrak-automation

**Automated wireless security auditing framework with AI-powered password cracking.**

Aircrak-automation is a fully automated wireless penetration testing framework that combines traditional aircrack-ng tooling with an adaptive artificial intelligence engine for intelligent brute-force password cracking. It automatically discovers networks, analyzes target profiles, captures WPA handshakes, and executes a multi-phase AI-driven password cracking pipeline.

---

## Features

### Intelligence Layer
- **22 vendor default password databases** — TP-Link, Netgear, Linksys, D-Link, Asus, Huawei, Tenda, Belkin, Zyxel, and 12 ISP routers (Orange, SFR, Free, BT, Virgin, Sky, etc.)
- **OUI-based hardware identification** — 25 MAC prefixes mapped to manufacturers for automatic default password lookup
- **SSID pattern classification** — automatically detects router type (default, ISP, enterprise, public, mobile hotspot, personal)
- **Markov chain password generator** — order-3 Markov model trained on real-world WiFi passwords for statistically probable candidate generation
- **Automatic seed extraction** — extracts password hints from SSID names, BSSID vendors, and network context

### Adaptive Attack Pipeline (5 Phases)
| Phase | Priority | Description |
|-------|----------|-------------|
| 1. Defaults & Seeds | 1.0 | Vendor default passwords + user-provided seeds mutated via rules engine |
| 2. Common Passwords | 0.9 | Top 500 most common WiFi passwords + hashcat-style mutations |
| 3. Markov Generation | 0.7 | AI-generated passwords from trained Markov chain model |
| 4. Genetic Evolution | 0.6 | Population-based genetic algorithm with crossover, mutation, elitism |
| 5. Smart Brute-force | 0.4 | Targeted brute force based on SSID pattern (signal-dependent) |

### Mutation Engine
- **Rules-based engine** — 130+ hashcat-compatible mutation rules (case variants, reversals, duplications, numeric suffixes, special characters, year combinations, compound transformations)
- **266 mutations per seed word** — comprehensive coverage of common password patterns
- **Genetic algorithm** — evolving population over 10 generations with adaptive mutation rate (0.15 → 0.05) and growing population (50 → 200)

### Automation
- **Fully autonomous batch mode** — scan, filter, attack, and crack without user intervention
- **Persistent monitor mode** — automatic setup/teardown via airmon-ng with signal handler cleanup
- **Multi-pass aggregated scanning** — merges multiple scan passes by BSSID with averaged signal/probability
- **Scan caching and resume** — save scan results to JSON and resume interrupted sessions
- **Automatic checkpointing** — saves brute-force progress per BSSID for crash recovery
- **Wordlist management** — download rockyou, SecLists, and WPA-probable wordlists automatically

### Cracking Backends
- **Aircrack-ng** — parallel batch testing with ProcessPoolExecutor
- **Hashcat** — GPU-accelerated dictionary and mask attacks (WPA-PBKDF2 mode 22000)
- **Crunch** — smart wordlist generation based on target profile
- **Auto-benchmark** — measures real cracking speed for optimal time allocation

### Reporting
- **HTML reports** — dark-themed professional reports with statistics dashboard, success/failure breakdowns, and credential database
- **JSON reports** — machine-readable output for integration
- **Performance tracking** — persistent attack history with success pattern analysis across sessions
- **Model persistence** — saves and loads Markov models between sessions for continuous learning

---

## Requirements

### System Tools
- `aircrack-ng` suite (airodump-ng, aireplay-ng, aircrack-ng, airmon-ng)
- `hashcat` (optional, for GPU acceleration)
- `crunch` (wordlist generator)
- `wash` (from `reaver`, for WPS detection)
- `hcxpcapngtool` (from `hcxtools`, for hashcat conversion)
- `iwconfig` (from `wireless-tools`)
- `mdk4` (optional, for deauthentication)

### Python
- Python 3.9+
- `psutil` — hardware detection
- `python-dotenv` — environment variable support

---

## Installation

```bash
# Clone the repository
git clone https://github.com/A-ghost-42/Aircrak-automation.git
cd Aircrak-automation

# Install Python dependencies
pip install -r requirements.txt

# Or using the Makefile
make install
make dev-install   # includes dev tools (pytest, mypy, ruff)
```

### Docker

```bash
make docker-build
make docker-run
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
python3 main.py --batch -i wlan0 --min-signal -70 --encryption WPA2 --wps-only

# Interactive mode with custom seed suggestions
python3 main.py -i wlan0 --seeds admin companyname2024 summer2025

# HTML report generation
python3 main.py --batch -i wlan0 --html-report

# Download wordlists
python3 main.py --download-wordlists

# Benchmark cracking speed
python3 main.py --benchmark --list-only
```

---

## CLI Reference

```
operation modes:
  --batch, --auto       Fully automated mode — no prompts
  --list-only           Scan and display networks only, no attack
  --cap-status          Show live monitor interface status and exit

target filtering (batch mode):
  --min-signal dBm      Minimum signal strength (default: -80)
  --max-targets N       Maximum targets to attack (0 = unlimited)
  --encryption {WPA2,WPA,WEP,OPEN}
  --channel N           Only attack networks on this channel
  --wps-only            Only attack WPS-unlocked networks
  --seeds [WORDS ...]   Seed keywords for password mutation

wordlists:
  --download-wordlists  Download rockyou, SecLists, WPA-probable wordlists
  --list-wordlists      Show available wordlists and exit

advanced:
  --timeout SECONDS     Per-target timeout (default: 3600)
  --html-report         Generate HTML visual report
  --benchmark           Benchmark cracking speed before attack
  --cache-scans         Save scan results to JSON cache
  --resume FILE         Resume from a cached scan file
  --no-wps              Skip WPS detection phase
```

---

## Architecture

```
core/                          # Foundation layer
  bootstrap.py                 System initialization + hardware checks
  config.py                    12-factor config (JSON + env vars)
  error_handler.py             Error codes, severity, recovery actions

intelligence/                  # Reconnaissance phase
  monitor_manager.py           Monitor mode setup/teardown (airmon-ng)
  network_scanner.py           airodump-ng CSV parsing
  target_analyzer.py           SSID classification + probability scoring
  wps_detector.py              WPS lock status detection (wash)
  password_intelligence.py     Markov chains, router defaults, attack planning

engines/                       # Attack execution
  password_generator.py        Stream generation + mutation rules
  password_tester.py           Parallel/sync aircrack-ng testing
  handshake_capture.py         Deauth + capture + verify
  adaptive_engine.py           5-phase AI attack pipeline (genetic, Markov, rules)
  attack_strategy.py           Strategy selection and planning
  real_attack_engine.py        Full attack orchestration
  rules_engine.py              130+ hashcat-compatible mutation rules
  streaming_engine.py          Demo/simulation engine

learning/                      # Adaptive learning
  genetic_engine.py            Genetic algorithm (crossover, mutation, elitism)
  performance_tracker.py       Attack history + pattern analysis
  model_persistence.py         Save/load Markov models, benchmark

tools/                         # External tool wrappers
  aircrack_wrapper.py          aircrack-ng wrapper
  hashcat_wrapper.py           hashcat GPU cracking
  crunch_wrapper.py            crunch wordlist generator
  wordlist_manager.py          Auto-download rockyou, SecLists
  report_generator.py          HTML + JSON report generation

orchestration/                 # Controllers
  main_controller.py           Master orchestrator
  real_attack_controller.py    Real attack cycle
  attack_controller.py         Demo attack cycle
  state_manager.py             Session persistence
```

### Attack Pipeline Flow

```
[Network Scan] → [Target Analysis] → [WPS Detection]
       ↓
[Password Intelligence]
  ├── Extract seeds from SSID/BSSID
  ├── Lookup vendor defaults (22 DBs)
  └── Generate Markov model
       ↓
[Adaptive Attack Engine]
  ├── Phase 1: Defaults + Seeds (rules ×266)
  ├── Phase 2: Common passwords (rules ×266)
  ├── Phase 3: Markov-generated candidates
  ├── Phase 4: Genetic evolution (10 gens)
  └── Phase 5: Smart brute force (targeted)
       ↓
[Report] → [Performance Tracker] → [Model Persistence]
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
