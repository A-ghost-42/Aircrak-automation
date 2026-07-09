import subprocess
import os
import time
import shutil
import json
from pathlib import Path


HEALTH_DB_PATH = Path.home() / ".pegasus_nexus" / "health.json"


class HealthGuardian:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.health_file = HEALTH_DB_PATH
        self.health_file.parent.mkdir(parents=True, exist_ok=True)
        self.tool_cache = self._load_cache()

    REQUIRED_TOOLS = {
        "aircrack-ng": {
            "pkg": "aircrack-ng",
            "critical": True,
            "check": ["aircrack-ng", "--help"],
        },
        "airodump-ng": {
            "pkg": "aircrack-ng",
            "critical": True,
            "check": ["airodump-ng", "--help"],
        },
        "aireplay-ng": {
            "pkg": "aircrack-ng",
            "critical": True,
            "check": ["aireplay-ng", "--help"],
        },
        "iw": {
            "pkg": "iw",
            "critical": True,
            "check": ["iw", "--version"],
        },
        "macchanger": {
            "pkg": "macchanger",
            "critical": False,
            "check": ["macchanger", "--version"],
        },
        "hashcat": {
            "pkg": "hashcat",
            "critical": False,
            "check": ["hashcat", "--version"],
        },
        "hcxdumptool": {
            "pkg": "hcxtools",
            "critical": False,
            "check": ["hcxdumptool", "--version"],
        },
        "hcxpcaptool": {
            "pkg": "hcxtools",
            "critical": False,
            "check": ["hcxpcaptool", "--version"],
        },
        "wpaclean": {
            "pkg": "aircrack-ng",
            "critical": False,
            "check": ["wpaclean", "--help"],
        },
        "mdk4": {
            "pkg": "mdk4",
            "critical": False,
            "check": ["mdk4", "--help"],
        },
        "wash": {
            "pkg": "reaver",
            "critical": False,
            "check": ["wash", "--help"],
        },
        "reaver": {
            "pkg": "reaver",
            "critical": False,
            "check": ["reaver", "--help"],
        },
        "python3": {
            "pkg": "python3",
            "critical": True,
            "check": ["python3", "--version"],
        },
    }

    OPTIONAL_TOOLS = {
        "hcxpcapngtool": {"pkg": "hcxtools", "check": ["hcxpcapngtool", "--version"]},
        "tcpdump": {"pkg": "tcpdump", "check": ["tcpdump", "--version"]},
        "tshark": {"pkg": "tshark", "check": ["tshark", "--version"]},
    }

    def _load_cache(self):
        try:
            if self.health_file.exists():
                return json.loads(self.health_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _save_cache(self):
        try:
            self.health_file.write_text(json.dumps(self.tool_cache, indent=2))
        except OSError:
            pass

    def check_tool(self, name, config=None):
        info = self.REQUIRED_TOOLS.get(name) or self.OPTIONAL_TOOLS.get(name)
        if not info:
            return {"name": name, "found": False, "error": "unknown tool"}

        now = time.time()
        cached = self.tool_cache.get(name, {})
        cache_age = now - cached.get("last_check", 0) if cached.get("last_check") else 9999
        if cache_age < 60 and cached.get("found") is not None:
            return cached

        check = config if config else info.get("check", [name])
        try:
            r = subprocess.run(
                check, capture_output=True, text=True, timeout=5
            )
            found = r.returncode == 0
            version = (
                r.stdout.strip()[:50] or r.stderr.strip()[:50] or "?"
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            found = False
            version = None
        except Exception:
            found = False
            version = None

        if not found:
            alt_check = ["which", name]
            try:
                r2 = subprocess.run(alt_check, capture_output=True, text=True, timeout=3)
                if r2.returncode == 0:
                    found = True
                    version = r2.stdout.strip()
            except Exception:
                pass

        result = {
            "name": name,
            "found": found,
            "version": version,
            "critical": info.get("critical", False),
            "pkg": info.get("pkg", name),
            "last_check": now,
        }
        self.tool_cache[name] = result
        self._save_cache()
        return result

    def check_all(self):
        results = {}
        for name in self.REQUIRED_TOOLS:
            results[name] = self.check_tool(name)
        for name in self.OPTIONAL_TOOLS:
            results[name] = self.check_tool(name)
        return results

    def get_missing(self):
        results = self.check_all()
        missing = []
        for name, info in results.items():
            if not info["found"]:
                missing.append(info)
        return missing

    def get_critical_missing(self):
        results = self.check_all()
        missing = []
        for name, info in results.items():
            if not info["found"] and info.get("critical"):
                missing.append(info)
        return missing

    def auto_install(self, tool_name):
        info = self.REQUIRED_TOOLS.get(tool_name) or self.OPTIONAL_TOOLS.get(tool_name)
        if not info:
            return {"tool": tool_name, "success": False, "error": "unknown tool"}

        pkg = info["pkg"]
        print(f"   Installing {pkg} (for {tool_name})...")

        cmds = [
            ["sudo", "apt-get", "install", "-y", pkg],
            ["sudo", "apt", "install", "-y", pkg],
            ["sudo", "pacman", "-S", "--noconfirm", pkg],
            ["sudo", "dnf", "install", "-y", pkg],
            ["sudo", "zypper", "install", "-y", pkg],
        ]

        for cmd in cmds:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if r.returncode == 0:
                    print(f"      {pkg} installed successfully")
                    self.tool_cache.pop(tool_name, None)
                    self._save_cache()
                    return {"tool": tool_name, "success": True}
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        return {"tool": tool_name, "success": False, "error": "install failed"}

    def auto_install_all_missing(self):
        missing = self.get_missing()
        if not missing:
            print("   All tools found")
            return {"installed": 0, "failed": 0}

        critical = [m for m in missing if m.get("critical")]
        optional = [m for m in missing if not m.get("critical")]

        installed = 0
        failed = 0

        if critical:
            print(f"\n   Critical missing tools ({len(critical)}):")
            for m in critical:
                r = self.auto_install(m["name"])
                if r["success"]:
                    installed += 1
                else:
                    failed += 1
                    print(f"      FAILED: {m['name']}")

        if optional:
            print(f"\n   Optional missing tools ({len(optional)}):")
            for m in optional:
                r = self.auto_install(m["name"])
                if r["success"]:
                    installed += 1
                else:
                    print(f"      SKIPPED: {m['name']} (optional)")

        self._save_cache()
        return {"installed": installed, "failed": failed}

    def verify_interface(self, interface):
        try:
            r = subprocess.run(
                ["iwconfig", interface],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                return {"ready": False, "error": "not found"}

            output = r.stdout.lower()
            is_monitor = "mode:monitor" in output or "monitor mode" in output
            has_txpower = "tx-power" in output or "txpower" in output

            return {
                "ready": is_monitor,
                "interface": interface,
                "mode": "monitor" if is_monitor else "managed",
                "has_txpower": has_txpower,
            }
        except Exception as e:
            return {"ready": False, "error": str(e)}

    def repair_interface(self, interface):
        cmds = [
            ["sudo", "ip", "link", "set", interface, "down"],
            ["sudo", "iw", "dev", interface, "set", "type", "monitor"],
            ["sudo", "ip", "link", "set", interface, "up"],
            ["sudo", "iwconfig", interface, "mode", "monitor"],
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            except Exception:
                pass

        time.sleep(2)
        return self.verify_interface(interface)

    def health_report(self):
        results = self.check_all()
        missing = [r for r in results.values() if not r["found"]]
        critical = [r for r in missing if r.get("critical")]
        optional = [r for r in missing if not r.get("critical")]

        print(f"\n{'='*50}")
        print(f"🩺 SYSTEM HEALTH REPORT")
        print(f"{'='*50}")
        print(f"   Tools checked: {len(results)}")
        print(f"   Healthy: {len(results) - len(missing)}")
        print(f"   Missing critical: {len(critical)}")
        print(f"   Missing optional: {len(optional)}")

        if critical:
            print(f"\n   ❌ CRITICAL MISSING:")
            for m in critical:
                print(f"      {m['name']:<20} install: sudo apt-get install {m['pkg']}")

        if optional:
            print(f"\n   ⚠️  OPTIONAL MISSING:")
            for m in optional:
                print(f"      {m['name']:<20} install: sudo apt-get install {m['pkg']}")

        healthy = [r for r in results.values() if r["found"]]
        if healthy:
            print(f"\n   ✅ HEALTHY TOOLS:")
            for h in healthy[:10]:
                ver = (h.get("version") or "?")[:30]
                print(f"      {h['name']:<20} {ver}")
            if len(healthy) > 10:
                print(f"      ... and {len(healthy)-10} more")

        print(f"{'='*50}")
        return {
            "total": len(results),
            "healthy": len(healthy),
            "missing_critical": len(critical),
            "missing_optional": len(optional),
            "can_proceed": len(critical) == 0,
        }
