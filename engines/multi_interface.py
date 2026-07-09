import subprocess
import re
import time
import threading


class MultiInterfaceManager:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.interfaces = {}
        self.scout_interface = None
        self.executioner_interface = None
        self._scanner_thread = None
        self._running = False

    def discover_interfaces(self):
        try:
            r = subprocess.run(
                ["iw", "dev"],
                capture_output=True, text=True, timeout=5,
            )
            interfaces = []
            for line in r.stdout.splitlines():
                m = re.search(r"Interface\s+(\S+)", line)
                if m:
                    iface = m.group(1)
                    if iface != "lo":
                        interfaces.append(iface)
            return interfaces
        except Exception:
            return []

    def get_phy_info(self, interface):
        try:
            r = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True, text=True, timeout=5,
            )
            phy = None
            bands = []
            for line in r.stdout.splitlines():
                m = re.search(r"wiphy\s+(\d+)", line)
                if m:
                    phy = int(m.group(1))
                m2 = re.search(r"(\d+)\s*MHz", line)
                if m2:
                    freq = int(m2.group(1))
                    if freq < 2500:
                        bands.append("2.4ghz")
                    elif 5000 <= freq <= 6000:
                        bands.append("5ghz")
                    elif freq > 6000:
                        bands.append("6ghz")

            if not bands:
                bands = ["2.4ghz"]

            r2 = subprocess.run(
                ["iwconfig", interface],
                capture_output=True, text=True, timeout=5,
            )
            mode = "managed"
            for line in r2.stdout.splitlines():
                m3 = re.search(r"Mode:(\S+)", line)
                if m3:
                    mode = m3.group(1)
                    break

            return {
                "interface": interface,
                "phy": phy,
                "bands": list(set(bands)),
                "mode": mode,
                "is_monitor": mode == "Monitor",
            }
        except Exception:
            return {"interface": interface, "phy": None, "bands": ["2.4ghz"],
                    "mode": "unknown", "is_monitor": False}

    def assign_roles(self, primary_interface):
        all_ifaces = self.discover_interfaces()
        print(f"   Interfaces detected: {all_ifaces}")

        if primary_interface not in all_ifaces:
            ifaces_info = [self.get_phy_info(i) for i in all_ifaces]
            managed = [
                i for i in ifaces_info if i["mode"] == "managed"
            ]
            if managed:
                primary_interface = managed[0]["interface"]
                print(f"   Using {primary_interface} as primary (default)")

        phy_groups = {}
        for iface in all_ifaces:
            info = self.get_phy_info(iface)
            phy = info["phy"]
            phy_groups.setdefault(phy, []).append(
                {"interface": iface, **info}
            )

        is_multi_phy = len(phy_groups) >= 2

        if not is_multi_phy or len(all_ifaces) < 2:
            print(f"   Single-radio mode: {primary_interface} does all")
            self.scout_interface = primary_interface
            self.executioner_interface = primary_interface
            return {
                "single_radio": True,
                "scout": primary_interface,
                "executioner": primary_interface,
            }

        scout_iface = None
        exec_iface = None

        for phy, ifaces in phy_groups.items():
            for info in ifaces:
                if info["interface"] == primary_interface and exec_iface is None:
                    exec_iface = primary_interface
                elif scout_iface is None:
                    scout_iface = info["interface"]
                elif exec_iface is None:
                    exec_iface = info["interface"]

        if not scout_iface:
            for phy, ifaces in phy_groups.items():
                for info in ifaces:
                    if info["interface"] != exec_iface:
                        scout_iface = info["interface"]
                        break
                if scout_iface:
                    break

        if not scout_iface:
            scout_iface = exec_iface

        self.scout_interface = scout_iface
        self.executioner_interface = exec_iface

        print(f"   Multi-radio mode:")
        print(f"      Scout (scanning):       {scout_iface}")
        print(f"      Executioner (inject):   {exec_iface}")

        return {
            "single_radio": False,
            "scout": scout_iface,
            "executioner": exec_iface,
        }

    def start_scout(self, hosts_file="/tmp/pegasus_scout_hosts.txt"):
        if self._running:
            return

        if not self.scout_interface:
            return

        self._running = True
        stop_event = threading.Event()

        def _scout_loop():
            scan_file = "/tmp/pegasus_scout_live"
            csv_path = f"{scan_file}-01.csv"

            try:
                proc = subprocess.Popen(
                    [
                        "sudo", "airodump-ng",
                        "--band", "abg",
                        "--write", scan_file,
                        "--output-format", "csv",
                        "--write-interval", "5",
                        self.scout_interface,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                last_hosts = set()

                while self._running:
                    time.sleep(10)
                    if not os.path.exists(csv_path):
                        continue

                    current_hosts = set()
                    try:
                        with open(csv_path) as f:
                            for line in f:
                                parts = [p.strip() for p in line.strip().split(",")]
                                if len(parts) >= 6:
                                    bssid = parts[0]
                                    if re.match(
                                        r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid
                                    ):
                                        channel = parts[3]
                                        ssid = parts[13] if len(parts) > 13 else ""
                                        enc = parts[5] if len(parts) > 5 else ""
                                        pwr = parts[8] if len(parts) > 8 else "0"
                                        if "WPA" in enc or "WEP" in enc:
                                            current_hosts.add(
                                                f"{bssid}|{channel}|{ssid}|{enc}|{pwr}"
                                            )
                    except Exception:
                        pass

                    if current_hosts != last_hosts:
                        with open(hosts_file, "w") as f:
                            for entry in sorted(current_hosts):
                                f.write(entry + "\n")
                        last_hosts = current_hosts
                        print(
                            f"   Scout: {len(current_hosts)} networks cached"
                        )

            except Exception:
                pass
            finally:
                try:
                    os.remove(csv_path)
                except OSError:
                    pass

        self._scanner_thread = threading.Thread(target=_scout_loop, daemon=True)
        self._scanner_thread.start()
        return True

    def stop_scout(self):
        self._running = False

    def get_scout_hosts(self, hosts_file="/tmp/pegasus_scout_hosts.txt"):
        if not os.path.exists(hosts_file):
            return []
        try:
            with open(hosts_file) as f:
                lines = f.read().strip().splitlines()
            targets = []
            for line in lines:
                parts = line.split("|")
                if len(parts) >= 5:
                    targets.append(
                        {
                            "bssid": parts[0],
                            "channel": int(parts[1]) if parts[1].isdigit() else 1,
                            "ssid": parts[2],
                            "encryption": parts[3],
                            "signal_strength": int(parts[4])
                            if parts[4].lstrip("-").isdigit()
                            else -100,
                        }
                    )
            return targets
        except Exception:
            return []
