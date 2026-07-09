import subprocess
import re
import os


class SnrEngine:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.blacklist = {}

    def get_noise_floor(self, interface):
        try:
            r = subprocess.run(
                ["iw", "dev", interface, "survey", "dump"],
                capture_output=True, text=True, timeout=5,
            )
            noise_values = []
            for line in r.stdout.splitlines():
                m = re.search(r"in use.*?noise:\s*(-?\d+)", line)
                if m:
                    noise_values.append(int(m.group(1)))

                m = re.search(r"noise:\s*(-?\d+)", line)
                if m:
                    val = int(m.group(1))
                    if val < 0:
                        noise_values.append(val)

            if noise_values:
                return round(sum(noise_values) / len(noise_values))
            return -95
        except Exception:
            return -95

    def get_snr(self, rssi, noise_floor=None):
        if noise_floor is None:
            noise_floor = -95
        return rssi - noise_floor

    def evaluate_target(self, target, noise_floor, snr_threshold=25,
                        rssi_threshold=-75):
        rssi = target.get("signal_strength", target.get("Power", -100))
        if isinstance(rssi, str):
            try:
                rssi = int(rssi)
            except ValueError:
                rssi = -100

        snr = self.get_snr(rssi, noise_floor)
        bssid = target.get("bssid", "")

        passed = True
        reasons = []

        if rssi < rssi_threshold:
            passed = False
            reasons.append(f"RSSI {rssi}dBm < {rssi_threshold}dBm")

        if snr < snr_threshold:
            passed = False
            reasons.append(f"SNR {snr}dB < {snr_threshold}dB")

        return {
            "passed": passed,
            "rssi": rssi,
            "noise_floor": noise_floor,
            "snr": snr,
            "failed_reasons": reasons,
            "adaptive_timeout": self.calc_adaptive_timeout(rssi),
        }

    def calc_adaptive_timeout(self, rssi):
        if rssi >= -30:
            return 5
        if rssi >= -50:
            return 10
        if rssi >= -60:
            return 15
        if rssi >= -70:
            return 30
        if rssi >= -80:
            return 60
        return 120

    def blacklist_target(self, bssid, reason):
        self.blacklist[bssid] = {"reason": reason, "time": __import__("time").time()}

    def is_blacklisted(self, bssid):
        entry = self.blacklist.get(bssid)
        if not entry:
            return False
        age = __import__("time").time() - entry["time"]
        if age > 600:
            del self.blacklist[bssid]
            return False
        return True

    def filter_targets(self, targets, interface):
        if not targets:
            return []

        noise_floor = self.get_noise_floor(interface)
        print(f"   Noise floor: {noise_floor} dBm")

        passed = []
        removed = []

        for t in targets:
            bssid = t.get("bssid", "")
            if self.is_blacklisted(bssid):
                removed.append((bssid, "blacklisted"))
                continue

            eval_result = self.evaluate_target(t, noise_floor)

            if eval_result["passed"]:
                t["snr"] = eval_result["snr"]
                t["noise_floor"] = eval_result["noise_floor"]
                t["adaptive_timeout"] = eval_result["adaptive_timeout"]
                passed.append(t)
            else:
                removed.append(
                    (t.get("ssid", "?"), "; ".join(eval_result["failed_reasons"]))
                )
                self.blacklist_target(
                    bssid, "; ".join(eval_result["failed_reasons"])
                )

        if removed:
            print(f"   SNR filter removed {len(removed)} weak target(s):")
            for name, reason in removed[:5]:
                print(f"      {name[:30]:<32} {reason}")
            if len(removed) > 5:
                print(f"      ... and {len(removed) - 5} more")

        print(f"   SNR filter passed: {len(passed)} / {len(targets)} targets")
        return passed
