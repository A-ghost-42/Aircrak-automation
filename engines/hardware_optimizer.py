import subprocess
import re
import time
import os


class HardwareOptimizer:
    def __init__(self, error_handler=None):
        self.error_handler = error_handler
        self.original_regdomain = None
        self.original_mac = {}
        self.optimizations_applied = []

    def set_regulatory_domain(self, domain="BO"):
        try:
            r = subprocess.run(["iw", "reg", "get"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                m = re.search(r"country (\w\w):", line)
                if m:
                    self.original_regdomain = m.group(1)
                    break

            result = subprocess.run(
                ["sudo", "iw", "reg", "set", domain],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                self.optimizations_applied.append(f"regdomain: {domain}")
                print(f"   Regulatory domain set to {domain} (was {self.original_regdomain})")
                return True
            else:
                print(f"   Failed to set regulatory domain: {result.stderr.strip()}")
                return False
        except Exception as e:
            print(f"   Regulatory domain error: {e}")
            return False

    def restore_regulatory_domain(self):
        if self.original_regdomain:
            try:
                subprocess.run(
                    ["sudo", "iw", "reg", "set", self.original_regdomain],
                    capture_output=True, text=True, timeout=5,
                )
                print(f"   Restored regulatory domain to {self.original_regdomain}")
            except Exception:
                pass

    def boost_tx_power(self, interface, power_mbm=3000):
        try:
            result = subprocess.run(
                ["sudo", "iw", "dev", interface, "set", "txpower", "fixed", str(power_mbm)],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                self.optimizations_applied.append(f"txpower: {power_mbm} mBm")
                print(f"   TX power boosted to {power_mbm // 100} dBm on {interface}")
                return True
            else:
                print(f"   TX power boost failed: {result.stderr.strip()}")
                return False
        except Exception as e:
            print(f"   TX power error: {e}")
            return False

    def get_tx_power(self, interface):
        try:
            r = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                m = re.search(r"txpower\s+([0-9.]+)\s+dBm", line)
                if m:
                    return float(m.group(1))
            return None
        except Exception:
            return None

    def spoof_mac(self, interface):
        try:
            r = subprocess.run(["macchanger", "-s", interface],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                m = re.search(r"Current MAC:\s+([0-9a-f:]{17})", line, re.I)
                if m:
                    self.original_mac[interface] = m.group(1)
                    break

            result = subprocess.run(
                ["sudo", "macchanger", "-r", interface],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                new_mac = None
                for line in result.stdout.splitlines():
                    m = re.search(r"New MAC:\s+([0-9a-f:]{17})", line, re.I)
                    if m:
                        new_mac = m.group(1)
                        break
                self.optimizations_applied.append(f"mac_spoof: {interface}")
                print(f"   MAC spoofed on {interface}: {new_mac}")
                return new_mac
            else:
                print(f"   MAC spoofing failed: {result.stderr.strip()}")
                return None
        except Exception as e:
            print(f"   MAC spoofing error: {e}")
            return None

    def restore_mac(self, interface):
        if interface in self.original_mac:
            try:
                subprocess.run(
                    ["sudo", "macchanger", "-p", interface],
                    capture_output=True, text=True, timeout=10,
                )
                print(f"   MAC restored on {interface}")
            except Exception:
                pass

    def detect_gpu(self):
        gpu_info = {"available": False, "backends": []}

        try:
            r = subprocess.run(["hashcat", "--version"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                gpu_info["backends"].append("hashcat")
                gpu_info["hashcat_version"] = r.stdout.strip()

                r2 = subprocess.run(["hashcat", "-I"],
                                    capture_output=True, text=True, timeout=10)
                for line in r2.stdout.splitlines():
                    if "CUDA" in line and "Device" in line:
                        gpu_info["backends"].append("cuda")
                    if "OpenCL" in line and "Device" in line:
                        gpu_info["backends"].append("opencl")
                    if "Intel" in line and "GPU" in line:
                        gpu_info["backends"].append("intel_gpu")
                    if "NVIDIA" in line:
                        gpu_info["gpu_type"] = "nvidia"
                    if "AMD" in line or "Radeon" in line:
                        gpu_info["gpu_type"] = "amd"

        except FileNotFoundError:
            pass
        except Exception:
            pass

        gpu_info["available"] = len(gpu_info["backends"]) > 0
        return gpu_info

    def benchmark_hashcat(self, hash_file=None):
        if not hash_file or not os.path.exists(hash_file):
            return {"speed": 0, "mode": "estimated"}
        try:
            cmd = [
                "hashcat", "-m", "22000", "-b", "--benchmark-all",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            for line in r.stdout.splitlines():
                if "Speed" in line and "H/s" in line:
                    m = re.search(r"([0-9.]+)\s+([KMGT])H/s", line)
                    if m:
                        val = float(m.group(1))
                        unit = m.group(2)
                        mult = {"K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}
                        speed = int(val * mult.get(unit, 1))
                        return {"speed": speed, "mode": "measured", "unit": unit}
            return {"speed": 50000, "mode": "estimated"}
        except Exception:
            return {"speed": 50000, "mode": "estimated"}

    def apply_all(self, interface):
        print("   Optimizing hardware...")
        self.set_regulatory_domain("BO")
        self.boost_tx_power(interface)
        self.spoof_mac(interface)
        gpu = self.detect_gpu()
        if gpu["available"]:
            print(f"   GPU acceleration available: {gpu['backends']}")
            if "hashcat" in gpu["backends"]:
                print(f"      Hashcat v{gpu.get('hashcat_version', '?')}")
                if "cuda" in gpu["backends"]:
                    print(f"      CUDA devices detected")
                if "opencl" in gpu["backends"]:
                    print(f"      OpenCL devices detected")
        else:
            print("   No GPU acceleration detected, using CPU only")
        return gpu

    def cleanup(self, interface=None):
        self.restore_regulatory_domain()
        if interface:
            self.restore_mac(interface)
