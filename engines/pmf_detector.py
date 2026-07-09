import subprocess
import os
import re
import time


class PmfDetector:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler

    def detect_pmf(self, bssid, channel, interface, scan_time=8):
        csv_file = f"/tmp/pegasus_pmf_{int(time.time())}"

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
                    for line in f:
                        parts = [p.strip() for p in line.strip().split(",")]
                        if len(parts) >= 14 and bssid.upper() in parts[0].upper():
                            rsn = ""
                            if len(parts) > 13:
                                rsn = parts[13]
                            pmf = self._parse_rsn_for_pmf(rsn)
                            return pmf

            return {"pmf_required": False, "pmf_capable": False, "method": "unknown"}
        except Exception:
            return {"pmf_required": False, "pmf_capable": False, "method": "error"}
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

    def detect_pmf_wash(self, bssid, interface, scan_time=10):
        try:
            r = subprocess.run(["which", "wash"], capture_output=True, text=True, timeout=3)
            if r.returncode != 0:
                return None

            cmd = ["sudo", "wash", "-i", interface, "-2", "--scan"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            time.sleep(scan_time)
            proc.terminate()
            out, _ = proc.communicate(timeout=5)

            for line in out.splitlines():
                if bssid.upper() in line.upper():
                    if "WPA2" in line or "WPA3" in line:
                        if "MFP" in line or "PMF" in line or "802.11w" in line:
                            return {
                                "pmf_required": True,
                                "pmf_capable": True,
                                "method": "wash",
                            }
            return None
        except Exception:
            return None

    def _parse_rsn_for_pmf(self, rsn_str):
        result = {"pmf_required": False, "pmf_capable": False, "method": "airodump"}

        if not rsn_str:
            return result

        rsn_lower = rsn_str.lower()

        if "required" in rsn_lower and ("mfp" in rsn_lower or "pmf" in rsn_lower):
            result["pmf_required"] = True
            result["pmf_capable"] = True

        if "capable" in rsn_lower and ("mfp" in rsn_lower or "pmf" in rsn_lower):
            result["pmf_capable"] = True

        if "11w" in rsn_lower:
            result["pmf_required"] = True
            result["pmf_capable"] = True

        if result["pmf_required"] or result["pmf_capable"]:
            return result

        if rsn_str and len(rsn_str) > 10:
            try:
                hex_parts = rsn_str.split()
                for part in hex_parts:
                    if "C0" in part or "40" in part or "20" in part:
                        if "C0" in part:
                            result["pmf_required"] = True
                            result["pmf_capable"] = True
                        elif "40" in part:
                            result["pmf_capable"] = True
            except Exception:
                pass

        return result

    def get_attack_strategy(self, bssid, channel, interface):
        pmf = self.detect_pmf(bssid, channel, interface)
        if pmf.get("pmf_required"):
            wash_pmf = self.detect_pmf_wash(bssid, interface)
            if wash_pmf:
                pmf = wash_pmf

        if pmf.get("pmf_required"):
            print(
                f"   PMF REQUIRED: deauth blocked, switching to PMKID-only"
            )
            return {
                "deauth_allowed": False,
                "pmf_required": True,
                "recommended": "pmkid_only",
                "reason": "802.11w PMF required - deauth will be ignored",
            }

        if pmf.get("pmf_capable"):
            print(
                f"   PMF CAPABLE: deauth may fail, prefer PMKID"
            )
            return {
                "deauth_allowed": True,
                "pmf_capable": True,
                "recommended": "dual",
                "reason": "802.11w PMF capable - prefer PMKID, fallback deauth",
            }

        return {
            "deauth_allowed": True,
            "pmf_required": False,
            "pmf_capable": False,
            "recommended": "handshake",
            "reason": "No PMF - standard deauth should work",
        }
