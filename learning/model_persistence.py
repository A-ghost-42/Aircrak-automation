import json
import time
import subprocess
import os
import tempfile
from pathlib import Path
from collections import Counter, defaultdict


MODEL_DIR = Path.home() / ".pegasus_nexus" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


class ModelPersistence:
    def __init__(self):
        self.model_dir = MODEL_DIR

    def save_markov(self, markov_chain, name="default"):
        path = self.model_dir / f"markov_{name}.json"
        data = {
            "order": markov_chain.order,
            "starts": dict(markov_chain.starts),
            "transitions": {
                prefix: dict(chars)
                for prefix, chars in markov_chain.transitions.items()
            },
            "trained": markov_chain._trained,
            "timestamp": time.time(),
        }
        try:
            path.write_text(json.dumps(data, indent=2))
            size = path.stat().st_size / 1024
            return {"status": "saved", "path": str(path), "size_kb": round(size, 1)}
        except OSError as e:
            return {"error": str(e)}

    def load_markov(self, name="default"):
        path = self.model_dir / f"markov_{name}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            from intelligence.password_intelligence import MarkovChain
            mc = MarkovChain(order=data.get("order", 3))
            mc.starts = Counter(data.get("starts", {}))
            mc.transitions = defaultdict(Counter)
            for prefix, chars in data.get("transitions", {}).items():
                mc.transitions[prefix] = Counter(chars)
            mc._trained = data.get("trained", False)
            return mc
        except (json.JSONDecodeError, OSError):
            return None

    def list_models(self):
        models = []
        for f in self.model_dir.iterdir():
            if f.suffix == ".json":
                try:
                    data = json.loads(f.read_text())
                    models.append({
                        "name": f.stem.replace("markov_", ""),
                        "path": str(f),
                        "size_kb": round(f.stat().st_size / 1024, 1),
                        "trained": data.get("trained", False),
                        "timestamp": data.get("timestamp", 0),
                    })
                except (json.JSONDecodeError, OSError):
                    pass
        return models

    def merge_markov_models(self, names, output_name="merged"):
        chains = []
        for name in names:
            mc = self.load_markov(name)
            if mc and mc._trained:
                chains.append(mc)
        if not chains:
            return {"error": "No valid models to merge"}
        if len(chains) == 1:
            self.save_markov(chains[0], output_name)
            return {"status": "single_model_copied", "name": output_name}

        from intelligence.password_intelligence import MarkovChain
        merged = MarkovChain(order=chains[0].order)
        for mc in chains:
            for prefix, count in mc.starts.items():
                merged.starts[prefix] += count
            for prefix, chars in mc.transitions.items():
                merged.transitions[prefix] += chars
        merged._trained = True
        return self.save_markov(merged, output_name)


class Benchmark:
    def __init__(self, config=None):
        self.config = config
        self.results_path = Path.home() / ".pegasus_nexus" / "benchmark.json"

    def run(self, handshake_file=None, bssid=None):
        print("   Running benchmark...")
        results = {}

        aircrack_speed = self._bench_aircrack(handshake_file, bssid)
        results["aircrack"] = aircrack_speed

        hashcat_available = self._check_hashcat()
        results["hashcat_available"] = hashcat_available
        if hashcat_available:
            results["hashcat"] = self._bench_hashcat()

        results["timestamp"] = time.time()
        self._save(results)
        return results

    def _bench_aircrack(self, handshake_file=None, bssid=None):
        test_passwords = ["testpassword123", "admin12345", "password123",
                          "1234567890", "qwertyuiop", "abcdefghij",
                          "sunshine1", "welcome123", "letmein12"]
        batch_size = len(test_passwords)
        count = 0
        start = time.time()

        if handshake_file and bssid and os.path.exists(handshake_file):
            with tempfile.NamedTemporaryFile(mode="w", delete=False,
                                              suffix=".txt") as f:
                for _ in range(20):
                    for pw in test_passwords:
                        f.write(pw + "\n")
                        count += 1
                f.flush()
                try:
                    subprocess.run(
                        ["aircrack-ng", "-b", bssid, "-w", f.name, handshake_file],
                        capture_output=True, text=True, timeout=30,
                    )
                except Exception:
                    pass
                os.unlink(f.name)

        elapsed = time.time() - start
        speed = count / elapsed if elapsed > 0 else 500
        return {"passwords_per_second": round(speed, 1), "tested": count, "elapsed": round(elapsed, 2)}

    def _check_hashcat(self):
        try:
            r = subprocess.run(["hashcat", "--version"],
                               capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _bench_hashcat(self):
        return {"passwords_per_second": 50000, "estimated": True}

    def _save(self, results):
        try:
            self.results_path.write_text(json.dumps(results, indent=2))
        except OSError:
            pass

    def load_last(self):
        if self.results_path.exists():
            try:
                return json.loads(self.results_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return None

    def get_estimated_speed(self):
        last = self.load_last()
        if last and "aircrack" in last:
            return last["aircrack"]["passwords_per_second"]
        return 500

    def estimate_time(self, password_count):
        speed = self.get_estimated_speed()
        if speed <= 0:
            return float("inf")
        return password_count / speed
