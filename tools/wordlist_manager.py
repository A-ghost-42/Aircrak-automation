import os
import gzip
import shutil
import subprocess
import urllib.request
import hashlib
from pathlib import Path


WORDLIST_DIR = Path.home() / ".pegasus_nexus" / "wordlists"
WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

WORDLIST_SOURCES = {
    "rockyou": {
        "url": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
        "expected_size": 139_921_507,
        "description": "14M real leaked passwords",
    },
    "common_wpa": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        "expected_size": 94_000,
        "description": "10K most common passwords",
    },
    "wpa_top1000": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top1000.txt",
        "expected_size": 15_000,
        "description": "Top 1000 WPA passwords",
    },
    "wpa_top4800": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
        "expected_size": 58_000,
        "description": "Top 4800 WPA passwords",
    },
}


class WordlistManager:
    def __init__(self):
        self.wordlist_dir = WORDLIST_DIR

    def list_available(self):
        available = []
        for f in self.wordlist_dir.iterdir():
            if f.is_file() and f.suffix in (".txt", ".lst", ".gz"):
                size_mb = f.stat().st_size / (1024 * 1024)
                available.append({
                    "name": f.stem,
                    "path": str(f),
                    "size_mb": round(size_mb, 1),
                })
        return available

    def download(self, name, force=False):
        if name not in WORDLIST_SOURCES:
            return {"error": f"Unknown wordlist: {name}. Options: {list(WORDLIST_SOURCES.keys())}"}

        info = WORDLIST_SOURCES[name]
        dest = self.wordlist_dir / f"{name}.txt"

        if dest.exists() and not force:
            size = dest.stat().st_size
            if abs(size - info["expected_size"]) < 1000:
                return {"status": "already_exists", "path": str(dest), "size_mb": round(size / (1024 * 1024), 1)}

        print(f"   Downloading {name} ({info['description']})...")
        try:
            url = info["url"]
            if url.endswith(".gz"):
                gz_path = str(dest) + ".gz"
                urllib.request.urlretrieve(url, gz_path)
                with gzip.open(gz_path, "rb") as gz_in:
                    with open(dest, "wb") as txt_out:
                        shutil.copyfileobj(gz_in, txt_out)
                os.remove(gz_path)
            else:
                urllib.request.urlretrieve(url, str(dest))

            size = dest.stat().st_size
            print(f"   Downloaded: {size / (1024 * 1024):.1f} MB")
            return {"status": "downloaded", "path": str(dest), "size_mb": round(size / (1024 * 1024), 1)}

        except Exception as e:
            if dest.exists():
                dest.unlink()
            return {"error": str(e)}

    def download_all(self, force=False):
        results = {}
        for name in WORDLIST_SOURCES:
            results[name] = self.download(name, force)
        return results

    def get_path(self, name):
        path = self.wordlist_dir / f"{name}.txt"
        if path.exists():
            return str(path)
        alt = self.wordlist_dir / f"{name}.lst"
        return str(alt) if alt.exists() else None

    def build_vendor_wordlist(self, output=None):
        from intelligence.password_intelligence import ROUTER_DEFAULTS, COMMON_WIFI_PASSWORDS

        if output is None:
            output = str(self.wordlist_dir / "vendor_defaults.txt")

        seen = set()
        with open(output, "w") as f:
            for vendor, passwords in ROUTER_DEFAULTS.items():
                for pw in passwords:
                    if pw not in seen:
                        seen.add(pw)
                        f.write(pw + "\n")
            for pw in COMMON_WIFI_PASSWORDS:
                if pw not in seen:
                    seen.add(pw)
                    f.write(pw + "\n")
            common = [
                "admin12345", "password123", "changeme1",
                "Welcome1", "Welcome123", "Passw0rd!",
                "Admin123!", "P@ssw0rd", "P@ssword1",
                "Summer2024", "Winter2024", "Spring2024",
                "Summer2025", "Winter2025",
                "qwerty12345", "qwerty123!", "abc123!@#",
                "1q2w3e4r5t", "qwerty123456",
                "iloveyou123", "sunshine1", "trustno1",
                "dragon123", "master123", "monkey123",
            ]
            for pw in common:
                if pw not in seen:
                    seen.add(pw)
                    f.write(pw + "\n")

        count = len(seen)
        size = os.path.getsize(output)
        print(f"   Vendor wordlist: {count} passwords, {size / 1024:.1f} KB")
        return output


def ensure_wordlists():
    mgr = WordlistManager()
    available = mgr.list_available()
    if not available:
        print("   No wordlists found. Building vendor defaults...")
        mgr.build_vendor_wordlist()
    return mgr
