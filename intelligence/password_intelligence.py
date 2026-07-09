import re
import os
import json
import math
from pathlib import Path
from collections import defaultdict, Counter
from typing import Optional


ROUTER_DEFAULTS = {
    "tp-link": ["admin", "admin123", "12345678", "password", "adminadmin",
                 "1234567890", "11111111", "00000000", "87654321"],
    "tplink": ["admin", "admin123", "12345678", "password", "adminadmin"],
    "netgear": ["password", "12345678", "password1", "admin", "netgear1",
                "1234", "admin123", "changeme"],
    "linksys": ["admin", "password", "linksys", "12345678", "admin123",
                "00000000", "11111111"],
    "d-link": ["admin", "12345678", "password", "dlink", "admin123",
               "11111111", "00000000"],
    "asus": ["admin", "password", "12345678", "asus", "admin123",
             "00000000"],
    "huawei": ["admin", "12345678", "password", "admin123", "huawei",
               "1234567890"],
    "tenda": ["admin", "12345678", "password", "tenda", "admin123"],
    "mercusys": ["admin", "12345678", "password", "mercury", "admin123"],
    "belkin": ["admin", "password", "12345678", "belkin", "admin123",
               "00000000"],
    "zyxel": ["admin", "12345678", "password", "zyxel", "admin123",
              "1234"],
    "vodafone": ["admin", "password", "12345678", "vodafone", "WLAN"],
    "att": ["attadmin", "password", "12345678", "admin", "att"],
    "xfinity": ["password", "12345678", "admin", "xfinity", "changeme"],
    "sky": ["sky", "admin", "password", "12345678", "sky123"],
    "bthomehub": ["admin", "password", "bt", "homehub", "12345678",
                  "admin123"],
    "virgin": ["admin", "password", "virgin", "12345678", "changeme"],
    "orange": ["admin", "orange", "password", "12345678", "admin123"],
    "sfr": ["admin", "sfr", "password", "12345678", "1234"],
    "free": ["admin", "free", "password", "12345678", "admin123",
             "00000000", "11111111"],
    "livebox": ["admin", "password", "12345678", "livebox", "admin123"],
    "fritz": ["admin", "password", "12345678", "fritz", "00000000",
              "11111111"],
}


COMMON_WIFI_PASSWORDS = [
    "12345678", "password", "1234567890", "123456789", "11111111",
    "00000000", "admin123", "admin", "password1", "12345678910",
    "abc12345", "qwerty123", "123123123", "iloveyou", "monkey123",
    "dragon123", "master123", "sunshine", "trustno1", "welcome1",
    "changeme", "summer2024", "winter2024", "spring2024", "autumn2024",
    "summer2025", "winter2025", "summer2026", "winter2026",
    "passw0rd", "P@ssw0rd", "Admin123", "Password123",
    "qwerty12345", "asdfgh123", "zxcvbn123", "letmein1",
    "123456a", "a1234567", "abcd1234", "test1234",
    "1234abcd", "abc123", "123abc", "1q2w3e4r",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "password123",
    "Passw0rd!", "Admin@123", "Admin123!", "P@ssword!",
    "secret123", "private1", "default1", "wireless",
    "homewifi", "mywifi", "MyWifi123", "HomeWiFi",
    "wifi12345", "guest1234", "freewifi", "FreeWifi",
]

COMMON_YEARS = [str(y) for y in range(2015, 2029)]


class MarkovChain:
    def __init__(self, order=2):
        self.order = order
        self.transitions = defaultdict(Counter)
        self.starts = Counter()
        self._trained = False

    def train(self, passwords):
        for pw in passwords:
            pw = pw.strip()
            if len(pw) < 4:
                continue
            self.starts[pw[:self.order]] += 1
            for i in range(len(pw) - self.order):
                prefix = pw[i:i + self.order]
                next_char = pw[i + self.order]
                self.transitions[prefix][next_char] += 1
        self._trained = True

    def generate(self, min_len=8, max_len=16):
        if not self._trained:
            return
        total_starts = sum(self.starts.values())
        if total_starts == 0:
            return
        cumsum = 0
        pick = __import__("random").random() * total_starts
        prefix = None
        for p, count in self.starts.most_common():
            cumsum += count
            if cumsum >= pick:
                prefix = p
                break
        if not prefix:
            return
        pw = list(prefix)
        while len(pw) < max_len:
            context = "".join(pw[-(self.order):])
            if context not in self.transitions:
                break
            chars = self.transitions[context]
            total = sum(chars.values())
            if total == 0:
                break
            cumsum = 0
            pick = __import__("random").random() * total
            for ch, count in chars.most_common():
                cumsum += count
                if cumsum >= pick:
                    pw.append(ch)
                    break
            if len(pw) >= min_len and __import__("random").random() < 0.15:
                break
        return "".join(pw)

    def generate_many(self, count=100, min_len=8, max_len=16):
        seen = set()
        results = []
        attempts = 0
        while len(results) < count and attempts < count * 10:
            pw = self.generate(min_len, max_len)
            if pw and pw not in seen and len(pw) >= 8:
                seen.add(pw)
                results.append(pw)
            attempts += 1
        return results


class PasswordIntelligence:
    def __init__(self):
        self.markov = MarkovChain(order=3)
        self._train_markov()
        self.oui_db = self._build_oui_map()

    def _train_markov(self):
        training = list(COMMON_WIFI_PASSWORDS)
        for vendor, passwords in ROUTER_DEFAULTS.items():
            training.extend(passwords)
        training.extend([
            "admin12345", "password12", "changeme1", "wireless1",
            "netgear123", "linksys123", "dlink123", "asus123",
            "tp-link@123", "admin@123", "Passw0rd!", "Admin123!",
            "Summer2024!", "Winter2024!", "Home@123", "WiFi@123",
            "MyNetwork1", "SecureNet1", "Family123", "HomeNet1",
            "!@#$%^&*", "qwerty123!", "abc123!@#", "test123!@",
        ])
        self.markov.train(training)

    def _build_oui_map(self):
        return {
            "00:14:6C": "netgear", "00:1A:6B": "netgear",
            "00:0F:B5": "netgear", "00:26:F2": "netgear",
            "00:09:5B": "tp-link", "00:1A:A9": "tp-link",
            "00:27:19": "tp-link", "00:1F:1F": "tp-link",
            "00:1B:2F": "linksys", "00:14:BF": "linksys",
            "00:12:17": "linksys", "00:1A:70": "d-link",
            "00:1B:11": "d-link", "00:1C:F0": "d-link",
            "00:22:B0": "d-link", "00:1E:2A": "asus",
            "00:26:18": "asus", "00:1A:92": "asus",
            "00:25:9C": "huawei", "00:1E:3A": "huawei",
            "00:1C:DF": "huawei", "00:24:A5": "belkin",
            "00:17:3F": "belkin", "00:1B:2F": "belkin",
            "00:26:5B": "tenda",
        }

    def extract_seeds_from_target(self, target):
        seeds = []
        ssid = target.get("ssid", "") or ""
        bssid = target.get("bssid", "") or ""
        ssid_lower = ssid.lower().strip()

        if ssid_lower:
            parts = re.split(r"[-_\s]+", ssid)
            for p in parts:
                p = p.strip()
                if len(p) >= 3 and not p.isdigit():
                    seeds.append(p)

        oui_prefix = bssid[:8].upper() if len(bssid) >= 8 else ""
        vendor = self.oui_db.get(oui_prefix)
        if vendor and vendor in ROUTER_DEFAULTS:
            seeds.extend(ROUTER_DEFAULTS[vendor])

        pattern = self._classify_ssid(ssid_lower)
        if pattern == "default_router":
            if "tp-link" in ssid_lower or "tplink" in ssid_lower:
                seeds.extend(ROUTER_DEFAULTS["tp-link"])
            elif "netgear" in ssid_lower:
                seeds.extend(ROUTER_DEFAULTS["netgear"])
            elif ssid_lower.startswith("sk") or ssid_lower.startswith("sky"):
                seeds.extend(ROUTER_DEFAULTS["sky"])

        if "phone" in ssid_lower or "mobile" in ssid_lower:
            seeds.extend(["12345678", "00000000", "11111111"])
        if "guest" in ssid_lower:
            seeds.extend(["guest1234", "guest", "Guest1234"])
        if "free" in ssid_lower or "public" in ssid_lower:
            seeds.extend(COMMON_WIFI_PASSWORDS[:10])

        seen = set()
        deduped = []
        for s in seeds:
            if s not in seen:
                seen.add(s)
                deduped.append(s)
        return deduped

    def _classify_ssid(self, ssid_lower):
        if re.match(r"(tp-link|tplink|netgear|linksys|d-link|dlink|asus|"
                     r"tenda|huawei|belkin|zyxel|mercusys)", ssid_lower):
            return "default_router"
        if re.match(r"(bt|bthomehub|virgin|sky|xfinity|att|spectrum|"
                     r"comcast|orange|sfr|free|livebox|fritz|vodafone)",
                     ssid_lower):
            return "isp_provided"
        if re.match(r".*(corp|office|company|business|enterprise|inc|llc|"
                     r"ltd|gmbh|saas|erp|crm).*", ssid_lower):
            return "business_network"
        if re.match(r".*(free|public|guest|open|wifi|cafe|hotel|"
                     r"airport|shop|restaurant).*", ssid_lower):
            return "public_wifi"
        if re.match(r".*(phone|iphone|android|galaxy|xiaomi|"
                     r"honor|huawei|oppo|vivo).*", ssid_lower):
            return "mobile_hotspot"
        return "personal_network"

    def generate_attack_plan(self, target, max_duration=3600):
        seeds = self.extract_seeds_from_target(target)
        signal = target.get("signal_strength", -80)
        signal_quality = max(0.1, min(1.0, (signal + 90) / 60))
        time_budget = max_duration * signal_quality

        plan = {
            "seeds": seeds,
            "signal_quality": signal_quality,
            "time_budget": time_budget,
            "phases": [],
        }

        if seeds:
            plan["phases"].append({
                "name": "defaults_and_seeds",
                "description": "Default passwords + seed mutations",
                "priority": 1.0,
                "time_allocation": min(60, time_budget * 0.02),
                "estimated_passwords": max(100, len(seeds) * 20),
            })

        plan["phases"].append({
            "name": "common_passwords",
            "description": "Top 500 common WiFi passwords",
            "priority": 0.9,
            "time_allocation": min(120, time_budget * 0.05),
            "estimated_passwords": 500,
        })

        plan["phases"].append({
            "name": "markov_generation",
            "description": "Markov chain generated passwords",
            "priority": 0.7,
            "time_allocation": min(300, time_budget * 0.10),
            "estimated_passwords": 5000,
        })

        plan["phases"].append({
            "name": "genetic_evolution",
            "description": "Genetic algorithm evolved passwords",
            "priority": 0.6,
            "time_allocation": min(600, time_budget * 0.20),
            "estimated_passwords": 10000,
        })

        if signal_quality > 0.6:
            plan["phases"].append({
                "name": "smart_bruteforce",
                "description": "Targeted brute force based on pattern",
                "priority": 0.4,
                "time_allocation": min(1200, time_budget * 0.40),
                "estimated_passwords": 500000,
            })

        return plan
