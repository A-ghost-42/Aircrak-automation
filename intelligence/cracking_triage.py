import re
import os
import json
from pathlib import Path


CACHED_PW_PATH = Path.home() / ".pegasus_nexus" / "cracked.json"


class CrackingTriage:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.isp_patterns = self._build_isp_patterns()
        self.leaked_db = self._load_leaked_db()

    def _build_isp_patterns(self):
        return {
            "xfinity": {
                "match": r"(xfinity|comcast).*",
                "generator": self._xfinity_generator,
                "priority": 95,
            },
            "verizon": {
                "match": r"(verizon|fioss).*",
                "generator": self._verizon_generator,
                "priority": 90,
            },
            "att": {
                "match": r"(att|attwifi|ubee).*",
                "generator": self._att_generator,
                "priority": 90,
            },
            "sky": {
                "match": r"(sky|sk|skyfibre).*",
                "generator": self._sky_generator,
                "priority": 90,
            },
            "virgin": {
                "match": r"(virgin|virginmedia).*",
                "generator": self._virgin_generator,
                "priority": 90,
            },
            "bt": {
                "match": r"(bt|bthomehub|btbusiness).*",
                "generator": self._bt_generator,
                "priority": 90,
            },
            "livebox": {
                "match": r"(livebox|orange|sfr|freebox).*",
                "generator": self._livebox_generator,
                "priority": 85,
            },
            "tplink": {
                "match": r"(tp-link|tplink).*",
                "generator": self._tplink_generator,
                "priority": 80,
            },
            "netgear": {
                "match": r"(netgear).*",
                "generator": self._netgear_generator,
                "priority": 80,
            },
            "dlink": {
                "match": r"(d-link|dlink).*",
                "generator": self._dlink_generator,
                "priority": 75,
            },
            "asus": {
                "match": r"(asus).*",
                "generator": self._asus_generator,
                "priority": 75,
            },
            "huawei": {
                "match": r"(huawei|b315|b525|b593).*",
                "generator": self._huawei_generator,
                "priority": 75,
            },
        }

    def classify_isp(self, ssid):
        if not ssid:
            return None
        ssid_lower = ssid.lower().strip()
        for name, cfg in self.isp_patterns.items():
            if re.match(cfg["match"], ssid_lower, re.I):
                return name
        return None

    def generate_isp_candidates(self, ssid, bssid):
        candidates = []
        isp_name = self.classify_isp(ssid)
        if isp_name:
            cfg = self.isp_patterns.get(isp_name)
            if cfg and cfg["generator"]:
                print(f"   ISP match '{isp_name}' — generating default candidates")
                candidates = cfg["generator"](ssid, bssid) or []
        return candidates

    def _xfinity_generator(self, ssid, bssid):
        return [
            "xfinity", "password", "admin", "12345678",
            "xfinity123", "xfinitywifi", "comcast123",
            "wireless", "homewifi", "password123",
        ]

    def _verizon_generator(self, ssid, bssid):
        serial = self._extract_serial(ssid)
        candidates = ["verizon", "admin", "password", "verizon123"]
        if serial:
            candidates.insert(0, serial)
            candidates.append(serial + "!")
            candidates.append(serial.lower())
        if bssid:
            last6 = bssid.replace(":", "")[-6:].upper()
            candidates.append(last6)
            candidates.append(last6.lower())
        return candidates

    def _att_generator(self, ssid, bssid):
        serial = self._extract_serial(ssid)
        candidates = [
            "attadmin", "wireless", "att1234", "password",
            "admin", "1234567890", "attwifi",
        ]
        if serial:
            candidates.insert(0, serial)
        if bssid:
            last8 = bssid.replace(":", "")[-8:].upper()
            candidates.append(last8)
            candidates.append(last8.lower())
        return candidates

    def _sky_generator(self, ssid, bssid):
        serial = self._extract_serial(ssid)
        candidates = [
            "sky", "admin", "password", "sky12345",
        ]
        if serial:
            candidates.insert(0, serial)
        if bssid:
            partial = bssid.replace(":", "")[6:12].upper()
            candidates.append(partial)
            candidates.append(partial.lower())
        return candidates

    def _virgin_generator(self, ssid, bssid):
        serial = self._extract_serial(ssid)
        candidates = [
            "virginmedia", "changeme", "password", "admin",
            "virgin123", "vm12345",
        ]
        if serial:
            candidates.insert(0, serial)
        if bssid:
            last6 = bssid.replace(":", "")[-6:].upper()
            candidates.append(last6)
        return candidates

    def _bt_generator(self, ssid, bssid):
        candidates = ["admin", "password", "bt12345", "bthomehub"]
        serial = self._extract_serial(ssid)
        if serial:
            candidates.insert(0, serial)
            candidates.insert(0, serial.lower())
        if bssid:
            last8 = bssid.replace(":", "")[-8:].upper()
            candidates.append(last8)
        return candidates

    def _livebox_generator(self, ssid, bssid):
        candidates = ["admin", "password"]
        serial = self._extract_serial(ssid)
        if serial:
            candidates.insert(0, serial)
        if bssid:
            last6 = bssid.replace(":", "")[-6:].upper()
            candidates.append(last6)
            candidates.append("livebox" + last6)
            candidates.append(last6.lower())
        return candidates

    def _tplink_generator(self, ssid, bssid):
        candidates = [
            "admin", "password", "12345678", "admin123",
        ]
        if bssid:
            last6 = bssid.replace(":", "")[-6:].upper()
            candidates.insert(0, last6)
            candidates.append("tp-link" + last6)
        return candidates

    def _netgear_generator(self, ssid, bssid):
        candidates = ["password", "admin", "12345678", "netgear1"]
        if bssid:
            last6 = bssid.replace(":", "")[-6:].upper()
            candidates.insert(0, last6)
            candidates.append("netgear" + last6)
        return candidates

    def _dlink_generator(self, ssid, bssid):
        candidates = ["admin", "1234567890", "password"]
        serial = self._extract_serial(ssid)
        if serial:
            candidates.insert(0, serial)
        return candidates

    def _asus_generator(self, ssid, bssid):
        candidates = ["admin", "password", "12345678", "asus123"]
        if bssid:
            last6 = bssid.replace(":", "")[-6:].upper()
            candidates.insert(0, last6)
        return candidates

    def _huawei_generator(self, ssid, bssid):
        candidates = ["admin", "password", "1234567890"]
        serial = self._extract_serial(ssid)
        if serial:
            candidates.insert(0, serial)
        if bssid:
            last8 = bssid.replace(":", "")[-8:].upper()
            candidates.insert(0, last8)
        return candidates

    def _extract_serial(self, ssid):
        if not ssid:
            return None
        m = re.search(r"[/_\-](\w{4,})$", ssid)
        if m:
            return m.group(1)
        m = re.search(r"(\d{4,})$", ssid)
        if m:
            return m.group(1)
        return None

    def _load_leaked_db(self):
        try:
            if os.path.exists(CACHED_PW_PATH):
                with open(CACHED_PW_PATH) as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def pre_screen_oui(self, bssid, ssid):
        from intelligence.password_intelligence import PasswordIntelligence

        pi = PasswordIntelligence()
        oui_prefix = bssid[:8].upper() if len(bssid) >= 8 else ""
        vendor = pi.oui_db.get(oui_prefix)

        candidates = []
        if vendor:
            from intelligence.password_intelligence import ROUTER_DEFAULTS

            if vendor in ROUTER_DEFAULTS:
                candidates.extend(ROUTER_DEFAULTS[vendor])
                print(
                    f"   OUI vendor '{vendor}' — {len(ROUTER_DEFAULTS[vendor])} defaults queued"
                )
        return candidates

    def pre_screen_leaked_db(self, bssid):
        if bssid in self.leaked_db:
            print(f"   Leaked DB hit for {bssid}")
            return [self.leaked_db[bssid]]
        return []

    def build_priority_seeds(self, target):
        ssid = target.get("ssid", "") or ""
        bssid = target.get("bssid", "") or ""

        seeds = []
        seen = set()

        leaked = self.pre_screen_leaked_db(bssid)
        for pw in leaked:
            if pw not in seen:
                seen.add(pw)
                seeds.append(("leaked_db", pw))

        isp_candidates = self.generate_isp_candidates(ssid, bssid)
        for pw in isp_candidates:
            if pw not in seen:
                seen.add(pw)
                seeds.append(("isp_default", pw))

        oui_candidates = self.pre_screen_oui(bssid, ssid)
        for pw in oui_candidates:
            if pw not in seen:
                seen.add(pw)
                seeds.append(("vendor_default", pw))

        return seeds
