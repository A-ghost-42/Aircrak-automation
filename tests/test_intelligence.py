import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from intelligence.password_intelligence import (
    PasswordIntelligence,
    MarkovChain,
    ROUTER_DEFAULTS,
    COMMON_WIFI_PASSWORDS,
)


class TestRouterDefaults:
    def test_at_least_20_vendors(self):
        assert len(ROUTER_DEFAULTS) >= 20

    def test_tp_link_has_defaults(self):
        assert len(ROUTER_DEFAULTS.get("tp-link", [])) > 0
        assert "admin" in ROUTER_DEFAULTS["tp-link"]

    def test_netgear_has_defaults(self):
        assert len(ROUTER_DEFAULTS.get("netgear", [])) > 0
        assert "password" in ROUTER_DEFAULTS["netgear"]


class TestCommonPasswords:
    def test_at_least_50_entries(self):
        assert len(COMMON_WIFI_PASSWORDS) >= 50

    def test_includes_common(self):
        assert "12345678" in COMMON_WIFI_PASSWORDS
        assert "password" in COMMON_WIFI_PASSWORDS


class TestMarkovChain:
    def test_init(self):
        mc = MarkovChain(order=2)
        assert mc.order == 2
        assert not mc._trained

    def test_train_and_generate(self):
        mc = MarkovChain(order=2)
        mc.train(["password123", "admin123", "12345678"])
        assert mc._trained
        pw = mc.generate(min_len=8, max_len=12)
        assert pw is None or len(pw) >= 8

    def test_generate_many(self):
        mc = MarkovChain(order=2)
        mc.train(["password123", "admin12345", "12345678",
                   "qwerty123", "letmein1", "sunshine1",
                   "Password123", "Admin123!", "Welcome1"])
        results = mc.generate_many(count=20, min_len=8, max_len=14)
        assert len(results) <= 20
        for pw in results:
            assert len(pw) >= 8

    def test_generate_no_training(self):
        mc = MarkovChain(order=2)
        assert mc.generate() is None


class TestPasswordIntelligence:
    def test_init(self):
        pi = PasswordIntelligence()
        assert pi.markov is not None
        assert pi.markov._trained

    def test_extract_seeds_tp_link(self):
        pi = PasswordIntelligence()
        seeds = pi.extract_seeds_from_target({
            "ssid": "TP-Link_ABC",
            "bssid": "00:09:5B:12:34:56",
        })
        assert len(seeds) > 0
        assert "admin" in seeds

    def test_extract_seeds_netgear(self):
        pi = PasswordIntelligence()
        seeds = pi.extract_seeds_from_target({
            "ssid": "Netgear42",
            "bssid": "00:14:6C:AB:CD:EF",
        })
        assert len(seeds) > 0
        assert "password" in seeds

    def test_extract_seeds_unknown(self):
        pi = PasswordIntelligence()
        seeds = pi.extract_seeds_from_target({
            "ssid": "MyHomeWiFi",
            "bssid": "AA:BB:CC:DD:EE:FF",
        })
        assert isinstance(seeds, list)

    def test_extract_seeds_guest(self):
        pi = PasswordIntelligence()
        seeds = pi.extract_seeds_from_target({
            "ssid": "Guest_Network",
            "bssid": "00:11:22:33:44:55",
        })
        assert "guest1234" in seeds

    def test_generate_attack_plan(self):
        pi = PasswordIntelligence()
        plan = pi.generate_attack_plan({
            "ssid": "Home_Network",
            "bssid": "00:11:22:33:44:55",
            "signal_strength": -65,
        })
        assert "phases" in plan
        assert len(plan["phases"]) >= 3
        assert plan["seeds"] is not None
        assert plan["time_budget"] > 0
        assert plan["signal_quality"] > 0

    def test_attack_plan_phase_names(self):
        pi = PasswordIntelligence()
        plan = pi.generate_attack_plan({
            "ssid": "Test",
            "bssid": "00:11:22:33:44:55",
            "signal_strength": -60,
        })
        names = [p["name"] for p in plan["phases"]]
        assert "defaults_and_seeds" in names
        assert "common_passwords" in names
        assert "markov_generation" in names
        assert "genetic_evolution" in names

    def test_attack_plan_weak_signal(self):
        pi = PasswordIntelligence()
        plan = pi.generate_attack_plan({
            "ssid": "Test",
            "bssid": "00:11:22:33:44:55",
            "signal_strength": -90,
        })
        assert plan["signal_quality"] <= 0.5
        names = [p["name"] for p in plan["phases"]]
        assert "smart_bruteforce" not in names

    def test_classify_ssid_default_router(self):
        pi = PasswordIntelligence()
        assert pi._classify_ssid("tp-link_xyz") == "default_router"
        assert pi._classify_ssid("netgear42") == "default_router"

    def test_classify_ssid_isp(self):
        pi = PasswordIntelligence()
        assert pi._classify_ssid("bthomehub-1234") == "isp_provided"
        assert pi._classify_ssid("virgin_media") == "isp_provided"

    def test_classify_ssid_business(self):
        pi = PasswordIntelligence()
        assert pi._classify_ssid("office_network") == "business_network"

    def test_classify_ssid_mobile(self):
        pi = PasswordIntelligence()
        assert pi._classify_ssid("iphone_de_ana") == "mobile_hotspot"
        assert pi._classify_ssid("android_hotspot") == "mobile_hotspot"
