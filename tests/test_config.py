import sys
import os
import json
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config


def test_config_directory_creation():
    config = Config()
    assert config.config_path is not None
    assert config.config_file is not None


def test_config_load_creates_default():
    with tempfile.TemporaryDirectory() as td:
        config_dir = Path(td) / ".pegasus_nexus"
        config = Config()
        config.config_path = config_dir
        config.config_file = config_dir / "config.json"
        cfg = config.load_configuration()
        assert "system" in cfg
        assert cfg["system"]["interface"] == "wlan0"


def test_config_persists():
    with tempfile.TemporaryDirectory() as td:
        config_dir = Path(td) / ".pegasus_nexus"
        config = Config()
        config.config_path = config_dir
        config.config_file = config_dir / "config.json"
        config.load_configuration()
        config.current_config["system"]["interface"] = "wlan1"
        config._save_configuration()
        config2 = Config()
        config2.config_path = config_dir
        config2.config_file = config_dir / "config.json"
        cfg2 = config2.load_configuration()
        config.current_config["system"]["interface"] = "wlan1"


def test_config_get_nested():
    config = Config()
    config.load_configuration()
    val = config.get("streaming.default_charsets")
    assert isinstance(val, list)
    assert "numeric" in val


def test_config_get_int():
    config = Config()
    config.load_configuration()
    val = config.get_int("system.max_parallel_attacks", 1)
    assert isinstance(val, int)


def test_config_get_int_fallback():
    config = Config()
    val = config.get_int("nonexistent.key", 42)
    assert val == 42
