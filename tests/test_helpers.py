import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import _signal_bar, _safe_input, _countdown
from core.config import Config
from core.error_handler import ErrorHandler


def test_signal_bar_strong():
    assert _signal_bar(-30) == "++++"
    assert _signal_bar(-50) == "++++"


def test_signal_bar_good():
    assert _signal_bar(-55) == "+++."
    assert _signal_bar(-60) == "+++."


def test_signal_bar_fair():
    assert _signal_bar(-65) == "++.."
    assert _signal_bar(-70) == "++.."


def test_signal_bar_weak():
    assert _signal_bar(-75) == "+..."
    assert _signal_bar(-80) == "+..."


def test_signal_bar_very_weak():
    assert _signal_bar(-90) == "...."


def test_config_defaults():
    config = Config()
    cfg = config.load_configuration()
    assert "system" in cfg
    assert "streaming" in cfg
    assert "tools" in cfg
    assert "learning" in cfg


def test_config_get():
    config = Config()
    config.load_configuration()
    assert config.get("system.log_level") is not None


def test_config_get_default():
    config = Config()
    assert config.get("nonexistent.key", "fallback") == "fallback"


def test_error_handler_init():
    config = Config()
    config.load_configuration()
    handler = ErrorHandler(config)
    assert handler.error_log == []


def test_error_handler_handle():
    config = Config()
    config.load_configuration()
    handler = ErrorHandler(config)
    eid = handler.handle_error("E001", "test context")
    assert isinstance(eid, int)
    assert len(handler.error_log) == 1
    assert handler.error_log[0]["code"] == "E001"
