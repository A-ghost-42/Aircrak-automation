import os
import json
from pathlib import Path


ENV_PREFIX = "PEGASUS_"

ENV_MAP = {
    "PEGASUS_INTERFACE": ("interface", str),
    "PEGASUS_OUTPUT_DIR": ("output_dir", str),
    "PEGASUS_LOG_LEVEL": ("log_level", str),
    "PEGASUS_LOG_FILE": ("log_file", str),
    "PEGASUS_LOG_MAX_MB": ("log_max_mb", int),
    "PEGASUS_LOG_BACKUPS": ("log_backups", int),
    "PEGASUS_TIMEOUT": ("timeout", int),
    "PEGASUS_MIN_SIGNAL": ("min_signal", int),
    "PEGASUS_CACHE_DIR": ("cache_dir", str),
    "PEGASUS_AIRCRACK_PATH": ("aircrack_path", str),
    "PEGASUS_HASHCAT_PATH": ("hashcat_path", str),
    "PEGASUS_CRUNCH_PATH": ("crunch_path", str),
}


class Config:
    def __init__(self):
        self.config_path = Path.home() / ".pegasus_nexus"
        self.config_file = self.config_path / "config.json"
        self.default_config = self._build_defaults()
        self.current_config = {}

    def _build_defaults(self):
        return {
            "system": {
                "max_parallel_attacks": 3,
                "operation_timeout": int(os.environ.get("PEGASUS_TIMEOUT", "3600")),
                "memory_limit_mb": 4096,
                "log_level": os.environ.get("PEGASUS_LOG_LEVEL", "INFO"),
                "log_file": os.environ.get("PEGASUS_LOG_FILE", "pegasus_nexus.log"),
                "log_max_mb": int(os.environ.get("PEGASUS_LOG_MAX_MB", "10")),
                "log_backups": int(os.environ.get("PEGASUS_LOG_BACKUPS", "5")),
                "interface": os.environ.get("PEGASUS_INTERFACE", "wlan0"),
                "output_dir": os.environ.get("PEGASUS_OUTPUT_DIR", "."),
                "cache_dir": os.environ.get("PEGASUS_CACHE_DIR", str(Path.home() / ".pegasus_nexus" / "scans")),
                "min_signal": int(os.environ.get("PEGASUS_MIN_SIGNAL", "-80")),
            },
            "streaming": {
                "max_password_length": 16,
                "default_charsets": ["numeric", "lowercase", "alphanumeric"],
                "batch_size": 1000,
            },
            "tools": {
                "aircrack_path": os.environ.get("PEGASUS_AIRCRACK_PATH", "/usr/bin/aircrack-ng"),
                "hashcat_path": os.environ.get("PEGASUS_HASHCAT_PATH", "/usr/bin/hashcat"),
                "crunch_path": os.environ.get("PEGASUS_CRUNCH_PATH", "/usr/bin/crunch"),
            },
            "learning": {
                "population_size": 25,
                "mutation_rate": 0.15,
                "elitism_count": 5,
            },
        }

    def _apply_env_overrides(self, cfg):
        system_keys = {"interface", "output_dir", "log_level", "log_file",
                        "log_max_mb", "log_backups", "timeout", "min_signal", "cache_dir"}
        int_keys = {"log_max_mb", "log_backups", "timeout", "min_signal"}

        for env_var, (cfg_key, cast) in ENV_MAP.items():
            val = os.environ.get(env_var)
            if val is None:
                continue
            if cfg_key in system_keys:
                cfg["system"][cfg_key] = int(val) if cfg_key in int_keys else val
            elif cfg_key in {"aircrack_path", "hashcat_path", "crunch_path"}:
                cfg["tools"][cfg_key] = val
        return cfg

    def load_configuration(self):
        try:
            self.config_path.mkdir(parents=True, exist_ok=True)

            if self.config_file.exists():
                with open(self.config_file) as f:
                    self.current_config = json.load(f)
            else:
                self.current_config = self.default_config
                self._save_configuration()

            self.current_config = self._apply_env_overrides(self.current_config)
        except Exception:
            self.current_config = self.default_config
        return self.current_config

    def _save_configuration(self):
        try:
            with open(self.config_file, "w") as f:
                json.dump(self.current_config, f, indent=4)
        except OSError:
            pass

    def get(self, key_path, default=None):
        keys = key_path.split(".")
        value = self.current_config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def get_int(self, key_path, default=0):
        v = self.get(key_path, default)
        try:
            return int(v)
        except (TypeError, ValueError):
            return default
