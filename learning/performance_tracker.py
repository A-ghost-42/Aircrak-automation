# File: learning/performance_tracker.py
import json
import os
import time
from pathlib import Path

class PerformanceTracker:
    def __init__(self, config_manager):
        self.config = config_manager
        self.stats_path = Path.home() / '.pegasus_nexus' / 'stats'
        self.stats_file = self.stats_path / 'attack_stats.json'
        self.history = self._load_history()

    def _load_history(self):
        """Load attack history from file"""
        try:
            self.stats_path.mkdir(exist_ok=True, parents=True)
            if self.stats_file.exists():
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"⚠️ Failed to load stats: {e}")
            return []

    def record_attack(self, target, result):
        """Record the outcome of an attack for future learning"""
        entry = {
            'timestamp': time.time(),
            'ssid': target.get('ssid'),
            'bssid': target.get('bssid'),
            'success': result.get('success', False),
            'duration': result.get('duration', 0),
            'tested_count': result.get('tested_count', 0),
            'password_found': result.get('password') if result.get('success') else None,
            'attack_type': result.get('attack_type', 'handshake')
        }
        
        self.history.append(entry)
        self._save_history()
        print(f"📊 Performance recorded for {entry['ssid']}")

    def _save_history(self):
        """Save history to disk"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.history, f, indent=4)
        except Exception as e:
            print(f"⚠️ Failed to save stats: {e}")

    def get_success_patterns(self):
        """Analyze history to find successful patterns"""
        patterns = {}
        for entry in self.history:
            if entry['success'] and entry['password_found']:
                pw = entry['password_found']
                length = len(pw)
                # Simple pattern analysis
                pattern_type = 'complex'
                if pw.isdigit(): pattern_type = 'numeric'
                elif pw.isalpha(): pattern_type = 'alpha'
                
                key = f"{length}_{pattern_type}"
                patterns[key] = patterns.get(key, 0) + 1
        
        return sorted(patterns.items(), key=lambda x: x[1], reverse=True)
