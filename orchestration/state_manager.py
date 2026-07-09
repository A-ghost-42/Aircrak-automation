# File: orchestration/state_manager.py
import json
import time
from pathlib import Path

class StateManager:
    """
    Manages the global state of the Pegasus-Nexus orchestration.
    Tracks discovered targets, active attacks, and captured credentials.
    """
    def __init__(self, config_manager):
        self.config = config_manager
        self.state_path = Path.home() / '.pegasus_nexus' / 'state'
        self.state_file = self.state_path / 'session_state.json'
        
        self.targets = {}
        self.active_attacks = []
        self.credentials = []
        self.session_start_time = time.time()
        
        self._initialize_storage()

    def _initialize_storage(self):
        """Ensure state storage directory exists"""
        self.state_path.mkdir(exist_ok=True, parents=True)
        if self.state_file.exists():
            self.load_state()

    def update_target(self, bssid, target_data):
        """Update or add a target to the state"""
        if bssid not in self.targets:
            self.targets[bssid] = {
                'first_seen': time.time(),
                'attacks_attempted': 0,
                'status': 'discovered'
            }
        
        self.targets[bssid].update(target_data)
        self.targets[bssid]['last_seen'] = time.time()
        self.save_state()

    def record_attack_start(self, bssid, attack_type):
        """Record the start of an attack"""
        if bssid in self.targets:
            self.targets[bssid]['status'] = 'attacking'
            self.targets[bssid]['attacks_attempted'] += 1
            self.targets[bssid]['last_attack_type'] = attack_type
            self.active_attacks.append({
                'bssid': bssid,
                'type': attack_type,
                'start_time': time.time()
            })
            self.save_state()

    def record_attack_end(self, bssid, success, password=None):
        """Record the end of an attack"""
        if bssid in self.targets:
            if success:
                self.targets[bssid]['status'] = 'compromised'
                if password:
                    self.add_credential(self.targets[bssid].get('ssid'), bssid, password)
            else:
                self.targets[bssid]['status'] = 'failed'
            
            # Remove from active attacks
            self.active_attacks = [a for a in self.active_attacks if a['bssid'] != bssid]
            self.save_state()

    def add_credential(self, ssid, bssid, password):
        """Add a discovered credential"""
        cred = {
            'ssid': ssid,
            'bssid': bssid,
            'password': password,
            'timestamp': time.time()
        }
        if cred not in self.credentials:
            self.credentials.append(cred)
            print(f"🔑 StateManager: New credential added for {ssid}")
            self.save_state()

    def save_state(self):
        """Persist state to disk"""
        state = {
            'session_start': self.session_start_time,
            'targets': self.targets,
            'active_attacks': self.active_attacks,
            'credentials': self.credentials,
            'last_updated': time.time()
        }
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=4)
        except Exception as e:
            print(f"⚠️ StateManager Error: Failed to save state: {e}")

    def load_state(self):
        """Load state from disk"""
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                self.targets = state.get('targets', {})
                self.credentials = state.get('credentials', [])
                # Don't resume active attacks automatically for safety
        except Exception as e:
            print(f"⚠️ StateManager Error: Failed to load state: {e}")

    def get_summary(self):
        """Get a summary of the current session state"""
        return {
            'total_targets': len(self.targets),
            'compromised': len(self.credentials),
            'active_attacks': len(self.active_attacks),
            'uptime': time.time() - self.session_start_time
        }
