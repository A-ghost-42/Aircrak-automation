# File: tools/aircrack_wrapper.py
import subprocess
import re
import os
import time

class AircrackWrapper:
    """
    Python wrapper for aircrack-ng with robust output parsing and process management.
    """
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.bin_path = self.config.get('tools.aircrack_path', 'aircrack-ng')

    def verify_handshake(self, cap_file, bssid=None):
        """Verify if a capture file contains a valid handshake"""
        cmd = [self.bin_path, cap_file]
        if bssid:
            cmd.extend(['-b', bssid])
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            # aircrack-ng output contains 'WPA (1 handshake)' if valid
            if '1 handshake' in result.stdout or '1 handshake' in result.stderr:
                return True
            return False
        except Exception as e:
            self.error_handler.handle_error('T001', f"Aircrack verification failed: {e}")
            return False

    def run_attack(self, cap_file, bssid, wordlist_path=None, stdin_mode=False):
        """Run a standard aircrack-ng attack"""
        cmd = [
            self.bin_path,
            '-b', bssid,
            cap_file
        ]
        
        if stdin_mode:
            cmd.extend(['-w', '-'])
        elif wordlist_path:
            cmd.extend(['-w', wordlist_path])
        else:
            raise ValueError("Either wordlist_path must be provided or stdin_mode must be True")

        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_mode else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return process
        except Exception as e:
            self.error_handler.handle_error('T001', f"Aircrack attack initiation failed: {e}")
            return None

    def parse_output(self, output):
        """Parse aircrack-ng output to find the key"""
        # Look for the classic [ KEY FOUND! [ password ] ]
        match = re.search(r"KEY FOUND! \[ (.*?) \]", output)
        if match:
            return match.group(1)
        
        # Alternative pattern check
        match = re.search(r"Master Key\s+:\s+([A-F0-9\s]+)", output)
        if match:
            return match.group(1).replace(" ", "")
            
        return None

    def get_version(self):
        """Get aircrack-ng version"""
        try:
            result = subprocess.run([self.bin_path], capture_output=True, text=True)
            first_line = result.stdout.split('\n')[0] or result.stderr.split('\n')[0]
            return first_line.strip()
        except:
            return "Unknown"
