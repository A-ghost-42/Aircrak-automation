# File: tools/hashcat_wrapper.py
import subprocess
import os
import re

class HashcatWrapper:
    """
    Python wrapper for hashcat with support for various attack modes and session management.
    """
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.bin_path = self.config.get('tools.hashcat_path', 'hashcat')
        self.session_name = "pegasus_session"

    def convert_cap_to_hcxpcapng(self, cap_file, output_hcx):
        """Convert .cap file to .hcxpcapng using hcxpcapngtool"""
        try:
            cmd = ['hcxpcapngtool', '-o', output_hcx, cap_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            self.error_handler.handle_error('T002', "hcxpcapngtool not found. Install hcxtools.")
            return False

    def run_dictionary_attack(self, hash_file, wordlist, workload="2"):
        """Run a standard dictionary attack (Mode 0)"""
        cmd = [
            self.bin_path,
            '-m', '22000', # WPA-PBKDF2-PMKID+EAPOL
            '-a', '0',     # Straight mode
            '-w', workload,
            '--session', self.session_name,
            hash_file,
            wordlist
        ]
        return self._execute_hashcat(cmd)

    def run_mask_attack(self, hash_file, mask, workload="2"):
        """Run a mask attack (Mode 3)"""
        cmd = [
            self.bin_path,
            '-m', '22000',
            '-a', '3',     # Mask mode
            '-w', workload,
            hash_file,
            mask
        ]
        return self._execute_hashcat(cmd)

    def _execute_hashcat(self, cmd):
        """Execute hashcat command and return process handle"""
        try:
            # Add --force if running in a virtualized or limited environment
            if self.config.get('system.force_hashcat', False):
                cmd.append('--force')
                
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return process
        except Exception as e:
            self.error_handler.handle_error('T002', f"Hashcat execution failed: {e}")
            return None

    def get_status(self, stdout_line):
        """Parse progress from hashcat status output"""
        # Example: [S]tatus [P]ause [R]esume [B]ye
        # This is complex in Popen; usually hashcat is polled for status.
        progress_match = re.search(r"Progress\.+:\s+(\d+/\d+)\s+\((\d+\.\d+)%\)", stdout_line)
        if progress_match:
            return {
                'counts': progress_match.group(1),
                'percentage': progress_match.group(2)
            }
        return None

    def get_cracked_key(self, hash_file):
        """Retrieve cracked key from hashcat show command"""
        cmd = [self.bin_path, '-m', '22000', '--show', hash_file]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.stdout:
                # Output format: hash:password
                parts = result.stdout.strip().split(':')
                if len(parts) >= 2:
                    return parts[-1]
            return None
        except Exception as e:
            self.error_handler.handle_error('T002', f"Hashcat show failed: {e}")
            return None
