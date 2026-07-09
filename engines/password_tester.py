# File: engines/password_tester.py
import re
import subprocess
import tempfile
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from core.error_handler import ErrorHandler

class PasswordTester:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.tested_count = 0
        self.found_password = None
        self.handshake_file = None
        self.testing_speed = 0
        
    def setup_handshake_test(self, handshake_file):
        """Setup for handshake-based password testing"""
        self.handshake_file = handshake_file
        if not os.path.exists(handshake_file):
            return False
        return True
    
    def bulk_test_passwords_parallel(self, target_bssid, password_generator, max_tests=1000000, batch_size=5000, workers=4):
        """
        Test passwords in parallel using multiple processes.
        """
        print(f"🚀 Parallel Cracking Active: {workers} workers | Batch size: {batch_size}")
        
        start_time = time.time()
        
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = []
            batch = []
            
            for password in password_generator:
                if self.found_password or self.tested_count >= max_tests:
                    break
                
                batch.append(password)
                
                if len(batch) >= batch_size:
                    futures.append(executor.submit(
                        self._test_batch_static, 
                        target_bssid, 
                        batch, 
                        self.handshake_file
                    ))
                    batch = []
                    
                    if len(futures) >= workers * 2:
                        self._process_completed_futures(futures)

            if batch and not self.found_password:
                futures.append(executor.submit(self._test_batch_static, target_bssid, batch, self.handshake_file))
            
            self._process_completed_futures(futures, wait=True)

        return self.found_password is not None

    def _process_completed_futures(self, futures, wait=False):
        """Check completed tasks and update state"""
        if not futures:
            return

        if wait:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found_password = result
                self.tested_count += 5000 
            futures.clear()
        else:
            for f in futures[:]:
                if f.done():
                    result = f.result()
                    if result:
                        self.found_password = result
                    self.tested_count += 5000
                    futures.remove(f)

    @staticmethod
    def _test_batch_static(target_bssid, passwords, handshake_file):
        """Static method for worker processes"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                for pw in passwords:
                    temp_file.write(pw + '\n')
                temp_file.flush()
                
                cmd = ['aircrack-ng', '-b', target_bssid, '-w', temp_file.name, handshake_file]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                os.unlink(temp_file.name)
                
                if 'KEY FOUND' in process.stdout:
                    match = re.search(r'KEY FOUND.*?\[(.*?)\]', process.stdout)
                    return match.group(1) if match else True
            return None
        except:
            return None

    def bulk_test_passwords_stream(self, target_bssid, password_generator, max_tests=1000000, batch_size=1000):
        """
        Test multiple passwords in batches (Synchronous Stream)
        """
        print(f"🎯 Starting sequential password testing on {target_bssid}...")
        start_time = time.time()
        batch_passwords = []
        
        for password in password_generator:
            if self.tested_count >= max_tests or self.found_password:
                break
                
            batch_passwords.append(password)
            
            if len(batch_passwords) >= batch_size:
                if self._test_password_batch(target_bssid, batch_passwords):
                    return True
                
                self.tested_count += len(batch_passwords)
                batch_passwords = []
                
                elapsed = time.time() - start_time
                speed = self.tested_count / elapsed if elapsed > 0 else 0
                print(f"   🔄 Progress: {self.tested_count:,} tests | Speed: {speed:.1f} p/s", end='\r')
        
        if batch_passwords and not self.found_password:
            self._test_password_batch(target_bssid, batch_passwords)
            self.tested_count += len(batch_passwords)
            
        return self.found_password is not None

    def _test_password_batch(self, target_bssid, passwords):
        """
        Test a batch of passwords using a temporary file (Synchronous)
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                for password in passwords:
                    temp_file.write(password + '\n')
                temp_file.flush()
                
                cmd = ['aircrack-ng', '-b', target_bssid, '-w', temp_file.name, self.handshake_file]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                os.unlink(temp_file.name)
                
                if 'KEY FOUND' in process.stdout:
                    match = re.search(r'KEY FOUND.*?\[(.*?)\]', process.stdout)
                    self.found_password = match.group(1) if match else True
                    return True
            return False
        except Exception as e:
            self.error_handler.handle_error('E302', f"Batch password test failed", e)
            return False
