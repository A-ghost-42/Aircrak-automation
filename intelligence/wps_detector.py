# File: intelligence/wps_detector.py
import subprocess
import re
import time

class WPSDetector:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        
    def detect_wps_status(self, target_bssid, interface='wlan0'):
        """
        Detect WPS status for a specific target using wash
        """
        # Silently check if we should even bother
        try:
            # Use wash to scan for WPS-enabled networks
            # We'll use a shorter timeout and multiple attempts for better reliability
            cmd = [
                'sudo', 'wash', '-i', interface,
                '--ignore-fcs', '-n', '5' # Scan 5 channels/packets
            ]
            
            # Use a longer timeout for the subprocess call
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=20
            )
            
            if process.returncode == 0:
                return self._parse_wash_output(process.stdout, target_bssid)
            return 'not_detected'
                
        except subprocess.TimeoutExpired:
            # Don't trigger a full system error for a single target timeout
            print(f"   ⚠️  WPS probe timed out for {target_bssid} - skipping")
            return 'timeout'
        except Exception as e:
            # Log as warning, not system-stopping error
            print(f"   ⚠️  WPS probe failed: {e}")
            return 'unknown'
    
    def _parse_wash_output(self, wash_output, target_bssid):
        """
        Parse wash output to find WPS status for specific BSSID
        """
        lines = wash_output.split('\n')
        
        for line in lines:
            if target_bssid.lower() in line.lower():
                parts = line.split()
                # Typical wash output: BSSID Ch RSSI WPS Locked Vendor ESSID
                if len(parts) >= 5:
                    # Look for Locked status (usually 'Yes' or 'No' or '0'/'1')
                    for i, part in enumerate(parts):
                        if part in ['Yes', 'No']:
                            return 'locked' if part == 'Yes' else 'unlocked'
                return 'detected' # Generic detected if we can't be sure about lock
        
        return 'not_detected'
    
    def bulk_detect_wps(self, targets, interface='wlan0'):
        """
        Detect WPS status for multiple targets efficiently
        """
        print("🔍 Performing bulk WPS detection...")
        
        updated_targets = []
        detected_count = 0
        
        # Only scan once for all targets to be more efficient
        try:
            cmd = ['sudo', 'timeout', '15', 'wash', '-i', interface, '--ignore-fcs']
            process = subprocess.run(cmd, capture_output=True, text=True)
            wash_results = process.stdout if process.returncode == 0 else ""
        except:
            wash_results = ""

        for target in targets:
            # Only check WPS for likely candidates (Routers)
            if target['ssid_pattern'] in ['default_router', 'isp_provided', 'personal_network']:
                if wash_results:
                    wps_status = self._parse_wash_output(wash_results, target['bssid'])
                else:
                    # Fallback to individual probe if bulk failed
                    wps_status = 'unknown'
                
                target['wps_status'] = wps_status
                
                if wps_status == 'unlocked':
                    detected_count += 1
                    target['success_probability'] = min(0.9, target['success_probability'] * 1.5)
            else:
                target['wps_status'] = 'not_applicable'
            
            updated_targets.append(target)
        
        print(f"✅ WPS detection complete. Identified {detected_count} viable WPS targets.")
        return updated_targets
