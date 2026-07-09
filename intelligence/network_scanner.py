# File: intelligence/network_scanner.py
import subprocess
import re
import time
import os
import csv
from pathlib import Path
from core.error_handler import ErrorHandler

class NetworkScanner:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.scan_results = []
        
    def perform_network_scan(self, interface='wlan0mon', duration=15):
        """
        Perform wireless network scan using airodump-ng with better error handling
        """
        print(f"📡 Scanning for networks on {interface}...")
        
        try:
            # Clean up any previous scan files
            self._cleanup_scan_files()
            
            # Start airodump-ng scan
            csv_file = '/tmp/pegasus_scan-01.csv'
            
            cmd = [
                'sudo', 'airodump-ng',
                '--write', '/tmp/pegasus_scan',
                '--output-format', 'csv',
                '--write-interval', '2',
                interface
            ]
            
            print(f"   🎯 Running: {' '.join(cmd)}")
            print(f"   ⏱️  Scanning for {duration} seconds...")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Let it run for specified duration with progress updates
            for i in range(duration):
                time.sleep(1)
                if i % 5 == 0:  # Progress update every 5 seconds
                    print(f"   🔄 Scanning... {i+1}/{duration} seconds")
            
            # Terminate the process
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            
            # Check if CSV file was created
            if not os.path.exists(csv_file):
                print(f"   ❌ Scan file not found: {csv_file}")
                print("   💡 Checking for alternative file names...")
                
                # Look for any CSV files in /tmp
                csv_files = list(Path('/tmp').glob('pegasus_scan*.csv'))
                if csv_files:
                    csv_file = str(csv_files[0])
                    print(f"   ✅ Found alternative file: {csv_file}")
                else:
                    self.error_handler.handle_error('E201', f"No scan files created. Check if {interface} is in monitor mode.")
                    return []
            
            # Parse results
            self.scan_results = self._parse_scan_results(csv_file)
            
            print(f"✅ Found {len(self.scan_results)} networks")
            
            # Display quick summary
            if self.scan_results:
                self._display_quick_summary()
            
            return self.scan_results
            
        except Exception as e:
            self.error_handler.handle_error('E200', f"Network scan failed on {interface}", e)
            return []
    
    def _cleanup_scan_files(self):
        """Clean up previous scan files"""
        try:
            for file in Path('/tmp').glob('pegasus_scan*'):
                try:
                    file.unlink()
                    print(f"   🧹 Cleaned up: {file}")
                except:
                    pass
        except Exception as e:
            print(f"   ⚠️  Cleanup warning: {e}")
    
    def _parse_scan_results(self, csv_file):
        """
        Parse airodump-ng CSV output with robust error handling
        """
        networks = []
        
        try:
            print(f"   📖 Parsing scan results from: {csv_file}")
            
            # Read the entire file first to understand structure
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip():
                print("   ❌ Empty scan file")
                return []
            
            lines = content.split('\n')
            print(f"   🔍 File has {len(lines)} lines")
            
            # Debug: Show file structure
            print("   📄 File structure analysis:")
            for i, line in enumerate(lines[:8]):  # Show first 8 lines
                if line.strip():
                    print(f"      {i+1}: {line[:100]}{'...' if len(line) > 100 else ''}")
            
            # Reset file pointer and use CSV reader
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                csv_reader = csv.reader(f)
                rows = list(csv_reader)
            
            if not rows:
                print("   ❌ No rows in CSV file")
                return []
            
            # Find the start of network data
            network_start = 0
            for i, row in enumerate(rows):
                if len(row) > 0 and 'BSSID' in row[0]:
                    network_start = i + 1
                    print(f"   ✅ Found network header at row {i+1}")
                    break
            
            # Parse network entries
            networks_found = 0
            for i in range(network_start, len(rows)):
                row = rows[i]
                
                # Skip empty rows
                if not row or len(row) < 5:
                    continue
                
                # Check if we've reached the client section
                if len(row) > 0 and 'Station MAC' in row[0]:
                    print(f"   🔚 Reached client section at row {i+1}")
                    break
                
                # Parse network data
                network = self._parse_network_row(row)
                if network and network.get('bssid') and network.get('ssid') is not None:
                    networks.append(network)
                    networks_found += 1
            
            print(f"   ✅ Successfully parsed {networks_found} networks")
                        
        except FileNotFoundError:
            self.error_handler.handle_error('E201', f"Scan file not found: {csv_file}")
        except Exception as e:
            self.error_handler.handle_error('E201', f"Failed to parse scan results: {str(e)}", e)
            print(f"   🐛 Debug: Exception type: {type(e).__name__}")
            
        return networks
    
    def _parse_network_row(self, row):
        """Parse a single network row from airodump-ng CSV"""
        try:
            # Airodump-ng CSV format typically has:
            # BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
            
            if len(row) < 14:
                return None
            
            bssid = row[0].strip()
            if not bssid or len(bssid) != 17:  # MAC address should be 17 chars
                return None
            
            # SSID might be in different positions, try common ones
            ssid = ""
            if len(row) >= 14:
                ssid = row[13].strip()
            elif len(row) >= 10:
                ssid = row[9].strip()
            
            # Skip hidden networks if desired, but include them for now
            if not ssid:
                ssid = "<hidden>"
            
            # Parse signal strength (Power)
            signal_str = row[8].strip().replace(' dBm', '') if len(row) > 8 and row[8].strip() else '-100'
            try:
                signal = int(signal_str)
            except:
                signal = -100
            
            # Parse channel
            channel_str = row[3].strip() if len(row) > 3 and row[3].strip() else '1'
            try:
                channel = int(channel_str)
            except:
                channel = 1
            
            # Parse encryption
            encryption_str = row[5].strip() if len(row) > 5 else ''
            encryption = self._parse_encryption(encryption_str)
            
            # Parse client count (simplified - airodump doesn't directly provide this in CSV)
            clients = 0
            if len(row) > 9:
                try:
                    # This is actually IV count, not client count, but we'll use it as indicator
                    iv_count = int(row[9].strip()) if row[9].strip() else 0
                    clients = 1 if iv_count > 0 else 0
                except:
                    clients = 0
            
            network = {
                'bssid': bssid,
                'ssid': ssid,
                'signal': signal,
                'channel': channel,
                'encryption': encryption,
                'clients': clients,
                'encryption_raw': encryption_str
            }
            
            # Debug output for first few networks
            if len(self.scan_results) < 3:
                print(f"   📝 Sample network: {ssid} ({bssid}) - {encryption} - {signal} dBm")
            
            return network
            
        except Exception as e:
            print(f"   ⚠️  Failed to parse network row: {e}")
            print(f"   🐛 Row data: {row}")
            return None
    
    def _parse_encryption(self, encryption_str):
        """Parse encryption type from airodump output"""
        encryption_str = encryption_str.upper()
        
        if 'WPA2' in encryption_str:
            return 'WPA2'
        elif 'WPA' in encryption_str:
            return 'WPA'
        elif 'WEP' in encryption_str:
            return 'WEP'
        elif 'OPN' in encryption_str or encryption_str == '':
            return 'OPEN'
        else:
            return 'UNKNOWN'
    
    def _display_quick_summary(self):
        """Display quick summary of found networks"""
        if not self.scan_results:
            return
            
        print("\n📊 NETWORK SCAN SUMMARY:")
        print("-" * 50)
        
        # Group by encryption
        encryption_stats = {}
        for network in self.scan_results:
            enc = network['encryption']
            encryption_stats[enc] = encryption_stats.get(enc, 0) + 1
        
        for enc, count in encryption_stats.items():
            print(f"   🔒 {enc}: {count} networks")
        
        # Show strongest signals
        strong_networks = sorted(self.scan_results, key=lambda x: x['signal'], reverse=True)[:5]
        print(f"\n   📶 Top 5 strongest signals:")
        for network in strong_networks:
            print(f"      • {network['ssid']} ({network['signal']} dBm) - {network['encryption']}")
    
    def get_network_summary(self):
        """Get summary of scanned networks"""
        if not self.scan_results:
            return "No networks scanned"
            
        encryption_types = {}
        for network in self.scan_results:
            enc = network['encryption']
            encryption_types[enc] = encryption_types.get(enc, 0) + 1
            
        summary = f"Networks: {len(self.scan_results)} | "
        summary += " | ".join([f"{k}: {v}" for k, v in encryption_types.items()])
        
        return summary