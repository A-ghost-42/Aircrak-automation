# File: intelligence/monitor_manager.py
import os
import subprocess
import time
import re

class MonitorModeManager:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.monitor_interfaces = []
        
    def setup_monitor_mode(self, interface='wlan0'):
        """
        Set up monitor mode on specified interface
        """
        print(f"📡 Setting up monitor mode on {interface}...")
        
        try:
            # Step 1: Kill conflicting processes
            self._kill_conflicting_processes()
            
            # Step 2: Check if interface exists
            if not self._check_interface_exists(interface):
                self.error_handler.handle_error('E004', f"Interface {interface} not found")
                return None
            
            # Step 3: Start monitor mode
            monitor_interface = self._start_monitor_mode(interface)
            
            if monitor_interface:
                print(f"✅ Monitor mode active on {monitor_interface}")
                self.monitor_interfaces.append(monitor_interface)
                return monitor_interface
            else:
                self.error_handler.handle_error('E004', f"Failed to start monitor mode on {interface}")
                return None
                
        except Exception as e:
            self.error_handler.handle_error('E004', f"Monitor mode setup failed on {interface}", e)
            return None
    
    def _kill_conflicting_processes(self):
        """Kill processes that might interfere with monitor mode"""
        try:
            print("   🔫 Killing conflicting processes...")
            
            kill_commands = [
                ['sudo', 'airmon-ng', 'check', 'kill'],
                ['sudo', 'pkill', 'NetworkManager'],
                ['sudo', 'pkill', 'wpa_supplicant'],
                ['sudo', 'systemctl', 'stop', 'NetworkManager'],
                ['sudo', 'systemctl', 'stop', 'wpa_supplicant']
            ]
            
            for cmd in kill_commands:
                try:
                    subprocess.run(cmd, capture_output=True, timeout=10)
                    time.sleep(1)
                except:
                    pass
                    
            print("   ✅ Conflicting processes terminated")
            
        except Exception as e:
            self.error_handler.handle_error('E004', "Failed to kill conflicting processes", e)
    
    def _check_interface_exists(self, interface):
        """Check if wireless interface exists"""
        try:
            result = subprocess.run(
                ['iwconfig', interface],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    
    def _start_monitor_mode(self, interface):
        """Start monitor mode using airmon-ng"""
        try:
            # Check current mode
            current_mode = self._get_interface_mode(interface)
            if current_mode == 'monitor':
                print(f"   ✅ {interface} already in monitor mode")
                return interface
            
            # Start monitor mode
            print(f"   🔄 Starting monitor mode on {interface}...")
            cmd = ['sudo', 'airmon-ng', 'start', interface]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if process.returncode == 0:
                # Find the new monitor interface
                monitor_iface = self._find_monitor_interface(interface)
                if monitor_iface:
                    print(f"   ✅ Monitor interface: {monitor_iface}")
                    return monitor_iface
                else:
                    # Sometimes airmon-ng uses the same interface name
                    return interface
            else:
                print(f"   ❌ Airmon-ng failed: {process.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            self.error_handler.handle_error('E002', f"Monitor mode start timeout on {interface}")
            return None
        except Exception as e:
            self.error_handler.handle_error('E004', f"Monitor mode start failed on {interface}", e)
            return None
    
    def _get_interface_mode(self, interface):
        """Get current mode of wireless interface"""
        try:
            result = subprocess.run(
                ['iwconfig', interface],
                capture_output=True,
                text=True
            )
            
            if 'Mode:Monitor' in result.stdout:
                return 'monitor'
            elif 'Mode:Managed' in result.stdout:
                return 'managed'
            else:
                return 'unknown'
                
        except:
            return 'unknown'
    
    def _find_monitor_interface(self, base_interface):
        """Find the monitor interface created by airmon-ng"""
        try:
            result = subprocess.run(
                ['iwconfig'],
                capture_output=True,
                text=True
            )
            
            # Look for interfaces in monitor mode
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Mode:Monitor' in line:
                    iface_match = re.match(r'^(\w+)\s+', line)
                    if iface_match:
                        iface_name = iface_match.group(1)
                        # Check if it's related to our base interface
                        if base_interface in iface_name or iface_name.startswith('mon'):
                            return iface_name
            
            # If no specific monitor interface found, try common patterns
            common_monitors = [f'{base_interface}mon', 'mon0', 'wlan0mon']
            for mon_iface in common_monitors:
                if self._check_interface_exists(mon_iface):
                    return mon_iface
            
            return base_interface  # Fallback to original
            
        except Exception as e:
            self.error_handler.handle_error('E004', "Failed to find monitor interface", e)
            return base_interface
    
    def stop_monitor_mode(self, interface):
        """Stop monitor mode and restore managed mode"""
        try:
            print(f"🛑 Stopping monitor mode on {interface}...")
            
            cmd = ['sudo', 'airmon-ng', 'stop', interface]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if process.returncode == 0:
                print(f"✅ Monitor mode stopped on {interface}")
                
                # Restart network services
                self._restart_network_services()
                
                if interface in self.monitor_interfaces:
                    self.monitor_interfaces.remove(interface)
                    
                return True
            else:
                self.error_handler.handle_error('E004', f"Failed to stop monitor mode on {interface}")
                return False
                
        except Exception as e:
            self.error_handler.handle_error('E004', f"Monitor mode stop failed on {interface}", e)
            return False
    
    def _restart_network_services(self):
        """Restart network services after monitor mode"""
        try:
            restart_commands = [
                ['sudo', 'systemctl', 'start', 'NetworkManager'],
                ['sudo', 'systemctl', 'start', 'wpa_supplicant']
            ]
            
            for cmd in restart_commands:
                subprocess.run(cmd, capture_output=True)
                
            print("   ✅ Network services restarted")
            
        except Exception as e:
            self.error_handler.handle_error('E004', "Failed to restart network services", e)
    
    def get_available_interfaces(self):
        """Get list of available wireless interfaces"""
        try:
            result = subprocess.run(
                ['iwconfig'],
                capture_output=True,
                text=True
            )
            
            interfaces = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                iface_match = re.match(r'^(\w+)\s+', line)
                if iface_match:
                    iface_name = iface_match.group(1)
                    if iface_name and not iface_name.startswith('lo'):
                        interfaces.append(iface_name)
            
            return list(set(interfaces))  # Remove duplicates
            
        except Exception as e:
            self.error_handler.handle_error('E004', "Failed to get available interfaces", e)
            return ['wlan0']  # Fallback
    
    def get_interface_info(self, interface):
        """Get detailed information about wireless interface"""
        try:
            info = {
                'name': interface,
                'mode': self._get_interface_mode(interface),
                'exists': self._check_interface_exists(interface)
            }
            
            # Get more details with iwconfig
            result = subprocess.run(
                ['iwconfig', interface],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                # Extract MAC address
                mac_match = re.search(r'Access Point: ([0-9A-Fa-f:]{17})', result.stdout)
                if mac_match:
                    info['mac'] = mac_match.group(1)
                
                # Extract frequency
                freq_match = re.search(r'Frequency:([0-9.]+) GHz', result.stdout)
                if freq_match:
                    info['frequency'] = freq_match.group(1)
            
            return info
            
        except Exception as e:
            self.error_handler.handle_error('E004', f"Failed to get interface info for {interface}", e)
            return {'name': interface, 'mode': 'unknown', 'exists': False}
    def verify_monitor_mode(self, interface):
        """Verify that monitor mode is actually working"""
        try:
            print(f"   🔍 Verifying monitor mode on {interface}...")
            
            # Test with a quick airodump-ng scan
            test_cmd = [
                'sudo', 'timeout', '5', 'airodump-ng',
                '--output-format', 'csv',
                '--write', '/tmp/monitor_test',
                interface
            ]
            
            process = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True
            )
            
            # Check if any output was generated
            test_file = '/tmp/monitor_test-01.csv'
            if os.path.exists(test_file):
                with open(test_file, 'r') as f:
                    content = f.read()
                
                if 'BSSID' in content:
                    print("   ✅ Monitor mode verification: SUCCESS")
                    return True
                else:
                    print("   ❌ Monitor mode verification: No networks detected")
                    return False
            else:
                print("   ❌ Monitor mode verification: No output file created")
                return False
                
        except Exception as e:
            print(f"   ❌ Monitor mode verification failed: {e}")
            return False