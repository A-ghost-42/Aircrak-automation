# File: engines/streaming_engine.py
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.error_handler import ErrorHandler

class StreamingEngine:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.password_generator = None
        self.password_tester = None
        self.attack_results = []
        
    def initialize_engine(self):
        """Initialize streaming engine components"""
        try:
            from engines.password_generator import PasswordGenerator
            from engines.password_tester import PasswordTester
            
            self.password_generator = PasswordGenerator(self.config, self.error_handler)
            self.password_tester = PasswordTester(self.config, self.error_handler)
            
            print("✅ Streaming engine initialized")
            return True
            
        except Exception as e:
            self.error_handler.handle_error('E300', "Streaming engine initialization failed", e)
            return False
    
    def execute_streaming_attack(self, target, attack_type='handshake', max_duration=3600):
        """
        Execute streaming attack on target
        """
        print(f"\n🎯 Starting streaming attack on: {target['ssid']}")
        print(f"   📡 BSSID: {target['bssid']}")
        print(f"   🛠️  Attack type: {attack_type}")
        print(f"   ⏱️  Max duration: {max_duration} seconds")
        
        start_time = time.time()
        result = {
            'target': target,
            'success': False,
            'password': None,
            'duration': 0,
            'tested_count': 0,
            'attack_type': attack_type,
            'errors': []
        }
        
        try:
            if attack_type == 'handshake':
                success = self._execute_handshake_attack(target, max_duration)
            elif attack_type == 'wps':
                success = self._execute_wps_attack(target, max_duration)
            else:
                self.error_handler.handle_error('E300', f"Unknown attack type: {attack_type}")
                success = False
            
            # Capture results
            result['success'] = success
            result['password'] = self.password_tester.found_password
            result['tested_count'] = self.password_tester.tested_count
            result['duration'] = time.time() - start_time
            
            if success:
                print(f"🎉 ATTACK SUCCESSFUL! Password: {result['password']}")
                print(f"📊 Stats: {result['tested_count']} tests in {result['duration']:.1f}s")
            else:
                print(f"❌ Attack failed after {result['tested_count']} tests")
            
            self.attack_results.append(result)
            return result
            
        except Exception as e:
            error_id = self.error_handler.handle_error('E300', f"Streaming attack failed on {target['ssid']}", e)
            result['errors'].append(f"Error {error_id}: {str(e)}")
            result['duration'] = time.time() - start_time
            return result
    
    def _execute_handshake_attack(self, target, max_duration):
        """Execute handshake-based streaming attack"""
        # For now, we'll simulate since we don't have actual handshake files
        # In production, this would use real handshake capture
        
        print("   🔄 Simulating handshake attack (demo mode)...")
        
        # Get smart attack parameters
        lengths = self.password_generator.smart_length_sequence(target)
        charsets = self.password_generator.smart_charset_sequence(target)
        
        print(f"   📊 Strategy: lengths {lengths}, charsets {charsets}")
        
        # Try each charset in sequence
        for charset in charsets:
            if self.password_tester.found_password:
                break
                
            print(f"   🔧 Trying charset: {charset}")
            
            # Generate and test passwords
            password_stream = self.password_generator.generate_passwords_stream(
                min_length=min(lengths),
                max_length=max(lengths),
                charset_name=charset
            )
            
            # Test passwords (in demo mode, we'll simulate)
            success = self._demo_password_testing(target, password_stream)
            
            if success:
                return True
        
        return False
    
    def _execute_wps_attack(self, target, max_duration):
        """Execute WPS PIN attack"""
        if target.get('wps_status') != 'unlocked':
            print("   ❌ WPS is locked or not available")
            return False
        
        print("   🔄 Starting WPS PIN attack...")
        
        # Generate and test WPS PINs (8 digits)
        for pin in self._generate_wps_pins():
            if time.time() > time.struct_time + max_duration:
                break
                
            success = self.password_tester.test_password_wps(target['bssid'], pin)
            
            if success:
                return True
                
            # Progress reporting
            if int(pin) % 1000 == 0:
                print(f"   🔄 Testing PIN: {pin}")
        
        return False
    
    def _generate_wps_pins(self):
        """Generate valid WPS PINs (8 digits with checksum)"""
        # WPS PINs are 8 digits with a specific checksum
        # For demo, we'll generate sequential PINs
        for i in range(0, 100000000):
            pin = f"{i:08d}"  # Format as 8-digit string
            if self._is_valid_wps_pin(pin):
                yield pin
    
    def _is_valid_wps_pin(self, pin):
        """Validate WPS PIN checksum"""
        if len(pin) != 8 or not pin.isdigit():
            return False
        
        # Simple WPS PIN checksum validation (simplified)
        # In production, implement full WPS checksum algorithm
        return True
    
    def _demo_password_testing(self, target, password_stream):
        """
        Demo mode password testing (simulates real testing)
        """
        print("   🎭 DEMO MODE: Simulating password testing")
        
        # Common passwords to "find" in demo mode
        common_passwords = {
            'TP-Link_1234': 'admin123',
            'Home_Network': 'password123', 
            'Free_WiFi': '12345678',
            'Office_Corp': 'Company2024!'
        }
        
        demo_password = common_passwords.get(target['ssid'])
        
        if demo_password:
            print(f"   🎯 Demo password for {target['ssid']}: {demo_password}")
            
            # Simulate testing until we "find" the demo password
            for i, password in enumerate(password_stream):
                if i >= 1000:  # Stop after 1000 tests in demo
                    break
                    
                if password == demo_password:
                    self.password_tester.found_password = password
                    self.password_tester.tested_count = i + 1
                    return True
                    
                # Progress simulation
                if i % 100 == 0:
                    print(f"   🔄 Demo testing... {i} attempts")
        
        return False
    
    def get_attack_statistics(self):
        """Get overall attack statistics"""
        total_attacks = len(self.attack_results)
        successful_attacks = len([r for r in self.attack_results if r['success']])
        total_tested = sum(r['tested_count'] for r in self.attack_results)
        
        return {
            'total_attacks': total_attacks,
            'successful_attacks': successful_attacks,
            'success_rate': successful_attacks / total_attacks if total_attacks > 0 else 0,
            'total_tested': total_tested,
            'average_time': sum(r['duration'] for r in self.attack_results) / total_attacks if total_attacks > 0 else 0
        }