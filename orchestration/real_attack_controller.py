# File: orchestration/real_attack_controller.py
class RealAttackController:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.real_attack_engine = None
        self.strategy_manager = None
        
    def initialize_attack_system(self):
        """Initialize real attack system components"""
        try:
            from engines.real_attack_engine import RealAttackEngine
            from engines.attack_strategy import AttackStrategyManager
            
            self.real_attack_engine = RealAttackEngine(self.config, self.error_handler)
            self.strategy_manager = AttackStrategyManager(self.config, self.error_handler)
            
            if self.real_attack_engine.initialize_engine():
                print("✅ Real attack system initialized")
                return True
            else:
                return False
                
        except Exception as e:
            self.error_handler.handle_error('E006', "Real attack system initialization failed", e)
            return False
    
    def execute_real_attack_cycle(self, targets, interface='wlan0mon', seeds=None):
        """
        Execute real attack cycle with handshake capture
        """
        print("\n" + "="*60)
        print("⚔️  REAL ATTACK CYCLE EXECUTION")
        print("="*60)
        
        results = []
        
        for target in targets:
            print(f"\n🎯 Attacking: {target['ssid']}")
            print(f"   📊 Success probability: {target['success_probability']*100:.1f}%")
            
            # FIX: Use the correct key names
            signal_strength = target.get('signal_strength', -100)
            channel = target.get('channel', 1)
            
            print(f"   📶 Signal: {signal_strength} dBm")
            print(f"   📡 Channel: {channel}")
            
            # Skip targets with weak signal (use correct key)
            if signal_strength < -80:
                print("   ⚠️  Skipping - signal too weak")
                continue
            
            # Execute real attack
            result = self.real_attack_engine.execute_real_attack(target, interface, seeds=seeds)
            
            results.append(result)
            
            # Stop if we found a password
            if result['success']:
                print(f"\n🎉 STOPPING ATTACKS - SUCCESS ACHIEVED!")
                break
        
        # Display attack summary
        self._display_real_attack_summary(results)
        
        return results
    
    def _display_real_attack_summary(self, results):
        """Display real attack cycle summary"""
        print("\n" + "="*60)
        print("📊 REAL ATTACK CYCLE SUMMARY")
        print("="*60)
        
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        handshakes = [r for r in results if r.get('handshake_captured', False)]
        
        print(f"✅ Successful attacks: {len(successful)}")
        print(f"❌ Failed attacks: {len(failed)}")
        print(f"📡 Handshakes captured: {len(handshakes)}/{len(results)}")
        print(f"🎯 Total targets attempted: {len(results)}")
        
        if successful:
            print(f"\n🎉 COMPROMISED NETWORKS:")
            for result in successful:
                target = result['target']
                print(f"   • {target['ssid']} ({target['bssid']})")
                print(f"     🔑 Password: {result['password']}")
                print(f"     ⏱️  Time: {result['duration']:.1f}s")
                print(f"     📊 Tests: {result['tested_count']:,}")
        
        # Display statistics
        if hasattr(self.real_attack_engine, 'get_attack_statistics'):
            stats = self.real_attack_engine.get_attack_statistics()
            print(f"\n📈 PERFORMANCE STATS:")
            print(f"   • Total passwords tested: {stats['total_tested']:,}")
            print(f"   • Success rate: {stats['success_rate']*100:.1f}%")
            print(f"   • Handshake capture rate: {stats['handshake_success_rate']*100:.1f}%")
            print(f"   • Average time per attack: {stats['average_time']:.1f}s")