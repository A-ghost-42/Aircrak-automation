# File: orchestration/attack_controller.py
class AttackController:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.streaming_engine = None
        self.strategy_manager = None
        
    def initialize_attack_system(self):
        """Initialize attack system components"""
        try:
            from engines.streaming_engine import StreamingEngine
            from engines.attack_strategy import AttackStrategyManager
            
            self.streaming_engine = StreamingEngine(self.config, self.error_handler)
            self.strategy_manager = AttackStrategyManager(self.config, self.error_handler)
            
            if self.streaming_engine.initialize_engine():
                print("✅ Attack system initialized")
                return True
            else:
                return False
                
        except Exception as e:
            self.error_handler.handle_error('E006', "Attack system initialization failed", e)
            return False
    
    def execute_attack_cycle(self, targets):
        """
        Execute attack cycle on multiple targets
        """
        print("\n" + "="*60)
        print("⚔️  ATTACK CYCLE EXECUTION")
        print("="*60)
        
        results = []
        
        for target in targets:
            print(f"\n🎯 Attacking: {target['ssid']}")
            print(f"   📊 Success probability: {target['success_probability']*100:.1f}%")
            
            # Create attack plan
            attack_plan = self.strategy_manager.create_attack_plan(target)
            print(f"   🛠️  Strategy: {attack_plan['primary_strategy']['type']}")
            print(f"   ⏱️  Estimated time: {attack_plan['primary_strategy']['estimated_time']}s")
            print(f"   🎯 Success chance: {attack_plan['primary_strategy']['success_probability']*100:.1f}%")
            
            # Execute attack
            result = self.streaming_engine.execute_streaming_attack(
                target, 
                attack_plan['primary_strategy']['type'],
                attack_plan['primary_strategy']['estimated_time']
            )
            
            results.append(result)
            
            # Stop if we found a password (demo mode)
            if result['success']:
                print(f"\n🎉 STOPPING ATTACKS - SUCCESS ACHIEVED!")
                break
        
        # Display attack summary
        self._display_attack_summary(results)
        
        return results
    
    def _display_attack_summary(self, results):
        """Display attack cycle summary"""
        print("\n" + "="*60)
        print("📊 ATTACK CYCLE SUMMARY")
        print("="*60)
        
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        
        print(f"✅ Successful attacks: {len(successful)}")
        print(f"❌ Failed attacks: {len(failed)}")
        print(f"🎯 Total targets: {len(results)}")
        
        if successful:
            print(f"\n🎉 COMPROMISED NETWORKS:")
            for result in successful:
                print(f"   • {result['target']['ssid']} - Password: {result['password']}")
        
        # Display statistics
        stats = self.streaming_engine.get_attack_statistics()
        print(f"\n📈 PERFORMANCE STATS:")
        print(f"   • Total passwords tested: {stats['total_tested']:,}")
        print(f"   • Success rate: {stats['success_rate']*100:.1f}%")
        print(f"   • Average time per attack: {stats['average_time']:.1f}s")