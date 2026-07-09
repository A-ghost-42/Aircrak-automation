# File: orchestration/main_controller.py
import time
from orchestration.attack_controller import AttackController
from orchestration.real_attack_controller import RealAttackController
from orchestration.state_manager import StateManager
from intelligence.intelligence_controller import IntelligenceController

class MainController:
    """
    The Master Controller for Pegasus-Nexus.
    Coordinates between intelligence gathering and attack execution.
    """
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        
        self.state = StateManager(config)
        self.intelligence = IntelligenceController(config, error_handler)
        self.demo_attack = AttackController(config, error_handler)
        self.real_attack = RealAttackController(config, error_handler)
        
    def initialize_system(self):
        """Initialize all sub-controllers"""
        print(" Pegasus-Nexus: Initializing Global Orchestration...")
        
        success = all([
            self.intelligence.initialize_intelligence_system(),
            self.demo_attack.initialize_attack_system(),
            self.real_attack.initialize_attack_system()
        ])
        
        if success:
            print(" All systems operational and linked to StateManager")
        return success

    def run_full_operation(self, interface='wlan0', mode='real', seeds=None):
        """
        Execute a full end-to-end operation:
        Intelligence -> Analysis -> Strategy -> Attack -> Recording
        """
        print(f"\n STARTING FULL OPERATION (Mode: {mode})")
        if seeds:
            print(f" User suggestions provided: {seeds}")
        
        # 1. Intelligence Phase
        targets = self.intelligence.execute_complete_intelligence_cycle(interface)
        if not targets:
            print(" No targets found. Aborting operation.")
            return
            
        # Record targets in state
        for t in targets:
            self.state.update_target(t['bssid'], t)
            
        # 2. Filtering Phase (Pick the best targets)
        top_targets = self.intelligence.get_top_targets(targets, count=3)
        print(f"\n Selected {len(top_targets)} high-probability targets for engagement")
        
        # 3. Engagement Phase
        results = []
        if mode == 'real':
            monitor_iface = self.intelligence.get_monitor_interface() or f"{interface}mon"
            results = self.real_attack.execute_real_attack_cycle(top_targets, monitor_iface, seeds=seeds)
        else:
            results = self.demo_attack.execute_attack_cycle(top_targets)
            
        # 4. Final Analysis & Cleanup
        self._process_results(results)
        
        # Cleanup monitor mode if we started it
        if self.intelligence.is_monitor_active():
            self.intelligence._cleanup_monitor_environment(self.intelligence.get_monitor_interface())
            
        summary = self.state.get_summary()
        print(f"\n OPERATION COMPLETE")
        print(f" Summary: {summary['total_targets']} targets seen, {summary['compromised']} passwords found.")

    def _process_results(self, results):
        """Update state with attack results"""
        for r in results:
            bssid = r['target']['bssid']
            self.state.record_attack_end(
                bssid, 
                r['success'], 
                r.get('password')
            )
            
    def get_system_status(self):
        """Get overall system health and progress"""
        return {
            'state': self.state.get_summary(),
            'monitor_active': self.intelligence.is_monitor_active(),
            'interface': self.intelligence.get_monitor_interface()
        }
