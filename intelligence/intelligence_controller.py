# File: orchestration/intelligence_controller.py
class IntelligenceController:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.monitor_manager = None
        self.scanner = None
        self.analyzer = None
        self.wps_detector = None
        self.current_monitor_interface = None
        
    def initialize_intelligence_system(self):
        """Initialize all intelligence components"""
        try:
            from intelligence.monitor_manager import MonitorModeManager
            from intelligence.network_scanner import NetworkScanner
            from intelligence.target_analyzer import TargetAnalyzer
            from intelligence.wps_detector import WPSDetector
            
            self.monitor_manager = MonitorModeManager(self.config, self.error_handler)
            self.scanner = NetworkScanner(self.config, self.error_handler)
            self.analyzer = TargetAnalyzer(self.config, self.error_handler)
            self.wps_detector = WPSDetector(self.config, self.error_handler)
            
            print("✅ Intelligence system initialized")
            return True
            
        except Exception as e:
            self.error_handler.handle_error('E006', "Intelligence system initialization failed", e)
            return False
    
    def quick_interface_check(self):
        """Quick check of available interfaces and their status"""
        if not self.monitor_manager:
            print("❌ Monitor manager not initialized")
            return []
            
        print("\n🔍 Wireless Interface Status:")
        print("-" * 40)
        
        available_ifaces = self.monitor_manager.get_available_interfaces()
        
        for iface in available_ifaces:
            info = self.monitor_manager.get_interface_info(iface)
            status = "✅" if info['exists'] else "❌"
            mode = info.get('mode', 'unknown')
            print(f"   {status} {iface}: {mode}")
        
        return available_ifaces
    
    def execute_complete_intelligence_cycle(self, interface='wlan0'):
        """
        Execute complete intelligence gathering cycle with monitor mode
        BUT DON'T CLEANUP - let main function handle it
        """
        print("\n" + "="*60)
        print("🕵️ INTELLIGENCE GATHERING CYCLE")
        print("="*60)
        
        # Step 0: Setup Monitor Mode
        monitor_interface = self._setup_monitor_environment(interface)
        if not monitor_interface:
            print("❌ Failed to setup monitor mode")
            return []
        
        try:
            # Step 1: Network Scanning
            networks = self.scanner.perform_network_scan(monitor_interface)
            if not networks:
                print("❌ No networks found during scan")
                return []
            
            # Step 2: Target Analysis
            analyzed_targets = self.analyzer.analyze_networks(networks)
            
            # Step 3: WPS Detection (requires monitor mode)
            final_targets = self.wps_detector.bulk_detect_wps(analyzed_targets, monitor_interface)
            
            # Display results
            self.analyzer.display_target_summary(final_targets)
            
            # Store monitor interface for later use
            self.current_monitor_interface = monitor_interface
            
            return final_targets
            
        except Exception as e:
            # If there's an error, cleanup monitor mode
            self._cleanup_monitor_environment(monitor_interface)
            raise e
        # DON'T cleanup here - let the main function handle it after attacks
    
    def _setup_monitor_environment(self, interface):
        """Setup monitor mode and return the monitor interface name"""
        print("📡 Setting up wireless monitoring environment...")
        
        # Display available interfaces
        available_ifaces = self.monitor_manager.get_available_interfaces()
        print(f"   📶 Available interfaces: {', '.join(available_ifaces)}")
        
        if interface not in available_ifaces:
            print(f"   ⚠️  Interface {interface} not found in available interfaces")
            if available_ifaces:
                interface = available_ifaces[0]
                print(f"   🔄 Using first available interface: {interface}")
            else:
                print("   ❌ No wireless interfaces available!")
                return None
        
        # Get interface info
        iface_info = self.monitor_manager.get_interface_info(interface)
        print(f"   🔍 Interface {interface}: mode={iface_info.get('mode', 'unknown')}")
        
        # Setup monitor mode
        monitor_interface = self.monitor_manager.setup_monitor_mode(interface)
        
        if monitor_interface:
            self.current_monitor_interface = monitor_interface
            
            # Verify monitor mode is active and working
            final_info = self.monitor_manager.get_interface_info(monitor_interface)
            if final_info.get('mode') == 'monitor':
                print(f"   ✅ Successfully activated monitor mode on {monitor_interface}")
            else:
                print(f"   ⚠️  Monitor mode may not be active on {monitor_interface}")
        
        return monitor_interface
    
    def _cleanup_monitor_environment(self, monitor_interface):
        """Cleanup monitor mode after intelligence gathering"""
        if monitor_interface and monitor_interface != 'wlan0':  # Don't stop if it's the original interface
            print(f"🧹 Cleaning up monitor mode on {monitor_interface}...")
            success = self.monitor_manager.stop_monitor_mode(monitor_interface)
            if success:
                self.current_monitor_interface = None
    
    def get_top_targets(self, targets, count=5):
        """Get top N targets by success probability"""
        return sorted(targets, key=lambda x: x['success_probability'], reverse=True)[:count]