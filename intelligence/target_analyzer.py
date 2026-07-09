# File: intelligence/target_analyzer.py
import re

class TargetAnalyzer:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.pattern_database = self._load_pattern_database()
        
    def analyze_networks(self, networks):
        """
        Analyze and prioritize networks based on multiple factors
        """
        print("🎯 Analyzing network targets...")
        
        analyzed_targets = []
        
        for network in networks:
            target_profile = self._create_target_profile(network)
            analyzed_targets.append(target_profile)
        
        # Sort by success probability (highest first)
        analyzed_targets.sort(key=lambda x: x['success_probability'], reverse=True)
        
        print(f"✅ Analysis complete. Top target: {analyzed_targets[0]['ssid'] if analyzed_targets else 'None'}")
        return analyzed_targets
    
    def _create_target_profile(self, network):
        """
        Create comprehensive target profile with success probability
        """
        profile = {
            'bssid': network['bssid'],
            'ssid': network['ssid'],
            'signal_strength': network['signal'],
            'encryption': network['encryption'],
            'channel': network['channel'],
            'client_count': network['clients'],
            'ssid_pattern': self._classify_ssid_pattern(network['ssid']),
            'wps_status': 'unknown',  # Will be detected separately
            'success_probability': 0.0,
            'recommended_strategies': [],
            'risk_level': 'MEDIUM'
        }
        
        # Calculate success probability
        profile['success_probability'] = self._calculate_success_probability(profile)
        
        # Determine recommended strategies
        profile['recommended_strategies'] = self._recommend_strategies(profile)
        
        # Determine risk level
        profile['risk_level'] = self._assess_risk_level(profile)
        
        return profile
    
    def _classify_ssid_pattern(self, ssid):
        """
        Classify SSID into known patterns for strategy selection
        """
        if not ssid or ssid.strip() == '':
            return 'hidden'
            
        ssid_lower = ssid.lower()
        
        # Common router default patterns
        default_patterns = [
            (r'(tp-link|tplink).*', 'default_router'),
            (r'(netgear).*', 'default_router'),
            (r'(linksys).*', 'default_router'),
            (r'(d-link|dlink).*', 'default_router'),
            (r'(asus).*', 'default_router'),
            (r'(tenda).*', 'default_router'),
            (r'(huawei).*', 'default_router')
        ]
        
        # ISP provided routers
        isp_patterns = [
            (r'(bt|bthomehub).*', 'isp_provided'),
            (r'(virginmedia).*', 'isp_provided'),
            (r'(sky).*', 'isp_provided'),
            (r'(xfinity).*', 'isp_provided'),
            (r'(spectrum).*', 'isp_provided'),
            (r'(att).*', 'isp_provided')
        ]
        
        # Business networks
        business_patterns = [
            (r'.*(corp|office|company|business|enterprise).*', 'business_network'),
            (r'.*(inc|llc|gmbh|ltd).*', 'business_network')
        ]
        
        # Public networks
        public_patterns = [
            (r'.*(free|public|guest|open|wifi).*', 'public_wifi'),
            (r'.*(hotel|airport|station|cafe).*', 'public_wifi')
        ]
        
        # Check all patterns
        patterns = default_patterns + isp_patterns + business_patterns + public_patterns
        
        for pattern, pattern_type in patterns:
            if re.match(pattern, ssid_lower, re.IGNORECASE):
                return pattern_type
                
        return 'personal_network'
    
    def _calculate_success_probability(self, profile):
        """
        Calculate success probability based on multiple factors
        """
        probability = 0.5  # Base probability
        
        # Encryption factors
        encryption_weights = {
            'WEP': 0.8,
            'WPA': 0.6,
            'WPA2': 0.4,
            'OPEN': 0.9
        }
        probability *= encryption_weights.get(profile['encryption'], 0.5)
        
        # Signal strength factors
        if profile['signal_strength'] > -60:  # Strong signal
            probability *= 1.3
        elif profile['signal_strength'] > -70:  # Good signal
            probability *= 1.1
        elif profile['signal_strength'] < -85:  # Weak signal
            probability *= 0.7
        
        # SSID pattern factors
        pattern_weights = {
            'default_router': 1.3,  # Often weak defaults
            'isp_provided': 1.2,    # Predictable patterns
            'public_wifi': 1.1,     # Often weak security
            'personal_network': 1.0, # Variable security
            'business_network': 0.7, # Usually stronger security
            'hidden': 0.8           # Harder to detect
        }
        probability *= pattern_weights.get(profile['ssid_pattern'], 1.0)
        
        # Client activity
        if profile['client_count'] > 0:
            probability *= 1.2  # Clients enable handshake capture
        
        # Ensure probability is between 0.1 and 0.95
        return max(0.1, min(0.95, probability))
    
    def _recommend_strategies(self, profile):
        """
        Recommend attack strategies based on target profile
        """
        strategies = []
        
        # WPS attacks for routers
        if profile['ssid_pattern'] in ['default_router', 'isp_provided']:
            strategies.append('wps_attack')
        
        # Handshake capture for networks with clients
        if profile['client_count'] > 0 and profile['encryption'] in ['WPA', 'WPA2']:
            strategies.append('handshake_capture')
        
        # Dictionary attacks for public networks
        if profile['ssid_pattern'] == 'public_wifi':
            strategies.append('dictionary_attack')
        
        # Always include brute force as fallback
        strategies.append('brute_force')
        
        return strategies
    
    def _assess_risk_level(self, profile):
        """
        Assess risk level for attacking this target
        """
        risk_score = 0
        
        # Business networks are higher risk
        if profile['ssid_pattern'] == 'business_network':
            risk_score += 2
        
        # Strong encryption = higher risk (more time exposed)
        if profile['encryption'] == 'WPA2':
            risk_score += 1
        
        # Many clients = higher risk of detection
        if profile['client_count'] > 5:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 3:
            return 'HIGH'
        elif risk_score >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _load_pattern_database(self):
        """Load pattern database for SSID classification"""
        return {
            'default_routers': ['tp-link', 'netgear', 'linksys', 'd-link', 'asus', 'tenda', 'huawei'],
            'isp_routers': ['bthomehub', 'virginmedia', 'sky', 'xfinity', 'spectrum', 'att'],
            'business_indicators': ['corp', 'office', 'company', 'business', 'enterprise', 'inc', 'llc']
        }
    
    def display_target_summary(self, targets):
        """Display formatted summary of analyzed targets"""
        if not targets:
            print("❌ No targets to display")
            return
            
        print("\n" + "="*80)
        print("🎯 ANALYZED TARGET SUMMARY")
        print("="*80)
        print(f"{'SSID':<25} {'BSSID':<18} {'Encryption':<10} {'Signal':<8} {'Success %':<10} {'Strategies'}")
        print("-"*80)
        
        for target in targets[:10]:  # Show top 10
            strategies_short = ', '.join(target['recommended_strategies'][:2])
            print(f"{target['ssid'][:24]:<25} {target['bssid']:<18} {target['encryption']:<10} "
                  f"{target['signal_strength']:<8} {target['success_probability']*100:<9.1f}% {strategies_short}")
        
        print("="*80)
