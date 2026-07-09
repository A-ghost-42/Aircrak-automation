# File: engines/attack_strategy.py
class AttackStrategyManager:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.strategy_history = []
        
    def select_optimal_strategy(self, target):
        """
        Select optimal attack strategy based on target profile
        """
        strategies = []
        
        # WPS attack (fastest if available)
        if target.get('wps_status') == 'unlocked':
            strategies.append({
                'type': 'wps',
                'priority': 1.0,
                'estimated_time': 300,  # 5 minutes
                'success_probability': 0.7
            })
        
        # Handshake capture and crack
        if target['encryption'] in ['WPA', 'WPA2'] and target.get('client_count', 0) > 0:
            strategies.append({
                'type': 'handshake', 
                'priority': 0.8,
                'estimated_time': 1800,  # 30 minutes
                'success_probability': 0.4
            })
        
        # Dictionary attack
        strategies.append({
            'type': 'dictionary',
            'priority': 0.6,
            'estimated_time': 600,  # 10 minutes
            'success_probability': 0.2
        })
        
        # Brute force (last resort)
        strategies.append({
            'type': 'brute_force',
            'priority': 0.3,
            'estimated_time': 7200,  # 2 hours
            'success_probability': 0.1
        })
        
        # Sort by priority
        strategies.sort(key=lambda x: x['priority'], reverse=True)
        
        return strategies[0] if strategies else None
    
    def create_attack_plan(self, target):
        """
        Create comprehensive attack plan for target
        """
        primary_strategy = self.select_optimal_strategy(target)
        
        plan = {
            'target': target,
            'primary_strategy': primary_strategy,
            'fallback_strategies': [],
            'estimated_total_time': primary_strategy['estimated_time'] if primary_strategy else 3600,
            'resource_requirements': self._calculate_resource_requirements(primary_strategy),
            'risk_level': self._assess_attack_risk(target, primary_strategy)
        }
        
        return plan
    
    def _calculate_resource_requirements(self, strategy):
        """Calculate resource requirements for strategy"""
        if strategy['type'] == 'wps':
            return {'cpu': 'low', 'memory': 'low', 'network': 'medium'}
        elif strategy['type'] == 'handshake':
            return {'cpu': 'high', 'memory': 'medium', 'network': 'high'}
        else:
            return {'cpu': 'medium', 'memory': 'medium', 'network': 'low'}
    
    def _assess_attack_risk(self, target, strategy):
        """Assess risk level of attack"""
        risk_score = 0
        
        # Business networks are higher risk
        if target['ssid_pattern'] == 'business_network':
            risk_score += 2
        
        # Long attacks are higher risk
        if strategy['estimated_time'] > 1800:  # 30 minutes
            risk_score += 1
        
        # Many clients = higher detection risk
        if target.get('client_count', 0) > 5:
            risk_score += 1
        
        if risk_score >= 3:
            return 'HIGH'
        elif risk_score >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'