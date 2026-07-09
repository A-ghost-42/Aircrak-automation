# File: core/error_handler.py
import time
import traceback
from datetime import datetime
from pathlib import Path

class ErrorHandler:
    ERROR_CODES = {
        # System Errors (E001-E099)
        'E001': 'Hardware detection failed',
        'E002': 'Tool execution timeout', 
        'E003': 'Memory allocation failed',
        'E004': 'Network adapter error',
        'E005': 'File system permission denied',
        'E006': 'Configuration loading failed',
        'E007': 'Dependency missing',
        
        # Tool Errors (E100-E199)
        'E100': 'Aircrack-ng execution failed',
        'E101': 'Hashcat GPU error',
        'E102': 'Crunch wordlist generation failed',
        
        # Network Errors (E200-E299)
        'E200': 'Network scan failed',
        'E201': 'Target analysis failed',
        'E202': 'Handshake capture timeout',
        
        # Attack Errors (E300-E399)
        'E300': 'Streaming attack failed',
        'E301': 'Password generation error',
        'E302': 'Real-time testing failed'
    }
    
    def __init__(self, config):
        self.config = config
        self.error_log = []
        self.log_path = Path.home() / '.pegasus_nexus' / 'logs'
        self.log_path.mkdir(parents=True, exist_ok=True)
        
    def handle_error(self, error_code, context=None, exception=None):
        """Standardized error handling with recovery actions"""
        error_entry = {
            'id': len(self.error_log) + 1,
            'code': error_code,
            'message': self.ERROR_CODES.get(error_code, 'Unknown error'),
            'context': context,
            'exception': str(exception) if exception else None,
            'stack_trace': traceback.format_exc() if exception else None,
            'timestamp': datetime.now().isoformat(),
            'severity': self._determine_severity(error_code)
        }
        
        # Add to memory log
        self.error_log.append(error_entry)
        
        # Write to file
        self._write_to_error_log(error_entry)
        
        # Console output
        self._display_error_console(error_entry)
        
        # Execute recovery if needed
        if error_entry['severity'] in ['HIGH', 'CRITICAL']:
            try:
                self._execute_recovery(error_code, error_entry)
            except Exception as e:
                print(f"   ⚠️  Recovery attempt failed: {e}")
        
        return error_entry['id']
    
    def _determine_severity(self, error_code):
        """Determine error severity level"""
        critical_errors = ['E001', 'E003', 'E004', 'E007']
        high_errors = ['E002', 'E005', 'E100', 'E101']
        
        if error_code in critical_errors:
            return 'CRITICAL'
        elif error_code in high_errors:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _write_to_error_log(self, error_entry):
        """Write error to log file"""
        try:
            log_file = self.log_path / 'error.log'
            with open(log_file, 'a') as f:
                f.write(f"[{error_entry['timestamp']}] {error_entry['code']}: {error_entry['message']}\n")
                if error_entry['context']:
                    f.write(f"   Context: {error_entry['context']}\n")
                if error_entry['exception']:
                    f.write(f"   Exception: {error_entry['exception']}\n")
                f.write("\n")
        except Exception as e:
            print(f"❌ Failed to write error log: {e}")
    
    def _display_error_console(self, error_entry):
        """Display error in console with colored output"""
        colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow  
            'MEDIUM': '\033[96m'     # Cyan
        }
        reset = '\033[0m'
        
        color = colors.get(error_entry['severity'], '\033[0m')
        print(f"{color}🚨 ERROR {error_entry['code']}: {error_entry['message']}{reset}")
        if error_entry['context']:
            print(f"   📍 Context: {error_entry['context']}")
    
    def _execute_recovery(self, error_code, error_entry):
        """Execute automatic recovery actions"""
        # Safely map recovery actions
        recovery_map = {
            'E001': '_recover_hardware_error',
            'E003': '_recover_memory_error',
            'E007': '_recover_dependency_error'
        }
        
        method_name = recovery_map.get(error_code)
        if method_name and hasattr(self, method_name):
            method = getattr(self, method_name)
            print(f"   🔄 Attempting automatic recovery via {method_name}...")
            method(error_entry)
        
    def _recover_memory_error(self, error_entry):
        """Recovery action for memory errors"""
        import gc
        gc.collect()
        print("   ♻️  Garbage collection executed")

    def _recover_hardware_error(self, error_entry):
        """Recovery action for hardware errors"""
        print("   📡 Tip: Try re-inserting your wireless adapter or checking 'rfkill list'")

    def _recover_dependency_error(self, error_entry):
        """Recovery action for dependency errors"""
        print("   📦 Tip: Run 'sudo apt update && sudo apt install aircrack-ng hashcat crunch'")
    
    def get_error_summary(self):
        """Get summary of recent errors"""
        recent_errors = self.error_log[-10:]  # Last 10 errors
        summary = {
            'total_errors': len(self.error_log),
            'recent_errors': len(recent_errors),
            'critical_count': len([e for e in recent_errors if e['severity'] == 'CRITICAL']),
            'last_error': self.error_log[-1] if self.error_log else None
        }
        return summary
