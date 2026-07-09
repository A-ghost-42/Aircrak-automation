# File: core/bootstrap.py
import os
import sys
import subprocess
import psutil
from pathlib import Path

class SystemBootstrap:
    def __init__(self):
        self.config_manager = None
        self.error_handler = None
        self.system_ready = False
        self.checks_passed = []
        self.checks_failed = []
        
    def initialize_system(self):
        """Main system initialization routine"""
        print(" Initializing Pegasus-Nexus System...")
        
        # Initialize configuration first
        if not self._initialize_configuration():
            return False
            
        # Initialize error handling
        if not self._initialize_error_handler():
            return False
            
        # Perform system checks
        checks = [
            self._check_operating_system,
            self._check_python_version,
            self._check_required_tools,
            self._check_hardware_requirements,
            self._check_file_permissions,
            self._check_network_capabilities
        ]
        
        for check in checks:
            try:
                result = check()
                if result:
                    self.checks_passed.append(check.__name__)
                else:
                    self.checks_failed.append(check.__name__)
            except Exception as e:
                self.error_handler.handle_error('E006', f"Check {check.__name__} failed", e)
                self.checks_failed.append(check.__name__)
        
        # Final initialization
        if not self.checks_failed:
            self.system_ready = True
            print(" All system checks passed!")
            self._display_system_summary()
            return True
        else:
            print(f" System initialization failed: {len(self.checks_failed)} checks failed")
            self._display_failed_checks()
            return False
    
    def _initialize_configuration(self):
        """Initialize configuration system"""
        try:
            from core.config import Config
            self.config_manager = Config()
            self.config_manager.load_configuration()
            print(" Configuration system initialized")
            return True
        except Exception as e:
            print(f" Configuration initialization failed: {e}")
            return False
    
    def _initialize_error_handler(self):
        """Initialize error handling system"""
        try:
            from core.error_handler import ErrorHandler
            self.error_handler = ErrorHandler(self.config_manager)
            print(" Error handling system initialized")
            return True
        except Exception as e:
            print(f" Error handler initialization failed: {e}")
            return False
    
    def _check_operating_system(self):
        """Check if running on supported OS"""
        supported_systems = ['linux', 'linux2']
        if sys.platform not in supported_systems:
            self.error_handler.handle_error('E001', f"Unsupported OS: {sys.platform}")
            return False
        
        print(" Operating system: Linux")
        return True
    
    def _check_python_version(self):
        """Check Python version requirements"""
        required_version = (3, 7)
        current_version = sys.version_info
        
        if current_version < required_version:
            self.error_handler.handle_error('E007', 
                f"Python {required_version[0]}.{required_version[1]}+ required, found {current_version[0]}.{current_version[1]}")
            return False
        
        print(f" Python version: {current_version[0]}.{current_version[1]}.{current_version[2]}")
        return True
    
    def _check_required_tools(self):
        """Check if required security tools are installed"""
        required_tools = {
            'aircrack-ng': ['aircrack-ng', '--version'],
            'hashcat': ['hashcat', '--version'],
            'crunch': ['crunch', '1', '1', '1234567890']  # Test with minimal parameters
        }
        
        missing_tools = []
        
        for tool_name, test_command in required_tools.items():
            try:
                # Try to execute the tool
                result = subprocess.run(
                    test_command, 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                
                if result.returncode not in [0, 1]:  # Some tools return 1 for version info
                    missing_tools.append(tool_name)
                else:
                    print(f" Tool available: {tool_name}")
                    
            except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
                missing_tools.append(tool_name)
        
        if missing_tools:
            self.error_handler.handle_error('E007', f"Missing tools: {', '.join(missing_tools)}")
            return False
        
        return True
    
    def _check_hardware_requirements(self):
        """Check if system meets hardware requirements"""
        checks = []
        
        # Check RAM
        memory = psutil.virtual_memory()
        min_ram_gb = 2
        if memory.total >= min_ram_gb * 1024**3:
            checks.append(('RAM', f"{memory.total // 1024**3}GB", ""))
        else:
            checks.append(('RAM', f"{memory.total // 1024**3}GB", ""))
        
        # Check CPU cores
        min_cores = 2
        cores = psutil.cpu_count(logical=False)
        if cores >= min_cores:
            checks.append(('CPU Cores', f"{cores}", ""))
        else:
            checks.append(('CPU Cores', f"{cores}", ""))
        
        # Display hardware info
        print("  Hardware Check:")
        for component, value, status in checks:
            print(f"   {status} {component}: {value}")
        
        # Overall result
        if all(status == "" for _, _, status in checks):
            return True
        else:
            self.error_handler.handle_error('E001', "Hardware requirements not met")
            return False
    
    def _check_file_permissions(self):
        """Check necessary file permissions"""
        required_paths = [
            Path.home() / '.pegasus_nexus',
            Path('/tmp')
        ]
        
        for path in required_paths:
            try:
                path.mkdir(exist_ok=True)
                test_file = path / '.write_test'
                test_file.touch()
                test_file.unlink()
            except (PermissionError, OSError) as e:
                self.error_handler.handle_error('E005', f"Permission denied: {path}")
                return False
        
        print(" File permissions: OK")
        return True
    
    def _check_network_capabilities(self):
        """Check basic network capabilities"""
        try:
            # Check if we can create network sockets
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                # This just tests socket creation, not actual network access
                pass
            print(" Network capabilities: OK")
            return True
        except Exception as e:
            self.error_handler.handle_error('E004', "Network socket creation failed")
            return False
    
    def _display_system_summary(self):
        """Display system initialization summary"""
        print("\n" + "="*50)
        print(" SYSTEM INITIALIZATION COMPLETE")
        print("="*50)
        print(f" Checks passed: {len(self.checks_passed)}")
        print(f" Configuration: Loaded")
        print(f" Error handling: Active")
        print(f" Log directory: {Path.home() / '.pegasus_nexus' / 'logs'}")
        print("="*50)
    
    def _display_failed_checks(self):
        """Display failed checks for debugging"""
        print("\n" + "="*50)
        print(" FAILED SYSTEM CHECKS")
        print("="*50)
        for check in self.checks_failed:
            print(f"   • {check}")
        print("="*50)
    
    def get_system_status(self):
        """Get current system status"""
        return {
            'ready': self.system_ready,
            'checks_passed': self.checks_passed,
            'checks_failed': self.checks_failed,
            'config_loaded': self.config_manager is not None,
            'error_handler_ready': self.error_handler is not None
        }
