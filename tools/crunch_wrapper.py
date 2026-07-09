# File: tools/crunch_wrapper.py
import subprocess
import os
import tempfile
from pathlib import Path
from core.error_handler import ErrorHandler

class CrunchWrapper:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.temp_files = []
        
    def generate_wordlist(self, min_length, max_length, charset=None, pattern=None, 
                         output_file=None, max_size_mb=100):
        """
        Generate wordlist using crunch with various options
        """
        try:
            # Default charset if not provided
            if charset is None:
                charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            
            # Create temp file if no output file specified
            if output_file is None:
                output_file = tempfile.NamedTemporaryFile(
                    mode='w', delete=False, suffix='.txt', prefix='crunch_'
                ).name
                self.temp_files.append(output_file)
            
            # Build crunch command
            cmd = [
                'crunch',
                str(min_length),
                str(max_length),
                charset
            ]
            
            # Add pattern if specified
            if pattern:
                cmd.extend(['-t', pattern])
            
            # Add output file
            cmd.extend(['-o', output_file])
            
            # Estimate file size and check limits
            estimated_size = self._estimate_file_size(min_length, max_length, charset, pattern)
            if estimated_size > max_size_mb * 1024 * 1024:
                print(f"  Estimated size: {estimated_size/(1024*1024):.1f}MB > {max_size_mb}MB limit")
                return None
            
            print(f" Generating wordlist with crunch...")
            print(f"    Length: {min_length}-{max_length} chars")
            print(f"    Charset: {charset[:50]}{'...' if len(charset) > 50 else ''}")
            if pattern:
                print(f"    Pattern: {pattern}")
            print(f"    Output: {output_file}")
            print(f"    Estimated size: {estimated_size/(1024*1024):.1f}MB")
            
            # Execute crunch
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if process.returncode == 0:
                # Verify file was created and has content
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    file_size = os.path.getsize(output_file)
                    line_count = self._count_lines(output_file)
                    
                    print(f" Wordlist generated successfully!")
                    print(f"    File: {output_file}")
                    print(f"    Size: {file_size/(1024*1024):.2f}MB")
                    print(f"    Entries: {line_count:,}")
                    
                    return output_file
                else:
                    self.error_handler.handle_error('E102', "Crunch generated empty file")
                    return None
            else:
                self.error_handler.handle_error('E102', f"Crunch execution failed: {process.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            self.error_handler.handle_error('E002', "Crunch generation timeout")
            return None
        except Exception as e:
            self.error_handler.handle_error('E102', f"Wordlist generation failed: {str(e)}", e)
            return None
    
    def generate_smart_wordlist(self, target_profile, output_file=None, max_size_mb=500):
        """
        Generate intelligent wordlist based on target analysis
        """
        print(f" Generating SMART wordlist for: {target_profile['ssid']}")
        
        # Get optimal parameters based on target type
        params = self._get_smart_parameters(target_profile)
        
        # Adjust max size based on target priority
        if target_profile['success_probability'] > 0.7:
            max_size_mb *= 2  # Double size for high-probability targets
        
        return self.generate_wordlist(
            min_length=params['min_length'],
            max_length=params['max_length'],
            charset=params['charset'],
            pattern=params.get('pattern'),
            output_file=output_file,
            max_size_mb=max_size_mb
        )
    
    def _get_smart_parameters(self, target_profile):
        """
        Get smart wordlist parameters based on target analysis
        """
        target_type = target_profile.get('ssid_pattern', 'personal_network')
        
        # Base parameters by target type
        base_params = {
            'default_router': {
                'min_length': 8,
                'max_length': 12,
                'charset': '0123456789abcdefghijklmnopqrstuvwxyz',
                'description': 'Router defaults often mix numbers and lowercase'
            },
            'isp_provided': {
                'min_length': 8,
                'max_length': 10, 
                'charset': '0123456789',
                'description': 'ISP routers often use numeric passwords'
            },
            'public_wifi': {
                'min_length': 8,
                'max_length': 10,
                'charset': '0123456789',
                'description': 'Public WiFi often uses simple numeric passwords'
            },
            'business_network': {
                'min_length': 12,
                'max_length': 16,
                'charset': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%',
                'description': 'Business networks use complex passwords'
            },
            'personal_network': {
                'min_length': 8,
                'max_length': 15,
                'charset': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                'description': 'Personal networks vary widely'
            }
        }
        
        params = base_params.get(target_type, base_params['personal_network'])
        
        # Adjust based on specific SSID patterns
        ssid = target_profile.get('ssid', '').lower()
        
        # Common pattern adjustments
        if 'phone' in ssid or 'mobile' in ssid or 'galaxy' in ssid:
            # Phone hotspots often use simpler passwords
            params['min_length'] = 8
            params['max_length'] = 12
            params['charset'] = '0123456789abcdefghijklmnopqrstuvwxyz'
        
        print(f"    Smart parameters: {params['description']}")
        print(f"    Length: {params['min_length']}-{params['max_length']}")
        print(f"    Charset size: {len(params['charset'])}")
        
        return params
    
    def _estimate_file_size(self, min_length, max_length, charset, pattern=None):
        """
        Estimate the size of the generated wordlist
        """
        charset_size = len(charset)
        total_combinations = 0
        
        for length in range(min_length, max_length + 1):
            if pattern:
                # For patterns, estimate based on variable positions
                variable_chars = pattern.count('@')  # @ represents variable chars in crunch
                if variable_chars > 0:
                    total_combinations += charset_size ** variable_chars
                else:
                    total_combinations += 1  # Fixed pattern
            else:
                # Standard combination calculation
                total_combinations += charset_size ** length
        
        # Estimate average word length and calculate size
        avg_word_length = (min_length + max_length) / 2
        estimated_bytes = total_combinations * (avg_word_length + 1)  # +1 for newline
        
        return estimated_bytes
    
    def _count_lines(self, filename):
        """Count lines in a file efficiently"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except:
            return 0
    
    def generate_common_passwords_wordlist(self, output_file=None):
        """
        Generate a wordlist with common passwords and patterns
        """
        common_params = {
            'min_length': 4,
            'max_length': 12,
            'charset': '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%',
            'pattern': None
        }
        
        return self.generate_wordlist(**common_params, output_file=output_file, max_size_mb=50)
    
    def generate_numeric_wordlist(self, min_length=4, max_length=10, output_file=None):
        """
        Generate numeric-only wordlist (for WPS pins, simple passwords)
        """
        return self.generate_wordlist(
            min_length=min_length,
            max_length=max_length,
            charset='0123456789',
            output_file=output_file,
            max_size_mb=10
        )
    
    def generate_custom_charset_wordlist(self, charset_name, min_length=6, max_length=12, output_file=None):
        """
        Generate wordlist with predefined character sets
        """
        charsets = {
            'numeric': '0123456789',
            'lowercase': 'abcdefghijklmnopqrstuvwxyz',
            'uppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'alpha': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'alphanumeric': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'hex_lower': '0123456789abcdef',
            'hex_upper': '0123456789ABCDEF',
            'simple_special': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%',
            'full_special': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|;:,.<>?'
        }
        
        charset = charsets.get(charset_name, charsets['alphanumeric'])
        
        return self.generate_wordlist(
            min_length=min_length,
            max_length=max_length,
            charset=charset,
            output_file=output_file,
            max_size_mb=100
        )
    
    def stream_wordlist_chunks(self, min_length, max_length, charset, chunk_size=10000):
        """
        Generate and yield wordlist in chunks (memory efficient)
        """
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        temp_file.close()
        self.temp_files.append(temp_file.name)
        
        # Generate full wordlist
        result_file = self.generate_wordlist(
            min_length=min_length,
            max_length=max_length,
            charset=charset,
            output_file=temp_file.name
        )
        
        if not result_file:
            return
        
        # Yield chunks from the file
        try:
            with open(result_file, 'r', encoding='utf-8', errors='ignore') as f:
                chunk = []
                for line in f:
                    chunk.append(line.strip())
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
                
                if chunk:  # Yield remaining lines
                    yield chunk
                    
        except Exception as e:
            self.error_handler.handle_error('E102', f"Wordlist streaming failed: {str(e)}", e)
    
    def cleanup_temp_files(self):
        """Clean up temporary wordlist files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
        self.temp_files = []
    
    def get_available_charsets(self):
        """Get list of available character set names"""
        return {
            'numeric': 'Numbers only (0-9)',
            'lowercase': 'Lowercase letters (a-z)',
            'uppercase': 'Uppercase letters (A-Z)',
            'alpha': 'All letters (a-z, A-Z)',
            'alphanumeric': 'Letters and numbers (a-z, A-Z, 0-9)',
            'hex_lower': 'Hexadecimal lowercase (0-9, a-f)',
            'hex_upper': 'Hexadecimal uppercase (0-9, A-F)',
            'simple_special': 'Alphanumeric with basic special chars',
            'full_special': 'Alphanumeric with all special chars'
        }
    
    def __del__(self):
        """Destructor to clean up temp files"""
        self.cleanup_temp_files()