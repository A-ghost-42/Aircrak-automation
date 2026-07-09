# File: engines/password_generator.py
import itertools
import string
import math
import re
from core.error_handler import ErrorHandler

class PasswordGenerator:
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
        self.generated_count = 0
        
    def get_charset(self, charset_name):
        """Get character set by name"""
        charsets = {
            'numeric': string.digits,
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'alpha': string.ascii_letters,
            'alphanumeric': string.ascii_letters + string.digits,
            'full': string.ascii_letters + string.digits + '!@#$%^&*()',
            'hex_lower': '0123456789abcdef',
            'hex_upper': '0123456789ABCDEF'
        }
        return charsets.get(charset_name, charsets['alphanumeric'])
    
    def generate_passwords_stream(self, min_length, max_length, charset_name, pattern=None, partition=None):
        """Generate passwords in real-time stream"""
        charset = self.get_charset(charset_name)
        for length in range(min_length, max_length + 1):
            if partition:
                yield from self._generate_partitioned_stream(length, charset, partition)
            else:
                yield from self._generate_fixed_length_stream(length, charset, pattern)

    def generate_mutations_stream(self, seed_words):
        """
        Generate mutations based on known passwords or keywords.
        seed_words: list of strings (e.g. ['Admin123', 'Summer2023'])
        """
        if isinstance(seed_words, str):
            seed_words = [seed_words]
            
        print(f"🧬 Generating mutations for {len(seed_words)} seed words...")
        
        for word in seed_words:
            yield from self._apply_mutations(word)

    def _apply_mutations(self, word):
        """Apply a comprehensive set of mutation rules to a word"""
        mutations = set()
        mutations.add(word)
        
        # 1. Case Variations
        mutations.add(word.lower())
        mutations.add(word.upper())
        mutations.add(word.capitalize())
        mutations.add(word.swapcase())
        
        # 2. Common Number Suffixes (Year, Sequence)
        years = [str(y) for y in range(2020, 2027)]
        sequences = ['1', '12', '123', '1234', '12345', '123456', '01']
        for s in years + sequences:
            mutations.add(f"{word}{s}")
            mutations.add(f"{word}_{s}")
            mutations.add(f"{s}{word}")
            
        # 3. Common Special Characters
        specials = ['!', '!!', '!!!', '?', '@', '#', '$', '*', '.', '_']
        for spec in specials:
            mutations.add(f"{word}{spec}")
            mutations.add(f"{spec}{word}")
            
        # 4. Leetspeak (Basic)
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'b': '8', 'g': '9'}
        leet_word = "".join(leet_map.get(c.lower(), c) for c in word)
        mutations.add(leet_word)
        
        # 5. Compound mutations (Word + Year + !)
        for year in years:
            mutations.add(f"{word}{year}!")
            mutations.add(f"{word.capitalize()}{year}!")
            mutations.add(f"{word.capitalize()}{year}!!")
            
        # 6. Advanced Variations
        mutations.add(word[::-1]) # Reverse
        mutations.add(f"{word}{word}") # Double
        mutations.add(f"{word.capitalize()}{word.lower()}") # Capitalized Double
        
        # Yield all unique mutations found
        for m in mutations:
            if len(m) >= 8: # WPA minimum length
                self.generated_count += 1
                yield m

    def _generate_fixed_length_stream(self, length, charset, pattern=None):
        for p in itertools.product(charset, repeat=length):
            self.generated_count += 1
            yield "".join(p)

    def _generate_partitioned_stream(self, length, charset, partition):
        idx, total = partition
        charset_len = len(charset)
        chunk_size = math.ceil(charset_len / total)
        start_char_idx = idx * chunk_size
        end_char_idx = min(start_char_idx + chunk_size, charset_len)
        if start_char_idx >= charset_len: return
        target_chars = charset[start_char_idx:end_char_idx]
        
        if length == 1:
            for c in target_chars: yield c
        else:
            for first_char in target_chars:
                for rest in itertools.product(charset, repeat=length - 1):
                    self.generated_count += 1
                    yield first_char + "".join(rest)

    def smart_length_sequence(self, target_profile):
        base_lengths = {'default_router': [8, 10, 12, 6, 14], 'isp_provided': [8, 10, 12, 14], 'business_network': [12, 15, 8, 10, 20], 'public_wifi': [8, 10, 12, 6], 'personal_network': [8, 10, 12, 6, 15], 'hidden': [8, 10, 12]}
        return base_lengths.get(target_profile.get('ssid_pattern', 'personal_network'), [8, 10, 12])
    
    def smart_charset_sequence(self, target_profile):
        charsets = [{'name': 'numeric', 'priority': 1.0}, {'name': 'lowercase', 'priority': 0.8}, {'name': 'alphanumeric', 'priority': 0.6}, {'name': 'full', 'priority': 0.4}]
        pattern = target_profile.get('ssid_pattern', 'personal_network')
        if pattern == 'public_wifi': charsets.sort(key=lambda x: x['name'] == 'numeric', reverse=True)
        elif pattern == 'business_network': charsets.sort(key=lambda x: x['name'] == 'full', reverse=True)
        return [cs['name'] for cs in charsets]
