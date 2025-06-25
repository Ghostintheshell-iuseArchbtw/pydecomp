"""
Advanced pattern recognition for binary analysis.
This module contains patterns and heuristics for better function identification
and code structure analysis.
"""

import re
from typing import List, Dict, Tuple, Optional
import capstone


class PatternMatcher:
    """Advanced pattern matching for binary analysis."""
    
    def __init__(self):
        self.x86_patterns = {
            'function_prologue': [
                b'\x55\x8b\xec',                    # push ebp; mov ebp, esp
                b'\x55\x89\xe5',                    # push ebp; mov ebp, esp (AT&T)
                b'\x55\x48\x89\xe5',               # push rbp; mov rbp, rsp (x64)
                b'\x48\x89\x5c\x24',               # mov [rsp+offset], rbx (x64)
                b'\x48\x83\xec',                   # sub rsp, immediate (x64)
                b'\x48\x89\x4c\x24',               # mov [rsp+offset], rcx (x64)
            ],
            'function_epilogue': [
                b'\x5d\xc3',                       # pop ebp; ret
                b'\x89\xec\x5d\xc3',               # mov esp, ebp; pop ebp; ret
                b'\x48\x89\xec\x5d\xc3',           # mov rsp, rbp; pop rbp; ret (x64)
                b'\xc3',                           # ret
                b'\xc2',                           # ret immediate
            ],
            'string_operations': [
                b'\xf3\xa4',                       # rep movsb
                b'\xf3\xa5',                       # rep movsd
                b'\xf3\xaa',                       # rep stosb
                b'\xf3\xab',                       # rep stosd
            ],
            'common_calls': [
                b'\xe8',                           # call relative
                b'\xff\x15',                       # call [displacement]
                b'\xff\xd0',                       # call eax
                b'\xff\xd1',                       # call ecx
            ]
        }
        
        self.api_patterns = {
            'file_operations': [
                'CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle',
                'SetFilePointer', 'GetFileSize', 'DeleteFile'
            ],
            'memory_operations': [
                'VirtualAlloc', 'VirtualFree', 'HeapAlloc', 'HeapFree',
                'malloc', 'free', 'calloc', 'realloc'
            ],
            'process_operations': [
                'CreateProcess', 'OpenProcess', 'TerminateProcess',
                'GetCurrentProcess', 'GetProcessHeap'
            ],
            'registry_operations': [
                'RegOpenKey', 'RegCloseKey', 'RegQueryValue', 'RegSetValue',
                'RegCreateKey', 'RegDeleteKey'
            ],
            'network_operations': [
                'WSAStartup', 'socket', 'connect', 'send', 'recv',
                'closesocket', 'WSACleanup'
            ],
            'crypto_operations': [
                'CryptAcquireContext', 'CryptCreateHash', 'CryptHashData',
                'CryptEncrypt', 'CryptDecrypt'
            ]
        }
    
    def find_patterns(self, data: bytes, patterns: List[bytes]) -> List[int]:
        """Find all occurrences of patterns in data."""
        matches = []
        for pattern in patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                matches.append(offset)
                offset += 1
        return sorted(matches)
    
    def analyze_function_characteristics(self, instructions: List[Dict]) -> Dict:
        """Analyze function characteristics from instructions."""
        characteristics = {
            'has_loops': False,
            'has_conditionals': False,
            'has_function_calls': False,
            'has_string_ops': False,
            'complexity_score': 0,
            'api_categories': set()
        }
        
        jump_targets = set()
        call_count = 0
        
        for insn in instructions:
            mnemonic = insn['mnemonic'].lower()
            op_str = insn['op_str'].lower()
            
            # Check for loops (backward jumps)
            if mnemonic.startswith('j') and mnemonic != 'jmp':
                characteristics['has_conditionals'] = True
                # Extract jump target
                if '0x' in op_str:
                    try:
                        target = int(op_str.split('0x')[1], 16)
                        if target < insn['address']:
                            characteristics['has_loops'] = True
                        jump_targets.add(target)
                    except:
                        pass
            
            # Check for function calls
            if mnemonic == 'call':
                characteristics['has_function_calls'] = True
                call_count += 1
            
            # Check for string operations
            if mnemonic in ['rep', 'movs', 'stos', 'cmps']:
                characteristics['has_string_ops'] = True
        
        # Calculate complexity score
        characteristics['complexity_score'] = (
            len(instructions) + 
            call_count * 2 + 
            len(jump_targets) * 3 +
            (10 if characteristics['has_loops'] else 0)
        )
        
        return characteristics
    
    def identify_api_usage(self, func_name: str, imports: Dict) -> List[str]:
        """Identify which API categories a function might use."""
        categories = []
        func_lower = func_name.lower()
        
        for category, apis in self.api_patterns.items():
            for api in apis:
                if api.lower() in func_lower:
                    categories.append(category)
                    break
        
        return categories
    
    def suggest_function_purpose(self, func_name: str, characteristics: Dict, 
                                imports: Dict) -> str:
        """Suggest the purpose of a function based on analysis."""
        purposes = []
        
        # Check API usage patterns
        api_categories = self.identify_api_usage(func_name, imports)
        if api_categories:
            purposes.extend(api_categories)
        
        # Check instruction patterns
        if characteristics['has_string_ops']:
            purposes.append('string_manipulation')
        
        if characteristics['has_loops'] and characteristics['complexity_score'] > 50:
            purposes.append('data_processing')
        
        if characteristics['has_function_calls'] and not characteristics['has_loops']:
            purposes.append('wrapper_function')
        
        # Function name analysis
        name_lower = func_name.lower()
        if any(word in name_lower for word in ['init', 'initialize', 'setup']):
            purposes.append('initialization')
        elif any(word in name_lower for word in ['cleanup', 'destroy', 'free']):
            purposes.append('cleanup')
        elif any(word in name_lower for word in ['get', 'retrieve', 'fetch']):
            purposes.append('getter')
        elif any(word in name_lower for word in ['set', 'store', 'save']):
            purposes.append('setter')
        elif any(word in name_lower for word in ['check', 'validate', 'verify']):
            purposes.append('validation')
        
        return purposes[0] if purposes else 'unknown'


class DataStructureAnalyzer:
    """Analyze and reconstruct data structures from binary."""
    
    def __init__(self):
        self.common_sizes = {
            1: 'uint8_t',
            2: 'uint16_t', 
            4: 'uint32_t',
            8: 'uint64_t'
        }
    
    def analyze_memory_accesses(self, instructions: List[Dict]) -> Dict:
        """Analyze memory access patterns to infer data structures."""
        memory_accesses = []
        
        for insn in instructions:
            # Look for memory access patterns like [reg+offset]
            if '[' in insn['op_str'] and '+' in insn['op_str']:
                # Extract offset information
                match = re.search(r'\[([^+]+)\+([^]]+)\]', insn['op_str'])
                if match:
                    base_reg = match.group(1).strip()
                    offset_str = match.group(2).strip()
                    try:
                        if '0x' in offset_str:
                            offset = int(offset_str, 16)
                        else:
                            offset = int(offset_str)
                        
                        memory_accesses.append({
                            'instruction': insn['mnemonic'],
                            'base_register': base_reg,
                            'offset': offset,
                            'address': insn['address']
                        })
                    except ValueError:
                        pass
        
        return self.infer_structure_from_accesses(memory_accesses)
    
    def infer_structure_from_accesses(self, accesses: List[Dict]) -> Dict:
        """Infer structure layout from memory accesses."""
        if not accesses:
            return {}
        
        # Group by base register
        by_register = {}
        for access in accesses:
            reg = access['base_register']
            if reg not in by_register:
                by_register[reg] = []
            by_register[reg].append(access)
        
        structures = {}
        for reg, reg_accesses in by_register.items():
            if len(reg_accesses) < 2:
                continue
                
            # Sort by offset
            reg_accesses.sort(key=lambda x: x['offset'])
            
            # Infer structure members
            members = []
            for i, access in enumerate(reg_accesses):
                offset = access['offset']
                
                # Guess size based on instruction
                size = 4  # default
                if access['instruction'].endswith('b'):
                    size = 1
                elif access['instruction'].endswith('w'):
                    size = 2
                elif access['instruction'].endswith('q'):
                    size = 8
                
                member_type = self.common_sizes.get(size, f'uint{size*8}_t')
                members.append({
                    'offset': offset,
                    'type': member_type,
                    'name': f'field_{offset:x}',
                    'size': size
                })
            
            if members:
                structures[f'struct_{reg}_data'] = members
        
        return structures
    
    def generate_structure_definitions(self, structures: Dict) -> str:
        """Generate C structure definitions."""
        definitions = []
        
        for struct_name, members in structures.items():
            definitions.append(f"typedef struct {struct_name} {{")
            
            current_offset = 0
            for member in members:
                # Add padding if needed
                if member['offset'] > current_offset:
                    padding_size = member['offset'] - current_offset
                    definitions.append(f"    uint8_t padding_{current_offset:x}[{padding_size}];")
                
                definitions.append(f"    {member['type']} {member['name']};")
                current_offset = member['offset'] + member['size']
            
            definitions.append(f"}} {struct_name}_t;\n")
        
        return '\n'.join(definitions)
