#!/usr/bin/env python3
"""
Enhanced Pattern Analyzer for Better Function Reconstruction
Improves function identification, parameter inference, and code structure analysis
"""

import re
import capstone
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
import json


class AdvancedPatternMatcher:
    """Advanced pattern matching for function analysis."""
    
    def __init__(self):
        self.function_patterns = {
            # Common function prologues
            'standard_prologue': [
                b'\x55',                    # push ebp
                b'\x8b\xec',               # mov ebp, esp
            ],
            'x64_prologue': [
                b'\x48\x89\x5c\x24',      # mov [rsp+xx], rbx
                b'\x48\x89\x6c\x24',      # mov [rsp+xx], rbp
                b'\x48\x89\x74\x24',      # mov [rsp+xx], rsi
            ],
            'fastcall_prologue': [
                b'\x8b\xff',               # mov edi, edi (padding)
                b'\x55',                   # push ebp
                b'\x8b\xec',              # mov ebp, esp
            ]
        }
        
        self.api_patterns = self.load_api_patterns()
        self.calling_conventions = {
            'stdcall': {'cleanup': 'callee', 'params': 'stack'},
            'cdecl': {'cleanup': 'caller', 'params': 'stack'},
            'fastcall': {'cleanup': 'callee', 'params': 'registers_then_stack'},
            'thiscall': {'cleanup': 'callee', 'params': 'ecx_then_stack'}
        }
        
    def load_api_patterns(self) -> Dict[str, Dict]:
        """Load Windows API patterns for better recognition."""
        return {
            # Kernel32.dll functions
            'CreateFileA': {
                'params': 7,
                'return_type': 'HANDLE',
                'calling_convention': 'stdcall',
                'category': 'file_operations'
            },
            'CreateFileW': {
                'params': 7,
                'return_type': 'HANDLE',
                'calling_convention': 'stdcall',
                'category': 'file_operations'
            },
            'WriteFile': {
                'params': 5,
                'return_type': 'BOOL',
                'calling_convention': 'stdcall',
                'category': 'file_operations'
            },
            'ReadFile': {
                'params': 5,
                'return_type': 'BOOL',
                'calling_convention': 'stdcall',
                'category': 'file_operations'
            },
            'VirtualAlloc': {
                'params': 4,
                'return_type': 'LPVOID',
                'calling_convention': 'stdcall',
                'category': 'memory_operations'
            },
            'VirtualFree': {
                'params': 3,
                'return_type': 'BOOL',
                'calling_convention': 'stdcall',
                'category': 'memory_operations'
            },
            'GetProcAddress': {
                'params': 2,
                'return_type': 'FARPROC',
                'calling_convention': 'stdcall',
                'category': 'process_operations'
            },
            'LoadLibraryA': {
                'params': 1,
                'return_type': 'HMODULE',
                'calling_convention': 'stdcall',
                'category': 'process_operations'
            },
            'LoadLibraryW': {
                'params': 1,
                'return_type': 'HMODULE',
                'calling_convention': 'stdcall',
                'category': 'process_operations'
            },
            # User32.dll functions
            'MessageBoxA': {
                'params': 4,
                'return_type': 'int',
                'calling_convention': 'stdcall',
                'category': 'ui_operations'
            },
            'MessageBoxW': {
                'params': 4,
                'return_type': 'int',
                'calling_convention': 'stdcall',
                'category': 'ui_operations'
            },
            'FindWindowA': {
                'params': 2,
                'return_type': 'HWND',
                'calling_convention': 'stdcall',
                'category': 'ui_operations'
            },
            'FindWindowW': {
                'params': 2,
                'return_type': 'HWND',
                'calling_convention': 'stdcall',
                'category': 'ui_operations'
            },
            # Registry functions
            'RegOpenKeyExA': {
                'params': 5,
                'return_type': 'LONG',
                'calling_convention': 'stdcall',
                'category': 'registry_operations'
            },
            'RegQueryValueExA': {
                'params': 6,
                'return_type': 'LONG',
                'calling_convention': 'stdcall',
                'category': 'registry_operations'
            },
            'RegSetValueExA': {
                'params': 6,
                'return_type': 'LONG',
                'calling_convention': 'stdcall',
                'category': 'registry_operations'
            },
            # Network functions
            'WSAStartup': {
                'params': 2,
                'return_type': 'int',
                'calling_convention': 'stdcall',
                'category': 'network_operations'
            },
            'socket': {
                'params': 3,
                'return_type': 'SOCKET',
                'calling_convention': 'stdcall',
                'category': 'network_operations'
            },
            'connect': {
                'params': 3,
                'return_type': 'int',
                'calling_convention': 'stdcall',
                'category': 'network_operations'
            },
            'send': {
                'params': 4,
                'return_type': 'int',
                'calling_convention': 'stdcall',
                'category': 'network_operations'
            },
            'recv': {
                'params': 4,
                'return_type': 'int',
                'calling_convention': 'stdcall',
                'category': 'network_operations'
            }
        }
        
    def identify_function_type(self, instructions: List, function_name: str = None) -> Dict[str, Any]:
        """Identify function type and characteristics."""
        result = {
            'type': 'unknown',
            'calling_convention': 'unknown',
            'parameter_count': 0,
            'local_vars': 0,
            'complexity': 0,
            'has_loops': False,
            'has_switches': False,
            'api_calls': [],
            'string_refs': [],
            'characteristics': []
        }
        
        if not instructions:
            return result
            
        # Analyze function prologue
        prologue_info = self.analyze_prologue(instructions[:10])
        result.update(prologue_info)
        
        # Analyze function body
        body_analysis = self.analyze_function_body(instructions)
        result.update(body_analysis)
        
        # Analyze epilogue
        epilogue_info = self.analyze_epilogue(instructions[-10:])
        result.update(epilogue_info)
        
        # Infer calling convention
        result['calling_convention'] = self.infer_calling_convention(instructions)
        
        # Calculate complexity
        result['complexity'] = self.calculate_complexity(instructions)
        
        # Check for specific function patterns
        if function_name and function_name in self.api_patterns:
            api_info = self.api_patterns[function_name]
            result.update(api_info)
            
        return result
        
    def analyze_prologue(self, instructions: List) -> Dict[str, Any]:
        """Analyze function prologue for calling convention and stack setup."""
        result = {
            'prologue_type': 'unknown',
            'stack_adjustment': 0,
            'saved_registers': []
        }
        
        if not instructions:
            return result
            
        # Convert instructions to bytes for pattern matching
        inst_bytes = b''.join(getattr(inst, 'bytes', b'') for inst in instructions)
        
        # Check for standard prologue patterns
        if b'\x55\x8b\xec' in inst_bytes:  # push ebp; mov ebp, esp
            result['prologue_type'] = 'standard'
        elif b'\x48\x89\x5c\x24' in inst_bytes:  # x64 prologue
            result['prologue_type'] = 'x64_standard'
        elif b'\x8b\xff\x55\x8b\xec' in inst_bytes:  # fastcall prologue
            result['prologue_type'] = 'fastcall'
            
        # Analyze stack adjustment
        for inst in instructions:
            if hasattr(inst, 'mnemonic'):
                if inst.mnemonic == 'sub' and 'esp' in inst.op_str:
                    # Extract stack adjustment value
                    match = re.search(r'(\d+)', inst.op_str)
                    if match:
                        result['stack_adjustment'] = int(match.group(1))
                elif inst.mnemonic == 'push':
                    # Track saved registers
                    reg = inst.op_str.strip()
                    if reg not in result['saved_registers']:
                        result['saved_registers'].append(reg)
                        
        return result
        
    def analyze_function_body(self, instructions: List) -> Dict[str, Any]:
        """Analyze function body for patterns and characteristics."""
        result = {
            'has_loops': False,
            'has_switches': False,
            'has_calls': False,
            'has_string_ops': False,
            'api_calls': [],
            'jump_targets': [],
            'conditional_jumps': 0,
            'unconditional_jumps': 0
        }
        
        jump_instructions = ['jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe']
        string_instructions = ['movs', 'stos', 'lods', 'scas', 'cmps']
        
        for inst in instructions:
            if not hasattr(inst, 'mnemonic'):
                continue
                
            mnemonic = inst.mnemonic.lower()
            
            # Check for jumps
            if mnemonic in jump_instructions:
                if mnemonic == 'jmp':
                    result['unconditional_jumps'] += 1
                else:
                    result['conditional_jumps'] += 1
                    
                # Track jump targets for loop detection
                if hasattr(inst, 'operands') and inst.operands:
                    target = inst.operands[0].value.mem.disp if hasattr(inst.operands[0], 'value') else None
                    if target:
                        result['jump_targets'].append(target)
                        
            # Check for function calls
            elif mnemonic == 'call':
                result['has_calls'] = True
                
            # Check for string operations
            elif any(mnemonic.startswith(s) for s in string_instructions):
                result['has_string_ops'] = True
                
            # Check for switch statements (indirect jumps with jump tables)
            elif mnemonic == 'jmp' and '[' in inst.op_str:
                result['has_switches'] = True
                
        # Detect loops (backward jumps)
        current_addr = 0
        for inst in instructions:
            if hasattr(inst, 'address'):
                if hasattr(inst, 'mnemonic') and inst.mnemonic.lower() in jump_instructions:
                    # Check if jump target is backward (potential loop)
                    target_match = re.search(r'0x([0-9a-fA-F]+)', inst.op_str)
                    if target_match:
                        target_addr = int(target_match.group(1), 16)
                        if target_addr <= inst.address:
                            result['has_loops'] = True
                current_addr = inst.address
                
        return result
        
    def analyze_epilogue(self, instructions: List) -> Dict[str, Any]:
        """Analyze function epilogue for return type and cleanup."""
        result = {
            'epilogue_type': 'unknown',
            'stack_cleanup': 0,
            'return_register': None
        }
        
        if not instructions:
            return result
            
        # Look for common epilogue patterns
        for inst in instructions:
            if not hasattr(inst, 'mnemonic'):
                continue
                
            mnemonic = inst.mnemonic.lower()
            
            if mnemonic == 'ret':
                # Check for stack cleanup in ret instruction
                if inst.op_str and inst.op_str.strip().isdigit():
                    result['stack_cleanup'] = int(inst.op_str.strip())
                result['epilogue_type'] = 'standard'
                
            elif mnemonic == 'pop' and 'ebp' in inst.op_str:
                result['epilogue_type'] = 'standard'
                
            elif mnemonic == 'mov' and 'esp' in inst.op_str and 'ebp' in inst.op_str:
                result['epilogue_type'] = 'standard'
                
        return result
        
    def infer_calling_convention(self, instructions: List) -> str:
        """Infer the calling convention based on instruction patterns."""
        # Look for stack cleanup patterns
        has_caller_cleanup = False
        has_callee_cleanup = False
        uses_ecx = False
        uses_registers = False
        
        for inst in instructions:
            if not hasattr(inst, 'mnemonic'):
                continue
                
            mnemonic = inst.mnemonic.lower()
            op_str = getattr(inst, 'op_str', '')
            
            # Check for register usage that indicates fastcall
            if 'ecx' in op_str or 'edx' in op_str:
                uses_ecx = True
                
            # Check for register parameter passing
            if mnemonic == 'mov' and any(reg in op_str for reg in ['ecx', 'edx', 'r8', 'r9']):
                uses_registers = True
                
            # Check for return with immediate (callee cleanup)
            if mnemonic == 'ret' and op_str and op_str.strip().isdigit():
                has_callee_cleanup = True
                
        # Infer convention based on patterns
        if uses_ecx and has_callee_cleanup:
            return 'fastcall'
        elif has_callee_cleanup:
            return 'stdcall'
        elif uses_registers:
            return 'fastcall'  # or x64 calling convention
        else:
            return 'cdecl'  # default assumption
            
    def calculate_complexity(self, instructions: List) -> int:
        """Calculate McCabe complexity for the function."""
        complexity = 1  # Base complexity
        
        conditional_instructions = ['je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe']
        
        for inst in instructions:
            if hasattr(inst, 'mnemonic'):
                mnemonic = inst.mnemonic.lower()
                
                # Add complexity for conditional branches
                if mnemonic in conditional_instructions:
                    complexity += 1
                    
                # Add complexity for loops (approximate)
                elif mnemonic == 'loop':
                    complexity += 2
                    
        return min(complexity, 50)  # Cap at reasonable value


class EnhancedDataStructureAnalyzer:
    """Enhanced data structure analysis for better type inference."""
    
    def __init__(self):
        self.structure_patterns = {}
        self.type_sizes = {
            'BYTE': 1, 'CHAR': 1, 'UCHAR': 1,
            'WORD': 2, 'SHORT': 2, 'USHORT': 2, 'WCHAR': 2,
            'DWORD': 4, 'INT': 4, 'UINT': 4, 'LONG': 4, 'ULONG': 4, 'FLOAT': 4,
            'QWORD': 8, 'LONGLONG': 8, 'ULONGLONG': 8, 'DOUBLE': 8,
            'POINTER': 8 if '64' in str(capstone.CS_ARCH_X86) else 4
        }
        
    def analyze_memory_accesses(self, instructions: List) -> Dict[str, Any]:
        """Analyze memory access patterns to infer data structures."""
        memory_accesses = defaultdict(list)
        structure_candidates = {}
        
        for inst in instructions:
            if not hasattr(inst, 'mnemonic') or not hasattr(inst, 'op_str'):
                continue
                
            # Look for memory operations
            if '[' in inst.op_str and ']' in inst.op_str:
                # Extract memory reference
                mem_match = re.search(r'\[([^\]]+)\]', inst.op_str)
                if mem_match:
                    mem_ref = mem_match.group(1)
                    
                    # Parse memory reference components
                    access_info = self.parse_memory_reference(mem_ref, inst.mnemonic)
                    if access_info:
                        base_reg = access_info.get('base_register')
                        if base_reg:
                            memory_accesses[base_reg].append(access_info)
                            
        # Analyze access patterns to identify structures
        for base_reg, accesses in memory_accesses.items():
            structure_info = self.infer_structure_from_accesses(accesses)
            if structure_info:
                structure_candidates[base_reg] = structure_info
                
        return {
            'memory_accesses': dict(memory_accesses),
            'structure_candidates': structure_candidates
        }
        
    def parse_memory_reference(self, mem_ref: str, instruction: str) -> Optional[Dict[str, Any]]:
        """Parse a memory reference to extract components."""
        # Handle different memory reference formats
        # [reg + offset], [reg], [reg + reg*scale + offset], etc.
        
        access_info = {
            'base_register': None,
            'index_register': None,
            'scale': 1,
            'offset': 0,
            'access_type': self.get_access_type(instruction),
            'data_size': self.get_data_size(instruction)
        }
        
        # Simple parsing - can be enhanced
        parts = mem_ref.replace(' ', '').split('+')
        for part in parts:
            if part.isdigit() or (part.startswith('-') and part[1:].isdigit()):
                access_info['offset'] = int(part)
            elif part.isalpha() or part in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']:
                if not access_info['base_register']:
                    access_info['base_register'] = part
                else:
                    access_info['index_register'] = part
                    
        return access_info if access_info['base_register'] else None
        
    def get_access_type(self, instruction: str) -> str:
        """Determine if memory access is read, write, or read-write."""
        instruction = instruction.lower()
        
        if instruction.startswith('mov') and ',' in instruction:
            return 'write' if '[' in instruction.split(',')[0] else 'read'
        elif instruction in ['push']:
            return 'read'
        elif instruction in ['pop']:
            return 'write'
        elif instruction.startswith('cmp'):
            return 'read'
        else:
            return 'read-write'
            
    def get_data_size(self, instruction: str) -> int:
        """Determine the size of data being accessed."""
        instruction = instruction.lower()
        
        if 'byte' in instruction or instruction.endswith('b'):
            return 1
        elif 'word' in instruction or instruction.endswith('w'):
            return 2
        elif 'dword' in instruction or instruction.endswith('d'):
            return 4
        elif 'qword' in instruction or instruction.endswith('q'):
            return 8
        else:
            return 4  # default assumption
            
    def infer_structure_from_accesses(self, accesses: List[Dict]) -> Optional[Dict]:
        """Infer structure definition from memory access patterns."""
        if len(accesses) < 2:
            return None
            
        # Sort by offset
        accesses.sort(key=lambda x: x.get('offset', 0))
        
        structure = {
            'members': [],
            'total_size': 0,
            'alignment': 4  # default alignment
        }
        
        current_offset = 0
        for access in accesses:
            offset = access.get('offset', 0)
            size = access.get('data_size', 4)
            access_type = access.get('access_type', 'read')
            
            # Skip if offset is before current position (overlap)
            if offset < current_offset:
                continue
                
            # Add padding if needed
            if offset > current_offset:
                padding_size = offset - current_offset
                structure['members'].append({
                    'name': f'padding_{current_offset}',
                    'type': f'BYTE[{padding_size}]',
                    'offset': current_offset,
                    'size': padding_size
                })
                
            # Add member
            member_name = f'member_{offset}'
            member_type = self.infer_member_type(size, access_type)
            
            structure['members'].append({
                'name': member_name,
                'type': member_type,
                'offset': offset,
                'size': size,
                'access_pattern': access_type
            })
            
            current_offset = offset + size
            
        structure['total_size'] = current_offset
        return structure
        
    def infer_member_type(self, size: int, access_type: str) -> str:
        """Infer C type based on size and access pattern."""
        type_mapping = {
            1: 'BYTE',
            2: 'WORD', 
            4: 'DWORD',
            8: 'QWORD'
        }
        
        base_type = type_mapping.get(size, f'UNKNOWN_{size}')
        
        # Modify based on access pattern
        if access_type == 'read' and size in [4, 8]:
            # Could be a pointer or function pointer
            return f'{base_type} /* possibly pointer */'
        elif access_type == 'write' and size == 1:
            # Could be a flag or character
            return 'BYTE /* flag or char */'
            
        return base_type
        
    def generate_structure_definition(self, structure_name: str, structure_info: Dict) -> str:
        """Generate C structure definition."""
        lines = [f"typedef struct _{structure_name} {{"]
        
        for member in structure_info['members']:
            lines.append(f"    {member['type']} {member['name']};  // offset: 0x{member['offset']:x}")
            
        lines.append(f"}} {structure_name}, *P{structure_name};")
        lines.append(f"// Total size: 0x{structure_info['total_size']:x} ({structure_info['total_size']} bytes)")
        
        return '\n'.join(lines)