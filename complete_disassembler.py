#!/usr/bin/env python3
"""
Complete Advanced Binary Disassembler with Perfect C Code Generation
This module provides deep binary analysis with full function reconstruction
and perfect C code generation.
"""

import capstone
from typing import Dict, List, Tuple, Optional, Set
import re
import json
from perfect_c_generator import PerfectCCodeGenerator


class AdvancedDisassembler:
    """Advanced disassembler with complete instruction mapping."""
    
    def __init__(self, arch='x64'):
        self.arch = arch
        self.disassembler = None
        self.instruction_cache = {}
        self.function_graphs = {}
        self.cross_references = {}
        
        # Initialize disassembler with all features
        if arch == 'x64':
            self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            
        self.disassembler.detail = True
        self.disassembler.syntax = capstone.CS_OPT_SYNTAX_INTEL
    
    def complete_function_analysis(self, start_addr: int, section_data: bytes, 
                                 section_base: int, max_size: int = 8192) -> Dict:
        """Perform complete function analysis with control flow mapping."""
        
        function_info = {
            'address': start_addr,
            'instructions': [],
            'basic_blocks': [],
            'control_flow': {
                'calls': [],
                'jumps': [],
                'returns': [],
                'loops': []
            },
            'data_references': [],
            'api_calls': [],
            'local_variables': {},
            'parameters': [],
            'stack_frame_size': 0,
            'register_usage': set(),
            'memory_accesses': []
        }
        
        # Calculate offset within section
        offset = start_addr - section_base
        if offset >= len(section_data):
            return function_info
        
        # Track analysis state
        analyzed_addresses = set()
        pending_addresses = [start_addr]
        instruction_map = {}
        
        while pending_addresses:
            current_addr = pending_addresses.pop(0)
            
            if current_addr in analyzed_addresses:
                continue
                
            # Disassemble from current address
            current_offset = current_addr - section_base
            if current_offset >= len(section_data):
                continue
                
            code = section_data[current_offset:current_offset + max_size]
            basic_block = []
            
            for insn in self.disassembler.disasm(code, current_addr):
                if insn.address in analyzed_addresses:
                    break
                
                analyzed_addresses.add(insn.address)
                
                # Create detailed instruction info
                insn_info = self._analyze_instruction(insn)
                instruction_map[insn.address] = insn_info
                basic_block.append(insn_info)
                
                # Track register usage
                function_info['register_usage'].update(insn_info['registers_read'])
                function_info['register_usage'].update(insn_info['registers_written'])
                
                # Track memory accesses
                if insn_info['memory_access']:
                    function_info['memory_accesses'].append(insn_info['memory_access'])
                
                # Track API calls
                if insn_info['is_call'] and insn_info['call_target']:
                    function_info['api_calls'].append({
                        'address': insn.address,
                        'target': insn_info['call_target'],
                        'instruction': insn_info
                    })
                
                # Handle control flow
                if insn.mnemonic in ['ret', 'retn', 'retf']:
                    function_info['control_flow']['returns'].append(insn.address)
                    break  # End of basic block
                    
                elif insn.mnemonic.startswith('j'):
                    # Handle jumps
                    target = self._extract_jump_target(insn)
                    if target:
                        function_info['control_flow']['jumps'].append({
                            'source': insn.address,
                            'target': target,
                            'condition': insn.mnemonic,
                            'is_conditional': insn.mnemonic != 'jmp'
                        })
                        
                        # Add target to pending addresses if within function
                        if self._is_within_function(target, start_addr):
                            pending_addresses.append(target)
                    
                    if insn.mnemonic == 'jmp':
                        break  # Unconditional jump ends basic block
                
                elif insn.mnemonic == 'call':
                    target = self._extract_call_target(insn)
                    if target:
                        function_info['control_flow']['calls'].append({
                            'source': insn.address,
                            'target': target,
                            'instruction': insn_info
                        })
                
                # Check for function end conditions
                if len(basic_block) > 1000:  # Prevent runaway analysis
                    break
            
            if basic_block:
                function_info['basic_blocks'].append({
                    'start_address': basic_block[0]['address'],
                    'end_address': basic_block[-1]['address'],
                    'instructions': basic_block,
                    'size': len(basic_block)
                })
        
        # Collect all instructions for function info
        all_instructions = []
        for block in function_info['basic_blocks']:
            all_instructions.extend(block['instructions'])
        
        function_info['instructions'] = all_instructions
        
        # Analyze function prologue/epilogue
        function_info.update(self._analyze_function_structure(instruction_map))
        
        # Convert all instructions to list
        function_info['instructions'] = list(instruction_map.values())
        
        return function_info
    
    def _analyze_instruction(self, insn) -> Dict:
        """Perform detailed analysis of a single instruction."""
        insn_info = {
            'address': insn.address,
            'mnemonic': insn.mnemonic,
            'op_str': insn.op_str,
            'bytes': insn.bytes.hex(),
            'size': insn.size,
            'groups': [insn.group_name(g) for g in insn.groups],
            'registers_read': [],
            'registers_written': [],
            'operands': [],
            'memory_access': None,
            'immediate_value': None,
            'is_call': False,
            'is_jump': False,
            'is_return': False,
            'call_target': None,
            'jump_target': None,
            'stack_operation': None,
            'arithmetic_operation': None,
            'data_movement': None
        }
        
        # Analyze operands
        if hasattr(insn, 'operands'):
            for op in insn.operands:
                op_info = self._analyze_operand(op, insn)
                insn_info['operands'].append(op_info)
                
                # Track register usage
                if op.type == capstone.CS_OP_REG:
                    reg_name = insn.reg_name(op.reg)
                    if op.access & capstone.CS_AC_READ:
                        insn_info['registers_read'].append(reg_name)
                    if op.access & capstone.CS_AC_WRITE:
                        insn_info['registers_written'].append(reg_name)
                
                # Track memory access
                elif op.type == capstone.CS_OP_MEM:
                    insn_info['memory_access'] = {
                        'base': insn.reg_name(op.mem.base) if op.mem.base else None,
                        'index': insn.reg_name(op.mem.index) if op.mem.index else None,
                        'scale': op.mem.scale,
                        'displacement': op.mem.disp,
                        'size': op.size,
                        'access': 'read' if op.access & capstone.CS_AC_READ else 'write'
                    }
                
                # Track immediate values
                elif op.type == capstone.CS_OP_IMM:
                    insn_info['immediate_value'] = op.imm
        
        # Classify instruction type
        self._classify_instruction(insn_info, insn)
        
        return insn_info
    
    def _analyze_operand(self, operand, insn) -> Dict:
        """Analyze a single operand."""
        op_info = {
            'type': operand.type,
            'size': operand.size,
            'access': operand.access
        }
        
        if operand.type == capstone.CS_OP_REG:
            op_info['register'] = insn.reg_name(operand.reg)
            
        elif operand.type == capstone.CS_OP_IMM:
            op_info['immediate'] = operand.imm
            # Safe immediate formatting
            if isinstance(operand.imm, str):
                try:
                    imm_val = int(operand.imm, 16) if operand.imm.startswith('0x') else int(operand.imm)
                except (ValueError, TypeError):
                    imm_val = 0
            else:
                imm_val = operand.imm
            op_info['immediate_hex'] = f"0x{imm_val:x}"
            
        elif operand.type == capstone.CS_OP_MEM:
            op_info['memory'] = {
                'base': insn.reg_name(operand.mem.base) if operand.mem.base else None,
                'index': insn.reg_name(operand.mem.index) if operand.mem.index else None,
                'scale': operand.mem.scale,
                'displacement': operand.mem.disp,
                'segment': insn.reg_name(operand.mem.segment) if operand.mem.segment else None
            }
        
        return op_info
    
    def _classify_instruction(self, insn_info: Dict, insn) -> None:
        """Classify instruction by its function."""
        mnemonic = insn.mnemonic.lower()
        
        # Control flow instructions
        if mnemonic in ['call']:
            insn_info['is_call'] = True
            insn_info['call_target'] = self._extract_call_target(insn)
            
        elif mnemonic.startswith('j'):
            insn_info['is_jump'] = True
            insn_info['jump_target'] = self._extract_jump_target(insn)
            
        elif mnemonic in ['ret', 'retn', 'retf']:
            insn_info['is_return'] = True
        
        # Stack operations
        elif mnemonic in ['push', 'pop']:
            insn_info['stack_operation'] = {
                'type': mnemonic,
                'operand': insn_info['operands'][0] if insn_info['operands'] else None
            }
        
        # Arithmetic operations
        elif mnemonic in ['add', 'sub', 'mul', 'div', 'inc', 'dec', 'shl', 'shr', 'and', 'or', 'xor']:
            insn_info['arithmetic_operation'] = {
                'type': mnemonic,
                'operands': insn_info['operands']
            }
        
        # Data movement
        elif mnemonic in ['mov', 'lea', 'movzx', 'movsx']:
            insn_info['data_movement'] = {
                'type': mnemonic,
                'source': insn_info['operands'][1] if len(insn_info['operands']) > 1 else None,
                'destination': insn_info['operands'][0] if insn_info['operands'] else None
            }
    
    def _extract_call_target(self, insn) -> Optional[int]:
        """Extract call target address."""
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == capstone.CS_OP_IMM:
                return op.imm
        return None
    
    def _extract_jump_target(self, insn) -> Optional[int]:
        """Extract jump target address."""
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == capstone.CS_OP_IMM:
                return op.imm
        return None
    
    def _is_within_function(self, address: int, function_start: int) -> bool:
        """Check if address is likely within the same function."""
        # Simple heuristic: within 64KB of function start
        return abs(address - function_start) < 65536
    
    def _analyze_function_structure(self, instruction_map: Dict) -> Dict:
        """Analyze function prologue, epilogue, and structure."""
        structure_info = {
            'has_prologue': False,
            'has_epilogue': False,
            'stack_frame_size': 0,
            'saved_registers': [],
            'local_variables': {},
            'function_type': 'unknown'
        }
        
        instructions = sorted(instruction_map.values(), key=lambda x: x['address'])
        
        if not instructions:
            return structure_info
        
        # Analyze prologue (first few instructions)
        prologue = instructions[:5]
        for insn in prologue:
            if insn['mnemonic'] == 'push' and 'rbp' in str(insn['operands']):
                structure_info['has_prologue'] = True
                structure_info['saved_registers'].append('rbp')
            elif insn['mnemonic'] == 'mov' and 'rbp' in str(insn['operands']):
                structure_info['has_prologue'] = True
            elif insn['mnemonic'] == 'sub' and 'rsp' in str(insn['operands']):
                # Extract stack frame size
                if insn['immediate_value']:
                    structure_info['stack_frame_size'] = insn['immediate_value']
        
        # Analyze epilogue (last few instructions)
        epilogue = instructions[-5:]
        for insn in epilogue:
            if insn['mnemonic'] in ['ret', 'retn', 'retf']:
                structure_info['has_epilogue'] = True
        
        # Analyze local variable access patterns
        stack_accesses = {}
        for insn in instructions:
            if insn['memory_access']:
                mem = insn['memory_access']
                if mem['base'] in ['rbp', 'esp', 'rsp']:
                    offset = mem['displacement']
                    if offset not in stack_accesses:
                        stack_accesses[offset] = []
                    stack_accesses[offset].append(insn)
        
        # Infer local variables from stack accesses
        for offset, accesses in stack_accesses.items():
            if offset < 0:  # Local variables (negative offset from rbp)
                var_size = self._infer_variable_size(accesses)
                abs_offset = abs(offset) if isinstance(offset, int) else 0
                offset_str = self._safe_hex_format(abs_offset)
                structure_info['local_variables'][f'var_{offset_str[2:]}'] = {
                    'offset': offset,
                    'size': var_size,
                    'type': self._infer_variable_type(accesses, var_size),
                    'accesses': len(accesses)
                }
        
        return structure_info
    
    def _infer_variable_size(self, accesses: List[Dict]) -> int:
        """Infer variable size from access patterns."""
        sizes = [acc.get('memory_access', {}).get('size', 4) for acc in accesses if acc.get('memory_access')]
        return max(sizes) if sizes else 4
    
    def _infer_variable_type(self, accesses: List[Dict], size: int) -> str:
        """Infer variable type from size and usage."""
        type_map = {
            1: 'uint8_t',
            2: 'uint16_t', 
            4: 'uint32_t',
            8: 'uint64_t'
        }
        
        # Check if used in floating point operations
        for acc in accesses:
            if any(group in ['FPU', 'SSE'] for group in acc.get('groups', [])):
                return 'double' if size == 8 else 'float'
        
        return type_map.get(size, f'uint{size*8}_t')


class CompleteCodeGenerator:
    """Enhanced code generator with perfect C output."""
    
    def __init__(self):
        self.perfect_c_generator = PerfectCCodeGenerator()
        
        self.instruction_translators = {
            'mov': self._translate_mov,
            'add': self._translate_add,
            'sub': self._translate_sub,
            'mul': self._translate_mul,
            'div': self._translate_div,
            'cmp': self._translate_cmp,
            'test': self._translate_test,
            'call': self._translate_call,
            'jmp': self._translate_jmp,
            'je': self._translate_conditional_jump,
            'jne': self._translate_conditional_jump,
            'jz': self._translate_conditional_jump,
            'jnz': self._translate_conditional_jump,
            'jl': self._translate_conditional_jump,
            'jg': self._translate_conditional_jump,
            'push': self._translate_push,
            'pop': self._translate_pop,
            'ret': self._translate_ret,
            'lea': self._translate_lea,
            'inc': self._translate_inc,
            'dec': self._translate_dec,
            'and': self._translate_and,
            'or': self._translate_or,
            'xor': self._translate_xor,
            'shl': self._translate_shl,
            'shr': self._translate_shr,
        }
    
    def generate_complete_function(self, func_name: str, func_info: Dict) -> str:
        """Generate complete function implementation with instruction mapping."""
        
        # Generate function signature
        signature = self._generate_enhanced_signature(func_name, func_info)
        
        # Generate register declarations
        register_vars = self._generate_register_declarations(func_info)
        
        # Generate local variables
        local_vars = self._generate_local_variables(func_info)
        
        # Generate labels for jumps
        labels = self._generate_labels(func_info)
        
        # Generate function body with instruction translation
        body = self._generate_complete_body(func_info)
        
        # Safe address formatting
        address = func_info.get('address', 0)
        if isinstance(address, str):
            try:
                address = int(address, 16) if address.startswith('0x') else int(address)
            except (ValueError, TypeError):
                address = 0
        
        code_lines = [
            f"// ============================================",
            f"// Complete implementation of {func_name}",
            f"// Original Address: {self._safe_hex_format(address)}",
            f"// Total Instructions: {len(func_info.get('instructions', []))}",
            f"// Basic Blocks: {len(func_info['basic_blocks'])}",
            f"// Register Usage: {', '.join(sorted(func_info.get('register_usage', set())))}",
            f"// ============================================",
            signature + " {",
        ]
        
        # Add register variable declarations
        if register_vars:
            code_lines.extend(["    // CPU Register simulation"] + register_vars + [""])
        
        # Add flags
        code_lines.extend([
            "    // CPU Flags simulation", 
            "    bool zero_flag = false;",
            "    bool carry_flag = false;",
            "    bool sign_flag = false;",
            "    bool overflow_flag = false;",
            ""
        ])
        
        # Add local variables
        if local_vars:
            code_lines.extend(["    // Local variables"] + local_vars + [""])
        
        # Add function body
        code_lines.extend(body)
        
        code_lines.append("}")
        
        return "\n".join(code_lines)
    
    def generate_perfect_c_files(self, binary_name: str, functions: Dict[str, Dict], 
                                exports: Dict[str, Dict], imports: Dict[str, List],
                                arch: str) -> Tuple[str, str]:
        """Generate perfect C header and implementation files."""
        
        header_content = self.perfect_c_generator.generate_perfect_header(
            binary_name, functions, exports, imports, arch
        )
        
        implementation_content = self.perfect_c_generator.generate_perfect_c_file(
            binary_name, functions, exports, imports, arch
        )
        
        return header_content, implementation_content
    
    def _generate_register_declarations(self, func_info: Dict) -> List[str]:
        """Generate register variable declarations."""
        registers = func_info.get('register_usage', set())
        reg_lines = []
        
        for reg in sorted(registers):
            if reg in ['rax', 'eax', 'ax', 'al']:
                reg_lines.append("    uint64_t reg_rax = 0;  // Accumulator register")
            elif reg in ['rbx', 'ebx', 'bx', 'bl']:
                reg_lines.append("    uint64_t reg_rbx = 0;  // Base register")
            elif reg in ['rcx', 'ecx', 'cx', 'cl']:
                reg_lines.append("    uint64_t reg_rcx = 0;  // Counter register")
            elif reg in ['rdx', 'edx', 'dx', 'dl']:
                reg_lines.append("    uint64_t reg_rdx = 0;  // Data register")
            elif reg in ['rsi', 'esi', 'si']:
                reg_lines.append("    uint64_t reg_rsi = 0;  // Source index")
            elif reg in ['rdi', 'edi', 'di']:
                reg_lines.append("    uint64_t reg_rdi = 0;  // Destination index")
            elif reg in ['rsp', 'esp', 'sp']:
                reg_lines.append("    uint64_t reg_rsp = 0;  // Stack pointer")
            elif reg in ['rbp', 'ebp', 'bp']:
                reg_lines.append("    uint64_t reg_rbp = 0;  // Base pointer")
            elif reg.startswith('r') and reg[1:].isdigit():
                reg_lines.append(f"    uint64_t reg_{reg} = 0;  // General purpose register")
            else:
                reg_lines.append(f"    uint64_t reg_{reg} = 0;")
        
        return list(set(reg_lines))  # Remove duplicates
    
    def _safe_hex_format(self, value, default=0) -> str:
        """Safely format a value as hexadecimal."""
        if isinstance(value, str):
            try:
                # Try to parse as hex string first
                if value.startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value)
            except (ValueError, TypeError):
                # DEBUG: Log problematic string values
                print(f"DEBUG: Failed to convert string to int: '{value}' (type: {type(value)})")
                value = default
        elif value is None:
            value = default
        elif not isinstance(value, (int, float)):
            try:
                value = int(value)
            except (ValueError, TypeError):
                # DEBUG: Log problematic values
                print(f"DEBUG: Failed to convert to int: '{value}' (type: {type(value)})")
                value = default
        
        # Ensure it's an integer
        try:
            value = int(value)
            return f"0x{value:x}"
        except (ValueError, TypeError):
            print(f"DEBUG: Final conversion failed: '{value}' (type: {type(value)})")
            return f"0x{default:x}"
    
    def _generate_labels(self, func_info: Dict) -> Dict[int, str]:
        """Generate labels for jump targets."""
        labels = {}
        
        for block in func_info['basic_blocks']:
            for insn in block['instructions']:
                jump_target = insn.get('jump_target')
                if jump_target and isinstance(jump_target, int):
                    labels[jump_target] = f"label_{self._safe_hex_format(jump_target)}"
                elif jump_target and isinstance(jump_target, str):
                    try:
                        target_int = int(jump_target, 16) if jump_target.startswith('0x') else int(jump_target)
                        labels[target_int] = f"label_{self._safe_hex_format(target_int)}"
                    except (ValueError, TypeError):
                        pass
        
        return labels
    
    def _generate_enhanced_signature(self, func_name: str, func_info: Dict) -> str:
        """Generate enhanced function signature with proper parameter inference."""
        
        # Analyze calling convention and parameters
        params = self._infer_parameters(func_info)
        return_type = self._infer_return_type(func_info)
        
        param_strs = []
        for i, param in enumerate(params):
            param_strs.append(f"{param['type']} {param['name']}")
        
        param_list = ", ".join(param_strs) if param_strs else "void"
        
        return f"{return_type} {func_name}({param_list})"
    
    def _generate_local_variables(self, func_info: Dict) -> List[str]:
        """Generate local variable declarations."""
        var_lines = []
        
        for var_name, var_info in func_info.get('local_variables', {}).items():
            var_type = var_info['type']
            var_lines.append(f"    {var_type} {var_name};  // Offset: {var_info['offset']}")
        
        return var_lines
    
    def _generate_complete_body(self, func_info: Dict) -> List[str]:
        """Generate complete function body with instruction translation."""
        body_lines = []
        labels = self._generate_labels(func_info)
        
        # Process each basic block
        for i, block in enumerate(func_info['basic_blocks']):
            start_addr = block['start_address']
            
            # Add label if this block is a jump target
            if start_addr in labels:
                body_lines.append(f"{labels[start_addr]}:")
            
            body_lines.append(f"    // ============= Basic Block {i+1} =============")
            start_addr_str = self._safe_hex_format(block.get('start_address', 0))
            end_addr_str = self._safe_hex_format(block.get('end_address', 0))
            body_lines.append(f"    // Address Range: {start_addr_str} - {end_addr_str}")
            body_lines.append(f"    // Instructions: {block['size']}")
            body_lines.append("")
            
            for insn in block['instructions']:
                # Add instruction address and bytes as comment
                insn_addr_str = self._safe_hex_format(insn.get('address', 0))
                insn_comment = f"    // {insn_addr_str}: {insn['mnemonic']} {insn['op_str']}"
                if 'bytes' in insn:
                    # insn['bytes'] is a hex string, convert to formatted bytes
                    hex_str = insn['bytes']
                    if isinstance(hex_str, str):
                        # Convert hex string to space-separated hex bytes
                        bytes_list = [hex_str[i:i+2] for i in range(0, min(len(hex_str), 16), 2)]
                        bytes_str = ' '.join(bytes_list)
                    else:
                        # Fallback for other formats
                        bytes_str = str(hex_str)[:16]
                    insn_comment += f"  [{bytes_str}]"
                body_lines.append(insn_comment)
                
                # Translate instruction to C code
                c_code = self._translate_instruction(insn)
                
                if c_code:
                    body_lines.append(f"    {c_code}")
                
                # Add analysis notes for important instructions
                if insn.get('is_call'):
                    body_lines.append(f"    // >>> Function call detected")
                elif insn.get('is_jump'):
                    jump_target = insn.get('jump_target', 0)
                    if isinstance(jump_target, int):
                        jump_target_str = self._safe_hex_format(jump_target)
                        body_lines.append(f"    // >>> Control flow: Jump to {jump_target_str}")
                    else:
                        body_lines.append(f"    // >>> Control flow: Jump detected")
                elif insn.get('is_return'):
                    body_lines.append(f"    // >>> Function return")
                
                body_lines.append("")
            
            body_lines.append("")
        
        # Add default return if no explicit return found
        has_return = any(insn.get('is_return', False) for block in func_info['basic_blocks'] 
                        for insn in block['instructions'])
        
        if not has_return:
            return_type = self._infer_return_type(func_info)
            if return_type != 'void':
                body_lines.append("    // Default return - no explicit return found")
                body_lines.append("    return 0;")
        
        return body_lines
    
    def _translate_instruction(self, insn: Dict) -> Optional[str]:
        """Translate assembly instruction to C code."""
        mnemonic = insn['mnemonic'].lower()
        
        if mnemonic in self.instruction_translators:
            return self.instruction_translators[mnemonic](insn)
        
        # Fallback for unsupported instructions - provide detailed comment
        address_str = self._safe_hex_format(insn.get('address', 0))
        return f"// ASM: {insn['mnemonic']} {insn['op_str']} (Address: {address_str})"
    
    def _translate_mov(self, insn: Dict) -> str:
        """Translate MOV instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} = {src};"
        return "// MOV translation failed"
    
    def _translate_add(self, insn: Dict) -> str:
        """Translate ADD instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} += {src};"
        return "// ADD translation failed"
    
    def _translate_sub(self, insn: Dict) -> str:
        """Translate SUB instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} -= {src};"
        return "// SUB translation failed"
    
    def _translate_cmp(self, insn: Dict) -> str:
        """Translate CMP instruction."""
        if len(insn['operands']) >= 2:
            op1 = self._operand_to_c(insn['operands'][0])
            op2 = self._operand_to_c(insn['operands'][1])
            return f"// Compare: {op1} vs {op2}"
        return "// CMP translation failed"
    
    def _translate_call(self, insn: Dict) -> str:
        """Translate CALL instruction."""
        call_target = insn.get('call_target')
        if call_target and isinstance(call_target, int):
            return f"call_function_{self._safe_hex_format(call_target)}();"
        elif call_target and isinstance(call_target, str):
            try:
                target_int = int(call_target, 16) if call_target.startswith('0x') else int(call_target)
                return f"call_function_{self._safe_hex_format(target_int)}();"
            except (ValueError, TypeError):
                pass
        return "// Function call"
    
    def _translate_ret(self, insn: Dict) -> str:
        """Translate RET instruction."""
        return "return result;"
    
    def _translate_conditional_jump(self, insn: Dict) -> str:
        """Translate conditional jump."""
        condition = self._jump_to_condition(insn['mnemonic'])
        target = insn.get('jump_target', 0)
        if isinstance(target, int):
            return f"if ({condition}) goto label_{self._safe_hex_format(target)};"
        elif isinstance(target, str):
            try:
                target_int = int(target, 16) if target.startswith('0x') else int(target)
                return f"if ({condition}) goto label_{self._safe_hex_format(target_int)};"
            except (ValueError, TypeError):
                pass
        return f"if ({condition}) goto label_unknown;"
    
    def _translate_push(self, insn: Dict) -> str:
        """Translate PUSH instruction."""
        if insn['operands']:
            op = self._operand_to_c(insn['operands'][0])
            return f"// PUSH {op}"
        return "// PUSH"
    
    def _translate_pop(self, insn: Dict) -> str:
        """Translate POP instruction."""
        if insn['operands']:
            op = self._operand_to_c(insn['operands'][0])
            return f"// POP {op}"
        return "// POP"
    
    def _translate_lea(self, insn: Dict) -> str:
        """Translate LEA instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} = &{src};"
        return "// LEA translation failed"
    
    def _translate_inc(self, insn: Dict) -> str:
        """Translate INC instruction."""
        if insn['operands']:
            op = self._operand_to_c(insn['operands'][0])
            return f"{op}++;"
        return "// INC translation failed"
    
    def _translate_dec(self, insn: Dict) -> str:
        """Translate DEC instruction."""
        if insn['operands']:
            op = self._operand_to_c(insn['operands'][0])
            return f"{op}--;"
        return "// DEC translation failed"
    
    def _translate_mul(self, insn: Dict) -> str:
        """Translate MUL instruction.""" 
        if insn['operands']:
            op = self._operand_to_c(insn['operands'][0])
            return f"eax *= {op};"
        return "// MUL translation failed"
    
    def _translate_div(self, insn: Dict) -> str:
        """Translate DIV instruction."""
        if insn['operands']:
            op = self._operand_to_c(insn['operands'][0])
            return f"eax /= {op};"
        return "// DIV translation failed"
    
    def _translate_test(self, insn: Dict) -> str:
        """Translate TEST instruction."""
        if len(insn['operands']) >= 2:
            op1 = self._operand_to_c(insn['operands'][0])
            op2 = self._operand_to_c(insn['operands'][1])
            return f"// Test: {op1} & {op2}"
        return "// TEST translation failed"
    
    def _translate_jmp(self, insn: Dict) -> str:
        """Translate JMP instruction."""
        target = insn.get('jump_target', 0)
        if isinstance(target, int):
            return f"goto label_{self._safe_hex_format(target)};"
        elif isinstance(target, str):
            try:
                target_int = int(target, 16) if target.startswith('0x') else int(target)
                return f"goto label_{self._safe_hex_format(target_int)};"
            except (ValueError, TypeError):
                pass
        return "goto label_unknown;"
    
    def _translate_and(self, insn: Dict) -> str:
        """Translate AND instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} &= {src};"
        return "// AND translation failed"
    
    def _translate_or(self, insn: Dict) -> str:
        """Translate OR instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} |= {src};"
        return "// OR translation failed"
    
    def _translate_xor(self, insn: Dict) -> str:
        """Translate XOR instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} ^= {src};"
        return "// XOR translation failed"
    
    def _translate_shl(self, insn: Dict) -> str:
        """Translate SHL instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} <<= {src};"
        return "// SHL translation failed"
    
    def _translate_shr(self, insn: Dict) -> str:
        """Translate SHR instruction."""
        if len(insn['operands']) >= 2:
            dst = self._operand_to_c(insn['operands'][0])
            src = self._operand_to_c(insn['operands'][1])
            return f"{dst} >>= {src};"
        return "// SHR translation failed"
    
    def _operand_to_c(self, operand: Dict) -> str:
        """Convert assembly operand to C expression."""
        if operand['type'] == capstone.CS_OP_REG:
            return self._register_to_c(operand['register'])
        elif operand['type'] == capstone.CS_OP_IMM:
            return str(operand['immediate'])
        elif operand['type'] == capstone.CS_OP_MEM:
            return self._memory_to_c(operand['memory'])
        else:
            return "unknown_operand"
    
    def _register_to_c(self, register: str) -> str:
        """Convert register name to C variable."""
        reg_map = {
            'eax': 'reg_eax', 'ebx': 'reg_ebx', 'ecx': 'reg_ecx', 'edx': 'reg_edx',
            'esi': 'reg_esi', 'edi': 'reg_edi', 'esp': 'reg_esp', 'ebp': 'reg_ebp',
            'rax': 'reg_rax', 'rbx': 'reg_rbx', 'rcx': 'reg_rcx', 'rdx': 'reg_rdx',
            'rsi': 'reg_rsi', 'rdi': 'reg_rdi', 'rsp': 'reg_rsp', 'rbp': 'reg_rbp',
            'r8': 'reg_r8', 'r9': 'reg_r9', 'r10': 'reg_r10', 'r11': 'reg_r11',
            'r12': 'reg_r12', 'r13': 'reg_r13', 'r14': 'reg_r14', 'r15': 'reg_r15'
        }
        return reg_map.get(register.lower(), f"reg_{register}")
    
    def _memory_to_c(self, memory: Dict) -> str:
        """Convert memory operand to C expression."""
        base = memory.get('base')
        index = memory.get('index')
        scale = memory.get('scale', 1)
        disp = memory.get('displacement', 0)
        
        expr_parts = []
        
        if base:
            if base in ['rbp', 'ebp'] and disp < 0:
                # Local variable access - safe formatting for displacement
                abs_disp = abs(disp) if isinstance(disp, int) else 0
                abs_disp_str = self._safe_hex_format(abs_disp)
                return f"var_{abs_disp_str[2:]}"  # Remove '0x' prefix
            else:
                expr_parts.append(self._register_to_c(base))
        
        if index:
            if scale > 1:
                expr_parts.append(f"({self._register_to_c(index)} * {scale})")
            else:
                expr_parts.append(self._register_to_c(index))
        
        if disp != 0:
            # Safe displacement formatting
            if isinstance(disp, str):
                try:
                    disp = int(disp, 16) if disp.startswith('0x') else int(disp)
                except (ValueError, TypeError):
                    disp = 0
            
            if disp != 0:
                if expr_parts:
                    expr_parts.append(f"{disp:+d}")
                else:
                    expr_parts.append(str(disp))
        
        if not expr_parts:
            return "0"
        
        expr = " + ".join(expr_parts)
        return f"*({expr})" if expr_parts else "0"
    
    def _jump_to_condition(self, mnemonic: str) -> str:
        """Convert jump mnemonic to C condition."""
        condition_map = {
            'je': 'zero_flag',
            'jne': '!zero_flag',
            'jz': 'zero_flag',
            'jnz': '!zero_flag',
            'jl': 'sign_flag != overflow_flag',
            'jg': '!zero_flag && (sign_flag == overflow_flag)',
            'jle': 'zero_flag || (sign_flag != overflow_flag)',
            'jge': 'sign_flag == overflow_flag',
            'ja': '!carry_flag && !zero_flag',
            'jb': 'carry_flag',
            'jae': '!carry_flag',
            'jbe': 'carry_flag || zero_flag'
        }
        return condition_map.get(mnemonic.lower(), 'condition')
    
    def _infer_parameters(self, func_info: Dict) -> List[Dict]:
        """Infer function parameters from analysis."""
        params = []
        
        # Check first few instructions for parameter usage
        instructions = func_info.get('instructions', [])[:10]
        param_regs = ['rcx', 'rdx', 'r8', 'r9']  # x64 calling convention
        
        for i, reg in enumerate(param_regs):
            # Check if register is used before being set
            for insn in instructions:
                if reg in insn.get('registers_read', []):
                    params.append({
                        'name': f'param{i+1}',
                        'type': 'uint64_t',  # Default type
                        'register': reg
                    })
                    break
        
        return params
    
    def _infer_return_type(self, func_info: Dict) -> str:
        """Infer return type from function analysis."""
        # Check for return value in EAX/RAX
        for insn in func_info.get('instructions', []):
            if insn['is_return']:
                # Check previous instructions for EAX/RAX assignment
                return 'uint64_t'  # Default return type
        
        return 'void'
