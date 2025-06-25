#!/usr/bin/env python3
"""
Enhanced Binary Disassembler and C/C++ Recreation Tool
Author: AI Assistant
Date: June 24, 2025

This enhanced version includes advanced pattern recognition, data structure analysis,
and improved code generation capabilities.
"""

import os
import sys
import argparse
import pefile
import capstone
from pathlib import Path
import json
from typing import Dict, List, Tuple, Optional
import re

from pattern_analyzer import PatternMatcher, DataStructureAnalyzer
from code_generator import CodeGenerator
from complete_disassembler import AdvancedDisassembler, CompleteCodeGenerator


class EnhancedBinaryAnalyzer:
    """Enhanced binary analyzer with advanced pattern recognition."""
    
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.pe = None
        self.disassembler = None
        self.functions = {}
        self.imports = {}
        self.exports = {}
        self.sections = {}
        self.strings = []
        
        # Enhanced analysis components
        self.pattern_matcher = PatternMatcher()
        self.structure_analyzer = DataStructureAnalyzer()
        self.code_generator = CodeGenerator()
        self.advanced_disassembler = None
        self.complete_code_generator = CompleteCodeGenerator()
        
    def load_binary(self) -> bool:
        """Load and parse the binary file."""
        try:
            self.pe = pefile.PE(str(self.binary_path))
            
            # Initialize disassembler based on architecture
            if self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                self.arch = 'x64'
            elif self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                self.arch = 'x86'
            else:
                print(f"Unsupported architecture: {self.pe.FILE_HEADER.Machine}")
                return False
                
            self.disassembler.detail = True
            
            # Initialize advanced disassembler
            self.advanced_disassembler = AdvancedDisassembler(self.arch)
            
            return True
            
        except Exception as e:
            print(f"Error loading binary: {e}")
            return False
    
    def extract_strings(self, min_length: int = 4):
        """Extract ASCII strings from the binary."""
        self.strings = []
        
        for section in self.pe.sections:
            data = section.get_data()
            
            # Find ASCII strings
            ascii_strings = re.findall(rb'[\x20-\x7e]{%d,}' % min_length, data)
            for s in ascii_strings:
                try:
                    decoded = s.decode('ascii')
                    self.strings.append({
                        'value': decoded,
                        'offset': data.find(s),
                        'section': section.Name.decode('utf-8').rstrip('\x00'),
                        'type': 'ascii'
                    })
                except:
                    pass
            
            # Find Unicode strings
            unicode_strings = re.findall(rb'(?:[\x20-\x7e]\x00){%d,}' % min_length, data)
            for s in unicode_strings:
                try:
                    decoded = s.decode('utf-16le')
                    self.strings.append({
                        'value': decoded,
                        'offset': data.find(s),
                        'section': section.Name.decode('utf-8').rstrip('\x00'),
                        'type': 'unicode'
                    })
                except:
                    pass
    
    def analyze_imports(self):
        """Extract imported functions and libraries with enhanced analysis."""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return
            
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            self.imports[dll_name] = []
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    
                    # Analyze function signature if it's a known API
                    signature = self.get_api_signature(func_name)
                    
                    self.imports[dll_name].append({
                        'name': func_name,
                        'address': imp.address,
                        'ordinal': imp.ordinal,
                        'signature': signature
                    })
    
    def get_api_signature(self, func_name: str) -> Optional[str]:
        """Get known API function signature."""
        # Common Windows API signatures
        api_signatures = {
            'CreateFileA': 'HANDLE CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)',
            'CreateFileW': 'HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)',
            'ReadFile': 'BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)',
            'WriteFile': 'BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)',
            'CloseHandle': 'BOOL CloseHandle(HANDLE)',
            'VirtualAlloc': 'LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD)',
            'VirtualFree': 'BOOL VirtualFree(LPVOID, SIZE_T, DWORD)',
            'GetProcAddress': 'FARPROC GetProcAddress(HMODULE, LPCSTR)',
            'LoadLibraryA': 'HMODULE LoadLibraryA(LPCSTR)',
            'LoadLibraryW': 'HMODULE LoadLibraryW(LPCWSTR)',
            'ExitProcess': 'void ExitProcess(UINT)',
            'GetCurrentProcess': 'HANDLE GetCurrentProcess(void)',
            'GetCurrentThread': 'HANDLE GetCurrentThread(void)',
            'Sleep': 'void Sleep(DWORD)',
            'MessageBoxA': 'int MessageBoxA(HWND, LPCSTR, LPCSTR, UINT)',
            'MessageBoxW': 'int MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT)',
            'RegOpenKeyA': 'LONG RegOpenKeyA(HKEY, LPCSTR, PHKEY)',
            'RegOpenKeyW': 'LONG RegOpenKeyW(HKEY, LPCWSTR, PHKEY)',
            'RegCloseKey': 'LONG RegCloseKey(HKEY)',
            'malloc': 'void* malloc(size_t)',
            'free': 'void free(void*)',
            'printf': 'int printf(const char*, ...)',
            'sprintf': 'int sprintf(char*, const char*, ...)',
            'strlen': 'size_t strlen(const char*)',
            'strcpy': 'char* strcpy(char*, const char*)',
            'strcmp': 'int strcmp(const char*, const char*)',
        }
        
        return api_signatures.get(func_name)
    
    def analyze_exports(self):
        """Extract exported functions with enhanced analysis."""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return
            
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                func_name = exp.name.decode('utf-8')
                # Ensure address is an integer
                address = exp.address
                if isinstance(address, str):
                    try:
                        address = int(address, 16) if address.startswith('0x') else int(address)
                    except (ValueError, TypeError):
                        address = 0
                elif not isinstance(address, int):
                    try:
                        address = int(address)
                    except (ValueError, TypeError):
                        address = 0
                
                self.exports[func_name] = {
                    'address': address,
                    'ordinal': exp.ordinal,
                    'rva': address
                }
    
    def analyze_sections(self):
        """Analyze PE sections with enhanced information."""
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            
            # Determine section purpose
            purpose = self.identify_section_purpose(section_name, section.Characteristics)
            
            self.sections[section_name] = {
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': section.Characteristics,
                'purpose': purpose,
                'data': section.get_data(),
                'entropy': self.calculate_entropy(section.get_data())
            }
    
    def identify_section_purpose(self, name: str, characteristics: int) -> str:
        """Identify the purpose of a PE section."""
        name_lower = name.lower()
        
        if '.text' in name_lower:
            return 'executable_code'
        elif '.data' in name_lower:
            return 'initialized_data'
        elif '.bss' in name_lower:
            return 'uninitialized_data'
        elif '.rdata' in name_lower or '.rodata' in name_lower:
            return 'read_only_data'
        elif '.rsrc' in name_lower:
            return 'resources'
        elif '.reloc' in name_lower:
            return 'relocations'
        elif '.idata' in name_lower:
            return 'import_data'
        elif '.edata' in name_lower:
            return 'export_data'
        elif '.pdata' in name_lower:
            return 'exception_data'
        elif '.debug' in name_lower:
            return 'debug_info'
        else:
            # Check characteristics
            if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                return 'executable_code'
            elif characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                return 'writable_data'
            else:
                return 'unknown'
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate entropy of data to detect packed/encrypted sections."""
        if not data:
            return 0.0
        
        import math
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def disassemble_function(self, start_addr: int, max_size: int = 2048) -> List[Dict]:
        """Enhanced function disassembly with complete analysis."""
        
        # Get section containing this address
        section_data = None
        section_base = 0
        
        for section in self.pe.sections:
            if (section.VirtualAddress <= start_addr < 
                section.VirtualAddress + section.Misc_VirtualSize):
                section_data = section.get_data()
                section_base = section.VirtualAddress
                break
        
        if not section_data or not self.advanced_disassembler:
            # Fallback to basic disassembly
            return self._basic_disassemble_function(start_addr, max_size)
        
        # Use advanced disassembler for complete analysis
        try:
            complete_analysis = self.advanced_disassembler.complete_function_analysis(
                start_addr, section_data, section_base, max_size
            )
            return complete_analysis.get('instructions', [])
        except Exception as e:
            print(f"Advanced disassembly failed for {self._safe_hex_format(start_addr)}: {e}")
            return self._basic_disassemble_function(start_addr, max_size)
    
    def _basic_disassemble_function(self, start_addr: int, max_size: int = 2048) -> List[Dict]:
        """Fallback basic function disassembly."""
        instructions = []
        
        try:
            # Get section containing this address
            section_data = None
            section_base = 0
            
            for section in self.pe.sections:
                if (section.VirtualAddress <= start_addr < 
                    section.VirtualAddress + section.Misc_VirtualSize):
                    section_data = section.get_data()
                    section_base = section.VirtualAddress
                    break
            
            if not section_data:
                return instructions
            
            # Calculate offset within section
            offset = start_addr - section_base
            if offset >= len(section_data):
                return instructions
                
            # Disassemble with improved stopping conditions
            code = section_data[offset:offset + max_size]
            
            for insn in self.disassembler.disasm(code, start_addr):
                instruction_info = {
                    'address': insn.address,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': insn.bytes.hex(),
                    'size': insn.size,
                    'groups': [g for g in insn.groups],
                }
                
                # Add operand analysis
                if hasattr(insn, 'operands'):
                    instruction_info['operands'] = []
                    for op in insn.operands:
                        op_info = {
                            'type': op.type,
                            'size': op.size
                        }
                        if op.type == capstone.CS_OP_REG:
                            op_info['reg'] = insn.reg_name(op.reg)
                        elif op.type == capstone.CS_OP_IMM:
                            op_info['imm'] = op.imm
                        elif op.type == capstone.CS_OP_MEM:
                            op_info['mem'] = {
                                'base': insn.reg_name(op.mem.base) if op.mem.base else None,
                                'index': insn.reg_name(op.mem.index) if op.mem.index else None,
                                'disp': op.mem.disp
                            }
                        instruction_info['operands'].append(op_info)
                
                instructions.append(instruction_info)
                
                # Enhanced stopping conditions
                if insn.mnemonic in ['ret', 'retn', 'retf']:
                    break
                elif insn.mnemonic == 'jmp' and not insn.op_str.startswith('0x'):
                    # Indirect jump might be end of function
                    break
                elif len(instructions) > 1000:  # Prevent runaway disassembly
                    break
                    
        except Exception as e:
            print(f"Error disassembling function at {self._safe_hex_format(start_addr)}: {e}")
            
        return instructions
    
    def identify_functions(self):
        """Enhanced function identification with complete analysis."""
        # Start with exported functions
        for name, info in self.exports.items():
            # The address from exports should already be an RVA (relative to base)
            addr = info['address']
            
            # Use complete function analysis
            complete_analysis = self._complete_function_analysis(addr)
            
            if complete_analysis:
                # Extract detailed information
                instructions = complete_analysis.get('instructions', [])
                characteristics = self.pattern_matcher.analyze_function_characteristics(instructions)
                purpose = self.pattern_matcher.suggest_function_purpose(name, characteristics, self.imports)
                
                self.functions[name] = {
                    'address': addr,
                    'type': 'exported',
                    'instructions': instructions,
                    'characteristics': characteristics,
                    'purpose': purpose,
                    'data_structures': self.structure_analyzer.analyze_memory_accesses(instructions),
                    'complete_analysis': complete_analysis
                }
        
        # Enhanced prologue-based function discovery
        text_section = None
        for section in self.pe.sections:
            if b'.text' in section.Name:
                text_section = section
                break
        
        if text_section:
            data = text_section.get_data()
            base_addr = text_section.VirtualAddress  # RVA, not full address
            
            # Find function prologues using pattern matcher
            prologue_matches = self.pattern_matcher.find_patterns(
                data, self.pattern_matcher.x86_patterns['function_prologue']
            )
            
            # Limit discovered functions to prevent excessive analysis
            discovered_count = 0
            max_discovered = 50  # Reasonable limit
            
            for offset in prologue_matches:
                if discovered_count >= max_discovered:
                    break
                    
                addr = base_addr + offset  # This is now an RVA
                try:
                    func_name = f"sub_{self._safe_hex_format(addr)[2:]}"  # Remove '0x' prefix
                except (ValueError, TypeError):
                    func_name = f"sub_{addr}"
                
                if func_name not in self.functions:
                    complete_analysis = self._complete_function_analysis(addr)
                    
                    if complete_analysis and len(complete_analysis.get('instructions', [])) > 3:
                        instructions = complete_analysis['instructions']
                        characteristics = self.pattern_matcher.analyze_function_characteristics(instructions)
                        purpose = self.pattern_matcher.suggest_function_purpose(func_name, characteristics, self.imports)
                        
                        self.functions[func_name] = {
                            'address': addr,
                            'type': 'discovered',
                            'instructions': instructions,
                            'characteristics': characteristics,
                            'purpose': purpose,
                            'data_structures': self.structure_analyzer.analyze_memory_accesses(instructions),
                            'complete_analysis': complete_analysis
                        }
                        
                        discovered_count += 1
    
    def _complete_function_analysis(self, addr: int) -> Optional[Dict]:
        """Perform complete function analysis using advanced disassembler."""
        if not self.advanced_disassembler:
            return None
        
        try:
            # Get section containing this address
            section_data = None
            section_base = 0
            
            for section in self.pe.sections:
                if (section.VirtualAddress <= addr < 
                    section.VirtualAddress + section.Misc_VirtualSize):
                    section_data = section.get_data()
                    section_base = section.VirtualAddress
                    break
            
            if not section_data:
                return None
            
            # Perform complete analysis
            return self.advanced_disassembler.complete_function_analysis(
                addr, section_data, section_base
            )
            
        except Exception as e:
            print(f"Complete analysis failed for {self._safe_hex_format(addr)}: {e}")
            return None
    
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
                value = default
        elif value is None:
            value = default
        elif not isinstance(value, (int, float)):
            try:
                value = int(value)
            except (ValueError, TypeError):
                value = default
        
        # Ensure it's an integer
        try:
            value = int(value)
            return f"0x{value:x}"
        except (ValueError, TypeError):
            return f"0x{default:x}"
        

class EnhancedCppGenerator:
    """Enhanced C++ code generator with better output quality."""
    
    def __init__(self, analyzer: EnhancedBinaryAnalyzer):
        self.analyzer = analyzer
        self.code_gen = CodeGenerator()
    
    def generate_header_file(self) -> str:
        """Generate comprehensive header file."""
        header_lines = [
            f"// Generated header for {self.analyzer.binary_path.name}",
            f"// Generated on: June 24, 2025",
            f"// Architecture: {self.analyzer.arch}",
            f"// Original file: {self.analyzer.binary_path}",
            "",
            "#pragma once",
        ]
        
        # Add includes
        includes = self.code_gen.generate_include_statements(
            self.analyzer.imports, self.analyzer.exports
        )
        header_lines.extend(includes)
        header_lines.append("")
        
        # Add data structure definitions
        all_structures = {}
        for func_name, func_info in self.analyzer.functions.items():
            all_structures.update(func_info.get('data_structures', {}))
        
        if all_structures:
            header_lines.append("// Data Structures")
            struct_defs = self.analyzer.structure_analyzer.generate_structure_definitions(all_structures)
            header_lines.append(struct_defs)
        
        # Add function declarations
        header_lines.extend([
            "// Function Declarations",
            "extern \"C\" {",
        ])
        
        for func_name, func_info in self.analyzer.functions.items():
            signature = self.code_gen.generate_function_signature(
                func_name, func_info['instructions'], func_info['purpose']
            )
            header_lines.append(f"    {signature};")
        
        header_lines.extend([
            "}",
            "",
            f"#endif // __{self.analyzer.binary_path.stem.upper()}_H__"
        ])
        
        return "\n".join(header_lines)
    
    def generate_cpp_file(self) -> str:
        """Generate comprehensive C++ implementation."""
        cpp_lines = [
            f"// Generated C++ recreation of {self.analyzer.binary_path.name}",
            f"// Generated on: June 24, 2025",
            f"// Architecture: {self.analyzer.arch}",
            f"// Total functions analyzed: {len(self.analyzer.functions)}",
            "",
            f"#include \"{self.analyzer.binary_path.stem}.h\"",
            "",
        ]
        
        # Sort functions by type and complexity
        exported_funcs = []
        discovered_funcs = []
        
        for func_name, func_info in self.analyzer.functions.items():
            if func_info['type'] == 'exported':
                exported_funcs.append((func_name, func_info))
            else:
                discovered_funcs.append((func_name, func_info))
        
        # Sort by complexity (simpler functions first)
        exported_funcs.sort(key=lambda x: x[1]['characteristics'].get('complexity_score', 0))
        discovered_funcs.sort(key=lambda x: x[1]['characteristics'].get('complexity_score', 0))
        
        # Generate exported functions first
        if exported_funcs:
            cpp_lines.append("// ============ EXPORTED FUNCTIONS ============")
            cpp_lines.append("")
            
            for func_name, func_info in exported_funcs:
                cpp_lines.append(self.generate_enhanced_function(func_name, func_info))
                cpp_lines.append("")
        
        # Generate discovered functions
        if discovered_funcs:
            cpp_lines.append("// ============ DISCOVERED FUNCTIONS ============")
            cpp_lines.append("")
            
            # Only include most promising discovered functions
            for func_name, func_info in discovered_funcs[:20]:  # Limit output
                complexity = func_info['characteristics'].get('complexity_score', 0)
                if complexity > 10:  # Only include substantial functions
                    cpp_lines.append(self.generate_enhanced_function(func_name, func_info))
                    cpp_lines.append("")
        
        return "\n".join(cpp_lines)
    
    def generate_enhanced_function(self, func_name: str, func_info: Dict) -> str:
        """Generate enhanced function with complete implementation."""
        
        # Use complete code generator if we have complete analysis
        if 'complete_analysis' in func_info and func_info['complete_analysis']:
            try:
                return self.analyzer.complete_code_generator.generate_complete_function(
                    func_name, func_info['complete_analysis']
                )
            except Exception as e:
                import traceback
                print(f"Complete code generation failed for {func_name}: {e}")
                print(f"Exception type: {type(e)}")
                # Debug information about the function info
                if 'complete_analysis' in func_info:
                    analysis = func_info['complete_analysis']
                    if 'address' in analysis:
                        print(f"Function address: {repr(analysis['address'])} (type: {type(analysis['address'])})")
                    if 'basic_blocks' in analysis:
                        print(f"Basic blocks: {len(analysis['basic_blocks'])}")
                # Fall back to basic generation
        
        # Fall back to basic code generation
        signature = self.code_gen.generate_function_signature(
            func_name, func_info['instructions'], func_info['purpose']
        )
        
        code_lines = [signature + " {"]
        
        # Add enhanced function body
        body_lines = self.code_gen.generate_function_body(
            func_name, func_info['instructions'], 
            func_info['purpose'], func_info['characteristics']
        )
        
        code_lines.extend(body_lines)
        code_lines.append("}")
        
        return "\n".join(code_lines)
    
    def generate_analysis_report(self) -> str:
        """Generate comprehensive analysis report."""
        report_lines = [
            f"COMPREHENSIVE BINARY ANALYSIS REPORT",
            f"{'=' * 80}",
            f"File: {self.analyzer.binary_path}",
            f"Analysis Date: June 24, 2025",
            f"Architecture: {self.analyzer.arch}",
            "",
            f"BASIC PE INFORMATION:",
            f"  Entry Point: 0x{self.analyzer.pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
            f"  Image Base: 0x{self.analyzer.pe.OPTIONAL_HEADER.ImageBase:x}",
            f"  File Size: {self.analyzer.binary_path.stat().st_size} bytes",
            "",
        ]
        
        # Section analysis
        report_lines.extend([
            f"SECTIONS ({len(self.analyzer.sections)}):",
            f"{'Name':<12} {'Purpose':<20} {'Size':<10} {'Entropy':<8} {'Characteristics'}",
            f"{'-'*80}",
        ])
        
        for name, info in self.analyzer.sections.items():
            report_lines.append(
                f"{name:<12} {info['purpose']:<20} "
                f"{info['virtual_size']:<10} {info['entropy']:<8.2f} "
                f"0x{info['characteristics']:x}"
            )
        
        # Import analysis
        total_imports = sum(len(funcs) for funcs in self.analyzer.imports.values())
        report_lines.extend([
            "",
            f"IMPORTS ({len(self.analyzer.imports)} DLLs, {total_imports} functions):",
        ])
        
        for dll, functions in self.analyzer.imports.items():
            report_lines.append(f"  {dll}: {len(functions)} functions")
            # Show interesting functions
            for func in functions[:5]:  # Show first 5
                purpose = self.analyzer.pattern_matcher.identify_api_usage(func['name'], self.analyzer.imports)
                purpose_str = ', '.join(purpose) if purpose else 'general'
                report_lines.append(f"    - {func['name']} ({purpose_str})")
            if len(functions) > 5:
                report_lines.append(f"    ... and {len(functions) - 5} more")
        
        # Export analysis
        report_lines.extend([
            "",
            f"EXPORTS ({len(self.analyzer.exports)} functions):",
        ])
        
        for func_name, info in self.analyzer.exports.items():
            try:
                addr = info['address']
                addr_str = self._safe_hex_format(addr)
            except (ValueError, TypeError):
                addr_str = str(info.get('address', '0x0'))
            report_lines.append(f"  {func_name}: {addr_str}")
        
        # Function analysis
        by_purpose = {}
        for func_name, func_info in self.analyzer.functions.items():
            purpose = func_info['purpose']
            if purpose not in by_purpose:
                by_purpose[purpose] = []
            by_purpose[purpose].append((func_name, func_info))
        
        report_lines.extend([
            "",
            f"FUNCTION ANALYSIS ({len(self.analyzer.functions)} functions analyzed):",
        ])
        
        for purpose, functions in by_purpose.items():
            report_lines.append(f"  {purpose}: {len(functions)} functions")
            avg_complexity = sum(f[1]['characteristics'].get('complexity_score', 0) 
                               for f in functions) / len(functions)
            report_lines.append(f"    Average complexity: {avg_complexity:.1f}")
        
        # String analysis
        if self.analyzer.strings:
            report_lines.extend([
                "",
                f"STRINGS ({len(self.analyzer.strings)} found):",
            ])
            
            # Show interesting strings
            interesting_strings = []
            for s in self.analyzer.strings:
                value = s['value']
                if (len(value) > 3 and 
                    any(keyword in value.lower() for keyword in 
                        ['error', 'fail', 'success', 'debug', 'log', 'file', 'key', 'pass'])):
                    interesting_strings.append(value[:50])
            
            for s in interesting_strings[:10]:
                report_lines.append(f"  \"{s}\"")
            
            if len(interesting_strings) > 10:
                report_lines.append(f"  ... and {len(interesting_strings) - 10} more interesting strings")
        
        return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Binary Disassembler and C/C++ Recreation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enhanced_disassembler.py sample.dll
  python enhanced_disassembler.py driver.sys --output analysis --report --build-files
  python enhanced_disassembler.py malware.exe --strings --detailed
        """
    )
    
    parser.add_argument("binary_path", help="Path to the binary file (.dll, .sys, .exe)")
    parser.add_argument("-o", "--output", help="Output directory", default="output")
    parser.add_argument("--report", action="store_true", help="Generate detailed analysis report")
    parser.add_argument("--strings", action="store_true", help="Extract and analyze strings")
    parser.add_argument("--build-files", action="store_true", help="Generate build files (Makefile, CMake)")
    parser.add_argument("--detailed", action="store_true", help="Enable detailed analysis (slower)")
    parser.add_argument("--complete", action="store_true", help="Enable complete disassembly with full instruction mapping")
    parser.add_argument("--max-functions", type=int, default=100, help="Maximum number of functions to analyze in complete mode")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary_path):
        print(f"Error: Binary file '{args.binary_path}' not found")
        return 1
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    print(f"Enhanced Binary Analysis Tool")
    print(f"Analyzing: {args.binary_path}")
    print(f"Output: {output_dir}")
    print("-" * 50)
    
    # Initialize enhanced analyzer
    analyzer = EnhancedBinaryAnalyzer(args.binary_path)
    
    if not analyzer.load_binary():
        print("Failed to load binary file")
        return 1
    
    print(f"✓ Loaded {analyzer.arch} binary")
    
    print("Analyzing sections...")
    analyzer.analyze_sections()
    print(f"✓ Found {len(analyzer.sections)} sections")
    
    print("Analyzing imports...")
    analyzer.analyze_imports()
    total_imports = sum(len(funcs) for funcs in analyzer.imports.values())
    print(f"✓ Found {total_imports} imported functions from {len(analyzer.imports)} DLLs")
    
    print("Analyzing exports...")
    analyzer.analyze_exports()
    print(f"✓ Found {len(analyzer.exports)} exported functions")
    
    if args.strings:
        print("Extracting strings...")
        analyzer.extract_strings()
        print(f"✓ Found {len(analyzer.strings)} strings")
    
    print("Identifying and analyzing functions...")
    analyzer.identify_functions()
    print(f"✓ Analyzed {len(analyzer.functions)} functions")
    
    # Generate C++ code
    generator = EnhancedCppGenerator(analyzer)
    
    # Write header file
    header_file = output_dir / f"{analyzer.binary_path.stem}.h"
    with open(header_file, 'w', encoding='utf-8') as f:
        f.write(generator.generate_header_file())
    print(f"✓ Generated header: {header_file}")
    
    # Write implementation file
    cpp_file = output_dir / f"{analyzer.binary_path.stem}.cpp"
    with open(cpp_file, 'w', encoding='utf-8') as f:
        f.write(generator.generate_cpp_file())
    print(f"✓ Generated implementation: {cpp_file}")
    
    # Generate perfect C files (new improved version)
    header_content, implementation_content = analyzer.complete_code_generator.generate_perfect_c_files(
        analyzer.binary_path.name, analyzer.functions, analyzer.exports, analyzer.imports, analyzer.arch
    )
    
    # Write perfect C header
    perfect_header_file = output_dir / f"{analyzer.binary_path.stem}_perfect.h"
    with open(perfect_header_file, 'w', encoding='utf-8') as f:
        f.write(header_content)
    print(f"✓ Generated perfect C header: {perfect_header_file}")
    
    # Write perfect C implementation
    perfect_impl_file = output_dir / f"{analyzer.binary_path.stem}_perfect.c"
    with open(perfect_impl_file, 'w', encoding='utf-8') as f:
        f.write(implementation_content)
    print(f"✓ Generated perfect C implementation: {perfect_impl_file}")
    
    # Generate build files if requested
    if args.build_files:
        # Generate Makefile
        makefile = output_dir / "Makefile"
        with open(makefile, 'w', encoding='utf-8') as f:
            f.write(analyzer.code_generator.generate_makefile(analyzer.binary_path.stem))
        print(f"✓ Generated Makefile: {makefile}")
        
        # Generate CMakeLists.txt
        cmake_file = output_dir / "CMakeLists.txt"
        with open(cmake_file, 'w', encoding='utf-8') as f:
            f.write(analyzer.code_generator.generate_cmake_file(analyzer.binary_path.stem))
        print(f"✓ Generated CMake file: {cmake_file}")
    
    # Write analysis report
    if args.report:
        report_file = output_dir / f"{analyzer.binary_path.stem}_analysis_report.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(generator.generate_analysis_report())
        print(f"✓ Generated analysis report: {report_file}")
    
    # Generate summary JSON
    summary_file = output_dir / f"{analyzer.binary_path.stem}_summary.json"
    summary_data = {
        'file_info': {
            'path': str(analyzer.binary_path),
            'architecture': analyzer.arch,
            'size_bytes': analyzer.binary_path.stat().st_size,
        },
        'analysis_stats': {
            'sections': len(analyzer.sections),
            'imports': sum(len(funcs) for funcs in analyzer.imports.values()),
            'exports': len(analyzer.exports),
            'functions_analyzed': len(analyzer.functions),
            'strings_found': len(analyzer.strings),
        },
        'function_purposes': {},
    }
    
    # Count functions by purpose
    for func_info in analyzer.functions.values():
        purpose = func_info['purpose']
        summary_data['function_purposes'][purpose] = summary_data['function_purposes'].get(purpose, 0) + 1
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary_data, f, indent=2)
    print(f"✓ Generated summary: {summary_file}")
    
    print("-" * 50)
    print("Analysis complete! 🎉")
    print(f"Check the '{output_dir}' directory for generated files.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
