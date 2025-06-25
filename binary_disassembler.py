#!/usr/bin/env python3
"""
Binary Disassembler and C/C++ Recreation Tool
Author: AI Assistant
Date: June 24, 2025

This tool disassembles binary DLL or .sys files and attempts to recreate
the original C/C++ source code structure.
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


class BinaryAnalyzer:
    """Main class for analyzing binary files and generating C/C++ recreations."""
    
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.pe = None
        self.disassembler = None
        self.functions = {}
        self.imports = {}
        self.exports = {}
        self.sections = {}
        
    def load_binary(self) -> bool:
        """Load and parse the binary file."""
        try:
            self.pe = pefile.PE(str(self.binary_path))
            
            # Initialize disassembler based on architecture
            if self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            else:
                print(f"Unsupported architecture: {self.pe.FILE_HEADER.Machine}")
                return False
                
            self.disassembler.detail = True
            return True
            
        except Exception as e:
            print(f"Error loading binary: {e}")
            return False
    
    def analyze_imports(self):
        """Extract imported functions and libraries."""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return
            
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            self.imports[dll_name] = []
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    self.imports[dll_name].append({
                        'name': func_name,
                        'address': imp.address,
                        'ordinal': imp.ordinal
                    })
    
    def analyze_exports(self):
        """Extract exported functions."""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return
            
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                func_name = exp.name.decode('utf-8')
                self.exports[func_name] = {
                    'address': exp.address,
                    'ordinal': exp.ordinal
                }
    
    def analyze_sections(self):
        """Analyze PE sections."""
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            self.sections[section_name] = {
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': section.Characteristics,
                'data': section.get_data()
            }
    
    def disassemble_function(self, start_addr: int, max_size: int = 1024) -> List[Dict]:
        """Disassemble a function starting at the given address."""
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
                
            # Disassemble
            code = section_data[offset:offset + max_size]
            
            for insn in self.disassembler.disasm(code, start_addr):
                instructions.append({
                    'address': insn.address,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': insn.bytes.hex(),
                    'size': insn.size
                })
                
                # Stop at return instructions
                if insn.mnemonic in ['ret', 'retn', 'retf']:
                    break
                    
        except Exception as e:
            print(f"Error disassembling function at 0x{start_addr:x}: {e}")
            
        return instructions
    
    def identify_functions(self):
        """Identify function entry points in the binary."""
        # Start with exported functions
        for name, info in self.exports.items():
            addr = info['address'] + self.pe.OPTIONAL_HEADER.ImageBase
            self.functions[name] = {
                'address': addr,
                'type': 'exported',
                'instructions': self.disassemble_function(addr)
            }
        
        # Look for common function prologues in .text section
        text_section = None
        for section in self.pe.sections:
            if b'.text' in section.Name:
                text_section = section
                break
        
        if text_section:
            data = text_section.get_data()
            base_addr = text_section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase
            
            # Common x86/x64 function prologues
            prologues = [
                b'\x55\x8b\xec',           # push ebp; mov ebp, esp
                b'\x48\x89\x5c\x24',       # mov [rsp+offset], rbx (x64)
                b'\x48\x83\xec',           # sub rsp, immediate (x64)
                b'\x55\x48\x89\xe5',       # push rbp; mov rbp, rsp (x64)
            ]
            
            for prologue in prologues:
                offset = 0
                while True:
                    offset = data.find(prologue, offset)
                    if offset == -1:
                        break
                    
                    addr = base_addr + offset
                    func_name = f"sub_{addr:x}"
                    
                    if func_name not in self.functions:
                        self.functions[func_name] = {
                            'address': addr,
                            'type': 'discovered',
                            'instructions': self.disassemble_function(addr)
                        }
                    
                    offset += len(prologue)


class CppGenerator:
    """Generate C/C++ code from disassembled functions."""
    
    def __init__(self, analyzer: BinaryAnalyzer):
        self.analyzer = analyzer
        self.generated_code = []
        self.type_mappings = {
            'DWORD': 'uint32_t',
            'WORD': 'uint16_t',
            'BYTE': 'uint8_t',
            'HANDLE': 'void*',
            'LPVOID': 'void*',
            'LPCSTR': 'const char*',
            'LPSTR': 'char*',
            'BOOL': 'int'
        }
    
    def guess_function_signature(self, func_name: str, instructions: List[Dict]) -> str:
        """Attempt to guess function signature from instructions."""
        # Simple heuristic-based approach
        param_count = 0
        return_type = "int"
        
        # Count stack operations that might indicate parameters
        for insn in instructions[:10]:  # Check first few instructions
            if 'mov' in insn['mnemonic'] and 'ebp' in insn['op_str']:
                param_count += 1
        
        # Generate parameter list
        params = []
        for i in range(min(param_count, 4)):  # Limit to reasonable number
            params.append(f"int param{i+1}")
        
        param_str = ", ".join(params) if params else "void"
        return f"{return_type} {func_name}({param_str})"
    
    def instruction_to_c(self, insn: Dict) -> str:
        """Convert assembly instruction to C-like comment."""
        return f"    // {insn['mnemonic']} {insn['op_str']} ; 0x{insn['address']:x}"
    
    def generate_function_code(self, func_name: str, func_info: Dict) -> str:
        """Generate C++ code for a function."""
        signature = self.guess_function_signature(func_name, func_info['instructions'])
        
        code_lines = [
            f"// Function: {func_name}",
            f"// Address: 0x{func_info['address']:x}",
            f"// Type: {func_info['type']}",
            signature + " {",
        ]
        
        # Add assembly instructions as comments
        for insn in func_info['instructions']:
            code_lines.append(self.instruction_to_c(insn))
        
        # Add placeholder return
        code_lines.extend([
            "    // TODO: Implement function logic",
            "    return 0;",
            "}"
        ])
        
        return "\n".join(code_lines)
    
    def generate_header_file(self) -> str:
        """Generate header file with function declarations."""
        header_lines = [
            f"// Generated header for {self.analyzer.binary_path.name}",
            f"// Generated on: June 24, 2025",
            "",
            "#pragma once",
            "#include <windows.h>",
            "#include <cstdint>",
            "",
            "// Imported Functions",
        ]
        
        # Add import declarations
        for dll, functions in self.analyzer.imports.items():
            header_lines.append(f"// From {dll}")
            for func in functions:
                header_lines.append(f"extern \"C\" int {func['name']}();")
        
        header_lines.extend(["", "// Exported Functions"])
        
        # Add export declarations
        for func_name in self.analyzer.exports:
            signature = self.guess_function_signature(func_name, 
                       self.analyzer.functions.get(func_name, {}).get('instructions', []))
            header_lines.append(f"extern \"C\" {signature};")
        
        return "\n".join(header_lines)
    
    def generate_cpp_file(self) -> str:
        """Generate main C++ implementation file."""
        cpp_lines = [
            f"// Generated C++ recreation of {self.analyzer.binary_path.name}",
            f"// Generated on: June 24, 2025",
            "",
            f"#include \"{self.analyzer.binary_path.stem}.h\"",
            "",
        ]
        
        # Generate function implementations
        for func_name, func_info in self.analyzer.functions.items():
            cpp_lines.append(self.generate_function_code(func_name, func_info))
            cpp_lines.append("")
        
        return "\n".join(cpp_lines)
    
    def generate_analysis_report(self) -> str:
        """Generate analysis report."""
        report_lines = [
            f"Binary Analysis Report for {self.analyzer.binary_path.name}",
            "=" * 60,
            "",
            f"Architecture: {self.analyzer.pe.FILE_HEADER.Machine}",
            f"Entry Point: 0x{self.analyzer.pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
            f"Image Base: 0x{self.analyzer.pe.OPTIONAL_HEADER.ImageBase:x}",
            "",
            f"Sections ({len(self.analyzer.sections)}):",
        ]
        
        for name, info in self.analyzer.sections.items():
            report_lines.append(f"  {name}: VA=0x{info['virtual_address']:x}, "
                              f"Size=0x{info['virtual_size']:x}")
        
        report_lines.extend([
            "",
            f"Imported DLLs ({len(self.analyzer.imports)}):",
        ])
        
        for dll, functions in self.analyzer.imports.items():
            report_lines.append(f"  {dll}: {len(functions)} functions")
        
        report_lines.extend([
            "",
            f"Exported Functions ({len(self.analyzer.exports)}):",
        ])
        
        for func_name in self.analyzer.exports:
            addr = self.analyzer.exports[func_name]['address']
            report_lines.append(f"  {func_name}: 0x{addr:x}")
        
        report_lines.extend([
            "",
            f"Discovered Functions ({len(self.analyzer.functions)}):",
        ])
        
        for func_name, func_info in self.analyzer.functions.items():
            insn_count = len(func_info['instructions'])
            report_lines.append(f"  {func_name}: 0x{func_info['address']:x} "
                              f"({insn_count} instructions)")
        
        return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Disassemble binary files and generate C/C++ recreations"
    )
    parser.add_argument("binary_path", help="Path to the binary file (.dll or .sys)")
    parser.add_argument("-o", "--output", help="Output directory", default="output")
    parser.add_argument("--report", action="store_true", 
                       help="Generate analysis report")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary_path):
        print(f"Error: Binary file '{args.binary_path}' not found")
        return 1
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    print(f"Analyzing binary: {args.binary_path}")
    
    # Initialize analyzer
    analyzer = BinaryAnalyzer(args.binary_path)
    
    if not analyzer.load_binary():
        print("Failed to load binary file")
        return 1
    
    print("Analyzing imports...")
    analyzer.analyze_imports()
    
    print("Analyzing exports...")
    analyzer.analyze_exports()
    
    print("Analyzing sections...")
    analyzer.analyze_sections()
    
    print("Identifying functions...")
    analyzer.identify_functions()
    
    print(f"Found {len(analyzer.functions)} functions")
    
    # Generate C++ code
    generator = CppGenerator(analyzer)
    
    # Write header file
    header_file = output_dir / f"{analyzer.binary_path.stem}.h"
    with open(header_file, 'w') as f:
        f.write(generator.generate_header_file())
    print(f"Generated header: {header_file}")
    
    # Write implementation file
    cpp_file = output_dir / f"{analyzer.binary_path.stem}.cpp"
    with open(cpp_file, 'w') as f:
        f.write(generator.generate_cpp_file())
    print(f"Generated implementation: {cpp_file}")
    
    # Write analysis report if requested
    if args.report:
        report_file = output_dir / f"{analyzer.binary_path.stem}_analysis.txt"
        with open(report_file, 'w') as f:
            f.write(generator.generate_analysis_report())
        print(f"Generated report: {report_file}")
    
    print("Analysis complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
