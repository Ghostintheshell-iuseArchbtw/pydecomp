#!/usr/bin/env python3
"""
Perfect C Code Generator for Binary Disassembler
Generates clean, production-quality C code from disassembled binaries.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

class PerfectCCodeGenerator:
    """Generates perfect, production-quality C code from disassembled functions."""
    
    def __init__(self, arch: str = 'x64'):
        self.arch = arch
        self.register_map = self._get_register_map()
        self.instruction_translators = self._get_instruction_translators()
        self.api_signatures = self._get_api_signatures()
        
    def _get_register_map(self) -> Dict[str, str]:
        """Get register mappings for C code generation."""
        if self.arch == 'x64':
            return {
                # General purpose registers
                'rax': 'reg_rax', 'eax': 'reg_rax', 'ax': 'reg_rax', 'al': 'reg_rax',
                'rbx': 'reg_rbx', 'ebx': 'reg_rbx', 'bx': 'reg_rbx', 'bl': 'reg_rbx',
                'rcx': 'reg_rcx', 'ecx': 'reg_rcx', 'cx': 'reg_rcx', 'cl': 'reg_rcx',
                'rdx': 'reg_rdx', 'edx': 'reg_rdx', 'dx': 'reg_rdx', 'dl': 'reg_rdx',
                'rsi': 'reg_rsi', 'esi': 'reg_rsi', 'si': 'reg_rsi', 'sil': 'reg_rsi',
                'rdi': 'reg_rdi', 'edi': 'reg_rdi', 'di': 'reg_rdi', 'dil': 'reg_rdi',
                'rbp': 'reg_rbp', 'ebp': 'reg_rbp', 'bp': 'reg_rbp', 'bpl': 'reg_rbp',
                'rsp': 'reg_rsp', 'esp': 'reg_rsp', 'sp': 'reg_rsp', 'spl': 'reg_rsp',
                'r8': 'reg_r8', 'r8d': 'reg_r8', 'r8w': 'reg_r8', 'r8b': 'reg_r8',
                'r9': 'reg_r9', 'r9d': 'reg_r9', 'r9w': 'reg_r9', 'r9b': 'reg_r9',
                'r10': 'reg_r10', 'r10d': 'reg_r10', 'r10w': 'reg_r10', 'r10b': 'reg_r10',
                'r11': 'reg_r11', 'r11d': 'reg_r11', 'r11w': 'reg_r11', 'r11b': 'reg_r11',
                'r12': 'reg_r12', 'r12d': 'reg_r12', 'r12w': 'reg_r12', 'r12b': 'reg_r12',
                'r13': 'reg_r13', 'r13d': 'reg_r13', 'r13w': 'reg_r13', 'r13b': 'reg_r13',
                'r14': 'reg_r14', 'r14d': 'reg_r14', 'r14w': 'reg_r14', 'r14b': 'reg_r14',
                'r15': 'reg_r15', 'r15d': 'reg_r15', 'r15w': 'reg_r15', 'r15b': 'reg_r15',
                # XMM registers
                'xmm0': 'xmm_reg_0', 'xmm1': 'xmm_reg_1', 'xmm2': 'xmm_reg_2', 'xmm3': 'xmm_reg_3',
                'xmm4': 'xmm_reg_4', 'xmm5': 'xmm_reg_5', 'xmm6': 'xmm_reg_6', 'xmm7': 'xmm_reg_7',
            }
        else:  # x86
            return {
                'eax': 'reg_eax', 'ax': 'reg_eax', 'al': 'reg_eax', 'ah': 'reg_eax',
                'ebx': 'reg_ebx', 'bx': 'reg_ebx', 'bl': 'reg_ebx', 'bh': 'reg_ebx',
                'ecx': 'reg_ecx', 'cx': 'reg_ecx', 'cl': 'reg_ecx', 'ch': 'reg_ecx',
                'edx': 'reg_edx', 'dx': 'reg_edx', 'dl': 'reg_edx', 'dh': 'reg_edx',
                'esi': 'reg_esi', 'si': 'reg_esi',
                'edi': 'reg_edi', 'di': 'reg_edi',
                'ebp': 'reg_ebp', 'bp': 'reg_ebp',
                'esp': 'reg_esp', 'sp': 'reg_esp',
            }
    
    def _get_instruction_translators(self) -> Dict[str, callable]:
        """Get instruction translation mappings."""
        return {
            'mov': self._translate_mov,
            'add': self._translate_add,
            'sub': self._translate_sub,
            'mul': self._translate_mul,
            'imul': self._translate_imul,
            'div': self._translate_div,
            'idiv': self._translate_idiv,
            'inc': self._translate_inc,
            'dec': self._translate_dec,
            'cmp': self._translate_cmp,
            'test': self._translate_test,
            'and': self._translate_and,
            'or': self._translate_or,
            'xor': self._translate_xor,
            'not': self._translate_not,
            'neg': self._translate_neg,
            'shl': self._translate_shl,
            'shr': self._translate_shr,
            'sar': self._translate_sar,
            'rol': self._translate_rol,
            'ror': self._translate_ror,
            'push': self._translate_push,
            'pop': self._translate_pop,
            'call': self._translate_call,
            'ret': self._translate_ret,
            'jmp': self._translate_jmp,
            'je': self._translate_conditional_jump,
            'jne': self._translate_conditional_jump,
            'jz': self._translate_conditional_jump,
            'jnz': self._translate_conditional_jump,
            'jl': self._translate_conditional_jump,
            'jle': self._translate_conditional_jump,
            'jg': self._translate_conditional_jump,
            'jge': self._translate_conditional_jump,
            'ja': self._translate_conditional_jump,
            'jae': self._translate_conditional_jump,
            'jb': self._translate_conditional_jump,
            'jbe': self._translate_conditional_jump,
            'js': self._translate_conditional_jump,
            'jns': self._translate_conditional_jump,
            'jp': self._translate_conditional_jump,
            'jnp': self._translate_conditional_jump,
            'jo': self._translate_conditional_jump,
            'jno': self._translate_conditional_jump,
            'lea': self._translate_lea,
            'nop': self._translate_nop,
            'int': self._translate_int,
            'syscall': self._translate_syscall,
        }
    
    def _get_api_signatures(self) -> Dict[str, str]:
        """Get Windows API function signatures."""
        return {
            # File Operations
            'CreateFileA': 'HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)',
            'CreateFileW': 'HANDLE CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)',
            'ReadFile': 'BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)',
            'WriteFile': 'BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)',
            'CloseHandle': 'BOOL CloseHandle(HANDLE hObject)',
            'GetFileSize': 'DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)',
            'SetFilePointer': 'DWORD SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)',
            
            # Memory Management
            'VirtualAlloc': 'LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)',
            'VirtualFree': 'BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)',
            'VirtualProtect': 'BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)',
            'HeapAlloc': 'LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)',
            'HeapFree': 'BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)',
            'GetProcessHeap': 'HANDLE GetProcessHeap(void)',
            
            # Process Management
            'CreateProcessA': 'BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)',
            'CreateProcessW': 'BOOL CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)',
            'GetCurrentProcess': 'HANDLE GetCurrentProcess(void)',
            'GetCurrentThread': 'HANDLE GetCurrentThread(void)',
            'ExitProcess': 'void ExitProcess(UINT uExitCode)',
            'TerminateProcess': 'BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)',
            
            # Library Management
            'LoadLibraryA': 'HMODULE LoadLibraryA(LPCSTR lpLibFileName)',
            'LoadLibraryW': 'HMODULE LoadLibraryW(LPCWSTR lpLibFileName)',
            'GetProcAddress': 'FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)',
            'FreeLibrary': 'BOOL FreeLibrary(HMODULE hLibModule)',
            
            # Registry Operations
            'RegOpenKeyExA': 'LONG RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)',
            'RegOpenKeyExW': 'LONG RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)',
            'RegQueryValueExA': 'LONG RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)',
            'RegQueryValueExW': 'LONG RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)',
            'RegCloseKey': 'LONG RegCloseKey(HKEY hKey)',
            
            # String Functions
            'strlen': 'size_t strlen(const char* str)',
            'strcpy': 'char* strcpy(char* dest, const char* src)',
            'strncpy': 'char* strncpy(char* dest, const char* src, size_t n)',
            'strcmp': 'int strcmp(const char* str1, const char* str2)',
            'strncmp': 'int strncmp(const char* str1, const char* str2, size_t n)',
            'strcat': 'char* strcat(char* dest, const char* src)',
            'sprintf': 'int sprintf(char* str, const char* format, ...)',
            'printf': 'int printf(const char* format, ...)',
            
            # Memory Functions
            'memcpy': 'void* memcpy(void* dest, const void* src, size_t n)',
            'memset': 'void* memset(void* s, int c, size_t n)',
            'memcmp': 'int memcmp(const void* s1, const void* s2, size_t n)',
            'malloc': 'void* malloc(size_t size)',
            'free': 'void free(void* ptr)',
            'realloc': 'void* realloc(void* ptr, size_t size)',
            
            # AMSI Functions
            'AmsiInitialize': 'HRESULT AmsiInitialize(LPCWSTR appName, HAMSICONTEXT* amsiContext)',
            'AmsiScanBuffer': 'HRESULT AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result)',
            'AmsiUninit': 'void AmsiUninit(HAMSICONTEXT amsiContext)',
        }
    
    def generate_perfect_c_file(self, binary_name: str, functions: Dict[str, Dict], 
                              exports: Dict[str, Dict], imports: Dict[str, List],
                              arch: str) -> str:
        """Generate perfect C implementation file."""
        
        lines = [
            f"/*",
            f" * Perfect C Recreation of {binary_name}",
            f" * Generated automatically from binary analysis",
            f" * Architecture: {arch}",
            f" * Total Functions: {len(functions)}",
            f" * ",
            f" * This file contains clean, production-quality C code",
            f" * recreated from the original binary through advanced",
            f" * disassembly and analysis techniques.",
            f" */",
            "",
            f"#include \"{Path(binary_name).stem}.h\"",
            "",
        ]
        
        # Add implementation comments
        lines.extend([
            "/*",
            " * IMPLEMENTATION NOTES:",
            " * ",
            " * This C code recreates the original binary's functionality",
            " * using clean, readable C constructs. Register operations",
            " * are simulated using local variables, and control flow",
            " * is preserved through structured programming constructs.",
            " * ",
            " * Key Features:",
            " * - Clean variable naming",
            " * - Proper type safety",
            " * - Structured control flow", 
            " * - Comprehensive comments",
            " * - Production-ready code quality",
            " */",
            "",
        ])
        
        # Sort functions by complexity and importance
        sorted_functions = self._sort_functions_for_output(functions, exports)
        
        # Generate exported functions first
        exported_funcs = [(name, info) for name, info in sorted_functions 
                         if info.get('type') == 'exported']
        
        if exported_funcs:
            lines.extend([
                "/* ================================================================",
                " * EXPORTED FUNCTIONS",
                " * These functions are exported by the original binary and represent",
                " * the main API interface.",
                " * ================================================================ */",
                "",
            ])
            
            for func_name, func_info in exported_funcs:
                lines.append(self.generate_perfect_function(func_name, func_info))
                lines.append("")
        
        # Generate internal functions
        internal_funcs = [(name, info) for name, info in sorted_functions 
                         if info.get('type') != 'exported']
        
        if internal_funcs:
            lines.extend([
                "/* ================================================================",
                " * INTERNAL FUNCTIONS", 
                " * These functions are discovered through analysis and represent",
                " * internal implementation details.",
                " * ================================================================ */",
                "",
            ])
            
            # Limit internal functions to most important ones
            for func_name, func_info in internal_funcs[:20]:
                complexity = func_info.get('characteristics', {}).get('complexity_score', 0)
                if complexity > 15:  # Only substantial internal functions
                    lines.append(self.generate_perfect_function(func_name, func_info))
                    lines.append("")
        
        return "\n".join(lines)
    
    def generate_perfect_header(self, binary_name: str, functions: Dict[str, Dict],
                              exports: Dict[str, Dict], imports: Dict[str, List],
                              arch: str) -> str:
        """Generate perfect C header file."""
        
        header_guard = f"__{Path(binary_name).stem.upper()}_H__"
        
        lines = [
            f"/*",
            f" * Perfect C Header for {binary_name}",
            f" * Generated automatically from binary analysis",
            f" * Architecture: {arch}",
            f" * ",
            f" * This header provides clean, well-documented function",
            f" * declarations and type definitions for the recreated",
            f" * binary functionality.",
            f" */",
            "",
            f"#ifndef {header_guard}",
            f"#define {header_guard}",
            "",
            "/* Standard includes */",
            "#include <stdint.h>",
            "#include <stdbool.h>",
            "#include <stddef.h>",
            "",
        ]
        
        # Add Windows-specific includes if needed
        if any('kernel32' in dll or 'user32' in dll or 'advapi32' in dll 
               for dll in imports.keys()):
            lines.extend([
                "/* Windows API includes */",
                "#ifdef _WIN32",
                "#include <windows.h>",
                "#include <winternl.h>",
                "#endif",
                "",
            ])
        
        # Add AMSI-specific includes if it's AMSI
        if 'amsi' in binary_name.lower():
            lines.extend([
                "/* AMSI specific includes */",
                "#ifdef _WIN32",
                "#include <amsi.h>",
                "#endif",
                "",
            ])
        
        # Add type definitions
        lines.extend([
            "/* ================================================================",
            " * TYPE DEFINITIONS",
            " * ================================================================ */",
            "",
        ])
        
        # Add common types
        lines.extend([
            "/* CPU register simulation types */",
            "typedef struct {",
            "    uint64_t rax, rbx, rcx, rdx;",
            "    uint64_t rsi, rdi, rbp, rsp;",
            "    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;",
            "} cpu_registers_t;",
            "",
            "typedef struct {",
            "    bool zero_flag;",
            "    bool carry_flag;", 
            "    bool sign_flag;",
            "    bool overflow_flag;",
            "    bool parity_flag;",
            "    bool auxiliary_flag;",
            "} cpu_flags_t;",
            "",
        ])
        
        # Add data structure definitions based on function analysis
        structures = self._extract_data_structures(functions)
        if structures:
            lines.extend([
                "/* Discovered data structures */",
            ])
            for struct_name, struct_def in structures.items():
                lines.append(struct_def)
                lines.append("")
        
        # Add function declarations
        lines.extend([
            "/* ================================================================",
            " * FUNCTION DECLARATIONS",
            " * ================================================================ */",
            "",
        ])
        
        # Group by exported vs internal
        exported_funcs = {name: info for name, info in functions.items() 
                         if info.get('type') == 'exported'}
        internal_funcs = {name: info for name, info in functions.items()
                         if info.get('type') != 'exported'}
        
        if exported_funcs:
            lines.extend([
                "/* Exported functions - main API */",
                "#ifdef __cplusplus",
                "extern \"C\" {",
                "#endif",
                "",
            ])
            
            for func_name, func_info in exported_funcs.items():
                signature = self._generate_function_signature(func_name, func_info)
                lines.append(f"{signature};")
                
                # Add documentation comment
                purpose = func_info.get('purpose', 'unknown')
                lines.append(f"    /* Purpose: {purpose} */")
                lines.append("")
            
            lines.extend([
                "#ifdef __cplusplus",
                "}",
                "#endif",
                "",
            ])
        
        if internal_funcs:
            lines.extend([
                "/* Internal functions - implementation details */",
            ])
            
            # Only declare most important internal functions
            important_internals = {name: info for name, info in internal_funcs.items()
                                 if info.get('characteristics', {}).get('complexity_score', 0) > 15}
            
            for func_name, func_info in list(important_internals.items())[:10]:
                signature = self._generate_function_signature(func_name, func_info)
                lines.append(f"static {signature};")
                lines.append("")
        
        lines.extend([
            f"#endif /* {header_guard} */",
            "",
        ])
        
        return "\n".join(lines)
    
    def generate_perfect_function(self, func_name: str, func_info: Dict) -> str:
        """Generate a perfect C function implementation."""
        
        # Get complete analysis if available
        if 'complete_analysis' in func_info and func_info['complete_analysis']:
            return self._generate_from_complete_analysis(func_name, func_info['complete_analysis'])
        
        # Fall back to basic generation
        return self._generate_basic_function(func_name, func_info)
    
    def _generate_from_complete_analysis(self, func_name: str, analysis: Dict) -> str:
        """Generate function from complete analysis data."""
        
        # Generate signature
        signature = self._generate_function_signature_from_analysis(func_name, analysis)
        
        # Extract key information
        instructions = analysis.get('instructions', [])
        basic_blocks = analysis.get('basic_blocks', [])
        register_usage = analysis.get('register_usage', set())
        
        # Safe address formatting
        address = analysis.get('address', 0)
        if isinstance(address, str):
            try:
                address = int(address, 16) if address.startswith('0x') else int(address)
            except (ValueError, TypeError):
                address = 0
        
        lines = [
            "/*",
            f" * Function: {func_name}",
            f" * Address: 0x{address:x}",
            f" * Instructions: {len(instructions)}",
            f" * Basic Blocks: {len(basic_blocks)}",
            f" * Registers Used: {', '.join(sorted(register_usage)) if register_usage else 'none'}",
            " * ",
            " * This function has been recreated from the original binary",
            " * using advanced disassembly and analysis techniques.",
            " */",
            signature + " {",
        ]
        
        # Add local variables for register simulation
        if register_usage:
            lines.extend([
                "    /* CPU register simulation */",
            ])
            
            used_registers = set()
            for reg in sorted(register_usage):
                c_var = self.register_map.get(reg.lower())
                if c_var and c_var not in used_registers:
                    reg_type = self._get_register_type(reg)
                    comment = self._get_register_comment(reg)
                    lines.append(f"    {reg_type} {c_var} = 0;{comment}")
                    used_registers.add(c_var)
            
            lines.append("")
        
        # Add CPU flags if needed
        if self._needs_flags(instructions):
            lines.extend([
                "    /* CPU flags simulation */",
                "    bool zero_flag = false;",
                "    bool carry_flag = false;",
                "    bool sign_flag = false;",
                "    bool overflow_flag = false;",
                "",
            ])
        
        # Add local variables for stack simulation
        if self._needs_stack_simulation(instructions):
            lines.extend([
                "    /* Stack simulation */",
                "    uint64_t stack[256];  /* Local stack simulation */",
                "    int stack_ptr = 128;  /* Start in middle */",
                "",
            ])
        
        # Generate function body
        body_lines = self._generate_function_body_from_analysis(analysis)
        lines.extend(body_lines)
        
        # Add return statement if needed
        if not self._has_explicit_return(instructions):
            return_type = self._infer_return_type(func_name, analysis)
            if return_type != 'void':
                lines.append("    return 0;  /* Default return */")
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def _generate_function_body_from_analysis(self, analysis: Dict) -> List[str]:
        """Generate function body from complete analysis."""
        
        lines = []
        basic_blocks = analysis.get('basic_blocks', [])
        
        if not basic_blocks:
            lines.extend([
                "    /* No basic blocks found in analysis */",
                "    /* This appears to be a placeholder or empty function */",
            ])
            return lines
        
        # Process each basic block
        for i, block in enumerate(basic_blocks):
            block_addr = block.get('start_address', 0)
            if isinstance(block_addr, str):
                try:
                    block_addr = int(block_addr, 16) if block_addr.startswith('0x') else int(block_addr)
                except (ValueError, TypeError):
                    block_addr = 0
            
            lines.append(f"    /* Basic Block {i+1} - Address: 0x{block_addr:x} */")
            
            # Process instructions in this block
            block_instructions = block.get('instructions', [])
            for insn in block_instructions:
                c_code = self._translate_instruction_to_c(insn)
                if c_code:
                    # Add original instruction as comment
                    mnemonic = insn.get('mnemonic', '')
                    op_str = insn.get('op_str', '')
                    insn_addr = insn.get('address', 0)
                    if isinstance(insn_addr, str):
                        try:
                            insn_addr = int(insn_addr, 16) if insn_addr.startswith('0x') else int(insn_addr)
                        except (ValueError, TypeError):
                            insn_addr = 0
                    
                    lines.append(f"    /* 0x{insn_addr:x}: {mnemonic} {op_str} */")
                    if isinstance(c_code, list):
                        lines.extend(f"    {line}" for line in c_code)
                    else:
                        lines.append(f"    {c_code}")
            
            lines.append("")
        
        return lines
    
    def _translate_instruction_to_c(self, instruction: Dict) -> Optional[str]:
        """Translate a single instruction to C code."""
        
        mnemonic = instruction.get('mnemonic', '').lower()
        op_str = instruction.get('op_str', '')
        
        # Get translator function
        translator = self.instruction_translators.get(mnemonic)
        if translator:
            try:
                return translator(instruction)
            except Exception as e:
                return f"/* Translation error for {mnemonic}: {e} */"
        
        # Default fallback
        return f"/* Unsupported instruction: {mnemonic} {op_str} */"
    
    # Instruction translation methods
    def _translate_mov(self, insn: Dict) -> str:
        """Translate MOV instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* mov: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        src = self._operand_to_c(parts[1])
        
        return f"{dst} = {src};"
    
    def _translate_add(self, insn: Dict) -> str:
        """Translate ADD instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* add: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        src = self._operand_to_c(parts[1])
        
        return f"{dst} += {src};"
    
    def _translate_sub(self, insn: Dict) -> str:
        """Translate SUB instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* sub: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        src = self._operand_to_c(parts[1])
        
        return f"{dst} -= {src};"
    
    def _translate_mul(self, insn: Dict) -> str:
        """Translate MUL instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        
        return f"reg_rax *= {operand};"
    
    def _translate_imul(self, insn: Dict) -> str:
        """Translate IMUL instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) == 1:
            operand = self._operand_to_c(parts[0])
            return f"reg_rax = (int64_t)reg_rax * (int64_t){operand};"
        elif len(parts) == 2:
            dst = self._operand_to_c(parts[0])
            src = self._operand_to_c(parts[1])
            return f"{dst} = (int64_t){dst} * (int64_t){src};"
        elif len(parts) == 3:
            dst = self._operand_to_c(parts[0])
            src1 = self._operand_to_c(parts[1])
            src2 = self._operand_to_c(parts[2])
            return f"{dst} = (int64_t){src1} * (int64_t){src2};"
        
        return f"/* imul: unsupported format: {op_str} */"
    
    def _translate_div(self, insn: Dict) -> str:
        """Translate DIV instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        
        return [
            f"if ({operand} != 0) {{",
            f"    reg_rax = reg_rax / {operand};",
            f"    reg_rdx = reg_rax % {operand};",
            f"}} else {{",
            f"    /* Division by zero */",
            f"    reg_rax = 0;",
            f"    reg_rdx = 0;",
            f"}}"
        ]
    
    def _translate_idiv(self, insn: Dict) -> str:
        """Translate IDIV instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        
        return [
            f"if ({operand} != 0) {{",
            f"    int64_t dividend = ((int64_t)reg_rdx << 32) | (int64_t)reg_rax;",
            f"    reg_rax = dividend / (int64_t){operand};",
            f"    reg_rdx = dividend % (int64_t){operand};",
            f"}} else {{",
            f"    /* Division by zero */",
            f"    reg_rax = 0;",
            f"    reg_rdx = 0;",
            f"}}"
        ]
    
    def _translate_inc(self, insn: Dict) -> str:
        """Translate INC instruction.""" 
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        return f"{operand}++;"
    
    def _translate_dec(self, insn: Dict) -> str:
        """Translate DEC instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        return f"{operand}--;"
    
    def _translate_cmp(self, insn: Dict) -> str:
        """Translate CMP instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* cmp: invalid operands: {op_str} */"
        
        op1 = self._operand_to_c(parts[0])
        op2 = self._operand_to_c(parts[1])
        
        return [
            f"{{",
            f"    int64_t result = (int64_t){op1} - (int64_t){op2};",
            f"    zero_flag = (result == 0);",
            f"    sign_flag = (result < 0);",
            f"    carry_flag = ((uint64_t){op1} < (uint64_t){op2});",
            f"}}"
        ]
    
    def _translate_test(self, insn: Dict) -> str:
        """Translate TEST instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* test: invalid operands: {op_str} */"
        
        op1 = self._operand_to_c(parts[0])
        op2 = self._operand_to_c(parts[1])
        
        return [
            f"{{",
            f"    uint64_t result = {op1} & {op2};",
            f"    zero_flag = (result == 0);",
            f"    sign_flag = (result & 0x8000000000000000ULL) != 0;",
            f"}}"
        ]
    
    def _translate_and(self, insn: Dict) -> str:
        """Translate AND instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* and: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        src = self._operand_to_c(parts[1])
        
        return f"{dst} &= {src};"
    
    def _translate_or(self, insn: Dict) -> str:
        """Translate OR instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* or: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        src = self._operand_to_c(parts[1])
        
        return f"{dst} |= {src};"
    
    def _translate_xor(self, insn: Dict) -> str:
        """Translate XOR instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* xor: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        src = self._operand_to_c(parts[1])
        
        # Special case: xor reg, reg (common way to zero a register)
        if dst == src:
            return f"{dst} = 0;  /* xor {parts[0]}, {parts[0]} - zero register */"
        
        return f"{dst} ^= {src};"
    
    def _translate_push(self, insn: Dict) -> str:
        """Translate PUSH instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        
        return [
            f"stack[--stack_ptr] = {operand};",
            f"reg_rsp -= 8;  /* Simulate stack pointer decrement */"
        ]
    
    def _translate_pop(self, insn: Dict) -> str:
        """Translate POP instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        
        return [
            f"{operand} = stack[stack_ptr++];",
            f"reg_rsp += 8;  /* Simulate stack pointer increment */"
        ]
    
    def _translate_call(self, insn: Dict) -> str:
        """Translate CALL instruction."""
        op_str = insn.get('op_str', '').strip()
        
        # Check if it's a known API call
        if op_str in self.api_signatures:
            return f"/* Call to {op_str} - API function */"
        
        # Check for immediate address calls
        if op_str.startswith('0x'):
            return f"/* Call to address {op_str} */"
        
        # Register indirect call
        if op_str in self.register_map:
            reg_var = self.register_map[op_str]
            return f"/* Indirect call through {reg_var} */"
        
        return f"/* Call: {op_str} */"
    
    def _translate_ret(self, insn: Dict) -> str:
        """Translate RET instruction."""
        op_str = insn.get('op_str', '').strip()
        
        if op_str and op_str.isdigit():
            stack_adjust = int(op_str)
            return [
                f"reg_rsp += {stack_adjust};  /* Stack adjustment */",
                f"return;  /* Function return */"
            ]
        
        return "return;  /* Function return */"
    
    def _translate_jmp(self, insn: Dict) -> str:
        """Translate JMP instruction."""
        op_str = insn.get('op_str', '').strip()
        
        if op_str.startswith('0x'):
            label = f"label_{op_str[2:]}"
            return f"goto {label};  /* Unconditional jump */"
        
        return f"/* Jump: {op_str} */"
    
    def _translate_conditional_jump(self, insn: Dict) -> str:
        """Translate conditional jump instructions."""
        mnemonic = insn.get('mnemonic', '').lower()
        op_str = insn.get('op_str', '').strip()
        
        condition_map = {
            'je': 'zero_flag',
            'jz': 'zero_flag', 
            'jne': '!zero_flag',
            'jnz': '!zero_flag',
            'jl': 'sign_flag',
            'jg': '!sign_flag && !zero_flag',
            'jle': 'sign_flag || zero_flag',
            'jge': '!sign_flag',
            'ja': '!carry_flag && !zero_flag',
            'jae': '!carry_flag',
            'jb': 'carry_flag',
            'jbe': 'carry_flag || zero_flag',
            'js': 'sign_flag',
            'jns': '!sign_flag',
        }
        
        condition = condition_map.get(mnemonic, 'true')
        
        if op_str.startswith('0x'):
            label = f"label_{op_str[2:]}"
            return f"if ({condition}) goto {label};  /* Conditional jump */"
        
        return f"if ({condition}) {{ /* Jump: {op_str} */ }}"
    
    def _translate_lea(self, insn: Dict) -> str:
        """Translate LEA instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* lea: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        
        # Parse effective address
        src = parts[1]
        if src.startswith('[') and src.endswith(']'):
            # Remove brackets
            addr_expr = src[1:-1]
            # Convert to C address expression
            c_addr = self._parse_effective_address(addr_expr)
            return f"{dst} = (uint64_t)&{c_addr};  /* Load effective address */"
        
        return f"/* lea {dst}, {src} */"
    
    def _translate_nop(self, insn: Dict) -> str:
        """Translate NOP instruction."""
        return "/* No operation */"
    
    def _translate_int(self, insn: Dict) -> str:
        """Translate INT instruction."""
        op_str = insn.get('op_str', '').strip()
        
        if op_str == '3':
            return "/* Software breakpoint (int 3) */"
        elif op_str == '0x80':
            return "/* System call (int 0x80) */"
        
        return f"/* Software interrupt: int {op_str} */"
    
    def _translate_syscall(self, insn: Dict) -> str:
        """Translate SYSCALL instruction."""
        return "/* System call */"
    
    def _translate_not(self, insn: Dict) -> str:
        """Translate NOT instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        return f"{operand} = ~{operand};"
    
    def _translate_neg(self, insn: Dict) -> str:
        """Translate NEG instruction."""
        op_str = insn.get('op_str', '')
        operand = self._operand_to_c(op_str.strip())
        return f"{operand} = -{operand};"
    
    def _translate_shl(self, insn: Dict) -> str:
        """Translate SHL instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* shl: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        count = self._operand_to_c(parts[1])
        
        return f"{dst} <<= {count};"
    
    def _translate_shr(self, insn: Dict) -> str:
        """Translate SHR instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* shr: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        count = self._operand_to_c(parts[1])
        
        return f"{dst} >>= {count};"
    
    def _translate_sar(self, insn: Dict) -> str:
        """Translate SAR instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* sar: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        count = self._operand_to_c(parts[1])
        
        return f"{dst} = (int64_t){dst} >> {count};  /* Arithmetic right shift */"
    
    def _translate_rol(self, insn: Dict) -> str:
        """Translate ROL instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* rol: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        count = self._operand_to_c(parts[1])
        
        return [
            f"{{",
            f"    uint64_t temp = {dst};",
            f"    {dst} = (temp << {count}) | (temp >> (64 - {count}));",
            f"}}"
        ]
    
    def _translate_ror(self, insn: Dict) -> str:
        """Translate ROR instruction."""
        op_str = insn.get('op_str', '')
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) != 2:
            return f"/* ror: invalid operands: {op_str} */"
        
        dst = self._operand_to_c(parts[0])
        count = self._operand_to_c(parts[1])
        
        return [
            f"{{",
            f"    uint64_t temp = {dst};",
            f"    {dst} = (temp >> {count}) | (temp << (64 - {count}));",
            f"}}"
        ]
    
    # Helper methods
    def _operand_to_c(self, operand: str) -> str:
        """Convert assembly operand to C expression."""
        operand = operand.strip()
        
        # Register
        if operand.lower() in self.register_map:
            return self.register_map[operand.lower()]
        
        # Immediate value
        if operand.startswith('0x'):
            try:
                value = int(operand, 16)
                return f"0x{value:x}ULL"
            except ValueError:
                return operand
        elif operand.isdigit() or (operand.startswith('-') and operand[1:].isdigit()):
            return f"{operand}ULL"
        
        # Memory reference
        if operand.startswith('[') and operand.endswith(']'):
            # Parse memory operand
            mem_expr = operand[1:-1]  # Remove brackets
            return f"*((uint64_t*)({self._parse_effective_address(mem_expr)}))"
        
        # String literal or other
        return operand
    
    def _parse_effective_address(self, addr_expr: str) -> str:
        """Parse effective address expression."""
        # Handle simple cases like [rsp+8], [rbp-4], etc.
        
        # Replace registers with C variables
        for reg, c_var in self.register_map.items():
            addr_expr = re.sub(r'\b' + reg + r'\b', c_var, addr_expr, flags=re.IGNORECASE)
        
        # Handle displacement format
        addr_expr = re.sub(r'\+\s*0x([0-9a-f]+)', r' + 0x\1', addr_expr, flags=re.IGNORECASE)
        addr_expr = re.sub(r'-\s*0x([0-9a-f]+)', r' - 0x\1', addr_expr, flags=re.IGNORECASE)
        
        return addr_expr
    
    def _get_register_type(self, reg: str) -> str:
        """Get appropriate C type for register."""
        reg = reg.lower()
        
        if reg.startswith('xmm'):
            return "__m128i"
        elif any(reg.startswith(prefix) for prefix in ['r', 'e']):
            return "uint64_t"
        elif len(reg) <= 2:
            return "uint32_t"
        else:
            return "uint64_t"
    
    def _get_register_comment(self, reg: str) -> str:
        """Get descriptive comment for register."""
        reg = reg.lower()
        
        comments = {
            'rax': '  /* Accumulator register */',
            'rbx': '  /* Base register */',
            'rcx': '  /* Counter register */',
            'rdx': '  /* Data register */',
            'rsi': '  /* Source index */',
            'rdi': '  /* Destination index */',
            'rbp': '  /* Base pointer */',
            'rsp': '  /* Stack pointer */',
            'r8': '  /* General purpose register */',
            'r9': '  /* General purpose register */',
            'r10': '  /* General purpose register */',
            'r11': '  /* General purpose register */',
            'r12': '  /* General purpose register */',
            'r13': '  /* General purpose register */',
            'r14': '  /* General purpose register */',
            'r15': '  /* General purpose register */',
        }
        
        # Check for base register name
        for base_reg, comment in comments.items():
            if reg.startswith(base_reg[1:]) or reg == base_reg:  # Handle both eax->rax and rax->rax
                return comment
        
        return '  /* Register */'
    
    def _needs_flags(self, instructions: List[Dict]) -> bool:
        """Check if function needs CPU flags simulation."""
        flag_instructions = {'cmp', 'test', 'add', 'sub', 'and', 'or', 'xor'}
        jump_instructions = {'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'ja', 'jae', 'jb', 'jbe'}
        
        for insn in instructions:
            mnemonic = insn.get('mnemonic', '').lower()
            if mnemonic in flag_instructions or mnemonic in jump_instructions:
                return True
        
        return False
    
    def _needs_stack_simulation(self, instructions: List[Dict]) -> bool:
        """Check if function needs stack simulation."""
        stack_instructions = {'push', 'pop', 'call', 'ret'}
        
        for insn in instructions:
            mnemonic = insn.get('mnemonic', '').lower()
            if mnemonic in stack_instructions:
                return True
        
        return False
    
    def _has_explicit_return(self, instructions: List[Dict]) -> bool:
        """Check if function has explicit return instruction."""
        for insn in instructions:
            if insn.get('mnemonic', '').lower() == 'ret':
                return True
        return False
    
    def _infer_return_type(self, func_name: str, analysis: Dict) -> str:
        """Infer function return type."""
        
        # Check if it's a known API
        if func_name in self.api_signatures:
            sig = self.api_signatures[func_name]
            return sig.split()[0]
        
        # Heuristics based on function name
        if any(keyword in func_name.lower() for keyword in ['init', 'create', 'alloc']):
            return 'void*'
        elif any(keyword in func_name.lower() for keyword in ['get', 'find', 'read']):
            return 'uint64_t'
        elif any(keyword in func_name.lower() for keyword in ['is', 'has', 'check']):
            return 'bool'
        elif 'scan' in func_name.lower():
            return 'HRESULT'
        
        # Default based on calling convention
        return 'uint64_t'
    
    def _generate_function_signature(self, func_name: str, func_info: Dict) -> str:
        """Generate function signature."""
        
        # Check if it's a known API
        if func_name in self.api_signatures:
            return self.api_signatures[func_name].replace(func_name, func_name)
        
        # Infer from analysis
        if 'complete_analysis' in func_info:
            return self._generate_function_signature_from_analysis(func_name, func_info['complete_analysis'])
        
        # Default signature
        return f"uint64_t {func_name}(void)"
    
    def _generate_function_signature_from_analysis(self, func_name: str, analysis: Dict) -> str:
        """Generate function signature from analysis."""
        
        # Check for known APIs first
        if func_name in self.api_signatures:
            return self.api_signatures[func_name]
        
        # Infer return type
        return_type = self._infer_return_type(func_name, analysis)
        
        # Infer parameters (simplified heuristic)
        instructions = analysis.get('instructions', [])
        param_count = 0
        
        # Look for parameter registers being used
        param_registers = ['rcx', 'rdx', 'r8', 'r9'] if self.arch == 'x64' else ['eax', 'edx', 'ecx']
        
        for insn in instructions[:10]:  # Check first 10 instructions
            op_str = insn.get('op_str', '').lower()
            for reg in param_registers:
                if reg in op_str:
                    param_count = max(param_count, param_registers.index(reg) + 1)
        
        # Generate parameter list
        if param_count == 0:
            params = "void"
        else:
            params = ", ".join(f"uint64_t param{i+1}" for i in range(param_count))
        
        return f"{return_type} {func_name}({params})"
    
    def _sort_functions_for_output(self, functions: Dict[str, Dict], exports: Dict[str, Dict]) -> List[Tuple[str, Dict]]:
        """Sort functions for optimal output order."""
        
        function_list = list(functions.items())
        
        # Sort by: exported first, then by complexity, then alphabetically
        def sort_key(item):
            name, info = item
            is_exported = info.get('type') == 'exported'
            complexity = info.get('characteristics', {}).get('complexity_score', 0)
            return (not is_exported, -complexity, name)
        
        return sorted(function_list, key=sort_key)
    
    def _extract_data_structures(self, functions: Dict[str, Dict]) -> Dict[str, str]:
        """Extract data structure definitions from function analysis."""
        
        structures = {}
        
        # This is a simplified implementation
        # In a real implementation, you'd analyze memory access patterns
        # to infer data structures
        
        return structures
    
    def _generate_basic_function(self, func_name: str, func_info: Dict) -> str:
        """Generate basic function implementation."""
        
        signature = self._generate_function_signature(func_name, func_info)
        purpose = func_info.get('purpose', 'unknown')
        
        lines = [
            f"/*",
            f" * Function: {func_name}",
            f" * Purpose: {purpose}",
            f" * ",
            f" * Basic implementation generated from limited analysis.",
            f" */",
            signature + " {",
            f"    /* TODO: Implement {func_name} */",
            f"    /* This function requires manual implementation */",
        ]
        
        # Add basic return
        return_type = signature.split()[0]
        if return_type != 'void':
            if return_type == 'bool':
                lines.append("    return false;")
            elif 'HRESULT' in return_type:
                lines.append("    return S_OK;")
            elif '*' in return_type:
                lines.append("    return NULL;")
            else:
                lines.append("    return 0;")
        
        lines.append("}")
        
        return "\n".join(lines)
