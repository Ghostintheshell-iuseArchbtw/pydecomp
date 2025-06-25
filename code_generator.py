"""
Code generation utilities for creating clean C/C++ code from disassembled binaries.
"""

from typing import Dict, List, Optional
import re


class CodeGenerator:
    """Enhanced code generation with better C/C++ output."""
    
    def __init__(self):
        self.windows_types = {
            'BOOL': 'int',
            'BOOLEAN': 'unsigned char',
            'BYTE': 'unsigned char',
            'CHAR': 'char',
            'DWORD': 'unsigned long',
            'DWORDLONG': 'unsigned long long',
            'DWORD_PTR': 'unsigned long*',
            'FLOAT': 'float',
            'HANDLE': 'void*',
            'HMODULE': 'void*',
            'INT': 'int',
            'LONG': 'long',
            'LONGLONG': 'long long',
            'LPBYTE': 'unsigned char*',
            'LPCSTR': 'const char*',
            'LPCTSTR': 'const char*',
            'LPCWSTR': 'const wchar_t*',
            'LPDWORD': 'unsigned long*',
            'LPSTR': 'char*',
            'LPTSTR': 'char*',
            'LPVOID': 'void*',
            'LPWSTR': 'wchar_t*',
            'PBYTE': 'unsigned char*',
            'PCHAR': 'char*',
            'PDWORD': 'unsigned long*',
            'PHANDLE': 'void**',
            'PLONG': 'long*',
            'PUCHAR': 'unsigned char*',
            'PULONG': 'unsigned long*',
            'PVOID': 'void*',
            'SHORT': 'short',
            'SIZE_T': 'size_t',
            'UCHAR': 'unsigned char',
            'UINT': 'unsigned int',
            'ULONG': 'unsigned long',
            'ULONGLONG': 'unsigned long long',
            'USHORT': 'unsigned short',
            'WCHAR': 'wchar_t',
            'WORD': 'unsigned short',
        }
        
        self.common_functions = {
            'strlen': ('size_t', ['const char* str']),
            'strcpy': ('char*', ['char* dest', 'const char* src']),
            'strcmp': ('int', ['const char* str1', 'const char* str2']),
            'malloc': ('void*', ['size_t size']),
            'free': ('void', ['void* ptr']),
            'memcpy': ('void*', ['void* dest', 'const void* src', 'size_t n']),
            'memset': ('void*', ['void* ptr', 'int value', 'size_t n']),
            'printf': ('int', ['const char* format', '...']),
            'sprintf': ('int', ['char* buffer', 'const char* format', '...']),
        }
    
    def clean_function_name(self, name: str) -> str:
        """Clean and normalize function names."""
        # Remove special characters and make valid C identifier
        cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        
        # Ensure it doesn't start with a number
        if cleaned and cleaned[0].isdigit():
            cleaned = 'func_' + cleaned
        
        # Handle empty or invalid names
        if not cleaned or cleaned == '_':
            cleaned = 'unknown_function'
        
        return cleaned
    
    def infer_parameter_types(self, instructions: List[Dict]) -> List[str]:
        """Infer parameter types from function instructions."""
        params = []
        
        # Look for standard calling convention patterns
        register_usage = {'rcx': False, 'rdx': False, 'r8': False, 'r9': False}
        stack_params = 0
        
        for insn in instructions[:20]:  # Check first 20 instructions
            op_str = insn['op_str'].lower()
            
            # x64 fastcall: first 4 params in RCX, RDX, R8, R9
            for reg in register_usage:
                if reg in op_str and not register_usage[reg]:
                    params.append('uint64_t')
                    register_usage[reg] = True
            
            # Check for stack parameter access
            if 'rsp+' in op_str or 'rbp+' in op_str:
                stack_params += 1
        
        # Add additional parameters for stack usage
        for i in range(min(stack_params // 2, 4)):  # Reasonable limit
            params.append('uint64_t')
        
        return params[:8]  # Reasonable maximum
    
    def generate_function_signature(self, func_name: str, instructions: List[Dict],
                                  purpose: str = 'unknown') -> str:
        """Generate a proper function signature."""
        clean_name = self.clean_function_name(func_name)
        
        # Determine return type based on purpose
        return_type = 'int'  # default
        if purpose in ['getter', 'data_processing']:
            return_type = 'uint32_t'
        elif purpose in ['validation', 'checker']:
            return_type = 'bool'
        elif purpose in ['cleanup', 'setter']:
            return_type = 'void'
        elif 'string' in purpose:
            return_type = 'char*'
        
        # Infer parameters
        param_types = self.infer_parameter_types(instructions)
        
        if not param_types:
            params = 'void'
        else:
            param_list = []
            for i, ptype in enumerate(param_types):
                param_list.append(f'{ptype} param{i+1}')
            params = ', '.join(param_list)
        
        return f'{return_type} {clean_name}({params})'
    
    def generate_function_body(self, func_name: str, instructions: List[Dict],
                             purpose: str, characteristics: Dict) -> List[str]:
        """Generate function body with meaningful comments and structure."""
        body = []
        
        # Add function documentation
        body.append(f'    // Function: {func_name}')
        body.append(f'    // Purpose: {purpose}')
        body.append(f'    // Complexity: {characteristics.get("complexity_score", 0)}')
        body.append('')
        
        # Group instructions into logical blocks
        current_block = []
        block_type = 'setup'
        
        for i, insn in enumerate(instructions):
            mnemonic = insn['mnemonic'].lower()
            comment = f'    // {insn["mnemonic"]} {insn["op_str"]} ; {self._safe_hex_format(insn["address"])}'
            
            # Detect block boundaries
            if mnemonic in ['call']:
                if current_block:
                    body.extend(self.format_instruction_block(current_block, block_type))
                    current_block = []
                
                body.append('    // Function call')
                body.append(comment)
                body.append('')
                block_type = 'post_call'
                
            elif mnemonic.startswith('j') and mnemonic != 'jmp':
                if current_block:
                    body.extend(self.format_instruction_block(current_block, block_type))
                    current_block = []
                
                body.append('    // Conditional branch')
                body.append(comment)
                body.append('')
                block_type = 'conditional'
                
            elif mnemonic in ['ret', 'retn']:
                current_block.append(comment)
                body.extend(self.format_instruction_block(current_block, 'return'))
                break
                
            else:
                current_block.append(comment)
        
        # Add any remaining instructions
        if current_block:
            body.extend(self.format_instruction_block(current_block, block_type))
        
        # Add implementation placeholder
        body.extend([
            '',
            '    // TODO: Implement actual logic based on disassembly',
            '    // This is a placeholder return value',
        ])
        
        # Add appropriate return statement
        if 'void' not in self.generate_function_signature(func_name, instructions, purpose):
            body.append('    return 0;')
        
        return body
    
    def format_instruction_block(self, instructions: List[str], block_type: str) -> List[str]:
        """Format a block of instructions with appropriate comments."""
        if not instructions:
            return []
        
        block_comments = {
            'setup': '    // Function setup/prologue',
            'post_call': '    // Post-function call processing', 
            'conditional': '    // Conditional logic',
            'return': '    // Function cleanup/epilogue',
            'loop': '    // Loop body',
            'default': '    // Code block'
        }
        
        result = [block_comments.get(block_type, block_comments['default'])]
        result.extend(instructions)
        result.append('')
        
        return result
    
    def generate_include_statements(self, imports: Dict, exports: Dict) -> List[str]:
        """Generate appropriate #include statements."""
        includes = [
            '#include <windows.h>',
            '#include <cstdint>',
            '#include <cstdlib>',
            '#include <cstring>',
        ]
        
        # Add specific includes based on imports
        api_includes = {
            'kernel32.dll': ['#include <processthreadsapi.h>', '#include <fileapi.h>'],
            'user32.dll': ['#include <winuser.h>'],
            'advapi32.dll': ['#include <winreg.h>', '#include <wincrypt.h>'],
            'ws2_32.dll': ['#include <winsock2.h>', '#include <ws2tcpip.h>'],
            'ntdll.dll': ['#include <winternl.h>'],
        }
        
        for dll in imports:
            if dll in api_includes:
                includes.extend(api_includes[dll])
        
        return list(set(includes))  # Remove duplicates
    
    def generate_makefile(self, project_name: str) -> str:
        """Generate a simple Makefile for the project."""
        return f"""# Makefile for {project_name}

CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -std=c11 -O2
CXXFLAGS = -Wall -Wextra -std=c++17 -O2
LDFLAGS = -lkernel32 -luser32 -ladvapi32

TARGET = {project_name}
SOURCES = {project_name}.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
\t$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
\t$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
\trm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
"""
    
    def generate_cmake_file(self, project_name: str) -> str:
        """Generate a CMakeLists.txt file."""
        return f"""cmake_minimum_required(VERSION 3.16)
project({project_name})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable
add_executable({project_name} {project_name}.cpp)

# Link Windows libraries
if(WIN32)
    target_link_libraries({project_name} 
        kernel32 
        user32 
        advapi32 
        ws2_32
    )
endif()

# Compiler-specific options
if(MSVC)
    target_compile_options({project_name} PRIVATE /W4)
else()
    target_compile_options({project_name} PRIVATE -Wall -Wextra -Wpedantic)
endif()
"""
    
    def _safe_hex_format(self, value, default=0):
        """Safely format a value as hexadecimal, handling str and int inputs."""
        if value is None:
            value = default
        
        if isinstance(value, str):
            try:
                if value.startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value, 16) if all(c in '0123456789abcdefABCDEF' for c in value) else int(value)
            except (ValueError, TypeError):
                value = default
        
        # Ensure it's an integer
        value = int(value)
        return f"0x{value:x}"
