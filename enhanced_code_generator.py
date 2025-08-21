#!/usr/bin/env python3
"""
Enhanced Code Generator for Compilable C/C++ Output
Generates more accurate and compilable C/C++ code from binary analysis
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from enhanced_pattern_analyzer import AdvancedPatternMatcher, EnhancedDataStructureAnalyzer


class EnhancedCodeGenerator:
    """Enhanced code generator with better type inference and structure."""
    
    def __init__(self):
        self.pattern_matcher = AdvancedPatternMatcher()
        self.structure_analyzer = EnhancedDataStructureAnalyzer()
        
        self.c_types = {
            'BYTE': 'uint8_t',
            'WORD': 'uint16_t', 
            'DWORD': 'uint32_t',
            'QWORD': 'uint64_t',
            'CHAR': 'char',
            'WCHAR': 'wchar_t',
            'BOOL': 'BOOL',
            'HANDLE': 'HANDLE',
            'HWND': 'HWND',
            'HDC': 'HDC',
            'HINSTANCE': 'HINSTANCE',
            'LPSTR': 'LPSTR',
            'LPCSTR': 'LPCSTR',
            'LPWSTR': 'LPWSTR',
            'LPCWSTR': 'LPCWSTR',
            'LPVOID': 'LPVOID'
        }
        
        self.common_includes = [
            '#include <windows.h>',
            '#include <cstdint>',
            '#include <cstring>',
            '#include <iostream>',
            '#include <vector>',
            '#include <memory>'
        ]
        
    def generate_complete_project(self, binary_info: Dict[str, Any], output_dir: Path, 
                                binary_name: str) -> Dict[str, str]:
        """Generate a complete C++ project with all necessary files."""
        generated_files = {}
        
        # Generate header file
        header_content = self.generate_enhanced_header(binary_info, binary_name)
        header_file = output_dir / f"{binary_name}.h"
        with open(header_file, 'w', encoding='utf-8') as f:
            f.write(header_content)
        generated_files['header'] = str(header_file)
        
        # Generate implementation file
        impl_content = self.generate_enhanced_implementation(binary_info, binary_name)
        impl_file = output_dir / f"{binary_name}.cpp"
        with open(impl_file, 'w', encoding='utf-8') as f:
            f.write(impl_content)
        generated_files['implementation'] = str(impl_file)
        
        # Generate types header for data structures
        types_content = self.generate_types_header(binary_info, binary_name)
        types_file = output_dir / f"{binary_name}_types.h"
        with open(types_file, 'w', encoding='utf-8') as f:
            f.write(types_content)
        generated_files['types'] = str(types_file)
        
        # Generate advanced Makefile
        makefile_content = self.generate_advanced_makefile(binary_name)
        makefile_file = output_dir / "Makefile"
        with open(makefile_file, 'w', encoding='utf-8') as f:
            f.write(makefile_content)
        generated_files['makefile'] = str(makefile_file)
        
        # Generate CMakeLists.txt
        cmake_content = self.generate_advanced_cmake(binary_name)
        cmake_file = output_dir / "CMakeLists.txt"
        with open(cmake_file, 'w', encoding='utf-8') as f:
            f.write(cmake_content)
        generated_files['cmake'] = str(cmake_file)
        
        # Generate Visual Studio project file
        vcxproj_content = self.generate_vcxproj(binary_name)
        vcxproj_file = output_dir / f"{binary_name}.vcxproj"
        with open(vcxproj_file, 'w', encoding='utf-8') as f:
            f.write(vcxproj_content)
        generated_files['vcxproj'] = str(vcxproj_file)
        
        return generated_files
        
    def generate_enhanced_header(self, binary_info: Dict[str, Any], binary_name: str) -> str:
        """Generate enhanced header file with proper declarations."""
        lines = []
        
        # Header guard
        guard_name = f"{binary_name.upper()}_H_"
        lines.extend([
            f"#ifndef {guard_name}",
            f"#define {guard_name}",
            ""
        ])
        
        # Include necessary headers
        lines.extend(self.common_includes)
        lines.extend([
            "",
            f'#include "{binary_name}_types.h"',
            "",
            "#ifdef __cplusplus",
            'extern "C" {',
            "#endif",
            ""
        ])
        
        # Generate function declarations
        exports = binary_info.get('exports', {})
        functions = binary_info.get('functions', {})
        
        if exports.get('details'):
            lines.append("// Exported Functions")
            lines.append("// ==================")
            lines.append("")
            
            for export in exports['details']:
                func_name = export.get('name', 'UnknownFunction')
                if func_name.startswith('Ordinal_'):
                    continue  # Skip ordinal-only exports
                    
                # Get function analysis if available
                func_analysis = functions.get(func_name, {})
                calling_conv = func_analysis.get('calling_convention', 'stdcall')
                param_count = func_analysis.get('parameter_count', 0)
                return_type = func_analysis.get('return_type', 'int')
                
                # Generate function signature
                signature = self.generate_function_signature(
                    func_name, return_type, param_count, calling_conv
                )
                
                lines.append(f"DECLSPEC {signature};")
                
                # Add comment with analysis info
                if func_analysis:
                    complexity = func_analysis.get('complexity', 0)
                    category = func_analysis.get('category', 'unknown')
                    lines.append(f"// Category: {category}, Complexity: {complexity}")
                    
                lines.append("")
                
        # Generate structure forward declarations
        structures = binary_info.get('structures', {})
        if structures:
            lines.append("// Forward Declarations")
            lines.append("// ===================")
            lines.append("")
            
            for struct_name in structures.keys():
                lines.append(f"typedef struct _{struct_name} {struct_name}, *P{struct_name};")
                
            lines.append("")
            
        # Generate constants and defines
        lines.extend([
            "// Constants and Defines",
            "// =====================",
            "",
            "#ifndef DECLSPEC",
            "#define DECLSPEC __declspec(dllexport)",
            "#endif",
            "",
            "#ifndef CALLBACK",
            "#define CALLBACK __stdcall",
            "#endif",
            ""
        ])
        
        # Close extern C block
        lines.extend([
            "#ifdef __cplusplus",
            "}",
            "#endif",
            "",
            f"#endif // {guard_name}"
        ])
        
        return '\n'.join(lines)
        
    def generate_enhanced_implementation(self, binary_info: Dict[str, Any], binary_name: str) -> str:
        """Generate enhanced implementation file."""
        lines = []
        
        # File header
        lines.extend([
            f"// {binary_name}.cpp",
            f"// Generated C++ implementation",
            f"// Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"// Source: {binary_name}",
            "",
            f'#include "{binary_name}.h"',
            '#include "pch.h" // Optional precompiled header',
            "",
            "// Global variables and static data",
            "// ================================",
            ""
        ])
        
        # Generate global variables based on data sections
        sections = binary_info.get('sections', {})
        if sections and sections.get('details'):
            for section in sections['details']:
                if section['name'] in ['.data', '.rdata']:
                    lines.extend([
                        f"// Data from {section['name']} section",
                        f"// Size: {section['virtual_size']} bytes",
                        f"static uint8_t {section['name'].replace('.', '')}_section[{section['virtual_size']}];",
                        ""
                    ])
                    
        # Generate helper functions
        lines.extend([
            "// Helper Functions",
            "// ================",
            "",
            "static void initialize_global_data() {",
            "    // Initialize global data structures",
            "    // TODO: Add initialization code based on analysis",
            "}",
            "",
            "static void cleanup_resources() {",
            "    // Cleanup allocated resources",
            "    // TODO: Add cleanup code",
            "}",
            ""
        ])
        
        # Generate function implementations
        exports = binary_info.get('exports', {})
        functions = binary_info.get('functions', {})
        
        if exports.get('details'):
            lines.extend([
                "// Function Implementations",
                "// ========================",
                ""
            ])
            
            for export in exports['details']:
                func_name = export.get('name', 'UnknownFunction')
                if func_name.startswith('Ordinal_'):
                    continue
                    
                func_impl = self.generate_enhanced_function_implementation(
                    func_name, functions.get(func_name, {}), binary_info
                )
                lines.extend(func_impl)
                lines.append("")
                
        # Generate DLL entry point if this is a DLL
        pe_info = binary_info.get('pe_info', {})
        if 'dll' in binary_name.lower() or pe_info.get('type') == 'DLL':
            lines.extend([
                "// DLL Entry Point",
                "// ===============",
                "",
                "BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {",
                "    switch (dwReason) {",
                "        case DLL_PROCESS_ATTACH:",
                "            // Initialize when DLL is loaded",
                "            initialize_global_data();",
                "            break;",
                "",
                "        case DLL_THREAD_ATTACH:",
                "            // Initialize when new thread is created",
                "            break;",
                "",
                "        case DLL_THREAD_DETACH:",
                "            // Cleanup when thread terminates",
                "            break;",
                "",
                "        case DLL_PROCESS_DETACH:",
                "            // Cleanup when DLL is unloaded",
                "            cleanup_resources();",
                "            break;",
                "    }",
                "    return TRUE;",
                "}",
                ""
            ])
            
        return '\n'.join(lines)
        
    def generate_types_header(self, binary_info: Dict[str, Any], binary_name: str) -> str:
        """Generate types header with data structures."""
        lines = []
        
        guard_name = f"{binary_name.upper()}_TYPES_H_"
        lines.extend([
            f"#ifndef {guard_name}",
            f"#define {guard_name}",
            "",
            "#include <cstdint>",
            "",
            "#ifdef __cplusplus",
            'extern "C" {',
            "#endif",
            ""
        ])
        
        # Generate common Windows types if needed
        lines.extend([
            "// Common Windows Types",
            "// ===================",
            "",
            "#ifndef _WINDEF_",
            "typedef int BOOL;",
            "typedef unsigned char BYTE;",
            "typedef unsigned short WORD;",
            "typedef unsigned long DWORD;",
            "typedef unsigned long long QWORD;",
            "typedef void* HANDLE;",
            "typedef void* HWND;",
            "typedef void* HDC;",
            "typedef void* HINSTANCE;",
            "typedef char* LPSTR;",
            "typedef const char* LPCSTR;",
            "typedef wchar_t* LPWSTR;",
            "typedef const wchar_t* LPCWSTR;",
            "typedef void* LPVOID;",
            "#define TRUE 1",
            "#define FALSE 0",
            "#define NULL ((void*)0)",
            "#endif",
            ""
        ])
        
        # Generate inferred structures
        structures = binary_info.get('structure_candidates', {})
        if structures:
            lines.extend([
                "// Inferred Data Structures",
                "// ========================",
                ""
            ])
            
            for i, (base_reg, struct_info) in enumerate(structures.items()):
                struct_name = f"InferredStruct_{i}"
                struct_def = self.structure_analyzer.generate_structure_definition(
                    struct_name, struct_info
                )
                lines.extend(struct_def.split('\n'))
                lines.append("")
                
        # Generate function pointer types
        functions = binary_info.get('functions', {})
        if functions:
            lines.extend([
                "// Function Pointer Types",
                "// =====================",
                ""
            ])
            
            for func_name, func_info in functions.items():
                if func_name.startswith('Ordinal_'):
                    continue
                    
                param_count = func_info.get('parameter_count', 0)
                return_type = func_info.get('return_type', 'int')
                calling_conv = func_info.get('calling_convention', 'stdcall')
                
                # Generate function pointer type
                conv_attr = "__stdcall" if calling_conv == "stdcall" else "__cdecl"
                params = ", ".join([f"void* param{i}" for i in range(param_count)]) if param_count > 0 else "void"
                
                lines.extend([
                    f"typedef {return_type} ({conv_attr} *PFN_{func_name.upper()})({params});",
                    ""
                ])
                
        # Close header
        lines.extend([
            "#ifdef __cplusplus",
            "}",
            "#endif",
            "",
            f"#endif // {guard_name}"
        ])
        
        return '\n'.join(lines)
        
    def generate_function_signature(self, func_name: str, return_type: str, 
                                  param_count: int, calling_convention: str) -> str:
        """Generate a proper function signature."""
        # Map calling conventions to attributes
        conv_attrs = {
            'stdcall': '__stdcall',
            'cdecl': '__cdecl',
            'fastcall': '__fastcall',
            'thiscall': '__thiscall'
        }
        
        conv_attr = conv_attrs.get(calling_convention, '__stdcall')
        
        # Generate parameter list
        if param_count == 0:
            params = "void"
        else:
            # Generate reasonable parameter types based on common patterns
            param_list = []
            for i in range(param_count):
                if i == 0 and calling_convention == 'thiscall':
                    param_list.append("void* this_ptr")
                else:
                    param_list.append(f"void* param{i}")
            params = ", ".join(param_list)
            
        return f"{return_type} {conv_attr} {func_name}({params})"
        
    def generate_enhanced_function_implementation(self, func_name: str, func_info: Dict[str, Any],
                                                binary_info: Dict[str, Any]) -> List[str]:
        """Generate enhanced function implementation with better logic."""
        lines = []
        
        # Function header comment
        category = func_info.get('category', 'unknown')
        complexity = func_info.get('complexity', 0)
        calling_conv = func_info.get('calling_convention', 'stdcall')
        param_count = func_info.get('parameter_count', 0)
        return_type = func_info.get('return_type', 'int')
        
        lines.extend([
            f"// Function: {func_name}",
            f"// Category: {category}",
            f"// Complexity: {complexity}",
            f"// Calling Convention: {calling_conv}",
            f"// Parameters: {param_count}"
        ])
        
        # Add analysis information
        if func_info.get('has_loops'):
            lines.append("// Contains loops")
        if func_info.get('has_calls'):
            lines.append("// Makes function calls")
        if func_info.get('api_calls'):
            lines.append(f"// API calls: {', '.join(func_info['api_calls'])}")
            
        # Generate function signature
        signature = self.generate_function_signature(func_name, return_type, param_count, calling_conv)
        lines.extend([
            "",
            f"{signature} {{",
        ])
        
        # Generate function body based on category and characteristics
        body_lines = self.generate_function_body(func_name, func_info, binary_info)
        lines.extend([f"    {line}" for line in body_lines])
        
        lines.append("}")
        
        return lines
        
    def generate_function_body(self, func_name: str, func_info: Dict[str, Any],
                             binary_info: Dict[str, Any]) -> List[str]:
        """Generate function body based on analysis."""
        lines = []
        category = func_info.get('category', 'unknown')
        complexity = func_info.get('complexity', 0)
        
        # Add parameter validation for complex functions
        if complexity > 5:
            lines.extend([
                "// Parameter validation",
                "if (!param0) {",
                "    return 0; // or appropriate error code",
                "}",
                ""
            ])
            
        # Generate body based on function category
        if category == 'initialization':
            lines.extend([
                "// Initialization function",
                "static bool initialized = false;",
                "if (initialized) {",
                "    return 1; // Already initialized",
                "}",
                "",
                "// TODO: Add initialization logic here",
                "// Based on analysis, this function likely:",
                "// - Sets up global variables",
                "// - Allocates resources",
                "// - Initializes data structures",
                "",
                "initialized = true;",
                "return 1; // Success"
            ])
            
        elif category == 'cleanup':
            lines.extend([
                "// Cleanup function", 
                "// TODO: Add cleanup logic here",
                "// Based on analysis, this function likely:",
                "// - Frees allocated memory",
                "// - Closes handles",
                "// - Resets global state",
                "",
                "return 1; // Success"
            ])
            
        elif category == 'file_operations':
            lines.extend([
                "// File operation function",
                "HANDLE hFile = INVALID_HANDLE_VALUE;",
                "",
                "// TODO: Implement file operation logic",
                "// Based on analysis, this function likely:",
                "// - Opens/creates files",
                "// - Reads/writes data",
                "// - Manages file attributes",
                "",
                "if (hFile != INVALID_HANDLE_VALUE) {",
                "    CloseHandle(hFile);",
                "}",
                "",
                "return 0; // TODO: Return appropriate value"
            ])
            
        elif category == 'memory_operations':
            lines.extend([
                "// Memory operation function",
                "void* pMemory = nullptr;",
                "",
                "// TODO: Implement memory operation logic",
                "// Based on analysis, this function likely:",
                "// - Allocates/frees memory",
                "// - Copies/moves data",
                "// - Manages memory protection",
                "",
                "return reinterpret_cast<intptr_t>(pMemory);"
            ])
            
        elif category == 'network_operations':
            lines.extend([
                "// Network operation function",
                "SOCKET sock = INVALID_SOCKET;",
                "",
                "// TODO: Implement network operation logic",
                "// Based on analysis, this function likely:",
                "// - Creates/manages sockets",
                "// - Sends/receives data",
                "// - Handles network protocols",
                "",
                "if (sock != INVALID_SOCKET) {",
                "    closesocket(sock);",
                "}",
                "",
                "return 0; // TODO: Return appropriate value"
            ])
            
        else:
            # Generic implementation
            lines.extend([
                f"// Generic implementation for {category} function",
                "// TODO: Implement function logic based on reverse engineering",
                ""
            ])
            
            # Add complexity-based scaffolding
            if complexity > 10:
                lines.extend([
                    "// High complexity function - likely contains:",
                    "// - Multiple conditional branches",
                    "// - Loop constructs", 
                    "// - Complex data processing",
                    ""
                ])
                
            if func_info.get('has_loops'):
                lines.extend([
                    "// Function contains loops",
                    "for (int i = 0; i < 10; ++i) {",
                    "    // TODO: Implement loop body",
                    "}",
                    ""
                ])
                
            if func_info.get('has_calls'):
                lines.extend([
                    "// Function makes calls to other functions",
                    "// TODO: Add function calls based on analysis",
                    ""
                ])
                
            # Add return statement
            return_type = func_info.get('return_type', 'int')
            if return_type == 'void':
                lines.append("// Function returns void")
            elif return_type in ['int', 'DWORD', 'BOOL']:
                lines.append("return 0; // TODO: Return appropriate value")
            elif return_type in ['HANDLE', 'HWND', 'void*', 'LPVOID']:
                lines.append("return nullptr; // TODO: Return appropriate pointer")
            else:
                lines.append(f"return ({return_type})0; // TODO: Return appropriate value")
                
        return lines
        
    def generate_advanced_makefile(self, binary_name: str) -> str:
        """Generate advanced Makefile with optimization options."""
        return f"""# Advanced Makefile for {binary_name}
# Generated by Binary Analyzer GUI

# Compiler settings
CXX = g++
CC = gcc
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
CFLAGS = -std=c11 -Wall -Wextra -O2 -g

# Platform specific settings
ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32 -ladvapi32 -lkernel32 -luser32
    EXECUTABLE = {binary_name}.exe
    RM = del /Q
else
    LDFLAGS += -lpthread -ldl
    EXECUTABLE = {binary_name}
    RM = rm -f
endif

# Source files
SOURCES = {binary_name}.cpp
HEADERS = {binary_name}.h {binary_name}_types.h
OBJECTS = $(SOURCES:.cpp=.o)

# Default target
all: $(EXECUTABLE)

# Build executable
$(EXECUTABLE): $(OBJECTS)
\t$(CXX) $(OBJECTS) $(LDFLAGS) -o $@

# Compile source files
%.o: %.cpp $(HEADERS)
\t$(CXX) $(CXXFLAGS) -c $< -o $@

# Debug build
debug: CXXFLAGS += -DDEBUG -g3 -O0
debug: $(EXECUTABLE)

# Release build
release: CXXFLAGS += -DNDEBUG -O3 -flto
release: $(EXECUTABLE)

# Clean build files
clean:
\t$(RM) $(OBJECTS) $(EXECUTABLE)

# Install (placeholder)
install: $(EXECUTABLE)
\t@echo "TODO: Add installation commands"

# Create distribution
dist: release
\t@echo "Creating distribution package..."
\t@echo "TODO: Add packaging commands"

# Show help
help:
\t@echo "Available targets:"
\t@echo "  all      - Build the project (default)"
\t@echo "  debug    - Build with debug information"
\t@echo "  release  - Build optimized release version"
\t@echo "  clean    - Remove build files"
\t@echo "  install  - Install the binary"
\t@echo "  dist     - Create distribution package"
\t@echo "  help     - Show this help message"

.PHONY: all debug release clean install dist help
"""

    def generate_advanced_cmake(self, binary_name: str) -> str:
        """Generate advanced CMakeLists.txt."""
        return f"""# Advanced CMakeLists.txt for {binary_name}
# Generated by Binary Analyzer GUI

cmake_minimum_required(VERSION 3.15)
project({binary_name} LANGUAGES CXX C)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4 /WX-)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Platform-specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX)
    set(PLATFORM_LIBS ws2_32 advapi32 kernel32 user32)
else()
    set(PLATFORM_LIBS pthread dl)
endif()

# Source files
set(SOURCES
    {binary_name}.cpp
)

set(HEADERS
    {binary_name}.h
    {binary_name}_types.h
)

# Create executable/library
add_executable(${{PROJECT_NAME}} ${{SOURCES}})

# Link libraries
target_link_libraries(${{PROJECT_NAME}} PRIVATE ${{PLATFORM_LIBS}})

# Include directories
target_include_directories(${{PROJECT_NAME}} PRIVATE 
    ${{CMAKE_CURRENT_SOURCE_DIR}}
)

# Compiler definitions
target_compile_definitions(${{PROJECT_NAME}} PRIVATE
    $<$<CONFIG:Debug>:DEBUG _DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
)

# Set target properties
set_target_properties(${{PROJECT_NAME}} PROPERTIES
    OUTPUT_NAME {binary_name}
    DEBUG_POSTFIX "_d"
)

# Installation
install(TARGETS ${{PROJECT_NAME}}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Custom targets
add_custom_target(clean-all
    COMMAND ${{CMAKE_COMMAND}} -E remove_directory ${{CMAKE_BINARY_DIR}}
    COMMENT "Removing all build files"
)

# CPack configuration for packaging
include(CPack)
set(CPACK_PACKAGE_NAME "{binary_name}")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Reverse engineered {binary_name}")
set(CPACK_PACKAGE_VENDOR "Binary Analyzer GUI")
"""

    def generate_vcxproj(self, binary_name: str) -> str:
        """Generate Visual Studio project file."""
        return f"""<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|Win32">
      <Configuration>Debug</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|Win32">
      <Configuration>Release</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Debug|x64">
      <Configuration>Debug</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  
  <PropertyGroup Label="Globals">
    <VCProjectVersion>16.0</VCProjectVersion>
    <Keyword>Win32Proj</Keyword>
    <ProjectGuid>{{$(guid)}}</ProjectGuid>
    <RootNamespace>{binary_name}</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
  
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
  
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <LanguageStandard>stdcpp17</LanguageStandard>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
    </Link>
  </ItemDefinitionGroup>
  
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <LanguageStandard>stdcpp17</LanguageStandard>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>true</GenerateDebugInformation>
    </Link>
  </ItemDefinitionGroup>
  
  <ItemGroup>
    <ClCompile Include="{binary_name}.cpp" />
  </ItemGroup>
  
  <ItemGroup>
    <ClInclude Include="{binary_name}.h" />
    <ClInclude Include="{binary_name}_types.h" />
  </ItemGroup>
  
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>"""