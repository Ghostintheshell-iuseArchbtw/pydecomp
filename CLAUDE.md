# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a binary reverse engineering toolkit that analyzes Windows PE files (DLL, SYS, EXE) and generates C/C++ recreations of the original code. The tool is designed for security research, malware analysis, and educational purposes.

## Development Commands

### Setup
```bash
pip install -r requirements.txt
```

### GUI Application
```bash
# Launch the GUI application
python run_gui.py
# or
python gui_main.py

# Create test binary for demonstration
python demo_gui.py --create-test
python demo_gui.py --launch-gui
```

### Command Line Usage
```bash
# Analyze a binary file (CLI mode)
python enhanced_disassembler.py target.dll

# Complete analysis with all features
python enhanced_disassembler.py target.dll --report --strings --build-files

# Custom output directory
python enhanced_disassembler.py target.dll -o analysis_output --report --strings
```

### Testing
Test with the GUI using the demo script:
```bash
python demo_gui.py --create-test  # Creates test_binaries/demo_test.c
# Compile the test C file with GCC or Visual Studio
python demo_gui.py --launch-gui   # Launch GUI and analyze the binary
```

Run the comprehensive test suite:
```bash
python test_suite.py              # Run all unit and integration tests
```

## Architecture

### Core Components

#### Command Line Interface
- **enhanced_disassembler.py**: Main CLI analysis engine with PE parsing and function identification
- **pattern_analyzer.py**: Basic pattern recognition for function classification
- **code_generator.py**: Basic C/C++ code generation utilities

#### GUI Application
- **gui_main.py**: Main GUI application with tkinter interface
- **gui_analyzer.py**: Thread-safe analysis worker with progress reporting
- **code_editor.py**: Enhanced code editor with syntax highlighting and find/replace
- **run_gui.py**: GUI launcher script

#### Enhanced Analysis Engine
- **enhanced_pattern_analyzer.py**: Advanced pattern matching and function reconstruction
- **enhanced_code_generator.py**: Improved code generation with better type inference
- **control_flow_analyzer.py**: Advanced control flow analysis and decompilation
- **complete_disassembler.py**: Advanced disassembly engine with comprehensive analysis
- **perfect_c_generator.py**: Enhanced C code generation for complex binary analysis

#### Build and Validation System
- **build_system.py**: Automated compiler detection, code validation, and build integration
- **settings_manager.py**: Comprehensive settings and preferences management
- **project_manager.py**: Project organization and workspace management
- **test_suite.py**: Comprehensive test suite for all components

### Analysis Flow

1. **Binary Loading**: Parse PE file structure using pefile library
2. **Section Analysis**: Analyze PE sections (.text, .data, .rdata, etc.)
3. **Import/Export Analysis**: Extract API dependencies and exported functions
4. **Function Discovery**: Identify function entry points using heuristics
5. **Disassembly**: Convert machine code to assembly using Capstone engine
6. **Pattern Recognition**: Analyze instruction patterns and categorize functions
7. **Code Generation**: Generate C/C++ recreations with proper structure

### Dependencies

- **capstone**: Disassembly engine for x86/x64 architectures
- **pefile**: PE file format parser
- **pyelftools**: ELF format support (future enhancement)
- **pygments**: Syntax highlighting for generated code
- **click**: Command-line interface framework
- **jinja2**: Template engine for code generation

## Generated Output

### CLI Mode Output
- **[filename].h**: Header file with function declarations and data structures
- **[filename].cpp**: Implementation with reconstructed functions and assembly comments
- **[filename]_analysis_report.txt**: Detailed analysis report
- **[filename]_summary.json**: Machine-readable analysis summary
- **Makefile**: Build configuration for GCC/MinGW
- **CMakeLists.txt**: CMake build configuration

### GUI Mode Output (Enhanced)
- **[filename].h**: Enhanced header with better type inference
- **[filename].cpp**: Improved implementation with function categorization
- **[filename]_types.h**: Separate types header with data structures
- **[filename]_analysis_report.txt**: Comprehensive analysis report
- **[filename]_summary.json**: Detailed JSON summary
- **Makefile**: Advanced Makefile with optimization options
- **CMakeLists.txt**: Full-featured CMake configuration
- **[filename].vcxproj**: Visual Studio project file

## Function Analysis

The pattern analyzer categorizes functions into:
- initialization, cleanup, getter, setter, validation
- file_operations, memory_operations, process_operations
- registry_operations, network_operations, crypto_operations

## GUI Features

### Core Interface
- **Modern GUI**: Professional dark/light theme interface with tkinter
- **File Management**: Drag-and-drop support for .exe/.dll/.sys files
- **Real-time Progress**: Live progress tracking with cancellation support
- **Analysis Options**: Configurable analysis depth, string extraction, build file generation

### Advanced Features
- **Project Management**: Complete workspace organization with project browser
- **Code Editor**: Syntax-highlighted C++ editor with line numbers and find/replace
- **Build Integration**: Automated compiler detection and code validation
- **Settings System**: Comprehensive preferences with theme customization
- **Export Options**: Generate Visual Studio, CMake, and Makefile projects

### Analysis Capabilities
- **Control Flow Analysis**: Advanced decompilation with loop and condition detection
- **Pattern Recognition**: 100+ Windows API signatures and function categorization
- **Data Structure Inference**: Automatic C struct generation from memory patterns
- **Code Validation**: Real-time syntax checking and compilation testing

## Security Considerations

This is a defensive security tool for binary analysis. When working with this codebase:
- Use isolated environments when analyzing potentially malicious binaries
- The generated code may contain original functionality - review before execution
- Respect intellectual property and licensing when reverse engineering
- The GUI provides safer analysis with sandboxed execution and progress monitoring