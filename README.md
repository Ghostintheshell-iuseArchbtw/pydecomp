# Binary Disassembler and C/C++ Recreation Tool

A comprehensive tool for reverse engineering binary files (DLL, SYS, EXE) and generating C/C++ recreations of the original code structure.

## Features

### Core Capabilities
- **Multi-Architecture Support**: x86 and x64 Windows PE files
- **Advanced Disassembly**: Uses Capstone engine for accurate disassembly
- **Function Discovery**: Identifies both exported and internal functions
- **Pattern Recognition**: Advanced heuristics for function identification
- **Data Structure Analysis**: Reconstructs data structures from memory access patterns
- **API Analysis**: Recognizes Windows API calls and their signatures
- **String Extraction**: Finds ASCII and Unicode strings in the binary
- **Code Generation**: Produces clean, compilable C/C++ code

### Advanced Analysis
- **Function Categorization**: Automatically categorizes functions by purpose
- **Complexity Analysis**: Calculates function complexity scores
- **Control Flow Analysis**: Identifies loops, conditionals, and call patterns
- **Section Analysis**: Detailed PE section analysis with entropy calculation
- **Import/Export Analysis**: Complete analysis of imported and exported functions

## Installation

### Prerequisites
- Python 3.7 or higher
- Windows environment (for PE file analysis)

### Install Dependencies
```powershell
cd c:\Users\kelly\darpa
pip install -r requirements.txt
```

### Required Python Packages
- `capstone`: Disassembly engine
- `pefile`: PE file parser
- `pyelftools`: ELF file support (future enhancement)
- `pygments`: Syntax highlighting
- `click`: Command-line interface
- `jinja2`: Template engine

## Usage

### Basic Usage
```powershell
# Analyze a DLL file
python enhanced_disassembler.py sample.dll

# Analyze with full reporting
python enhanced_disassembler.py sample.dll --report --strings

# Generate build files
python enhanced_disassembler.py sample.dll --build-files
```

### Advanced Usage
```powershell
# Complete analysis with custom output directory
python enhanced_disassembler.py malware.exe -o analysis_results --report --strings --build-files --detailed

# Quick analysis for large files
python enhanced_disassembler.py large_driver.sys -o quick_analysis
```

### Command Line Options
- `binary_path`: Path to the binary file to analyze
- `-o, --output`: Output directory (default: "output")
- `--report`: Generate detailed analysis report
- `--strings`: Extract and analyze strings from the binary
- `--build-files`: Generate Makefile and CMakeLists.txt
- `--detailed`: Enable detailed analysis (slower but more thorough)

## Output Files

### Generated Files
1. **`[filename].h`**: Header file with function declarations and data structures
2. **`[filename].cpp`**: C++ implementation with reconstructed functions
3. **`[filename]_analysis_report.txt`**: Detailed analysis report (with --report)
4. **`[filename]_summary.json`**: JSON summary of analysis results
5. **`Makefile`**: Build file for GCC/MinGW (with --build-files)
6. **`CMakeLists.txt`**: CMake build configuration (with --build-files)

### Example Output Structure
```
output/
├── sample.h                      # Header file
├── sample.cpp                    # Implementation
├── sample_analysis_report.txt    # Detailed report
├── sample_summary.json           # Analysis summary
├── Makefile                      # Build file
└── CMakeLists.txt               # CMake config
```

## Architecture Overview

### Core Components

#### 1. Enhanced Binary Analyzer (`enhanced_disassembler.py`)
- Main analysis engine
- PE file parsing and section analysis
- Function identification and disassembly
- Import/export analysis
- String extraction

#### 2. Pattern Matcher (`pattern_analyzer.py`)
- Function prologue/epilogue detection
- API usage pattern recognition
- Function purpose classification
- Control flow analysis

#### 3. Data Structure Analyzer (`pattern_analyzer.py`)
- Memory access pattern analysis
- Structure member inference
- Type reconstruction
- Offset calculation

#### 4. Code Generator (`code_generator.py`)
- C/C++ code generation
- Function signature inference
- Type mapping and conversion
- Build file generation

### Analysis Process
1. **Binary Loading**: Parse PE file structure
2. **Section Analysis**: Analyze all PE sections
3. **Import/Export Analysis**: Extract API dependencies
4. **Function Discovery**: Find function entry points
5. **Disassembly**: Convert machine code to assembly
6. **Pattern Recognition**: Analyze instruction patterns
7. **Code Generation**: Generate C/C++ recreation

## Function Analysis

### Function Categories
The tool automatically categorizes functions into:
- **initialization**: Setup and initialization functions
- **cleanup**: Cleanup and destruction functions
- **getter**: Data retrieval functions
- **setter**: Data modification functions
- **validation**: Input validation and checking
- **file_operations**: File I/O operations
- **memory_operations**: Memory management
- **process_operations**: Process manipulation
- **registry_operations**: Windows registry access
- **network_operations**: Network communication
- **crypto_operations**: Cryptographic functions

### Complexity Scoring
Functions are scored based on:
- Instruction count
- Number of function calls
- Control flow complexity
- Loop presence
- Conditional branches

## Limitations and Considerations

### Current Limitations
1. **Windows PE Only**: Currently supports only Windows PE files
2. **x86/x64 Only**: Limited to Intel architectures
3. **Static Analysis**: No dynamic analysis capabilities
4. **Heuristic-Based**: Function identification relies on heuristics
5. **No Obfuscation Handling**: Limited support for packed/obfuscated binaries

### Security Considerations
- **Malware Analysis**: Use in isolated environments when analyzing malware
- **Code Execution**: Generated code may contain original functionality
- **Intellectual Property**: Respect copyright and licensing when reverse engineering

## Advanced Features

### Pattern Recognition
The tool includes sophisticated pattern recognition for:
- Common function prologues and epilogues
- Windows API call patterns
- String manipulation routines
- Memory allocation patterns
- Control flow structures

### Data Structure Reconstruction
Automatically reconstructs C structures from:
- Memory access patterns
- Register usage
- Offset calculations
- Type inference

### API Signature Database
Includes signatures for common Windows APIs:
- Kernel32.dll functions
- User32.dll functions
- Advapi32.dll functions
- MSVCRT functions
- Custom API recognition

## Examples

### Example 1: Simple DLL Analysis
```powershell
python enhanced_disassembler.py simple.dll --report
```

This generates:
- `simple.h` with function declarations
- `simple.cpp` with function implementations
- `simple_analysis_report.txt` with detailed analysis

### Example 2: Driver Analysis
```powershell
python enhanced_disassembler.py driver.sys -o driver_analysis --strings --build-files
```

This creates a complete analysis package with build files.

### Example 3: Malware Analysis
```powershell
python enhanced_disassembler.py suspicious.exe -o malware_analysis --detailed --report --strings
```

This performs comprehensive analysis suitable for malware research.

## Building Generated Code

### Using GCC/MinGW
```powershell
cd output
make
```

### Using Visual Studio
```powershell
cl /EHsc sample.cpp /Fe:sample.exe
```

### Using CMake
```powershell
cd output
mkdir build
cd build
cmake ..
make
```

## Troubleshooting

### Common Issues
1. **Import Errors**: Ensure all dependencies are installed
2. **PE Format Errors**: Verify the file is a valid PE binary
3. **Architecture Mismatch**: Tool supports x86/x64 only
4. **Memory Issues**: Use `--detailed` flag carefully with large files

### Performance Tips
- Avoid `--detailed` for quick analysis
- Use `--strings` only when needed
- Limit output to relevant functions for large binaries

## Contributing

This tool is designed for educational and security research purposes. When contributing:
1. Maintain compatibility with existing interfaces
2. Add comprehensive documentation
3. Include test cases for new features
4. Follow security best practices

## Legal Notice

This tool is intended for:
- Security research
- Malware analysis
- Educational purposes
- Authorized reverse engineering

Users are responsible for complying with applicable laws and regulations regarding reverse engineering and binary analysis.

## Version History

- **v1.0**: Initial release with basic disassembly
- **v2.0**: Enhanced pattern recognition and code generation
- **v2.1**: Added data structure analysis
- **v2.2**: Improved API signature database

## Future Enhancements

Planned features:
- Linux ELF support
- ARM architecture support
- Dynamic analysis integration
- Decompilation improvements
- GUI interface
- Plugin system
