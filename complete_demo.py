#!/usr/bin/env python3
"""
Complete Disassembly Demonstration Script
Shows the enhanced capabilities of the complete binary disassembler.
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_disassembler import EnhancedBinaryAnalyzer, EnhancedCppGenerator


def demonstrate_complete_disassembly(binary_path: str, output_dir: str = "complete_demo"):
    """Demonstrate complete disassembly capabilities."""
    
    print("Complete Binary Disassembly Demonstration")
    print("=" * 60)
    print(f"Target Binary: {binary_path}")
    print(f"Output Directory: {output_dir}")
    print()
    
    if not os.path.exists(binary_path):
        print(f"❌ Binary file not found: {binary_path}")
        return False
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    try:
        # Initialize enhanced analyzer
        print("📊 Initializing Enhanced Binary Analyzer...")
        analyzer = EnhancedBinaryAnalyzer(binary_path)
        
        if not analyzer.load_binary():
            print("❌ Failed to load binary file")
            return False
        
        print(f"✅ Loaded {analyzer.arch} binary successfully")
        print(f"   Architecture: {analyzer.arch}")
        print(f"   Image Base: 0x{analyzer.pe.OPTIONAL_HEADER.ImageBase:x}")
        print(f"   Entry Point: 0x{analyzer.pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
        print()
        
        # Perform comprehensive analysis
        print("Performing Comprehensive Analysis...")
        
        # Analyze sections
        print("   📁 Analyzing sections...")
        analyzer.analyze_sections()
        print(f"      Found {len(analyzer.sections)} sections")
        
        # Analyze imports
        print("   📥 Analyzing imports...")
        analyzer.analyze_imports()
        total_imports = sum(len(funcs) for funcs in analyzer.imports.values())
        print(f"      Found {total_imports} imported functions from {len(analyzer.imports)} DLLs")
        
        # Analyze exports
        print("   📤 Analyzing exports...")
        analyzer.analyze_exports()
        print(f"      Found {len(analyzer.exports)} exported functions")
        
        # Extract strings
        print("   🔤 Extracting strings...")
        analyzer.extract_strings()
        print(f"      Found {len(analyzer.strings)} strings")
        
        # Perform complete function analysis
        print("   🎯 Performing complete function analysis...")
        analyzer.identify_functions()
        print(f"      Analyzed {len(analyzer.functions)} functions with complete disassembly")
        
        # Show analysis statistics
        print()
        print("📈 Analysis Statistics:")
        
        # Function categories
        by_purpose = {}
        complete_analysis_count = 0
        total_instructions = 0
        total_basic_blocks = 0
        
        for func_name, func_info in analyzer.functions.items():
            purpose = func_info['purpose']
            by_purpose[purpose] = by_purpose.get(purpose, 0) + 1
            
            if 'complete_analysis' in func_info and func_info['complete_analysis']:
                complete_analysis_count += 1
                complete_data = func_info['complete_analysis']
                total_instructions += len(complete_data.get('instructions', []))
                total_basic_blocks += len(complete_data.get('basic_blocks', []))
        
        print(f"   Functions with complete analysis: {complete_analysis_count}/{len(analyzer.functions)}")
        print(f"   Total instructions analyzed: {total_instructions}")
        print(f"   Total basic blocks identified: {total_basic_blocks}")
        print()
        
        print("   Function categories:")
        for purpose, count in sorted(by_purpose.items()):
            print(f"      {purpose}: {count} functions")
        print()
        
        # Generate enhanced code
        print("🏗️  Generating Enhanced C++ Code...")
        generator = EnhancedCppGenerator(analyzer)
        
        # Generate header file
        header_file = output_path / f"{analyzer.binary_path.stem}_complete.h"
        header_content = generator.generate_header_file()
        with open(header_file, 'w', encoding='utf-8') as f:
            f.write(header_content)
        print(f"   ✅ Generated header: {header_file}")
        
        # Generate implementation file with complete analysis
        cpp_file = output_path / f"{analyzer.binary_path.stem}_complete.cpp"
        cpp_content = generator.generate_cpp_file()
        with open(cpp_file, 'w', encoding='utf-8') as f:
            f.write(cpp_content)
        print(f"   ✅ Generated implementation: {cpp_file}")
        
        # Generate perfect C files
        print("🔧 Generating Perfect C Code...")
        perfect_header_content, perfect_impl_content = analyzer.complete_code_generator.generate_perfect_c_files(
            analyzer.binary_path.name, analyzer.functions, analyzer.exports, analyzer.imports, analyzer.arch
        )
        
        # Write perfect C header
        perfect_header_file = output_path / f"{analyzer.binary_path.stem}_perfect.h"
        with open(perfect_header_file, 'w', encoding='utf-8') as f:
            f.write(perfect_header_content)
        print(f"   ✅ Generated perfect C header: {perfect_header_file}")
        
        # Write perfect C implementation
        perfect_c_file = output_path / f"{analyzer.binary_path.stem}_perfect.c"
        with open(perfect_c_file, 'w', encoding='utf-8') as f:
            f.write(perfect_impl_content)
        print(f"   ✅ Generated perfect C implementation: {perfect_c_file}")
        
        # Generate detailed analysis report
        report_file = output_path / f"{analyzer.binary_path.stem}_complete_analysis.txt"
        report_content = generate_complete_analysis_report(analyzer)
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        print(f"   ✅ Generated complete analysis report: {report_file}")
        
        # Generate function analysis JSON
        json_file = output_path / f"{analyzer.binary_path.stem}_function_analysis.json"
        function_data = extract_function_analysis_data(analyzer)
        import json
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(function_data, f, indent=2, default=str)
        print(f"   ✅ Generated function analysis JSON: {json_file}")
        
        # Show sample of generated code
        print()
        print("📝 Sample Generated Code:")
        print("-" * 40)
        
        # Find a function with complete analysis to show
        sample_function = None
        for func_name, func_info in analyzer.functions.items():
            if ('complete_analysis' in func_info and 
                func_info['complete_analysis'] and
                len(func_info['complete_analysis'].get('instructions', [])) > 5):
                sample_function = (func_name, func_info)
                break
        
        if sample_function:
            func_name, func_info = sample_function
            try:
                sample_code = analyzer.complete_code_generator.generate_complete_function(
                    func_name, func_info['complete_analysis']
                )
                # Show first 20 lines
                lines = sample_code.split('\n')[:20]
                for line in lines:
                    print(line)
                if len(sample_code.split('\n')) > 20:
                    print("... (truncated)")
            except Exception as e:
                print(f"Error generating sample code: {e}")
        else:
            print("No suitable function found for sample code generation")
        
        print()
        print("🎉 Complete Disassembly Demonstration Finished!")
        print(f"   Check the '{output_dir}' directory for all generated files")
        print()
        
        return True
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return False


def generate_complete_analysis_report(analyzer) -> str:
    """Generate a comprehensive analysis report."""
    lines = [
        "COMPLETE BINARY ANALYSIS REPORT",
        "=" * 80,
        f"File: {analyzer.binary_path}",
        f"Architecture: {analyzer.arch}",
        f"Analysis Date: June 24, 2025",
        "",
        "OVERVIEW:",
        f"  Total Functions: {len(analyzer.functions)}",
        f"  Exported Functions: {sum(1 for f in analyzer.functions.values() if f['type'] == 'exported')}",
        f"  Discovered Functions: {sum(1 for f in analyzer.functions.values() if f['type'] == 'discovered')}",
        "",
    ]
    
    # Complete analysis statistics
    complete_count = 0
    total_instructions = 0
    total_blocks = 0
    total_api_calls = 0
    
    for func_name, func_info in analyzer.functions.items():
        if 'complete_analysis' in func_info and func_info['complete_analysis']:
            complete_count += 1
            complete_data = func_info['complete_analysis']
            total_instructions += len(complete_data.get('instructions', []))
            total_blocks += len(complete_data.get('basic_blocks', []))
            total_api_calls += len(complete_data.get('api_calls', []))
    
    lines.extend([
        "COMPLETE ANALYSIS STATISTICS:",
        f"  Functions with complete analysis: {complete_count}",
        f"  Total instructions analyzed: {total_instructions}",
        f"  Total basic blocks: {total_blocks}",
        f"  Total API calls identified: {total_api_calls}",
        "",
        "DETAILED FUNCTION ANALYSIS:",
        f"{'Function Name':<40} {'Type':<12} {'Instructions':<12} {'Blocks':<8} {'Purpose':<15}",
        "-" * 90,
    ])
    
    # Sort functions by complexity
    sorted_functions = sorted(
        analyzer.functions.items(),
        key=lambda x: len(x[1].get('instructions', [])),
        reverse=True
    )
    
    for func_name, func_info in sorted_functions[:50]:  # Show top 50
        func_type = func_info['type']
        insn_count = len(func_info.get('instructions', []))
        
        block_count = 0
        if 'complete_analysis' in func_info and func_info['complete_analysis']:
            block_count = len(func_info['complete_analysis'].get('basic_blocks', []))
        
        purpose = func_info.get('purpose', 'unknown')[:14]
        
        lines.append(f"{func_name[:39]:<40} {func_type:<12} {insn_count:<12} {block_count:<8} {purpose:<15}")
    
    return "\n".join(lines)


def extract_function_analysis_data(analyzer) -> dict:
    """Extract function analysis data for JSON export."""
    data = {
        'binary_info': {
            'path': str(analyzer.binary_path),
            'architecture': analyzer.arch,
            'image_base': analyzer.pe.OPTIONAL_HEADER.ImageBase,
            'entry_point': analyzer.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        },
        'analysis_summary': {
            'total_functions': len(analyzer.functions),
            'exported_functions': sum(1 for f in analyzer.functions.values() if f['type'] == 'exported'),
            'discovered_functions': sum(1 for f in analyzer.functions.values() if f['type'] == 'discovered'),
            'sections': len(analyzer.sections),
            'imports': sum(len(funcs) for funcs in analyzer.imports.values()),
            'exports': len(analyzer.exports),
            'strings': len(analyzer.strings),
        },
        'functions': {}
    }
    
    for func_name, func_info in analyzer.functions.items():
        func_data = {
            'address': func_info['address'],
            'type': func_info['type'],
            'purpose': func_info['purpose'],
            'instruction_count': len(func_info.get('instructions', [])),
            'complexity_score': func_info.get('characteristics', {}).get('complexity_score', 0),
        }
        
        if 'complete_analysis' in func_info and func_info['complete_analysis']:
            complete_data = func_info['complete_analysis']
            func_data['complete_analysis'] = {
                'basic_blocks': len(complete_data.get('basic_blocks', [])),
                'api_calls': len(complete_data.get('api_calls', [])),
                'control_flow': {
                    'calls': len(complete_data.get('control_flow', {}).get('calls', [])),
                    'jumps': len(complete_data.get('control_flow', {}).get('jumps', [])),
                    'returns': len(complete_data.get('control_flow', {}).get('returns', [])),
                },
                'local_variables': len(complete_data.get('local_variables', {})),
                'stack_frame_size': complete_data.get('stack_frame_size', 0),
                'register_usage': list(complete_data.get('register_usage', [])),
            }
        
        data['functions'][func_name] = func_data
    
    return data


def main():
    """Main demonstration function."""
    if len(sys.argv) < 2:
        print("Usage: python complete_demo.py <binary_path> [output_directory]")
        print("\nExamples:")
        print("  python complete_demo.py C:\\Windows\\System32\\notepad.exe")
        print("  python complete_demo.py sample.dll complete_analysis")
        return 1
    
    binary_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "complete_demo"
    
    success = demonstrate_complete_disassembly(binary_path, output_dir)
    
    if success:
        print("✅ Demonstration completed successfully!")
        return 0
    else:
        print("❌ Demonstration failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
