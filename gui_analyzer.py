#!/usr/bin/env python3
"""
GUI Integration Module for Binary Analysis
Provides thread-safe analysis with progress reporting
"""

import os
import sys
import threading
import queue
from pathlib import Path
import json
from datetime import datetime
from typing import Callable, Optional, Dict, Any

from enhanced_disassembler import EnhancedBinaryAnalyzer


class GUIAnalyzer:
    """Enhanced analyzer with GUI integration and progress reporting."""
    
    def __init__(self, binary_path: str, output_dir: str, progress_callback: Callable = None, log_callback: Callable = None):
        self.binary_path = Path(binary_path)
        self.output_dir = Path(output_dir)
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        
        # Analysis options
        self.generate_report = True
        self.extract_strings = True
        self.generate_build_files = True
        self.detailed_analysis = False
        
        # Internal state
        self.analyzer = None
        self.cancelled = False
        
    def set_options(self, **options):
        """Set analysis options."""
        self.generate_report = options.get('report', True)
        self.extract_strings = options.get('strings', True)
        self.generate_build_files = options.get('build_files', True)
        self.detailed_analysis = options.get('detailed', False)
        
    def log(self, message: str):
        """Thread-safe logging."""
        if self.log_callback:
            self.log_callback(message)
            
    def update_progress(self, message: str, progress: float):
        """Thread-safe progress update."""
        if self.progress_callback:
            self.progress_callback(message, progress)
        self.log(message)
        
    def cancel_analysis(self):
        """Cancel the current analysis."""
        self.cancelled = True
        
    def analyze(self) -> Dict[str, Any]:
        """
        Run complete binary analysis with progress reporting.
        Returns analysis results dictionary.
        """
        results = {
            'success': False,
            'error': None,
            'generated_files': [],
            'analysis_summary': {}
        }
        
        try:
            self.update_progress("Initializing analysis...", 0)
            
            # Create output directory
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            # Initialize analyzer
            self.update_progress("Loading binary file...", 5)
            self.analyzer = EnhancedBinaryAnalyzer(str(self.binary_path))
            
            if self.cancelled:
                return results
                
            # Load binary
            self.update_progress("Parsing PE structure...", 10)
            if not self.analyzer.load_binary():
                results['error'] = "Failed to load binary file - not a valid PE file"
                return results
                
            # Basic info
            pe_info = {
                'filename': self.binary_path.name,
                'size': self.binary_path.stat().st_size,
                'architecture': 'x64' if self.analyzer.pe.OPTIONAL_HEADER.Magic == 0x20b else 'x86',
                'timestamp': datetime.fromtimestamp(self.analyzer.pe.FILE_HEADER.TimeDateStamp).isoformat()
            }
            results['analysis_summary']['pe_info'] = pe_info
            
            if self.cancelled:
                return results
                
            # Analyze sections
            self.update_progress("Analyzing PE sections...", 20)
            section_results = self.analyze_sections()
            results['analysis_summary']['sections'] = section_results
            
            if self.cancelled:
                return results
                
            # Analyze imports
            self.update_progress("Analyzing imported functions...", 30)
            import_results = self.analyze_imports()
            results['analysis_summary']['imports'] = import_results
            
            if self.cancelled:
                return results
                
            # Analyze exports
            self.update_progress("Analyzing exported functions...", 40)
            export_results = self.analyze_exports()
            results['analysis_summary']['exports'] = export_results
            
            if self.cancelled:
                return results
                
            # Extract strings if requested
            if self.extract_strings:
                self.update_progress("Extracting strings from binary...", 50)
                string_results = self.analyze_strings()
                results['analysis_summary']['strings'] = string_results
            else:
                self.update_progress("Skipping string extraction...", 50)
                
            if self.cancelled:
                return results
                
            # Identify and analyze functions
            self.update_progress("Identifying and analyzing functions...", 60)
            function_results = self.analyze_functions()
            results['analysis_summary']['functions'] = function_results
            
            if self.cancelled:
                return results
                
            # Generate header file
            self.update_progress("Generating header file...", 70)
            header_file = self.generate_header_file()
            if header_file:
                results['generated_files'].append(header_file)
                
            if self.cancelled:
                return results
                
            # Generate implementation file
            self.update_progress("Generating implementation file...", 80)
            impl_file = self.generate_implementation_file()
            if impl_file:
                results['generated_files'].append(impl_file)
                
            if self.cancelled:
                return results
                
            # Generate build files if requested
            if self.generate_build_files:
                self.update_progress("Generating build files...", 85)
                build_files = self.generate_build_files_impl()
                results['generated_files'].extend(build_files)
                
            # Generate analysis report if requested
            if self.generate_report:
                self.update_progress("Generating analysis report...", 90)
                report_file = self.generate_analysis_report(results['analysis_summary'])
                if report_file:
                    results['generated_files'].append(report_file)
                    
            # Generate JSON summary
            self.update_progress("Generating summary file...", 95)
            summary_file = self.generate_json_summary(results['analysis_summary'])
            if summary_file:
                results['generated_files'].append(summary_file)
                
            self.update_progress("Analysis completed successfully!", 100)
            results['success'] = True
            
        except Exception as e:
            results['error'] = str(e)
            self.log(f"ERROR: {str(e)}")
            
        return results
        
    def analyze_sections(self) -> Dict[str, Any]:
        """Analyze PE sections."""
        sections = []
        
        for section in self.analyzer.pe.sections:
            section_info = {
                'name': section.Name.decode('utf-8').rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': hex(section.Characteristics),
                'entropy': section.get_entropy()
            }
            sections.append(section_info)
            
        return {
            'count': len(sections),
            'details': sections
        }
        
    def analyze_imports(self) -> Dict[str, Any]:
        """Analyze imported functions."""
        imports = {}
        
        if hasattr(self.analyzer.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.analyzer.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                functions = []
                
                for imp in entry.imports:
                    func_info = {
                        'name': imp.name.decode('utf-8') if imp.name else f"Ordinal_{imp.ordinal}",
                        'address': hex(imp.address) if imp.address else None,
                        'ordinal': imp.ordinal
                    }
                    functions.append(func_info)
                    
                imports[dll_name] = functions
                
        return {
            'dll_count': len(imports),
            'function_count': sum(len(funcs) for funcs in imports.values()),
            'details': imports
        }
        
    def analyze_exports(self) -> Dict[str, Any]:
        """Analyze exported functions."""
        exports = []
        
        if hasattr(self.analyzer.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.analyzer.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'name': exp.name.decode('utf-8') if exp.name else f"Ordinal_{exp.ordinal}",
                    'address': hex(exp.address) if exp.address else None,
                    'ordinal': exp.ordinal
                }
                exports.append(export_info)
                
        return {
            'count': len(exports),
            'details': exports
        }
        
    def analyze_strings(self) -> Dict[str, Any]:
        """Extract and analyze strings."""
        self.analyzer.extract_strings()
        
        return {
            'count': len(self.analyzer.strings),
            'sample': self.analyzer.strings[:20] if self.analyzer.strings else []
        }
        
    def analyze_functions(self) -> Dict[str, Any]:
        """Identify and analyze functions."""
        self.analyzer.identify_functions()
        
        # Categorize functions
        categories = {}
        for func_addr, func_info in self.analyzer.functions.items():
            category = func_info.get('category', 'unknown')
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
            
        return {
            'count': len(self.analyzer.functions),
            'categories': categories
        }
        
    def generate_header_file(self) -> Optional[str]:
        """Generate C++ header file."""
        try:
            header_path = self.output_dir / f"{self.binary_path.stem}.h"
            
            # Use the existing code generator
            self.analyzer.code_generator.generate_header(
                self.analyzer.exports,
                self.analyzer.functions,
                str(header_path)
            )
            
            return str(header_path)
            
        except Exception as e:
            self.log(f"Error generating header file: {e}")
            return None
            
    def generate_implementation_file(self) -> Optional[str]:
        """Generate C++ implementation file."""
        try:
            impl_path = self.output_dir / f"{self.binary_path.stem}.cpp"
            
            # Use the existing code generator
            self.analyzer.code_generator.generate_implementation(
                self.analyzer.exports,
                self.analyzer.functions,
                str(impl_path),
                self.binary_path.stem
            )
            
            return str(impl_path)
            
        except Exception as e:
            self.log(f"Error generating implementation file: {e}")
            return None
            
    def generate_build_files_impl(self) -> list:
        """Generate build files (Makefile, CMakeLists.txt)."""
        build_files = []
        
        try:
            # Generate Makefile
            makefile_path = self.output_dir / "Makefile"
            self.analyzer.code_generator.generate_makefile(
                self.binary_path.stem,
                str(makefile_path)
            )
            build_files.append(str(makefile_path))
            
            # Generate CMakeLists.txt
            cmake_path = self.output_dir / "CMakeLists.txt"
            self.analyzer.code_generator.generate_cmake(
                self.binary_path.stem,
                str(cmake_path)
            )
            build_files.append(str(cmake_path))
            
        except Exception as e:
            self.log(f"Error generating build files: {e}")
            
        return build_files
        
    def generate_analysis_report(self, summary: Dict[str, Any]) -> Optional[str]:
        """Generate detailed analysis report."""
        try:
            report_path = self.output_dir / f"{self.binary_path.stem}_analysis_report.txt"
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(f"Binary Analysis Report\n")
                f.write(f"=====================\n\n")
                f.write(f"File: {self.binary_path.name}\n")
                f.write(f"Analysis Date: {datetime.now().isoformat()}\n")
                f.write(f"Output Directory: {self.output_dir}\n\n")
                
                # PE Information
                if 'pe_info' in summary:
                    pe_info = summary['pe_info']
                    f.write(f"PE File Information:\n")
                    f.write(f"  Architecture: {pe_info.get('architecture', 'Unknown')}\n")
                    f.write(f"  File Size: {pe_info.get('size', 0):,} bytes\n")
                    f.write(f"  Timestamp: {pe_info.get('timestamp', 'Unknown')}\n\n")
                    
                # Section Analysis
                if 'sections' in summary:
                    sections = summary['sections']
                    f.write(f"Section Analysis:\n")
                    f.write(f"  Total Sections: {sections.get('count', 0)}\n")
                    for section in sections.get('details', []):
                        f.write(f"    {section['name']}: {section['virtual_size']:,} bytes (entropy: {section['entropy']:.2f})\n")
                    f.write("\n")
                    
                # Import Analysis
                if 'imports' in summary:
                    imports = summary['imports']
                    f.write(f"Import Analysis:\n")
                    f.write(f"  Imported DLLs: {imports.get('dll_count', 0)}\n")
                    f.write(f"  Imported Functions: {imports.get('function_count', 0)}\n\n")
                    
                # Export Analysis
                if 'exports' in summary:
                    exports = summary['exports']
                    f.write(f"Export Analysis:\n")
                    f.write(f"  Exported Functions: {exports.get('count', 0)}\n\n")
                    
                # Function Analysis
                if 'functions' in summary:
                    functions = summary['functions']
                    f.write(f"Function Analysis:\n")
                    f.write(f"  Identified Functions: {functions.get('count', 0)}\n")
                    f.write(f"  Function Categories:\n")
                    for category, count in functions.get('categories', {}).items():
                        f.write(f"    {category}: {count}\n")
                    f.write("\n")
                    
                # String Analysis
                if 'strings' in summary:
                    strings = summary['strings']
                    f.write(f"String Analysis:\n")
                    f.write(f"  Extracted Strings: {strings.get('count', 0)}\n\n")
                    
            return str(report_path)
            
        except Exception as e:
            self.log(f"Error generating analysis report: {e}")
            return None
            
    def generate_json_summary(self, summary: Dict[str, Any]) -> Optional[str]:
        """Generate JSON summary file."""
        try:
            summary_path = self.output_dir / f"{self.binary_path.stem}_summary.json"
            
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, default=str)
                
            return str(summary_path)
            
        except Exception as e:
            self.log(f"Error generating JSON summary: {e}")
            return None


class AnalysisWorker(threading.Thread):
    """Worker thread for running analysis."""
    
    def __init__(self, binary_path: str, output_dir: str, options: Dict[str, Any], 
                 progress_callback: Callable = None, log_callback: Callable = None,
                 completion_callback: Callable = None):
        super().__init__(daemon=True)
        
        self.analyzer = GUIAnalyzer(binary_path, output_dir, progress_callback, log_callback)
        self.analyzer.set_options(**options)
        self.completion_callback = completion_callback
        self.results = None
        
    def run(self):
        """Run the analysis."""
        self.results = self.analyzer.analyze()
        
        if self.completion_callback:
            self.completion_callback(self.results)
            
    def cancel(self):
        """Cancel the analysis."""
        self.analyzer.cancel_analysis()