#!/usr/bin/env python3
"""
Automated Build System Integration
Detects compilers, validates generated code, and provides automated building
"""

import os
import sys
import subprocess
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import json
import platform


class CompilerDetector:
    """Detect available compilers on the system."""
    
    def __init__(self):
        self.detected_compilers = {}
        self.detect_all_compilers()
        
    def detect_all_compilers(self):
        """Detect all available compilers."""
        self.detected_compilers = {
            'gcc': self.detect_gcc(),
            'clang': self.detect_clang(),
            'msvc': self.detect_msvc(),
            'mingw': self.detect_mingw()
        }
        
    def detect_gcc(self) -> Optional[Dict[str, str]]:
        """Detect GCC compiler."""
        try:
            result = subprocess.run(['gcc', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                return {
                    'name': 'GCC',
                    'path': shutil.which('gcc'),
                    'version': version_line,
                    'cxx_path': shutil.which('g++'),
                    'supported_standards': ['c89', 'c99', 'c11', 'c17', 'c++98', 'c++11', 'c++14', 'c++17', 'c++20']
                }
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return None
        
    def detect_clang(self) -> Optional[Dict[str, str]]:
        """Detect Clang compiler."""
        try:
            result = subprocess.run(['clang', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                return {
                    'name': 'Clang',
                    'path': shutil.which('clang'),
                    'version': version_line,
                    'cxx_path': shutil.which('clang++'),
                    'supported_standards': ['c89', 'c99', 'c11', 'c17', 'c++98', 'c++11', 'c++14', 'c++17', 'c++20']
                }
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return None
        
    def detect_msvc(self) -> Optional[Dict[str, str]]:
        """Detect Microsoft Visual C++ compiler."""
        if platform.system() != 'Windows':
            return None
            
        # Try to find Visual Studio installations
        vs_paths = [
            r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
            r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
            r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC"
        ]
        
        for vs_path in vs_paths:
            if os.path.exists(vs_path):
                # Find the latest MSVC version
                versions = [d for d in os.listdir(vs_path) if os.path.isdir(os.path.join(vs_path, d))]
                if versions:
                    latest_version = sorted(versions)[-1]
                    cl_path = os.path.join(vs_path, latest_version, "bin", "Hostx64", "x64", "cl.exe")
                    if os.path.exists(cl_path):
                        return {
                            'name': 'MSVC',
                            'path': cl_path,
                            'version': f"MSVC {latest_version}",
                            'cxx_path': cl_path,
                            'supported_standards': ['c89', 'c99', 'c11', 'c++98', 'c++11', 'c++14', 'c++17', 'c++20']
                        }
                        
        # Try to detect cl.exe in PATH
        cl_path = shutil.which('cl')
        if cl_path:
            try:
                result = subprocess.run([cl_path], capture_output=True, text=True, timeout=10)
                # cl.exe returns version info to stderr
                if "Microsoft" in result.stderr:
                    return {
                        'name': 'MSVC',
                        'path': cl_path,
                        'version': "MSVC (PATH)",
                        'cxx_path': cl_path,
                        'supported_standards': ['c89', 'c99', 'c11', 'c++98', 'c++11', 'c++14', 'c++17', 'c++20']
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                pass
                
        return None
        
    def detect_mingw(self) -> Optional[Dict[str, str]]:
        """Detect MinGW compiler."""
        mingw_gcc = shutil.which('mingw32-gcc') or shutil.which('x86_64-w64-mingw32-gcc')
        if mingw_gcc:
            try:
                result = subprocess.run([mingw_gcc, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_line = result.stdout.split('\n')[0]
                    mingw_gxx = mingw_gcc.replace('-gcc', '-g++')
                    return {
                        'name': 'MinGW',
                        'path': mingw_gcc,
                        'version': version_line,
                        'cxx_path': mingw_gxx if shutil.which(mingw_gxx) else None,
                        'supported_standards': ['c89', 'c99', 'c11', 'c17', 'c++98', 'c++11', 'c++14', 'c++17', 'c++20']
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                pass
        return None
        
    def get_available_compilers(self) -> Dict[str, Dict[str, str]]:
        """Get all available compilers."""
        return {k: v for k, v in self.detected_compilers.items() if v is not None}
        
    def get_recommended_compiler(self) -> Optional[str]:
        """Get the recommended compiler for the current platform."""
        available = self.get_available_compilers()
        
        if platform.system() == 'Windows':
            # Prefer MSVC on Windows, then MinGW, then GCC/Clang
            priority = ['msvc', 'mingw', 'gcc', 'clang']
        else:
            # Prefer GCC on Unix-like systems, then Clang
            priority = ['gcc', 'clang', 'mingw', 'msvc']
            
        for compiler in priority:
            if compiler in available:
                return compiler
                
        return None


class CodeValidator:
    """Validate generated C/C++ code for syntax and compilation errors."""
    
    def __init__(self, compiler_detector: CompilerDetector):
        self.compiler_detector = compiler_detector
        
    def validate_syntax(self, source_file: Path, compiler: str = None) -> Dict[str, Any]:
        """Validate C/C++ syntax without linking."""
        if compiler is None:
            compiler = self.compiler_detector.get_recommended_compiler()
            
        if not compiler:
            return {'success': False, 'error': 'No suitable compiler found'}
            
        compiler_info = self.compiler_detector.detected_compilers[compiler]
        if not compiler_info:
            return {'success': False, 'error': f'Compiler {compiler} not available'}
            
        return self._run_syntax_check(source_file, compiler_info)
        
    def _run_syntax_check(self, source_file: Path, compiler_info: Dict[str, str]) -> Dict[str, Any]:
        """Run syntax check with the specified compiler."""
        compiler_path = compiler_info['cxx_path'] if source_file.suffix in ['.cpp', '.cc', '.cxx'] else compiler_info['path']
        
        if not compiler_path:
            return {'success': False, 'error': 'Compiler path not found'}
            
        # Prepare compiler command for syntax check only
        cmd = self._build_syntax_check_command(compiler_path, source_file, compiler_info['name'])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=source_file.parent)
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(cmd),
                'warnings': self._extract_warnings(result.stderr, compiler_info['name']),
                'errors': self._extract_errors(result.stderr, compiler_info['name'])
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Compilation timeout'}
        except Exception as e:
            return {'success': False, 'error': f'Compilation error: {str(e)}'}
            
    def _build_syntax_check_command(self, compiler_path: str, source_file: Path, compiler_name: str) -> List[str]:
        """Build compiler command for syntax checking."""
        cmd = [compiler_path]
        
        if compiler_name == 'MSVC':
            cmd.extend([
                '/nologo',          # Suppress copyright message
                '/c',               # Compile only, don't link
                '/Zs',              # Syntax check only
                '/W3',              # Warning level 3
                '/EHsc',            # Exception handling
                str(source_file)
            ])
        else:  # GCC, Clang, MinGW
            cmd.extend([
                '-fsyntax-only',    # Syntax check only
                '-Wall',            # Enable warnings
                '-Wextra',          # Extra warnings
                '-std=c++17',       # Use C++17 standard
                str(source_file)
            ])
            
        return cmd
        
    def _extract_warnings(self, stderr: str, compiler_name: str) -> List[str]:
        """Extract warning messages from compiler output."""
        warnings = []
        lines = stderr.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if compiler_name == 'MSVC':
                if ': warning' in line:
                    warnings.append(line)
            else:  # GCC, Clang, MinGW
                if ': warning:' in line:
                    warnings.append(line)
                    
        return warnings
        
    def _extract_errors(self, stderr: str, compiler_name: str) -> List[str]:
        """Extract error messages from compiler output."""
        errors = []
        lines = stderr.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if compiler_name == 'MSVC':
                if ': error' in line:
                    errors.append(line)
            else:  # GCC, Clang, MinGW
                if ': error:' in line or ': fatal error:' in line:
                    errors.append(line)
                    
        return errors
        
    def validate_project(self, project_dir: Path) -> Dict[str, Any]:
        """Validate an entire project directory."""
        results = {
            'project_valid': True,
            'files_validated': 0,
            'files_with_errors': 0,
            'files_with_warnings': 0,
            'file_results': {},
            'summary': {
                'total_errors': 0,
                'total_warnings': 0,
                'compiler_used': self.compiler_detector.get_recommended_compiler()
            }
        }
        
        # Find all C/C++ source files
        source_files = []
        for pattern in ['*.c', '*.cpp', '*.cc', '*.cxx', '*.C']:
            source_files.extend(project_dir.glob(pattern))
            
        if not source_files:
            results['project_valid'] = False
            results['error'] = 'No C/C++ source files found'
            return results
            
        # Validate each source file
        for source_file in source_files:
            file_result = self.validate_syntax(source_file)
            results['file_results'][str(source_file.name)] = file_result
            results['files_validated'] += 1
            
            if not file_result['success']:
                results['files_with_errors'] += 1
                results['project_valid'] = False
                
            if file_result.get('warnings'):
                results['files_with_warnings'] += 1
                
            results['summary']['total_errors'] += len(file_result.get('errors', []))
            results['summary']['total_warnings'] += len(file_result.get('warnings', []))
            
        return results


class AutomatedBuilder:
    """Automated build system for generated projects."""
    
    def __init__(self, compiler_detector: CompilerDetector):
        self.compiler_detector = compiler_detector
        self.validator = CodeValidator(compiler_detector)
        
    def build_project(self, project_dir: Path, build_system: str = 'auto') -> Dict[str, Any]:
        """Build a project using the specified build system."""
        if build_system == 'auto':
            build_system = self._detect_build_system(project_dir)
            
        if build_system == 'cmake':
            return self._build_cmake_project(project_dir)
        elif build_system == 'make':
            return self._build_make_project(project_dir)
        elif build_system == 'msvc':
            return self._build_msvc_project(project_dir)
        else:
            return self._build_simple_project(project_dir)
            
    def _detect_build_system(self, project_dir: Path) -> str:
        """Detect the appropriate build system for the project."""
        if (project_dir / 'CMakeLists.txt').exists():
            return 'cmake'
        elif (project_dir / 'Makefile').exists():
            return 'make'
        elif any(project_dir.glob('*.vcxproj')):
            return 'msvc'
        else:
            return 'simple'
            
    def _build_cmake_project(self, project_dir: Path) -> Dict[str, Any]:
        """Build project using CMake."""
        build_dir = project_dir / 'build'
        build_dir.mkdir(exist_ok=True)
        
        try:
            # Configure
            configure_result = subprocess.run(
                ['cmake', '..'],
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if configure_result.returncode != 0:
                return {
                    'success': False,
                    'error': 'CMake configuration failed',
                    'stderr': configure_result.stderr,
                    'stdout': configure_result.stdout
                }
                
            # Build
            build_result = subprocess.run(
                ['cmake', '--build', '.'],
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'success': build_result.returncode == 0,
                'returncode': build_result.returncode,
                'stdout': build_result.stdout,
                'stderr': build_result.stderr,
                'build_system': 'cmake',
                'output_dir': str(build_dir)
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Build timeout'}
        except FileNotFoundError:
            return {'success': False, 'error': 'CMake not found'}
        except Exception as e:
            return {'success': False, 'error': f'Build error: {str(e)}'}
            
    def _build_make_project(self, project_dir: Path) -> Dict[str, Any]:
        """Build project using Make."""
        try:
            # Use make or nmake depending on platform
            make_cmd = 'nmake' if platform.system() == 'Windows' and shutil.which('nmake') else 'make'
            
            result = subprocess.run(
                [make_cmd],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'build_system': 'make',
                'output_dir': str(project_dir)
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Build timeout'}
        except FileNotFoundError:
            return {'success': False, 'error': f'{make_cmd} not found'}
        except Exception as e:
            return {'success': False, 'error': f'Build error: {str(e)}'}
            
    def _build_msvc_project(self, project_dir: Path) -> Dict[str, Any]:
        """Build project using MSBuild."""
        vcxproj_files = list(project_dir.glob('*.vcxproj'))
        if not vcxproj_files:
            return {'success': False, 'error': 'No .vcxproj file found'}
            
        try:
            result = subprocess.run(
                ['msbuild', str(vcxproj_files[0]), '/p:Configuration=Release'],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'build_system': 'msvc',
                'output_dir': str(project_dir)
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Build timeout'}
        except FileNotFoundError:
            return {'success': False, 'error': 'MSBuild not found'}
        except Exception as e:
            return {'success': False, 'error': f'Build error: {str(e)}'}
            
    def _build_simple_project(self, project_dir: Path) -> Dict[str, Any]:
        """Build project using direct compiler invocation."""
        compiler = self.compiler_detector.get_recommended_compiler()
        if not compiler:
            return {'success': False, 'error': 'No suitable compiler found'}
            
        compiler_info = self.compiler_detector.detected_compilers[compiler]
        
        # Find source files
        source_files = []
        for pattern in ['*.cpp', '*.c', '*.cc', '*.cxx']:
            source_files.extend(project_dir.glob(pattern))
            
        if not source_files:
            return {'success': False, 'error': 'No source files found'}
            
        # Build command
        compiler_path = compiler_info['cxx_path'] if any(f.suffix in ['.cpp', '.cc', '.cxx'] for f in source_files) else compiler_info['path']
        
        cmd = [compiler_path]
        cmd.extend([str(f) for f in source_files])
        
        # Add output file
        output_name = project_dir.name
        if platform.system() == 'Windows':
            output_name += '.exe'
        cmd.extend(['-o', output_name])
        
        # Add libraries for Windows
        if platform.system() == 'Windows':
            cmd.extend(['-luser32', '-lkernel32', '-ladvapi32', '-lws2_32'])
            
        try:
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'build_system': 'simple',
                'output_dir': str(project_dir),
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Build timeout'}
        except Exception as e:
            return {'success': False, 'error': f'Build error: {str(e)}'}
            
    def test_build(self, project_dir: Path) -> Dict[str, Any]:
        """Test build a project and return detailed results."""
        results = {
            'validation': self.validator.validate_project(project_dir),
            'build': self.build_project(project_dir),
            'compiler_info': self.compiler_detector.get_available_compilers(),
            'recommended_compiler': self.compiler_detector.get_recommended_compiler()
        }
        
        return results