#!/usr/bin/env python3
"""
Demo script for the Binary Analyzer GUI
Creates a simple test binary for demonstration
"""

import os
import sys
from pathlib import Path

# Create a simple test C file that we can compile to demonstrate the GUI
test_c_code = """
#include <stdio.h>
#include <windows.h>

// Simple test functions for demonstration
int test_function_1(int param1, char* param2) {
    if (param1 > 0 && param2) {
        printf("Test function 1 called with: %d, %s\\n", param1, param2);
        return param1 * 2;
    }
    return 0;
}

void test_function_2() {
    printf("Test function 2 called\\n");
    
    // Simple loop for complexity
    for (int i = 0; i < 5; i++) {
        printf("Loop iteration: %d\\n", i);
    }
}

BOOL WINAPI test_function_3(HWND hwnd, LPARAM lparam) {
    MessageBox(hwnd, L"Hello from test function 3!", L"Demo", MB_OK);
    return TRUE;
}

// Main function
int main() {
    printf("Demo binary for Binary Analyzer GUI\\n");
    
    test_function_1(42, "Hello World");
    test_function_2();
    
    return 0;
}
"""

def create_test_binary():
    """Create a test binary for GUI demonstration."""
    current_dir = Path(__file__).parent
    test_dir = current_dir / "test_binaries"
    test_dir.mkdir(exist_ok=True)
    
    # Write test C file
    test_c_file = test_dir / "demo_test.c"
    with open(test_c_file, 'w') as f:
        f.write(test_c_code)
    
    print(f"Created test C file: {test_c_file}")
    print("To create a test binary for the GUI demo:")
    print(f"1. Install a C compiler (GCC, MinGW, or Visual Studio)")
    print(f"2. Compile the test file:")
    print(f"   gcc -o {test_dir}/demo_test.exe {test_c_file} -luser32")
    print(f"   or")
    print(f"   cl /Fe:{test_dir}/demo_test.exe {test_c_file} user32.lib")
    print(f"3. Use the compiled binary with the GUI")
    
    return test_c_file

def launch_gui():
    """Launch the GUI application."""
    try:
        # Import and run the GUI
        from gui_main import main
        print("Launching Binary Analyzer GUI...")
        main()
    except ImportError as e:
        print(f"Error importing GUI: {e}")
        print("Make sure all dependencies are installed:")
        print("pip install -r requirements.txt")
    except Exception as e:
        print(f"Error launching GUI: {e}")

def show_usage():
    """Show usage information."""
    print("Binary Analyzer GUI - Demo Script")
    print("=================================")
    print()
    print("This script provides utilities for demonstrating the GUI:")
    print()
    print("Commands:")
    print("  --create-test    Create a test binary for demonstration")
    print("  --launch-gui     Launch the GUI application") 
    print("  --help          Show this help message")
    print()
    print("Quick Start:")
    print("1. python demo_gui.py --create-test")
    print("2. Compile the generated test C file")
    print("3. python demo_gui.py --launch-gui")
    print("4. Load the compiled binary in the GUI")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_usage()
        sys.exit(0)
        
    command = sys.argv[1]
    
    if command == "--create-test":
        create_test_binary()
    elif command == "--launch-gui":
        launch_gui()
    elif command == "--help":
        show_usage()
    else:
        print(f"Unknown command: {command}")
        show_usage()
        sys.exit(1)