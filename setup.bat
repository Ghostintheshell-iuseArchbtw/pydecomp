@echo off
REM Binary Disassembler Tool - Setup and Usage Script
REM This script helps set up and run the binary disassembler tool

echo Binary Disassembler and C/C++ Recreation Tool
echo ============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://python.org
    pause
    exit /b 1
)

echo Python found: 
python --version

REM Check if pip is available
pip --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: pip is not available
    echo Please ensure pip is installed with Python
    pause
    exit /b 1
)

echo.
echo Installing required packages...
pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    echo Please check your internet connection and try again
    pause
    exit /b 1
)

echo.
echo ✓ Dependencies installed successfully!
echo.

REM Show usage examples
echo Usage Examples:
echo ===============
echo.
echo Basic analysis:
echo   python enhanced_disassembler.py sample.dll
echo.
echo Full analysis with report:
echo   python enhanced_disassembler.py sample.dll --report --strings
echo.
echo Complete analysis with build files:
echo   python enhanced_disassembler.py sample.exe -o analysis --report --strings --build-files
echo.
echo Testing the tool:
echo   python test_tool.py
echo.

REM Ask if user wants to run a test
set /p choice="Would you like to run the test script? (y/n): "
if /i "%choice%"=="y" (
    echo.
    echo Running test script...
    python test_tool.py
)

echo.
echo Setup complete! The tool is ready to use.
echo Check README.md for detailed documentation.
pause
