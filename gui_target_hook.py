#!/usr/bin/env python3
"""
Target Hook Module for GUI
Provides functions to set and get the codegen target for the GUI application.
"""

# Global variable to store the current codegen target
_current_target = "windows"


def set_codegen_target(target: str) -> None:
    """
    Set the codegen target for the application.
    
    Args:
        target (str): The target platform, either "windows" or "portable"
    """
    global _current_target
    if target in ["windows", "portable"]:
        _current_target = target
    else:
        raise ValueError(f"Invalid target '{target}'. Must be 'windows' or 'portable'.")


def get_codegen_target() -> str:
    """
    Get the current codegen target for the application.
    
    Returns:
        str: The current target platform, either "windows" or "portable"
    """
    global _current_target
    return _current_target