#!/usr/bin/env python3
"""
Settings and Preferences Management System
Handles user preferences, application settings, and configuration persistence
"""

import os
import json
import tkinter as tk
from tkinter import ttk, filedialog, colorchooser, messagebox
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict
import platform


@dataclass
class ThemeSettings:
    """Theme and appearance settings."""
    theme_name: str = "dark"
    background_color: str = "#2b2b2b"
    foreground_color: str = "#ffffff"
    editor_background: str = "#1e1e1e"
    editor_foreground: str = "#d4d4d4"
    highlight_color: str = "#264f78"
    keyword_color: str = "#569cd6"
    comment_color: str = "#6a9955"
    string_color: str = "#ce9178"
    number_color: str = "#b5cea8"
    function_color: str = "#dcdcaa"
    type_color: str = "#4ec9b0"


@dataclass
class EditorSettings:
    """Code editor settings."""
    font_family: str = "Consolas" if platform.system() == "Windows" else "Monaco"
    font_size: int = 10
    tab_size: int = 4
    show_line_numbers: bool = True
    word_wrap: bool = False
    auto_indent: bool = True
    syntax_highlighting: bool = True
    bracket_matching: bool = True


@dataclass
class AnalysisSettings:
    """Analysis configuration settings."""
    default_output_dir: str = "analysis_output"
    generate_report: bool = True
    extract_strings: bool = True
    generate_build_files: bool = True
    detailed_analysis: bool = False
    max_function_size: int = 10000
    timeout_seconds: int = 300
    parallel_analysis: bool = True
    thread_count: int = 4


@dataclass
class UISettings:
    """User interface settings."""
    window_width: int = 1200
    window_height: int = 800
    window_maximized: bool = False
    show_toolbar: bool = True
    show_status_bar: bool = True
    auto_save_projects: bool = True
    recent_files_count: int = 10
    confirm_exit: bool = True
    show_splash_screen: bool = True


@dataclass
class CompilerSettings:
    """Compiler and build settings."""
    preferred_compiler: str = "auto"
    compiler_flags: str = "-Wall -O2"
    include_paths: list = None
    library_paths: list = None
    auto_detect_compilers: bool = True
    validate_generated_code: bool = True
    
    def __post_init__(self):
        if self.include_paths is None:
            self.include_paths = []
        if self.library_paths is None:
            self.library_paths = []


@dataclass
class ApplicationSettings:
    """Complete application settings."""
    theme: ThemeSettings
    editor: EditorSettings
    analysis: AnalysisSettings
    ui: UISettings
    compiler: CompilerSettings
    recent_files: list = None
    last_output_directory: str = ""
    
    def __post_init__(self):
        if self.recent_files is None:
            self.recent_files = []


class SettingsManager:
    """Manages application settings and preferences."""
    
    def __init__(self):
        self.settings_dir = self._get_settings_directory()
        self.settings_file = self.settings_dir / "settings.json"
        self.themes_dir = self.settings_dir / "themes"
        
        # Create directories if they don't exist
        self.settings_dir.mkdir(parents=True, exist_ok=True)
        self.themes_dir.mkdir(parents=True, exist_ok=True)
        
        # Load or create default settings
        self.settings = self._load_settings()
        
        # Callbacks for settings changes
        self.change_callbacks: Dict[str, list] = {}
        
    def _get_settings_directory(self) -> Path:
        """Get the appropriate settings directory for the current platform."""
        if platform.system() == "Windows":
            # Windows: %APPDATA%/BinaryAnalyzer
            app_data = os.environ.get("APPDATA", ".")
            return Path(app_data) / "BinaryAnalyzer"
        elif platform.system() == "Darwin":
            # macOS: ~/Library/Application Support/BinaryAnalyzer
            home = Path.home()
            return home / "Library" / "Application Support" / "BinaryAnalyzer"
        else:
            # Linux: ~/.config/BinaryAnalyzer
            config_home = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
            return Path(config_home) / "BinaryAnalyzer"
            
    def _load_settings(self) -> ApplicationSettings:
        """Load settings from file or create defaults."""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Convert dict to dataclass
                return ApplicationSettings(
                    theme=ThemeSettings(**data.get('theme', {})),
                    editor=EditorSettings(**data.get('editor', {})),
                    analysis=AnalysisSettings(**data.get('analysis', {})),
                    ui=UISettings(**data.get('ui', {})),
                    compiler=CompilerSettings(**data.get('compiler', {})),
                    recent_files=data.get('recent_files', []),
                    last_output_directory=data.get('last_output_directory', "")
                )
                
            except (json.JSONDecodeError, TypeError, KeyError) as e:
                print(f"Error loading settings: {e}. Using defaults.")
                
        # Return default settings
        return ApplicationSettings(
            theme=ThemeSettings(),
            editor=EditorSettings(),
            analysis=AnalysisSettings(),
            ui=UISettings(),
            compiler=CompilerSettings()
        )
        
    def save_settings(self):
        """Save current settings to file."""
        try:
            # Convert dataclass to dict
            data = asdict(self.settings)
            
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"Error saving settings: {e}")
            
    def get_setting(self, category: str, key: str, default=None):
        """Get a specific setting value."""
        category_obj = getattr(self.settings, category, None)
        if category_obj:
            return getattr(category_obj, key, default)
        return default
        
    def set_setting(self, category: str, key: str, value):
        """Set a specific setting value."""
        category_obj = getattr(self.settings, category, None)
        if category_obj:
            setattr(category_obj, key, value)
            self._notify_change(f"{category}.{key}", value)
            
    def add_recent_file(self, file_path: str):
        """Add a file to the recent files list."""
        if file_path in self.settings.recent_files:
            self.settings.recent_files.remove(file_path)
            
        self.settings.recent_files.insert(0, file_path)
        
        # Keep only the configured number of recent files
        max_count = self.settings.ui.recent_files_count
        self.settings.recent_files = self.settings.recent_files[:max_count]
        
        self._notify_change("recent_files", self.settings.recent_files)
        
    def get_recent_files(self) -> list:
        """Get the list of recent files."""
        # Filter out files that no longer exist
        existing_files = [f for f in self.settings.recent_files if Path(f).exists()]
        self.settings.recent_files = existing_files
        return existing_files
        
    def register_change_callback(self, setting_key: str, callback: Callable):
        """Register a callback for when a setting changes."""
        if setting_key not in self.change_callbacks:
            self.change_callbacks[setting_key] = []
        self.change_callbacks[setting_key].append(callback)
        
    def _notify_change(self, setting_key: str, value):
        """Notify registered callbacks about setting changes."""
        if setting_key in self.change_callbacks:
            for callback in self.change_callbacks[setting_key]:
                try:
                    callback(setting_key, value)
                except Exception as e:
                    print(f"Error in settings callback: {e}")
                    
    def export_settings(self, file_path: str):
        """Export settings to a file."""
        try:
            data = asdict(self.settings)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error exporting settings: {e}")
            return False
            
    def import_settings(self, file_path: str) -> bool:
        """Import settings from a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Create new settings object
            new_settings = ApplicationSettings(
                theme=ThemeSettings(**data.get('theme', {})),
                editor=EditorSettings(**data.get('editor', {})),
                analysis=AnalysisSettings(**data.get('analysis', {})),
                ui=UISettings(**data.get('ui', {})),
                compiler=CompilerSettings(**data.get('compiler', {})),
                recent_files=data.get('recent_files', []),
                last_output_directory=data.get('last_output_directory', "")
            )
            
            self.settings = new_settings
            self._notify_change("settings_imported", new_settings)
            return True
            
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False
            
    def reset_to_defaults(self):
        """Reset all settings to default values."""
        self.settings = ApplicationSettings(
            theme=ThemeSettings(),
            editor=EditorSettings(),
            analysis=AnalysisSettings(),
            ui=UISettings(),
            compiler=CompilerSettings()
        )
        self._notify_change("settings_reset", self.settings)
        
    def create_custom_theme(self, name: str, theme_data: dict) -> bool:
        """Create a custom theme."""
        try:
            theme_file = self.themes_dir / f"{name}.json"
            with open(theme_file, 'w', encoding='utf-8') as f:
                json.dump(theme_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error creating theme: {e}")
            return False
            
    def get_available_themes(self) -> list:
        """Get list of available themes."""
        themes = ["dark", "light"]  # Built-in themes
        
        # Add custom themes
        for theme_file in self.themes_dir.glob("*.json"):
            themes.append(theme_file.stem)
            
        return themes
        
    def load_theme(self, theme_name: str) -> Optional[ThemeSettings]:
        """Load a specific theme."""
        if theme_name in ["dark", "light"]:
            # Built-in themes
            if theme_name == "light":
                return ThemeSettings(
                    theme_name="light",
                    background_color="#ffffff",
                    foreground_color="#000000",
                    editor_background="#ffffff",
                    editor_foreground="#000000",
                    highlight_color="#316ac5",
                    keyword_color="#0000ff",
                    comment_color="#008000",
                    string_color="#a31515",
                    number_color="#098658",
                    function_color="#795e26",
                    type_color="#267f99"
                )
            else:
                return ThemeSettings()  # Default dark theme
        else:
            # Custom theme
            theme_file = self.themes_dir / f"{theme_name}.json"
            if theme_file.exists():
                try:
                    with open(theme_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    return ThemeSettings(**data)
                except Exception as e:
                    print(f"Error loading theme {theme_name}: {e}")
                    
        return None


class SettingsDialog:
    """Settings configuration dialog."""
    
    def __init__(self, parent, settings_manager: SettingsManager):
        self.parent = parent
        self.settings_manager = settings_manager
        self.dialog = None
        self.settings_copy = None
        
    def show(self):
        """Show the settings dialog."""
        if self.dialog and self.dialog.winfo_exists():
            self.dialog.lift()
            return
            
        # Create a copy of settings for editing
        import copy
        self.settings_copy = copy.deepcopy(self.settings_manager.settings)
        
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Settings")
        self.dialog.geometry("600x500")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        self._create_widgets()
        
    def _create_widgets(self):
        """Create dialog widgets."""
        # Main frame with notebook for different categories
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook for different settings categories
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create tabs
        self._create_general_tab(notebook)
        self._create_editor_tab(notebook)
        self._create_analysis_tab(notebook)
        self._create_theme_tab(notebook)
        self._create_compiler_tab(notebook)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X)
        
        ttk.Button(buttons_frame, text="OK", command=self._apply_settings).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(buttons_frame, text="Cancel", command=self._cancel).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(buttons_frame, text="Apply", command=self._apply_settings).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(buttons_frame, text="Reset to Defaults", command=self._reset_defaults).pack(side=tk.LEFT)
        
    def _create_general_tab(self, notebook):
        """Create general settings tab."""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="General")
        
        # Window settings
        window_frame = ttk.LabelFrame(frame, text="Window Settings", padding="10")
        window_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(window_frame, text="Default Width:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        width_var = tk.IntVar(value=self.settings_copy.ui.window_width)
        ttk.Spinbox(window_frame, from_=800, to=2000, textvariable=width_var, width=10).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(window_frame, text="Default Height:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        height_var = tk.IntVar(value=self.settings_copy.ui.window_height)
        ttk.Spinbox(window_frame, from_=600, to=1500, textvariable=height_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # UI options
        ui_frame = ttk.LabelFrame(frame, text="Interface Options", padding="10")
        ui_frame.pack(fill=tk.X, pady=(0, 10))
        
        show_toolbar_var = tk.BooleanVar(value=self.settings_copy.ui.show_toolbar)
        ttk.Checkbutton(ui_frame, text="Show Toolbar", variable=show_toolbar_var).pack(anchor=tk.W)
        
        show_statusbar_var = tk.BooleanVar(value=self.settings_copy.ui.show_status_bar)
        ttk.Checkbutton(ui_frame, text="Show Status Bar", variable=show_statusbar_var).pack(anchor=tk.W)
        
        confirm_exit_var = tk.BooleanVar(value=self.settings_copy.ui.confirm_exit)
        ttk.Checkbutton(ui_frame, text="Confirm Exit", variable=confirm_exit_var).pack(anchor=tk.W)
        
        # Store variables for later access
        self.ui_vars = {
            'width': width_var,
            'height': height_var,
            'show_toolbar': show_toolbar_var,
            'show_statusbar': show_statusbar_var,
            'confirm_exit': confirm_exit_var
        }
        
    def _create_editor_tab(self, notebook):
        """Create editor settings tab."""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Editor")
        
        # Font settings
        font_frame = ttk.LabelFrame(frame, text="Font Settings", padding="10")
        font_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(font_frame, text="Font Family:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        font_family_var = tk.StringVar(value=self.settings_copy.editor.font_family)
        font_combo = ttk.Combobox(font_frame, textvariable=font_family_var, width=20)
        font_combo['values'] = ['Consolas', 'Monaco', 'Courier New', 'DejaVu Sans Mono', 'Ubuntu Mono']
        font_combo.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(font_frame, text="Font Size:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        font_size_var = tk.IntVar(value=self.settings_copy.editor.font_size)
        ttk.Spinbox(font_frame, from_=8, to=24, textvariable=font_size_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # Editor options
        editor_frame = ttk.LabelFrame(frame, text="Editor Options", padding="10")
        editor_frame.pack(fill=tk.X)
        
        show_line_numbers_var = tk.BooleanVar(value=self.settings_copy.editor.show_line_numbers)
        ttk.Checkbutton(editor_frame, text="Show Line Numbers", variable=show_line_numbers_var).pack(anchor=tk.W)
        
        word_wrap_var = tk.BooleanVar(value=self.settings_copy.editor.word_wrap)
        ttk.Checkbutton(editor_frame, text="Word Wrap", variable=word_wrap_var).pack(anchor=tk.W)
        
        syntax_highlighting_var = tk.BooleanVar(value=self.settings_copy.editor.syntax_highlighting)
        ttk.Checkbutton(editor_frame, text="Syntax Highlighting", variable=syntax_highlighting_var).pack(anchor=tk.W)
        
        # Store variables
        self.editor_vars = {
            'font_family': font_family_var,
            'font_size': font_size_var,
            'show_line_numbers': show_line_numbers_var,
            'word_wrap': word_wrap_var,
            'syntax_highlighting': syntax_highlighting_var
        }
        
    def _create_analysis_tab(self, notebook):
        """Create analysis settings tab."""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Analysis")
        
        # Default options
        defaults_frame = ttk.LabelFrame(frame, text="Default Analysis Options", padding="10")
        defaults_frame.pack(fill=tk.X, pady=(0, 10))
        
        generate_report_var = tk.BooleanVar(value=self.settings_copy.analysis.generate_report)
        ttk.Checkbutton(defaults_frame, text="Generate Analysis Report", variable=generate_report_var).pack(anchor=tk.W)
        
        extract_strings_var = tk.BooleanVar(value=self.settings_copy.analysis.extract_strings)
        ttk.Checkbutton(defaults_frame, text="Extract Strings", variable=extract_strings_var).pack(anchor=tk.W)
        
        generate_build_files_var = tk.BooleanVar(value=self.settings_copy.analysis.generate_build_files)
        ttk.Checkbutton(defaults_frame, text="Generate Build Files", variable=generate_build_files_var).pack(anchor=tk.W)
        
        # Performance settings
        perf_frame = ttk.LabelFrame(frame, text="Performance Settings", padding="10")
        perf_frame.pack(fill=tk.X)
        
        ttk.Label(perf_frame, text="Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        timeout_var = tk.IntVar(value=self.settings_copy.analysis.timeout_seconds)
        ttk.Spinbox(perf_frame, from_=60, to=3600, textvariable=timeout_var, width=10).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(perf_frame, text="Thread Count:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        thread_count_var = tk.IntVar(value=self.settings_copy.analysis.thread_count)
        ttk.Spinbox(perf_frame, from_=1, to=16, textvariable=thread_count_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # Store variables
        self.analysis_vars = {
            'generate_report': generate_report_var,
            'extract_strings': extract_strings_var,
            'generate_build_files': generate_build_files_var,
            'timeout': timeout_var,
            'thread_count': thread_count_var
        }
        
    def _create_theme_tab(self, notebook):
        """Create theme settings tab."""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Theme")
        
        # Theme selection
        theme_frame = ttk.LabelFrame(frame, text="Theme Selection", padding="10")
        theme_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(theme_frame, text="Theme:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        theme_var = tk.StringVar(value=self.settings_copy.theme.theme_name)
        theme_combo = ttk.Combobox(theme_frame, textvariable=theme_var, width=20)
        theme_combo['values'] = self.settings_manager.get_available_themes()
        theme_combo.grid(row=0, column=1, sticky=tk.W)
        
        # Color customization
        colors_frame = ttk.LabelFrame(frame, text="Color Customization", padding="10")
        colors_frame.pack(fill=tk.X)
        
        # Create color selection buttons
        color_vars = {}
        color_labels = [
            ('Background', 'background_color'),
            ('Editor Background', 'editor_background'),
            ('Foreground', 'foreground_color'),
            ('Keywords', 'keyword_color'),
            ('Comments', 'comment_color'),
            ('Strings', 'string_color')
        ]
        
        for i, (label, attr) in enumerate(color_labels):
            ttk.Label(colors_frame, text=f"{label}:").grid(row=i//2, column=(i%2)*2, sticky=tk.W, padx=(0, 5), pady=2)
            
            color_var = tk.StringVar(value=getattr(self.settings_copy.theme, attr))
            color_vars[attr] = color_var
            
            color_button = tk.Button(colors_frame, text="Choose", width=10,
                                   command=lambda attr=attr, var=color_var: self._choose_color(attr, var))
            color_button.grid(row=i//2, column=(i%2)*2+1, sticky=tk.W, padx=(0, 20), pady=2)
            
        self.theme_vars = {'theme': theme_var, 'colors': color_vars}
        
    def _create_compiler_tab(self, notebook):
        """Create compiler settings tab."""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Compiler")
        
        # Compiler selection
        compiler_frame = ttk.LabelFrame(frame, text="Compiler Settings", padding="10")
        compiler_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(compiler_frame, text="Preferred Compiler:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        compiler_var = tk.StringVar(value=self.settings_copy.compiler.preferred_compiler)
        compiler_combo = ttk.Combobox(compiler_frame, textvariable=compiler_var, width=15)
        compiler_combo['values'] = ['auto', 'gcc', 'clang', 'msvc', 'mingw']
        compiler_combo.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(compiler_frame, text="Compiler Flags:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        flags_var = tk.StringVar(value=self.settings_copy.compiler.compiler_flags)
        ttk.Entry(compiler_frame, textvariable=flags_var, width=30).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # Options
        options_frame = ttk.LabelFrame(frame, text="Options", padding="10")
        options_frame.pack(fill=tk.X)
        
        auto_detect_var = tk.BooleanVar(value=self.settings_copy.compiler.auto_detect_compilers)
        ttk.Checkbutton(options_frame, text="Auto-detect Compilers", variable=auto_detect_var).pack(anchor=tk.W)
        
        validate_code_var = tk.BooleanVar(value=self.settings_copy.compiler.validate_generated_code)
        ttk.Checkbutton(options_frame, text="Validate Generated Code", variable=validate_code_var).pack(anchor=tk.W)
        
        # Store variables
        self.compiler_vars = {
            'preferred_compiler': compiler_var,
            'compiler_flags': flags_var,
            'auto_detect': auto_detect_var,
            'validate_code': validate_code_var
        }
        
    def _choose_color(self, attribute: str, color_var: tk.StringVar):
        """Open color chooser dialog."""
        current_color = color_var.get()
        color = colorchooser.askcolor(color=current_color)
        if color[1]:  # User didn't cancel
            color_var.set(color[1])
            
    def _apply_settings(self):
        """Apply the changed settings."""
        try:
            # Update settings copy with UI values
            # UI settings
            self.settings_copy.ui.window_width = self.ui_vars['width'].get()
            self.settings_copy.ui.window_height = self.ui_vars['height'].get()
            self.settings_copy.ui.show_toolbar = self.ui_vars['show_toolbar'].get()
            self.settings_copy.ui.show_status_bar = self.ui_vars['show_statusbar'].get()
            self.settings_copy.ui.confirm_exit = self.ui_vars['confirm_exit'].get()
            
            # Editor settings
            self.settings_copy.editor.font_family = self.editor_vars['font_family'].get()
            self.settings_copy.editor.font_size = self.editor_vars['font_size'].get()
            self.settings_copy.editor.show_line_numbers = self.editor_vars['show_line_numbers'].get()
            self.settings_copy.editor.word_wrap = self.editor_vars['word_wrap'].get()
            self.settings_copy.editor.syntax_highlighting = self.editor_vars['syntax_highlighting'].get()
            
            # Analysis settings
            self.settings_copy.analysis.generate_report = self.analysis_vars['generate_report'].get()
            self.settings_copy.analysis.extract_strings = self.analysis_vars['extract_strings'].get()
            self.settings_copy.analysis.generate_build_files = self.analysis_vars['generate_build_files'].get()
            self.settings_copy.analysis.timeout_seconds = self.analysis_vars['timeout'].get()
            self.settings_copy.analysis.thread_count = self.analysis_vars['thread_count'].get()
            
            # Theme settings
            self.settings_copy.theme.theme_name = self.theme_vars['theme'].get()
            for attr, var in self.theme_vars['colors'].items():
                setattr(self.settings_copy.theme, attr, var.get())
                
            # Compiler settings
            self.settings_copy.compiler.preferred_compiler = self.compiler_vars['preferred_compiler'].get()
            self.settings_copy.compiler.compiler_flags = self.compiler_vars['compiler_flags'].get()
            self.settings_copy.compiler.auto_detect_compilers = self.compiler_vars['auto_detect'].get()
            self.settings_copy.compiler.validate_generated_code = self.compiler_vars['validate_code'].get()
            
            # Apply changes to settings manager
            self.settings_manager.settings = self.settings_copy
            self.settings_manager.save_settings()
            
            messagebox.showinfo("Settings", "Settings applied successfully!")
            self.dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error applying settings: {str(e)}")
            
    def _cancel(self):
        """Cancel changes and close dialog."""
        self.dialog.destroy()
        
    def _reset_defaults(self):
        """Reset all settings to defaults."""
        if messagebox.askyesno("Reset Settings", "Are you sure you want to reset all settings to defaults?"):
            self.settings_manager.reset_to_defaults()
            self.dialog.destroy()
            messagebox.showinfo("Settings", "Settings have been reset to defaults.")