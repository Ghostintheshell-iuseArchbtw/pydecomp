#!/usr/bin/env python3
"""
Binary Analyzer GUI - Main Application
A graphical interface for the binary reverse engineering toolkit
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
from pathlib import Path
import json
from datetime import datetime

from gui_target_hook import set_codegen_target
from gui_analyzer import AnalysisWorker
from code_editor import CodeEditor, FindReplaceDialog
try:
    from settings_manager import SettingsManager
    settings_manager = SettingsManager()
except ImportError:
    settings_manager = None


class BinaryAnalyzerGUI:
    """Main GUI application for binary analysis."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Binary Reverse Engineering Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Application state
        self.current_file = None
        self.output_directory = "gui_output"
        self.analysis_thread = None
        self.log_queue = queue.Queue()
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        # Analysis options
        self.report_var = tk.BooleanVar(value=True)
        self.strings_var = tk.BooleanVar(value=True)
        self.build_files_var = tk.BooleanVar(value=True)
        self.detailed_var = tk.BooleanVar(value=False)
        
        # Analysis worker
        self.current_worker = None
        
        # Find/Replace dialog
        self.find_dialog = None
        
        self.setup_gui()
        self.setup_menu()
        self.check_log_queue()
        
    def setup_gui(self):
        """Set up the main GUI layout."""
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # File selection section
        self.create_file_section(main_frame)
        
        # Configuration section
        self.create_config_section(main_frame)
        
        # Results section with notebook
        self.create_results_section(main_frame)
        
        # Status and progress section
        self.create_status_section(main_frame)
        
    def create_file_section(self, parent):
        """Create file selection interface."""
        file_frame = ttk.LabelFrame(parent, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        # File path entry
        ttk.Label(file_frame, text="Binary File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_var, width=50)
        file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        
        # Browse button
        browse_btn = ttk.Button(file_frame, text="Browse...", command=self.browse_file)
        browse_btn.grid(row=0, column=2, padx=(0, 5))
        
        # Analyze button
        self.analyze_btn = ttk.Button(file_frame, text="Analyze", command=self.start_analysis, state=tk.DISABLED)
        self.analyze_btn.grid(row=0, column=3, padx=(5, 0))
        
        # Cancel button (initially hidden)
        self.cancel_btn = ttk.Button(file_frame, text="Cancel", command=self.cancel_analysis, state=tk.DISABLED)
        self.cancel_btn.grid(row=0, column=4, padx=(5, 0))
        
        # Output directory
        ttk.Label(file_frame, text="Output Dir:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        self.output_var = tk.StringVar(value=self.output_directory)
        output_entry = ttk.Entry(file_frame, textvariable=self.output_var, width=50)
        output_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(10, 0))
        
        # Output browse button
        output_browse_btn = ttk.Button(file_frame, text="Browse...", command=self.browse_output_dir)
        output_browse_btn.grid(row=1, column=2, pady=(10, 0))
        
        # TODO: Enable drag and drop (requires additional setup)
        # file_entry.drop_target_register(tk.DND_FILES)
        # file_entry.dnd_bind('<<Drop>>', self.on_file_drop)
        
    def create_config_section(self, parent):
        """Create configuration options panel."""
        config_frame = ttk.LabelFrame(parent, text="Analysis Options", padding="10")
        config_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N), pady=(0, 10), padx=(0, 10))
        
        # Analysis options checkboxes
        ttk.Checkbutton(config_frame, text="Generate Report", variable=self.report_var).pack(anchor=tk.W)
        ttk.Checkbutton(config_frame, text="Extract Strings", variable=self.strings_var).pack(anchor=tk.W)
        ttk.Checkbutton(config_frame, text="Generate Build Files", variable=self.build_files_var).pack(anchor=tk.W)
        ttk.Checkbutton(config_frame, text="Detailed Analysis (Slower)", variable=self.detailed_var).pack(anchor=tk.W)
        
    def create_results_section(self, parent):
        """Create results viewer with tabs."""
        self.notebook = ttk.Notebook(parent)
        self.notebook.grid(row=1, column=1, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Analysis Log")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20, width=80, bg='#1e1e1e', fg='#ffffff', insertbackground='#ffffff', font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Generated files tabs (will be added dynamically)
        self.file_tabs = {}
        
    def create_status_section(self, parent):
        """Create status bar and progress indicator."""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        status_frame.columnconfigure(1, weight=1)
        
        # Status label
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W)
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.grid(row=0, column=1, sticky=tk.W, padx=(5, 0))
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=2, sticky=tk.E, padx=(20, 0))
        
    def setup_menu(self):
        """Set up the application menu."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Binary...", command=self.browse_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Find & Replace", command=self.show_find_replace, accelerator="Ctrl+F")
        edit_menu.add_separator()
        edit_menu.add_command(label="Select All", command=self.select_all, accelerator="Ctrl+A")
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Clear Log", command=self.clear_log)
        tools_menu.add_command(label="Open Output Directory", command=self.open_output_dir)
        tools_menu.add_separator()
        tools_menu.add_command(label="Cancel Analysis", command=self.cancel_analysis)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
        # Keyboard bindings
        self.root.bind_all("<Control-o>", lambda e: self.browse_file())
        self.root.bind_all("<Control-q>", lambda e: self.root.quit())
        self.root.bind_all("<Control-f>", lambda e: self.show_find_replace())
        self.root.bind_all("<Control-a>", lambda e: self.select_all())
        
    def browse_file(self):
        """Open file browser for binary selection."""
        filetypes = [
            ("Executable Files", "*.exe *.dll *.sys"),
            ("Executable Files", "*.exe"),
            ("Dynamic Libraries", "*.dll"),
            ("System Files", "*.sys"),
            ("All Files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=filetypes
        )
        
        if filename:
            self.file_var.set(filename)
            self.current_file = filename
            self.analyze_btn.config(state=tk.NORMAL)
            self.log(f"Selected file: {filename}")
            
    def browse_output_dir(self):
        """Browse for output directory."""
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_var.set(directory)
            self.output_directory = directory
            
    def on_file_drop(self, event):
        """Handle drag and drop file selection."""
        files = self.root.splitlist(event.data)
        if files:
            filename = files[0]
            if filename.lower().endswith(('.exe', '.dll', '.sys')):
                self.file_var.set(filename)
                self.current_file = filename
                self.analyze_btn.config(state=tk.NORMAL)
                self.log(f"Dropped file: {filename}")
            else:
                messagebox.showwarning("Invalid File", "Please select an executable (.exe), library (.dll), or system (.sys) file.")
                
    def start_analysis(self):
        """Start the binary analysis in a separate thread."""
        if not self.current_file or not os.path.exists(self.current_file):
            messagebox.showerror("Error", "Please select a valid binary file.")
            return
            
        # Prepare analysis options
        options = {
            'report': self.report_var.get(),
            'strings': self.strings_var.get(),
            'build_files': self.build_files_var.get(),
            'detailed': self.detailed_var.get()
        }
        
        # Disable analyze button and enable cancel button during analysis
        self.analyze_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.status_var.set("Starting analysis...")
        self.progress_var.set(0)
        
        # Clear previous results
        self.clear_results()
        
        # Create and start analysis worker
        self.current_worker = AnalysisWorker(
            binary_path=self.current_file,
            output_dir=self.output_var.get(),
            options=options,
            progress_callback=self.on_progress_update,
            log_callback=self.on_log_message,
            completion_callback=self.on_analysis_complete
        )
        
        self.current_worker.start()
        
    def cancel_analysis(self):
        """Cancel the current analysis."""
        if self.current_worker and self.current_worker.is_alive():
            self.current_worker.cancel()
            self.log("Analysis cancelled by user")
            self.status_var.set("Analysis cancelled")
            
        self.analyze_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        
    def on_progress_update(self, message, progress):
        """Handle progress updates from worker thread."""
        self.log_queue.put(('status', message, progress))
        
    def on_log_message(self, message):
        """Handle log messages from worker thread."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(('log', f"[{timestamp}] {message}"))
        
    def on_analysis_complete(self, results):
        """Handle analysis completion."""
        self.root.after(0, lambda: self._handle_analysis_results(results))
        
    def _handle_analysis_results(self, results):
        """Handle analysis results in main thread."""
        # Re-enable buttons
        self.analyze_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        
        if results['success']:
            self.log("Analysis completed successfully!")
            
            # Load generated files into tabs
            output_dir = Path(self.output_var.get())
            self.load_generated_files(output_dir, Path(self.current_file).stem)
            
            # Show success message
            file_count = len(results['generated_files'])
            messagebox.showinfo("Analysis Complete", 
                              f"Analysis completed successfully!\n"
                              f"Generated {file_count} files in {output_dir}")
        else:
            error_msg = results.get('error', 'Unknown error')
            self.log(f"ERROR: {error_msg}")
            messagebox.showerror("Analysis Failed", f"Analysis failed: {error_msg}")
            
    def update_status(self, message, progress):
        """Update status and progress from worker thread."""
        self.log_queue.put(('status', message, progress))
        
    def log(self, message):
        """Add message to log queue for thread-safe logging."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(('log', f"[{timestamp}] {message}"))
        
    def check_log_queue(self):
        """Check for log messages and update GUI."""
        try:
            while True:
                msg_type, *args = self.log_queue.get_nowait()
                
                if msg_type == 'log':
                    message = args[0]
                    self.log_text.insert(tk.END, message + "\n")
                    self.log_text.see(tk.END)
                    
                elif msg_type == 'status':
                    message, progress = args
                    self.status_var.set(message)
                    self.progress_var.set(progress)
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.check_log_queue)
        
    def load_generated_files(self, output_dir, filename_stem):
        """Load generated files into tabs."""
        files_to_load = [
            (f"{filename_stem}.h", "Header File"),
            (f"{filename_stem}.cpp", "Implementation"),
            (f"{filename_stem}_analysis_report.txt", "Analysis Report"),
            ("Makefile", "Makefile"),
            ("CMakeLists.txt", "CMakeLists")
        ]
        
        for filename, tab_name in files_to_load:
            file_path = output_dir / filename
            if file_path.exists():
                self.add_file_tab(file_path, tab_name)
                
    def add_file_tab(self, file_path, tab_name):
        """Add a new tab with file contents."""
        tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(tab_frame, text=tab_name)
        
        # Determine if this is a code file that should use syntax highlighting
        is_code_file = str(file_path).endswith(('.h', '.cpp', '.c', '.hpp', '.cc'))
        
        if is_code_file:
            # Use enhanced code editor for code files
            code_editor = CodeEditor(tab_frame)
            code_editor.pack(fill=tk.BOTH, expand=True)
            
            # Load file contents
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    code_editor.set_content(content)
                    code_editor.set_readonly(True)
            except Exception as e:
                code_editor.set_content(f"Error loading file: {e}")
                
            self.file_tabs[tab_name] = code_editor
        else:
            # Use regular scrolled text for other files
            text_widget = scrolledtext.ScrolledText(
                tab_frame, 
                wrap=tk.WORD, 
                height=20, 
                width=100,
                bg='#1e1e1e', 
                fg='#ffffff',
                insertbackground='#ffffff',
                font=('Consolas', 9)
            )
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            # Load file contents
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    text_widget.insert('1.0', content)
                    text_widget.config(state=tk.DISABLED)  # Make read-only
            except Exception as e:
                text_widget.insert('1.0', f"Error loading file: {e}")
                
            self.file_tabs[tab_name] = text_widget
        
    def clear_results(self):
        """Clear previous analysis results."""
        # Remove all tabs except the log tab
        for tab_id in list(self.file_tabs.keys()):
            for i in range(self.notebook.index("end")):
                if self.notebook.tab(i, "text") == tab_id:
                    self.notebook.forget(i)
                    break
        self.file_tabs.clear()
        
    def clear_log(self):
        """Clear the analysis log."""
        self.log_text.delete('1.0', tk.END)
        
    def open_output_dir(self):
        """Open the output directory in file explorer."""
        output_dir = self.output_var.get()
        if os.path.exists(output_dir):
            if sys.platform.startswith('darwin'):  # macOS
                os.system(f'open "{output_dir}"')
            elif sys.platform.startswith('win'):  # Windows
                os.system(f'explorer "{output_dir}"')
            else:  # Linux
                os.system(f'xdg-open "{output_dir}"')
        else:
            messagebox.showwarning("Directory Not Found", f"Output directory does not exist: {output_dir}")
            
    def show_find_replace(self):
        """Show find and replace dialog for current tab."""
        current_tab = self.notebook.index(self.notebook.select())
        tab_name = self.notebook.tab(current_tab, 'text')
        
        if tab_name in self.file_tabs and isinstance(self.file_tabs[tab_name], CodeEditor):
            if not self.find_dialog:
                self.find_dialog = FindReplaceDialog(self.root, self.file_tabs[tab_name])
            self.find_dialog.show()
        else:
            messagebox.showinfo("Find & Replace", "Find & Replace is only available for code files.")
            
    def select_all(self):
        """Select all text in current tab."""
        current_tab = self.notebook.index(self.notebook.select())
        tab_name = self.notebook.tab(current_tab, 'text')
        
        if tab_name in self.file_tabs:
            widget = self.file_tabs[tab_name]
            if isinstance(widget, CodeEditor):
                widget.text_editor.tag_add('sel', '1.0', 'end')
            elif hasattr(widget, 'tag_add'):
                widget.tag_add('sel', '1.0', 'end')
                
    def show_about(self):
        """Show about dialog."""
        about_text = """Binary Reverse Engineering Tool - GUI Version

A graphical interface for analyzing Windows PE files (.exe, .dll, .sys)
and generating C/C++ recreations of the original code.

Features:
• Advanced binary analysis with progress tracking
• Function identification and categorization
• C/C++ code generation with syntax highlighting
• Build file generation (Makefile, CMakeLists.txt)
• String extraction and analysis
• Pattern recognition and data structure inference
• Real-time analysis logging
• Integrated code editor with find/replace

Version: 2.0
Author: AI Assistant

Built with Python and tkinter"""
        
        messagebox.showinfo("About", about_text)


def main():
    """Main application entry point."""
    root = tk.Tk()

    # Add codegen target selector if settings manager is available
    if settings_manager is not None:
        try:
            _add_target_selector(root, settings_manager)
        except Exception:
            pass
    
    app = BinaryAnalyzerGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)


if __name__ == "__main__":
    main()

# --- V3 UI: Codegen target selector (with status) ---
def _add_target_selector(root, settings_manager):
    top = getattr(root, 'codegen_topbar', None)
    if top is None:
        top = ttk.Frame(root)
        root.codegen_topbar = top
        top.pack(anchor='w', fill='x')

    lbl = ttk.Label(top, text="Codegen Target:")
    lbl.pack(side='left', padx=6, pady=4)

    var = tk.StringVar(value=getattr(getattr(settings_manager.settings, 'codegen', object()), 'target', 'windows'))
    cmb = ttk.Combobox(top, textvariable=var, values=["windows","portable"], state="readonly", width=16)
    cmb.pack(side='left', padx=6, pady=4)

    # Status bar
    status = getattr(root, 'statusbar', None)
    if status is None:
        status = ttk.Label(root, text=f"Target: {var.get()}", anchor='w')
        root.statusbar = status
        status.pack(side='bottom', fill='x')
    else:
        status.configure(text=f"Target: {var.get()}")

    def on_sel(*_):
        tgt = var.get()
        try:
            settings_manager.settings.codegen.target = tgt
            settings_manager.save_settings()
        except Exception:
            pass
        set_codegen_target(tgt)
        # update status
        try:
            root.statusbar.configure(text=f"Target: {tgt}")
        except Exception:
            pass

    cmb.bind("<<ComboboxSelected>>", on_sel)

    # initialize hook with current value
    try:
        set_codegen_target(var.get())
    except Exception:
        pass

    return var
