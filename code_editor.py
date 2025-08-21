#!/usr/bin/env python3
"""
Code Editor Widget with Syntax Highlighting
Provides C/C++ syntax highlighting for generated code
"""

import tkinter as tk
from tkinter import scrolledtext, font
import re
from typing import Dict, List, Tuple


class SyntaxHighlighter:
    """Simple syntax highlighter for C/C++ code."""
    
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.setup_tags()
        self.setup_patterns()
        
    def setup_tags(self):
        """Configure text tags for syntax highlighting."""
        # Keywords - blue
        self.text_widget.tag_configure("keyword", foreground="#569cd6")
        
        # Comments - green
        self.text_widget.tag_configure("comment", foreground="#6a9955")
        
        # Strings - orange
        self.text_widget.tag_configure("string", foreground="#ce9178")
        
        # Numbers - light green
        self.text_widget.tag_configure("number", foreground="#b5cea8")
        
        # Preprocessor - gray
        self.text_widget.tag_configure("preprocessor", foreground="#c586c0")
        
        # Function names - yellow
        self.text_widget.tag_configure("function", foreground="#dcdcaa")
        
        # Types - cyan
        self.text_widget.tag_configure("type", foreground="#4ec9b0")
        
    def setup_patterns(self):
        """Define regex patterns for syntax elements."""
        self.patterns = [
            # C/C++ keywords
            (r'\b(auto|break|case|char|const|continue|default|do|double|else|enum|extern|float|for|goto|if|int|long|register|return|short|signed|sizeof|static|struct|switch|typedef|union|unsigned|void|volatile|while|class|public|private|protected|virtual|namespace|using|template|typename|bool|true|false|nullptr|new|delete|this|override|final)\b', "keyword"),
            
            # Preprocessor directives
            (r'#\w+', "preprocessor"),
            
            # Single line comments
            (r'//.*$', "comment"),
            
            # Multi-line comments
            (r'/\*.*?\*/', "comment"),
            
            # String literals
            (r'"([^"\\\\]|\\\\.)*"', "string"),
            (r"'([^'\\\\]|\\\\.)*'", "string"),
            
            # Numbers
            (r'\b\d+\.?\d*([eE][+-]?\d+)?[fFlL]?\b', "number"),
            (r'\b0[xX][0-9a-fA-F]+[lL]?\b', "number"),
            
            # Function calls
            (r'\b(\w+)(?=\s*\()', "function"),
            
            # Common types
            (r'\b(DWORD|WORD|BYTE|HANDLE|HWND|HDC|HINSTANCE|LPSTR|LPCSTR|LPWSTR|LPCWSTR|BOOL|TRUE|FALSE|NULL|uint32_t|uint64_t|int32_t|int64_t|size_t|wchar_t)\b', "type"),
        ]
        
    def highlight(self):
        """Apply syntax highlighting to the entire text."""
        # Clear existing tags
        for tag in ["keyword", "comment", "string", "number", "preprocessor", "function", "type"]:
            self.text_widget.tag_remove(tag, "1.0", "end")
            
        content = self.text_widget.get("1.0", "end-1c")
        
        for pattern, tag in self.patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                start_idx = f"1.0+{match.start()}c"
                end_idx = f"1.0+{match.end()}c"
                self.text_widget.tag_add(tag, start_idx, end_idx)
                
    def on_text_change(self, event=None):
        """Handle text changes for real-time highlighting."""
        # Schedule highlighting update
        self.text_widget.after_idle(self.highlight)


class CodeEditor(tk.Frame):
    """Enhanced code editor with syntax highlighting and line numbers."""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.setup_ui()
        self.setup_bindings()
        
    def setup_ui(self):
        """Set up the editor UI."""
        # Configure grid
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        
        # Line numbers text widget
        self.line_numbers = tk.Text(
            self, 
            width=4, 
            padx=3, 
            takefocus=0,
            border=0,
            state='disabled',
            wrap='none',
            bg='#2d2d30',
            fg='#858585',
            font=('Consolas', 10)
        )
        self.line_numbers.grid(row=0, column=0, sticky='nsew')
        
        # Main text editor
        self.text_editor = scrolledtext.ScrolledText(
            self,
            wrap=tk.NONE,
            undo=True,
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='#ffffff',
            selectbackground='#264f78',
            font=('Consolas', 10),
            tabs='    '  # 4-space tabs
        )
        self.text_editor.grid(row=0, column=1, sticky='nsew')
        
        # Syntax highlighter
        self.highlighter = SyntaxHighlighter(self.text_editor)
        
        # Initial line numbers
        self.update_line_numbers()
        
    def setup_bindings(self):
        """Set up event bindings."""
        # Update line numbers on content change
        self.text_editor.bind('<KeyRelease>', self.on_content_change)
        self.text_editor.bind('<ButtonRelease>', self.on_content_change)
        self.text_editor.bind('<MouseWheel>', self.on_scroll)
        
        # Synchronize scrolling
        self.text_editor.bind('<Configure>', self.on_scroll)
        
        # Syntax highlighting
        self.text_editor.bind('<KeyRelease>', self.highlighter.on_text_change)
        
        # Tab handling
        self.text_editor.bind('<Tab>', self.handle_tab)
        self.text_editor.bind('<Shift-Tab>', self.handle_shift_tab)
        
    def on_content_change(self, event=None):
        """Handle content changes."""
        self.update_line_numbers()
        
    def on_scroll(self, event=None):
        """Synchronize scrolling between line numbers and text."""
        try:
            top, bottom = self.text_editor.yview()
            self.line_numbers.yview_moveto(top)
        except:
            pass
            
    def update_line_numbers(self):
        """Update line numbers display."""
        self.line_numbers.config(state='normal')
        self.line_numbers.delete('1.0', 'end')
        
        content = self.text_editor.get('1.0', 'end-1c')
        lines = content.split('\n')
        
        line_numbers_text = '\n'.join(str(i + 1) for i in range(len(lines)))
        self.line_numbers.insert('1.0', line_numbers_text)
        
        self.line_numbers.config(state='disabled')
        
    def handle_tab(self, event):
        """Handle tab key press."""
        self.text_editor.insert('insert', '    ')
        return 'break'
        
    def handle_shift_tab(self, event):
        """Handle shift+tab key press."""
        # Get current line
        current_pos = self.text_editor.index('insert')
        line_start = current_pos.split('.')[0] + '.0'
        line_end = current_pos.split('.')[0] + '.end'
        
        line_content = self.text_editor.get(line_start, line_end)
        
        # Remove leading spaces/tabs
        if line_content.startswith('    '):
            self.text_editor.delete(line_start, f"{line_start}+4c")
        elif line_content.startswith('\t'):
            self.text_editor.delete(line_start, f"{line_start}+1c")
            
        return 'break'
        
    def set_content(self, content: str):
        """Set the editor content."""
        self.text_editor.delete('1.0', 'end')
        self.text_editor.insert('1.0', content)
        self.highlighter.highlight()
        self.update_line_numbers()
        
    def get_content(self) -> str:
        """Get the editor content."""
        return self.text_editor.get('1.0', 'end-1c')
        
    def set_readonly(self, readonly: bool = True):
        """Set editor to read-only mode."""
        if readonly:
            self.text_editor.config(state='disabled')
        else:
            self.text_editor.config(state='normal')
            
    def find_text(self, search_term: str, start_pos: str = '1.0') -> str:
        """Find text in the editor."""
        return self.text_editor.search(search_term, start_pos, 'end')
        
    def highlight_line(self, line_number: int):
        """Highlight a specific line."""
        self.text_editor.tag_remove('highlight', '1.0', 'end')
        start_pos = f"{line_number}.0"
        end_pos = f"{line_number}.end"
        self.text_editor.tag_add('highlight', start_pos, end_pos)
        self.text_editor.tag_config('highlight', background='#3a3a3a')
        self.text_editor.see(start_pos)


class FindReplaceDialog:
    """Find and replace dialog for the code editor."""
    
    def __init__(self, parent, code_editor):
        self.parent = parent
        self.code_editor = code_editor
        self.dialog = None
        
    def show(self):
        """Show the find/replace dialog."""
        if self.dialog and self.dialog.winfo_exists():
            self.dialog.lift()
            return
            
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Find & Replace")
        self.dialog.geometry("400x150")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Find entry
        tk.Label(self.dialog, text="Find:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.find_var = tk.StringVar()
        find_entry = tk.Entry(self.dialog, textvariable=self.find_var, width=30)
        find_entry.grid(row=0, column=1, padx=5, pady=5)
        find_entry.focus()
        
        # Replace entry
        tk.Label(self.dialog, text="Replace:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.replace_var = tk.StringVar()
        replace_entry = tk.Entry(self.dialog, textvariable=self.replace_var, width=30)
        replace_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Buttons
        button_frame = tk.Frame(self.dialog)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        tk.Button(button_frame, text="Find Next", command=self.find_next).pack(side='left', padx=5)
        tk.Button(button_frame, text="Replace", command=self.replace_current).pack(side='left', padx=5)
        tk.Button(button_frame, text="Replace All", command=self.replace_all).pack(side='left', padx=5)
        tk.Button(button_frame, text="Close", command=self.dialog.destroy).pack(side='left', padx=5)
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.find_next())
        
    def find_next(self):
        """Find next occurrence."""
        search_term = self.find_var.get()
        if not search_term:
            return
            
        # Start search from current cursor position
        current_pos = self.code_editor.text_editor.index('insert')
        found_pos = self.code_editor.find_text(search_term, current_pos)
        
        if not found_pos:
            # Search from beginning
            found_pos = self.code_editor.find_text(search_term, '1.0')
            
        if found_pos:
            # Select found text
            end_pos = f"{found_pos}+{len(search_term)}c"
            self.code_editor.text_editor.tag_remove('sel', '1.0', 'end')
            self.code_editor.text_editor.tag_add('sel', found_pos, end_pos)
            self.code_editor.text_editor.mark_set('insert', end_pos)
            self.code_editor.text_editor.see(found_pos)
            
    def replace_current(self):
        """Replace current selection."""
        try:
            sel_start = self.code_editor.text_editor.index('sel.first')
            sel_end = self.code_editor.text_editor.index('sel.last')
            
            self.code_editor.text_editor.delete(sel_start, sel_end)
            self.code_editor.text_editor.insert(sel_start, self.replace_var.get())
            
            self.find_next()
            
        except tk.TclError:
            # No selection
            self.find_next()
            
    def replace_all(self):
        """Replace all occurrences."""
        search_term = self.find_var.get()
        replace_term = self.replace_var.get()
        
        if not search_term:
            return
            
        content = self.code_editor.get_content()
        new_content = content.replace(search_term, replace_term)
        
        if content != new_content:
            self.code_editor.set_content(new_content)
            tk.messagebox.showinfo("Replace All", f"Replaced {content.count(search_term)} occurrences.")
        else:
            tk.messagebox.showinfo("Replace All", "No occurrences found.")