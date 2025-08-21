#!/usr/bin/env python3
"""
Project Management System
Organizes and manages analysis projects, sessions, and workspaces
"""

import os
import json
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid


@dataclass
class AnalysisResult:
    """Represents the results of a binary analysis."""
    binary_path: str
    analysis_date: str
    output_directory: str
    generated_files: List[str]
    analysis_summary: Dict[str, Any]
    analysis_options: Dict[str, bool]
    success: bool
    error_message: str = ""


@dataclass
class ProjectInfo:
    """Information about an analysis project."""
    project_id: str
    name: str
    description: str
    created_date: str
    modified_date: str
    project_directory: str
    binary_files: List[str]
    analysis_results: List[AnalysisResult]
    tags: List[str]
    notes: str = ""


class ProjectManager:
    """Manages analysis projects and workspaces."""
    
    def __init__(self, workspace_dir: str = None):
        if workspace_dir is None:
            # Default workspace in user's documents
            if os.name == 'nt':  # Windows
                docs_dir = Path.home() / "Documents"
            else:  # Unix-like
                docs_dir = Path.home() / "Documents"
            workspace_dir = docs_dir / "BinaryAnalyzer" / "Projects"
            
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Project registry file
        self.registry_file = self.workspace_dir / "project_registry.json"
        self.projects: Dict[str, ProjectInfo] = {}
        
        # Load existing projects
        self.load_project_registry()
        
    def load_project_registry(self):
        """Load project registry from file."""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                for project_data in data.get('projects', []):
                    # Convert analysis results back to dataclass
                    analysis_results = []
                    for result_data in project_data.get('analysis_results', []):
                        analysis_results.append(AnalysisResult(**result_data))
                        
                    project_data['analysis_results'] = analysis_results
                    project = ProjectInfo(**project_data)
                    self.projects[project.project_id] = project
                    
            except (json.JSONDecodeError, TypeError, KeyError) as e:
                print(f"Error loading project registry: {e}")
                
    def save_project_registry(self):
        """Save project registry to file."""
        try:
            # Convert projects to serializable format
            projects_data = []
            for project in self.projects.values():
                project_dict = asdict(project)
                projects_data.append(project_dict)
                
            data = {
                'version': '1.0',
                'created': datetime.now().isoformat(),
                'projects': projects_data
            }
            
            with open(self.registry_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
                
        except Exception as e:
            print(f"Error saving project registry: {e}")
            
    def create_project(self, name: str, description: str = "", tags: List[str] = None) -> str:
        """Create a new analysis project."""
        if tags is None:
            tags = []
            
        # Generate unique project ID
        project_id = str(uuid.uuid4())
        
        # Create project directory
        safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '-', '_')).strip()
        project_dir = self.workspace_dir / f"{safe_name}_{project_id[:8]}"
        project_dir.mkdir(parents=True, exist_ok=True)
        
        # Create project info
        project = ProjectInfo(
            project_id=project_id,
            name=name,
            description=description,
            created_date=datetime.now().isoformat(),
            modified_date=datetime.now().isoformat(),
            project_directory=str(project_dir),
            binary_files=[],
            analysis_results=[],
            tags=tags
        )
        
        # Save project
        self.projects[project_id] = project
        self.save_project_registry()
        
        # Create project structure
        self._create_project_structure(project_dir)
        
        return project_id
        
    def _create_project_structure(self, project_dir: Path):
        """Create standard project directory structure."""
        subdirs = [
            "binaries",      # Original binary files
            "analysis",      # Analysis results
            "generated",     # Generated code
            "builds",        # Compiled outputs
            "notes",         # Project notes and documentation
            "exports"        # Exported files
        ]
        
        for subdir in subdirs:
            (project_dir / subdir).mkdir(exist_ok=True)
            
        # Create project README
        readme_content = f"""# Binary Analysis Project
        
Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Project Structure
- `binaries/` - Original binary files
- `analysis/` - Analysis results and reports  
- `generated/` - Generated C/C++ code
- `builds/` - Compiled outputs
- `notes/` - Project notes and documentation
- `exports/` - Exported project files

## Usage
Use the Binary Analyzer GUI to add binary files and perform analysis.
Results will be organized automatically in the appropriate directories.
"""
        
        with open(project_dir / "README.md", 'w', encoding='utf-8') as f:
            f.write(readme_content)
            
    def add_binary_to_project(self, project_id: str, binary_path: str) -> bool:
        """Add a binary file to a project."""
        if project_id not in self.projects:
            return False
            
        project = self.projects[project_id]
        binary_path = str(Path(binary_path).absolute())
        
        if binary_path not in project.binary_files:
            # Copy binary to project directory
            project_dir = Path(project.project_directory)
            binaries_dir = project_dir / "binaries"
            
            source_file = Path(binary_path)
            dest_file = binaries_dir / source_file.name
            
            try:
                shutil.copy2(source_file, dest_file)
                project.binary_files.append(str(dest_file))
                project.modified_date = datetime.now().isoformat()
                self.save_project_registry()
                return True
            except Exception as e:
                print(f"Error copying binary file: {e}")
                return False
                
        return True  # Already exists
        
    def add_analysis_result(self, project_id: str, result: AnalysisResult) -> bool:
        """Add an analysis result to a project."""
        if project_id not in self.projects:
            return False
            
        project = self.projects[project_id]
        
        # Copy analysis results to project directory
        project_dir = Path(project.project_directory)
        analysis_dir = project_dir / "analysis"
        generated_dir = project_dir / "generated"
        
        try:
            # Create timestamped subdirectories
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            binary_name = Path(result.binary_path).stem
            
            analysis_subdir = analysis_dir / f"{binary_name}_{timestamp}"
            generated_subdir = generated_dir / f"{binary_name}_{timestamp}"
            
            analysis_subdir.mkdir(exist_ok=True)
            generated_subdir.mkdir(exist_ok=True)
            
            # Copy generated files
            copied_files = []
            for file_path in result.generated_files:
                source_file = Path(file_path)
                if source_file.exists():
                    # Determine destination based on file type
                    if source_file.suffix in ['.txt', '.json']:
                        dest_dir = analysis_subdir
                    else:
                        dest_dir = generated_subdir
                        
                    dest_file = dest_dir / source_file.name
                    shutil.copy2(source_file, dest_file)
                    copied_files.append(str(dest_file))
                    
            # Update result with new paths
            result.generated_files = copied_files
            result.output_directory = str(analysis_subdir)
            
            # Add to project
            project.analysis_results.append(result)
            project.modified_date = datetime.now().isoformat()
            
            # Save metadata
            metadata = {
                'analysis_date': result.analysis_date,
                'binary_path': result.binary_path,
                'success': result.success,
                'options': result.analysis_options,
                'summary': result.analysis_summary
            }
            
            with open(analysis_subdir / "metadata.json", 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, default=str)
                
            self.save_project_registry()
            return True
            
        except Exception as e:
            print(f"Error adding analysis result: {e}")
            return False
            
    def get_project(self, project_id: str) -> Optional[ProjectInfo]:
        """Get project information."""
        return self.projects.get(project_id)
        
    def get_all_projects(self) -> List[ProjectInfo]:
        """Get all projects."""
        return list(self.projects.values())
        
    def delete_project(self, project_id: str) -> bool:
        """Delete a project and its files."""
        if project_id not in self.projects:
            return False
            
        project = self.projects[project_id]
        
        try:
            # Delete project directory
            project_dir = Path(project.project_directory)
            if project_dir.exists():
                shutil.rmtree(project_dir)
                
            # Remove from registry
            del self.projects[project_id]
            self.save_project_registry()
            
            return True
            
        except Exception as e:
            print(f"Error deleting project: {e}")
            return False
            
    def export_project(self, project_id: str, export_path: str, include_binaries: bool = True) -> bool:
        """Export a project to a zip file."""
        if project_id not in self.projects:
            return False
            
        project = self.projects[project_id]
        
        try:
            import zipfile
            
            with zipfile.ZipFile(export_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                project_dir = Path(project.project_directory)
                
                for file_path in project_dir.rglob('*'):
                    if file_path.is_file():
                        # Skip binaries if not requested
                        if not include_binaries and file_path.parent.name == 'binaries':
                            continue
                            
                        # Add file to zip with relative path
                        arcname = file_path.relative_to(project_dir.parent)
                        zipf.write(file_path, arcname)
                        
                # Add project metadata
                metadata = {
                    'project_info': asdict(project),
                    'export_date': datetime.now().isoformat(),
                    'exported_by': 'Binary Analyzer GUI'
                }
                
                zipf.writestr('project_export_info.json', 
                            json.dumps(metadata, indent=2, default=str))
                            
            return True
            
        except Exception as e:
            print(f"Error exporting project: {e}")
            return False
            
    def import_project(self, import_path: str) -> Optional[str]:
        """Import a project from a zip file."""
        try:
            import zipfile
            
            with zipfile.ZipFile(import_path, 'r') as zipf:
                # Extract metadata
                metadata_content = zipf.read('project_export_info.json')
                metadata = json.loads(metadata_content)
                
                project_info = metadata['project_info']
                
                # Generate new project ID to avoid conflicts
                new_project_id = str(uuid.uuid4())
                project_info['project_id'] = new_project_id
                
                # Create new project directory
                safe_name = "".join(c for c in project_info['name'] if c.isalnum() or c in (' ', '-', '_')).strip()
                project_dir = self.workspace_dir / f"{safe_name}_{new_project_id[:8]}_imported"
                project_dir.mkdir(parents=True, exist_ok=True)
                
                # Extract all files
                zipf.extractall(project_dir.parent)
                
                # Update project info
                project_info['project_directory'] = str(project_dir)
                project_info['modified_date'] = datetime.now().isoformat()
                
                # Convert analysis results
                analysis_results = []
                for result_data in project_info.get('analysis_results', []):
                    analysis_results.append(AnalysisResult(**result_data))
                project_info['analysis_results'] = analysis_results
                
                # Create project object
                project = ProjectInfo(**project_info)
                
                # Add to registry
                self.projects[new_project_id] = project
                self.save_project_registry()
                
                return new_project_id
                
        except Exception as e:
            print(f"Error importing project: {e}")
            return None
            
    def search_projects(self, query: str, search_in: List[str] = None) -> List[ProjectInfo]:
        """Search projects by name, description, or tags."""
        if search_in is None:
            search_in = ['name', 'description', 'tags']
            
        query = query.lower()
        results = []
        
        for project in self.projects.values():
            match = False
            
            if 'name' in search_in and query in project.name.lower():
                match = True
            elif 'description' in search_in and query in project.description.lower():
                match = True
            elif 'tags' in search_in and any(query in tag.lower() for tag in project.tags):
                match = True
                
            if match:
                results.append(project)
                
        return results
        
    def get_project_statistics(self, project_id: str) -> Dict[str, Any]:
        """Get statistics for a project."""
        if project_id not in self.projects:
            return {}
            
        project = self.projects[project_id]
        
        stats = {
            'total_binaries': len(project.binary_files),
            'total_analyses': len(project.analysis_results),
            'successful_analyses': len([r for r in project.analysis_results if r.success]),
            'failed_analyses': len([r for r in project.analysis_results if not r.success]),
            'total_generated_files': sum(len(r.generated_files) for r in project.analysis_results),
            'project_size': self._calculate_project_size(project.project_directory),
            'last_analysis': None
        }
        
        # Find last analysis date
        if project.analysis_results:
            last_result = max(project.analysis_results, 
                            key=lambda r: r.analysis_date)
            stats['last_analysis'] = last_result.analysis_date
            
        return stats
        
    def _calculate_project_size(self, project_dir: str) -> int:
        """Calculate total size of project directory in bytes."""
        total_size = 0
        try:
            for file_path in Path(project_dir).rglob('*'):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
        except Exception as e:
            print(f"Error calculating project size: {e}")
        return total_size


class ProjectDialog:
    """Dialog for managing projects."""
    
    def __init__(self, parent, project_manager: ProjectManager):
        self.parent = parent
        self.project_manager = project_manager
        self.dialog = None
        self.current_project = None
        
    def show_project_browser(self):
        """Show project browser dialog."""
        if self.dialog and self.dialog.winfo_exists():
            self.dialog.lift()
            return
            
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Project Manager")
        self.dialog.geometry("800x600")
        self.dialog.transient(self.parent)
        
        self._create_project_browser()
        
    def _create_project_browser(self):
        """Create project browser interface."""
        # Main frame with toolbar and content
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Toolbar
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar, text="New Project", command=self._new_project_dialog).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Import Project", command=self._import_project).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Export Project", command=self._export_project).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Delete Project", command=self._delete_project).pack(side=tk.LEFT, padx=(0, 5))
        
        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 5))
        search_entry.bind('<KeyRelease>', self._on_search)
        
        ttk.Button(search_frame, text="Clear", command=self._clear_search).pack(side=tk.LEFT)
        
        # Projects list with details
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for projects
        columns = ("Name", "Created", "Binaries", "Analyses", "Size")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="tree headings", height=15)
        
        # Configure columns
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=0, stretch=False)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
            
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.tree.bind('<Double-1>', self._on_project_double_click)
        self.tree.bind('<ButtonRelease-1>', self._on_project_select)
        
        # Details panel
        details_frame = ttk.LabelFrame(main_frame, text="Project Details", padding="10")
        details_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.details_text = tk.Text(details_frame, height=6, wrap=tk.WORD, state=tk.DISABLED)
        details_scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scrollbar.set)
        
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load projects
        self._refresh_project_list()
        
    def _refresh_project_list(self):
        """Refresh the project list."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Add projects
        projects = self.project_manager.get_all_projects()
        for project in sorted(projects, key=lambda p: p.modified_date, reverse=True):
            stats = self.project_manager.get_project_statistics(project.project_id)
            
            # Format size
            size_mb = stats['project_size'] / (1024 * 1024)
            size_str = f"{size_mb:.1f} MB"
            
            # Format date
            created_date = datetime.fromisoformat(project.created_date).strftime("%Y-%m-%d")
            
            values = (
                project.name,
                created_date,
                stats['total_binaries'],
                stats['total_analyses'],
                size_str
            )
            
            item_id = self.tree.insert("", tk.END, values=values)
            # Store project ID with item
            self.tree.set(item_id, "project_id", project.project_id)
            
    def _on_search(self, event):
        """Handle search input."""
        query = self.search_var.get()
        if query:
            results = self.project_manager.search_projects(query)
            self._display_search_results(results)
        else:
            self._refresh_project_list()
            
    def _display_search_results(self, results):
        """Display search results."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Add search results
        for project in results:
            stats = self.project_manager.get_project_statistics(project.project_id)
            
            size_mb = stats['project_size'] / (1024 * 1024)
            size_str = f"{size_mb:.1f} MB"
            
            created_date = datetime.fromisoformat(project.created_date).strftime("%Y-%m-%d")
            
            values = (
                project.name,
                created_date,
                stats['total_binaries'],
                stats['total_analyses'],
                size_str
            )
            
            item_id = self.tree.insert("", tk.END, values=values)
            self.tree.set(item_id, "project_id", project.project_id)
            
    def _clear_search(self):
        """Clear search and refresh full list."""
        self.search_var.set("")
        self._refresh_project_list()
        
    def _on_project_select(self, event):
        """Handle project selection."""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            project_id = self.tree.set(item, "project_id")
            project = self.project_manager.get_project(project_id)
            
            if project:
                self._display_project_details(project)
                
    def _on_project_double_click(self, event):
        """Handle project double-click."""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            project_id = self.tree.set(item, "project_id")
            self.current_project = project_id
            self.dialog.destroy()
            
    def _display_project_details(self, project: ProjectInfo):
        """Display project details in the details panel."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        details = f"""Name: {project.name}
Description: {project.description}
Created: {datetime.fromisoformat(project.created_date).strftime("%Y-%m-%d %H:%M")}
Modified: {datetime.fromisoformat(project.modified_date).strftime("%Y-%m-%d %H:%M")}
Tags: {', '.join(project.tags) if project.tags else 'None'}
Location: {project.project_directory}

Binary Files: {len(project.binary_files)}
Analysis Results: {len(project.analysis_results)}

Notes: {project.notes if project.notes else 'None'}"""
        
        self.details_text.insert(1.0, details)
        self.details_text.config(state=tk.DISABLED)
        
    def _new_project_dialog(self):
        """Show new project creation dialog."""
        dialog = tk.Toplevel(self.dialog)
        dialog.title("New Project")
        dialog.geometry("400x300")
        dialog.transient(self.dialog)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Project details
        ttk.Label(frame, text="Project Name:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        name_var = tk.StringVar()
        ttk.Entry(frame, textvariable=name_var, width=40).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Label(frame, text="Description:").grid(row=1, column=0, sticky=(tk.W, tk.N), pady=(0, 5))
        desc_text = tk.Text(frame, height=4, width=30)
        desc_text.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Label(frame, text="Tags (comma-separated):").grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        tags_var = tk.StringVar()
        ttk.Entry(frame, textvariable=tags_var, width=40).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(0, 5))
        
        # Configure grid
        frame.columnconfigure(1, weight=1)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(20, 0))
        
        def create_project():
            name = name_var.get().strip()
            if not name:
                messagebox.showerror("Error", "Project name is required!")
                return
                
            description = desc_text.get(1.0, tk.END).strip()
            tags = [tag.strip() for tag in tags_var.get().split(',') if tag.strip()]
            
            project_id = self.project_manager.create_project(name, description, tags)
            if project_id:
                messagebox.showinfo("Success", "Project created successfully!")
                dialog.destroy()
                self._refresh_project_list()
            else:
                messagebox.showerror("Error", "Failed to create project!")
                
        ttk.Button(button_frame, text="Create", command=create_project).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
    def _import_project(self):
        """Import a project from zip file."""
        file_path = filedialog.askopenfilename(
            title="Import Project",
            filetypes=[("Zip files", "*.zip"), ("All files", "*.*")]
        )
        
        if file_path:
            project_id = self.project_manager.import_project(file_path)
            if project_id:
                messagebox.showinfo("Success", "Project imported successfully!")
                self._refresh_project_list()
            else:
                messagebox.showerror("Error", "Failed to import project!")
                
    def _export_project(self):
        """Export selected project."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a project to export.")
            return
            
        item = selection[0]
        project_id = self.tree.set(item, "project_id")
        project = self.project_manager.get_project(project_id)
        
        if not project:
            messagebox.showerror("Error", "Project not found!")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Project",
            defaultextension=".zip",
            filetypes=[("Zip files", "*.zip"), ("All files", "*.*")],
            initialvalue=f"{project.name}_export.zip"
        )
        
        if file_path:
            include_binaries = messagebox.askyesno("Export Options", 
                                                 "Include binary files in export?\n"
                                                 "This will increase file size significantly.")
            
            if self.project_manager.export_project(project_id, file_path, include_binaries):
                messagebox.showinfo("Success", "Project exported successfully!")
            else:
                messagebox.showerror("Error", "Failed to export project!")
                
    def _delete_project(self):
        """Delete selected project."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a project to delete.")
            return
            
        item = selection[0]
        project_id = self.tree.set(item, "project_id")
        project = self.project_manager.get_project(project_id)
        
        if not project:
            messagebox.showerror("Error", "Project not found!")
            return
            
        if messagebox.askyesno("Confirm Delete", 
                             f"Are you sure you want to delete project '{project.name}'?\n"
                             "This will permanently delete all project files!"):
            
            if self.project_manager.delete_project(project_id):
                messagebox.showinfo("Success", "Project deleted successfully!")
                self._refresh_project_list()
            else:
                messagebox.showerror("Error", "Failed to delete project!")
                
    def get_selected_project(self) -> Optional[str]:
        """Get the currently selected project ID."""
        return self.current_project