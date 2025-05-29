import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import pefile
import struct
import os
import re
import ctypes
from ctypes import wintypes
import shutil
import time
import datetime
from typing import List, Dict, Tuple, Optional, Set
import json
import threading
import requests

# Windows API constants
RT_RCDATA = 10

# Windows API functions
kernel32 = ctypes.windll.kernel32

# Define Windows API function signatures
kernel32.BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
kernel32.BeginUpdateResourceW.restype = wintypes.HANDLE

kernel32.UpdateResourceW.argtypes = [
    wintypes.HANDLE,    # hUpdate
    wintypes.LPCWSTR,   # lpType
    wintypes.LPCWSTR,   # lpName
    wintypes.WORD,      # wLanguage
    wintypes.LPVOID,    # lpData
    wintypes.DWORD      # cb
]
kernel32.UpdateResourceW.restype = wintypes.BOOL

kernel32.EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
kernel32.EndUpdateResourceW.restype = wintypes.BOOL

kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD

def MAKEINTRESOURCE(i):
    """Convert integer resource ID to LPCWSTR"""
    return ctypes.c_wchar_p(i)

class DFMCaptionParser:
    """DFM Binary format parser for Caption extraction"""
    
    def __init__(self):
        self.debug = False
        # DFM value type constants
        self.vaNull = 0
        self.vaList = 1
        self.vaInt8 = 2
        self.vaInt16 = 3
        self.vaInt32 = 4
        self.vaExtended = 5
        self.vaString = 6
        self.vaIdent = 7
        self.vaFalse = 8
        self.vaTrue = 9
        self.vaBinary = 10
        self.vaSet = 11
        self.vaLString = 12
        self.vaNil = 13
        self.vaCollection = 14
        self.vaSingle = 15
        self.vaCurrency = 16
        self.vaDate = 17
        self.vaWString = 18
        self.vaInt64 = 19
        self.vaUTF8String = 20
        
        # Supported encodings for Korean
        self.encodings = ['utf-8', 'cp949', 'euc-kr', 'latin-1', 'cp1252']
        
    def find_captions_with_positions(self, data: bytes) -> List[Dict]:
        """Find all Caption property values in DFM data"""
        captions = []
        
        # Skip TPF header if present
        offset = 0
        if len(data) > 3 and data[0:3] == b'TPF':
            offset = 4  # Skip TPF0
        
        # Parse the DFM structure
        captions = self._parse_dfm_structure(data, offset)
        
        return captions
    
    def _parse_dfm_structure(self, data: bytes, start_offset: int) -> List[Dict]:
        """Parse DFM structure to find Caption properties"""
        captions = []
        pos = start_offset
        
        while pos < len(data) - 10:
            # Look for property name patterns
            # Property names in DFM are typically prefixed with length byte
            name_len = data[pos] if pos < len(data) else 0
            
            # Check if this could be a property name
            if 3 <= name_len <= 20 and pos + name_len + 1 < len(data):
                name_bytes = data[pos+1:pos+1+name_len]
                
                # Check if it's "Caption"
                if name_bytes == b'Caption':
                    # Found Caption property, now extract the value
                    value_pos = pos + 1 + name_len
                    caption_info = self._extract_caption_value(data, value_pos)
                    
                    if caption_info:
                        captions.append(caption_info)
                        pos = value_pos + caption_info.get('skip', 1)
                    else:
                        pos += 1
                else:
                    pos += 1
            else:
                pos += 1
        
        return captions
    
    def _extract_caption_value(self, data: bytes, pos: int) -> Optional[Dict]:
        """Extract caption value based on DFM value type"""
        if pos >= len(data):
            return None
        
        # Read value type
        value_type = data[pos]
        pos += 1
        
        # Handle different value types
        if value_type == self.vaString:
            # Short string (up to 255 chars)
            if pos < len(data):
                str_len = data[pos]
                if 0 < str_len < 255 and pos + str_len + 1 <= len(data):
                    string_bytes = data[pos + 1:pos + 1 + str_len]
                    text = self._safe_decode(string_bytes)
                    if text and self._is_valid_caption(text):
                        return {
                            'text': text,
                            'position': pos + 1,
                            'length': str_len,
                            'type': 'string',
                            'skip': str_len + 2
                        }
        
        elif value_type == self.vaLString:
            # Long string (4-byte length)
            if pos + 4 <= len(data):
                str_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                if 0 < str_len < 10000 and pos + str_len <= len(data):
                    string_bytes = data[pos:pos + str_len]
                    text = self._safe_decode(string_bytes)
                    if text and self._is_valid_caption(text):
                        return {
                            'text': text,
                            'position': pos,
                            'length': str_len,
                            'type': 'lstring',
                            'skip': str_len + 5
                        }
        
        elif value_type == self.vaWString:
            # Wide string (Unicode)
            if pos + 4 <= len(data):
                str_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                byte_len = str_len * 2  # Wide chars
                if 0 < byte_len < 20000 and pos + byte_len <= len(data):
                    string_bytes = data[pos:pos + byte_len]
                    try:
                        text = string_bytes.decode('utf-16-le', errors='ignore').strip('\x00')
                        if text and self._is_valid_caption(text):
                            return {
                                'text': text,
                                'position': pos,
                                'length': byte_len,
                                'type': 'wstring',
                                'skip': byte_len + 5
                            }
                    except:
                        pass
        
        elif value_type == self.vaUTF8String:
            # UTF-8 string
            if pos + 4 <= len(data):
                str_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                if 0 < str_len < 10000 and pos + str_len <= len(data):
                    string_bytes = data[pos:pos + str_len]
                    try:
                        text = string_bytes.decode('utf-8', errors='ignore')
                        if text and self._is_valid_caption(text):
                            return {
                                'text': text,
                                'position': pos,
                                'length': str_len,
                                'type': 'utf8string',
                                'skip': str_len + 5
                            }
                    except:
                        pass
        
        # If value type didn't match, try direct string extraction
        # This handles cases where type byte might be missing
        return self._try_direct_string_extraction(data, pos - 1)
    
    def _try_direct_string_extraction(self, data: bytes, pos: int) -> Optional[Dict]:
        """Try to extract string directly when type is unclear"""
        if pos >= len(data):
            return None
        
        # Try Pascal string format
        str_len = data[pos]
        if 0 < str_len < 255 and pos + str_len + 1 <= len(data):
            string_bytes = data[pos + 1:pos + 1 + str_len]
            
            # Check if it looks like valid text
            if self._looks_like_text(string_bytes):
                text = self._safe_decode(string_bytes)
                if text and self._is_valid_caption(text):
                    return {
                        'text': text,
                        'position': pos + 1,
                        'length': str_len,
                        'type': 'direct',
                        'skip': str_len + 1
                    }
        
        return None
    
    def _looks_like_text(self, data: bytes) -> bool:
        """Check if bytes look like valid text"""
        if not data:
            return False
        
        # Count printable characters
        printable = sum(1 for b in data if 32 <= b <= 126 or b in [169, 174])
        # Allow some extended ASCII
        extended = sum(1 for b in data if 128 <= b <= 255)
        
        total_valid = printable + extended
        
        # Should be mostly printable
        return total_valid >= len(data) * 0.8
    
    def _safe_decode(self, data: bytes) -> Optional[str]:
        """Safely decode bytes trying multiple encodings including Korean"""
        if not data:
            return None
        
        # Try different encodings in order of likelihood
        # Korean encodings first if data contains potential Korean bytes
        has_high_bytes = any(b >= 128 for b in data)
        
        if has_high_bytes:
            # Likely contains non-ASCII, try Korean encodings first
            encodings = ['cp949', 'euc-kr', 'utf-8', 'latin-1', 'cp1252', 'ascii']
        else:
            # Likely ASCII only
            encodings = ['ascii', 'utf-8', 'latin-1', 'cp1252', 'cp949', 'euc-kr']
        
        for encoding in encodings:
            try:
                text = data.decode(encoding, errors='strict')
                # Remove null bytes and trim
                text = text.replace('\x00', '').strip()
                if text:
                    # Additional validation for Korean encodings
                    if encoding in ['cp949', 'euc-kr']:
                        # Check if decoded text makes sense
                        # (not just random high bytes decoded)
                        if any('\uac00' <= char <= '\ud7a3' for char in text) or all(ord(c) < 128 for c in text):
                            return text
                    else:
                        return text
            except:
                continue
        
        # Last resort: use latin-1 with replacement
        return data.decode('latin-1', errors='replace').strip()
    
    def _is_valid_caption(self, text: str) -> bool:
        """Validate if text is a valid caption"""
        if not text or len(text) == 0:
            return False
        
        # Remove whitespace for validation
        clean = text.strip()
        if not clean:
            return False
        
        # Minimum length
        if len(clean) < 1:
            return False
        
        # Maximum reasonable length for a caption
        if len(clean) > 500:
            return False
        
        # Exclude obvious non-caption values
        excluded = {
            'True', 'False', 'nil', '0', '1', '-1',
            'clBtnFace', 'clWindow', 'clWindowText',
            'bsNone', 'bsSingle', 'bsDialog',
            'poMainFormCenter', 'poScreenCenter',
            'fsNormal', 'fsBold', 'fsItalic'
        }
        
        if clean in excluded:
            return False
        
        # Must contain at least one meaningful character
        if not any(c.isalnum() or c in ' .,!?-_()[]{}/@#$%&*+=:;\'"' for c in clean):
            return False
        
        # Check for binary data patterns
        if any(ord(c) < 32 and c not in '\t\n\r' for c in clean):
            return False
        
        return True

class ImprovedCaptionExtractorGUI:
    """GUI with improved DFM parsing and file modification"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Fixed Caption Extractor")
        self.root.geometry("1200x800")
        
        self.pe = None
        self.resources = []
        self.file_path = ""
        self.parser = DFMCaptionParser()
        self.modifications = {}
        
        # API related
        self.api_key = ""
        self.translation_cache = {}
        self.basic_translations = {
            # Essential UI terms
            "OK": "확인",
            "Cancel": "취소",
            "Yes": "예", 
            "No": "아니오",
            "File": "파일",
            "Edit": "편집",
            "View": "보기",
            "Help": "도움말",
            "About": "정보",
            "Exit": "종료",
            "Close": "닫기",
            "Open": "열기",
            "Save": "저장",
            "New": "새로",
            "Delete": "삭제",
            "Copy": "복사",
            "Paste": "붙여넣기",
            "Cut": "잘라내기",
            "Select All": "모두 선택",
            "Find": "찾기",
            "Replace": "바꾸기",
            "Print": "인쇄",
            "Options": "옵션",
            "Settings": "설정",
            "Properties": "속성",
            "Window": "창",
            "Tools": "도구",
            "Format": "서식",
            "Insert": "삽입"
        }
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=70).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=1)
        ttk.Button(file_frame, text="Load Resources", command=self.load_resources).grid(row=0, column=2, padx=5)
        
        # Debug mode
        self.debug_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(file_frame, text="Debug Mode", variable=self.debug_var,
                        command=self.toggle_debug).grid(row=0, column=3, padx=10)
        
        # API Key button
        ttk.Button(file_frame, text="API Key", command=self.set_api_key).grid(row=0, column=4, padx=5)
        
        # Statistics
        self.stats_label = ttk.Label(file_frame, text="")
        self.stats_label.grid(row=1, column=0, columnspan=4, pady=5)
        
        # Main paned window
        main_paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        main_paned.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Left panel - Resource list
        left_frame = ttk.LabelFrame(main_paned, text="T-Resources in RCData", padding="10")
        
        columns = ("ID", "Name", "Size", "Captions")
        self.resource_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=20)
        
        self.resource_tree.heading("ID", text="ID")
        self.resource_tree.heading("Name", text="Resource Name")
        self.resource_tree.heading("Size", text="Size (bytes)")
        self.resource_tree.heading("Captions", text="Captions")
        
        self.resource_tree.column("ID", width=60)
        self.resource_tree.column("Name", width=140)
        self.resource_tree.column("Size", width=100)
        self.resource_tree.column("Captions", width=80)
        
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.resource_tree.yview)
        self.resource_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.resource_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.resource_tree.bind('<<TreeviewSelect>>', self.on_resource_select)
        
        # Middle panel - Data view
        middle_frame = ttk.LabelFrame(main_paned, text="Resource Data", padding="10")
        
        # Notebook
        self.data_notebook = ttk.Notebook(middle_frame)
        self.data_notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Hex view
        hex_frame = ttk.Frame(self.data_notebook)
        self.hex_text = scrolledtext.ScrolledText(hex_frame, wrap=tk.NONE, font=("Courier", 9))
        self.hex_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        hex_frame.rowconfigure(0, weight=1)
        hex_frame.columnconfigure(0, weight=1)
        
        # Debug view
        debug_frame = ttk.Frame(self.data_notebook)
        self.debug_text = scrolledtext.ScrolledText(debug_frame, wrap=tk.WORD, font=("Courier", 9))
        self.debug_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        debug_frame.rowconfigure(0, weight=1)
        debug_frame.columnconfigure(0, weight=1)
        
        self.data_notebook.add(hex_frame, text="Hex View")
        self.data_notebook.add(debug_frame, text="Debug Analysis")
        
        # Right panel - Caption list
        right_frame = ttk.LabelFrame(main_paned, text="Caption Values", padding="10")
        
        # Caption list
        caption_columns = ("Caption Text", "Position", "Type")
        self.caption_tree = ttk.Treeview(right_frame, columns=caption_columns, show="headings", height=15)
        
        self.caption_tree.heading("Caption Text", text="Caption Text")
        self.caption_tree.heading("Position", text="Position")
        self.caption_tree.heading("Type", text="Type")
        
        self.caption_tree.column("Caption Text", width=300)
        self.caption_tree.column("Position", width=80)
        self.caption_tree.column("Type", width=80)
        
        caption_scroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.caption_tree.yview)
        self.caption_tree.configure(yscrollcommand=caption_scroll.set)
        
        self.caption_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        caption_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.caption_tree.bind('<Double-Button-1>', self.on_caption_double_click)
        
        # Caption operations
        ops_frame = ttk.Frame(right_frame)
        ops_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(ops_frame, text="Edit Selected", command=self.edit_caption).pack(side=tk.LEFT, padx=2)
        ttk.Button(ops_frame, text="Replace All", command=self.batch_replace).pack(side=tk.LEFT, padx=2)
        ttk.Button(ops_frame, text="Export", command=self.export_captions).pack(side=tk.LEFT, padx=2)
        ttk.Button(ops_frame, text="Clear", command=self.clear_modifications).pack(side=tk.LEFT, padx=2)
        
        # API Translation button
        self.translate_btn = ttk.Button(ops_frame, text="API Translate", command=self.api_translate_all)
        self.translate_btn.pack(side=tk.LEFT, padx=2)
        
        # Add panels
        main_paned.add(left_frame, weight=1)
        main_paned.add(middle_frame, weight=2)
        main_paned.add(right_frame, weight=2)
        
        # Bottom frame
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(bottom_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=2)
        
        # Action buttons
        button_frame = ttk.Frame(bottom_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Apply Modifications", command=self.apply_modifications).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Batch Modify", command=self.batch_modify).pack(side=tk.RIGHT, padx=5)
        
        # Configure weights
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        main_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(0, weight=1)
        left_frame.columnconfigure(0, weight=1)
        middle_frame.rowconfigure(0, weight=1)
        middle_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)
        right_frame.columnconfigure(0, weight=1)
    
    def toggle_debug(self):
        """Toggle debug mode"""
        self.parser.debug = self.debug_var.get()
        if self.resources:
            self.on_resource_select(None)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select EXE file",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)
    
    def load_resources(self):
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("Warning", "Please select an EXE file first.")
            return
        
        self.file_path = file_path
        
        try:
            self.status_var.set("Loading resources...")
            self.resources.clear()
            self.modifications.clear()
            
            # Clear UI
            for item in self.resource_tree.get_children():
                self.resource_tree.delete(item)
            self.clear_all_views()
            
            if self.pe:
                self.pe.close()
            
            self.pe = pefile.PE(file_path)
            
            t_resource_count = 0
            total_captions = 0
            
            # Extract RT_RCDATA resources
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
                        for resource_id in resource_type.directory.entries:
                            resource_name = self.get_resource_name(resource_id)
                            
                            # Filter T-resources
                            if resource_name.startswith('T') or resource_name.startswith('t'):
                                t_resource_count += 1
                                
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(
                                        resource_lang.data.struct.OffsetToData,
                                        resource_lang.data.struct.Size
                                    )
                                    
                                    lang_id = resource_lang.id if hasattr(resource_lang, 'id') else 0
                                    
                                    # Parse DFM and find captions
                                    captions = self.parser.find_captions_with_positions(data)
                                    
                                    # Additional validation - remove duplicates
                                    unique_captions = []
                                    seen_texts = set()
                                    for cap in captions:
                                        if cap['text'] not in seen_texts:
                                            unique_captions.append(cap)
                                            seen_texts.add(cap['text'])
                                    
                                    caption_count = len(unique_captions)
                                    total_captions += caption_count
                                    
                                    resource_info = {
                                        'id': resource_id.id if hasattr(resource_id, 'id') else 'N/A',
                                        'name': resource_name,
                                        'size': len(data),
                                        'language': f"0x{lang_id:04X}",
                                        'data': data,
                                        'offset': resource_lang.data.struct.OffsetToData,
                                        'captions': unique_captions
                                    }
                                    
                                    self.resources.append(resource_info)
                                    
                                    # Add to tree
                                    self.resource_tree.insert("", "end", values=(
                                        resource_info['id'],
                                        resource_info['name'],
                                        resource_info['size'],
                                        caption_count
                                    ))
            
            # Update statistics
            self.stats_label.config(text=f"Loaded {t_resource_count} resources with {total_captions} captions")
            self.status_var.set(f"Ready - {total_captions} captions found")
            
            if not self.resources:
                messagebox.showinfo("Info", "No T-resources found in RCData section.")
                
        except Exception as e:
            self.status_var.set("Error loading file")
            messagebox.showerror("Error", f"Error loading file: {str(e)}")
    
    def get_resource_name(self, resource_id):
        """Get resource name"""
        if hasattr(resource_id, 'name') and resource_id.name:
            return str(resource_id.name)
        elif hasattr(resource_id, 'id') and resource_id.id is not None:
            return f"ID_{resource_id.id}"
        return "UNKNOWN"
    
    def on_resource_select(self, event):
        """Handle resource selection"""
        selection = self.resource_tree.selection()
        if not selection:
            return
        
        item = self.resource_tree.item(selection[0])
        values = item['values']
        
        # Find selected resource
        for resource in self.resources:
            if str(resource['name']) == str(values[1]):
                self.display_resource_details(resource)
                break
    
    def display_resource_details(self, resource):
        """Display resource details"""
        self.clear_all_views()
        
        data = resource['data']
        
        # Hex view
        hex_lines = []
        for i in range(0, len(data), 16):
            hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
            hex_lines.append(f'{i:08X}  {hex_part:<48}  |{ascii_part}|')
        self.hex_text.insert(1.0, '\n'.join(hex_lines))
        
        # Debug analysis
        debug_info = f"Resource: {resource['name']}\n"
        debug_info += f"Size: {resource['size']} bytes\n"
        debug_info += f"Caption Values Found: {len(resource['captions'])}\n"
        
        # Check DFM signature
        if len(data) > 4:
            if data[0:3] == b'TPF':
                debug_info += f"DFM Format: Binary (TPF)\n"
            else:
                debug_info += f"DFM Format: Unknown\n"
        
        debug_info += "=" * 60 + "\n\n"
        
        if self.debug_var.get():
            # Show detailed analysis
            debug_info += "=== DFM Structure Analysis ===\n"
            
            # Look for all property names
            debug_info += "\nProperty Names Found:\n"
            prop_count = 0
            
            for i in range(len(data) - 20):
                name_len = data[i]
                if 3 <= name_len <= 20 and i + name_len + 1 < len(data):
                    name_bytes = data[i+1:i+1+name_len]
                    # Check if it looks like a property name
                    if all(32 <= b <= 126 for b in name_bytes):
                        try:
                            name = name_bytes.decode('ascii')
                            # Common property name pattern
                            if name[0].isupper() or name in ['object', 'item', 'end']:
                                prop_count += 1
                                debug_info += f"  {prop_count}. '{name}' at 0x{i:04X}\n"
                                
                                # If it's Caption, show what follows
                                if name == 'Caption':
                                    value_start = i + 1 + name_len
                                    debug_info += f"     Following bytes: "
                                    for j in range(value_start, min(value_start + 20, len(data))):
                                        debug_info += f"{data[j]:02X} "
                                    debug_info += "\n"
                        except:
                            pass
        
        # Show extracted caption values
        debug_info += "\n=== Extracted Caption Values ===\n"
        for i, caption in enumerate(resource['captions']):
            debug_info += f"\n#{i+1}: '{caption['text']}'\n"
            debug_info += f"  Position: 0x{caption['position']:04X}\n"
            debug_info += f"  Length: {caption['length']} bytes\n"
            debug_info += f"  Type: {caption.get('type', 'unknown')}\n"
        
        self.debug_text.insert(1.0, debug_info)
        
        # Caption list
        for item in self.caption_tree.get_children():
            self.caption_tree.delete(item)
        
        for caption in resource['captions']:
            # Check if text contains Korean
            has_korean = any('\uac00' <= char <= '\ud7a3' for char in caption['text'])
            
            # Add Korean indicator to type if applicable
            display_type = caption.get('type', 'unknown')
            if has_korean:
                display_type += " (KR)"
            
            self.caption_tree.insert("", "end", values=(
                caption['text'],
                f"0x{caption['position']:04X}",
                display_type
            ), tags=(resource['name'], caption['text'], str(caption['position'])))
    
    def clear_all_views(self):
        """Clear all views"""
        self.hex_text.delete(1.0, tk.END)
        self.debug_text.delete(1.0, tk.END)
        for item in self.caption_tree.get_children():
            self.caption_tree.delete(item)
    
    def on_caption_double_click(self, event):
        """Handle double click"""
        self.edit_caption()
    
    def edit_caption(self):
        """Edit selected caption with Korean support"""
        selection = self.caption_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a caption to edit.")
            return
        
        item = self.caption_tree.item(selection[0])
        values = item['values']
        tags = item['tags']
        
        if len(tags) >= 2:
            resource_name = tags[0]
            old_caption = tags[1]
            caption_type = values[2]  # Get caption type
            
            # Create custom dialog for editing
            dialog = tk.Toplevel(self.root)
            dialog.title("Edit Caption")
            dialog.geometry("500x380")
            dialog.transient(self.root)
            dialog.grab_set()
            dialog.resizable(False, False)
            
            # Center the dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
            y = (dialog.winfo_screenheight() // 2) - (380 // 2)
            dialog.geometry(f"500x380+{x}+{y}")
            
            # Information frame
            info_frame = ttk.LabelFrame(dialog, text="Caption Information", padding="10")
            info_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(info_frame, text=f"Resource: {resource_name}").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"Type: {caption_type}").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"Current: {old_caption}").pack(anchor=tk.W)
            
            # Edit frame
            edit_frame = ttk.LabelFrame(dialog, text="New Caption", padding="10")
            edit_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
            
            ttk.Label(edit_frame, text="Enter new caption (Korean supported):").pack(anchor=tk.W, pady=(0, 5))
            
            # Text widget with fixed height
            text_widget = tk.Text(edit_frame, height=3, width=50, font=("Arial", 10))
            text_widget.pack(fill=tk.X, pady=5)
            text_widget.insert("1.0", old_caption)
            text_widget.focus_set()
            text_widget.tag_add(tk.SEL, "1.0", tk.END)
            
            # Warning label
            warning_label = ttk.Label(edit_frame, text="", foreground="red", wraplength=450)
            warning_label.pack(anchor=tk.W, pady=(0, 5))
            
            def check_text(*args):
                """Check text and show warnings"""
                new_text = text_widget.get("1.0", tk.END).strip()
                has_korean = any('\uac00' <= char <= '\ud7a3' for char in new_text)
                
                if has_korean:
                    if caption_type == 'string':
                        # Check byte length for different encodings
                        warnings = []
                        for encoding in ['cp949', 'utf-8']:
                            try:
                                byte_len = len(new_text.encode(encoding))
                                if byte_len > 255:
                                    warnings.append(f"{encoding}: {byte_len} bytes (max 255)")
                            except:
                                pass
                        
                        if warnings:
                            warning_label.config(text="Warning: Text too long - " + ", ".join(warnings))
                        else:
                            warning_label.config(text="Korean text will be encoded with CP949")
                    elif caption_type in ['wstring', 'utf8string']:
                        warning_label.config(text="Korean text supported (Unicode)")
                    else:
                        warning_label.config(text="Korean text will be encoded with CP949")
                else:
                    warning_label.config(text="")
            
            text_widget.bind('<KeyRelease>', check_text)
            check_text()  # Initial check
            
            # Button frame at the bottom
            button_frame = ttk.Frame(dialog)
            button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
            
            # Define save function
            def save_caption():
                new_caption = text_widget.get("1.0", tk.END).strip()
                
                if new_caption and new_caption != old_caption:
                    # Check if it's safe to save
                    has_korean = any('\uac00' <= char <= '\ud7a3' for char in new_caption)
                    
                    # Get original caption info for length check
                    original_caption_info = None
                    for cap in [c for r in self.resources if r['name'] == resource_name for c in r['captions']]:
                        if cap['text'] == old_caption:
                            original_caption_info = cap
                            break
                    
                    if has_korean and caption_type == 'string' and original_caption_info:
                        # For Pascal strings with Korean, enforce length preservation
                        original_length = original_caption_info['length']
                        safe_to_save = False
                        
                        for encoding in ['cp949', 'euc-kr']:
                            try:
                                test_bytes = new_caption.encode(encoding)
                                if len(test_bytes) <= original_length:
                                    safe_to_save = True
                                    break
                                elif len(test_bytes) < original_length + 10:
                                    # Try with padding
                                    padded = new_caption + ' ' * 10
                                    if len(padded.encode(encoding)) >= original_length:
                                        new_caption = padded[:len(padded) - (len(padded.encode(encoding)) - original_length)]
                                        safe_to_save = True
                                        break
                            except:
                                pass
                        
                        if not safe_to_save:
                            messagebox.showerror("Error", 
                                               f"Korean text is too long for this caption.\n"
                                               f"Original length: {original_length} bytes\n"
                                               f"Your text needs: {len(new_caption.encode('cp949', errors='ignore'))} bytes\n\n"
                                               f"Please use shorter Korean text or English.")
                            return
                    
                    if resource_name not in self.modifications:
                        self.modifications[resource_name] = {}
                    self.modifications[resource_name][old_caption] = new_caption
                    
                    self.status_var.set(f"Caption modified: {old_caption} → {new_caption}")
                    dialog.destroy()
                    
                    # Refresh display
                    self.on_resource_select(None)
                else:
                    dialog.destroy()
            
            # Add buttons
            ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(button_frame, text="Save", command=save_caption).pack(side=tk.RIGHT)
            
            # Keyboard shortcuts
            dialog.bind('<Return>', lambda e: save_caption())
            dialog.bind('<Escape>', lambda e: dialog.destroy())
    
    def batch_replace(self):
        """Batch replace with Korean support"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Batch Replace Captions")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Replace in all captions (Korean supported):").pack(pady=5)
        
        # Find/Replace frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(input_frame, text="Find:").grid(row=0, column=0, padx=5, sticky=tk.W)
        find_entry = ttk.Entry(input_frame, width=40, font=("Arial", 10))
        find_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)
        
        ttk.Label(input_frame, text="Replace:").grid(row=1, column=0, padx=5, sticky=tk.W, pady=5)
        replace_entry = ttk.Entry(input_frame, width=40, font=("Arial", 10))
        replace_entry.grid(row=1, column=1, padx=5, sticky=tk.EW, pady=5)
        
        input_frame.columnconfigure(1, weight=1)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=10)
        
        case_sensitive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Case sensitive", 
                       variable=case_sensitive_var).pack(anchor=tk.W)
        
        whole_word_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Whole word only", 
                       variable=whole_word_var).pack(anchor=tk.W)
        
        # Info label
        info_label = ttk.Label(main_frame, text="", foreground="blue")
        info_label.pack(pady=5)
        
        def preview_replace():
            """Preview what will be replaced"""
            find_text = find_entry.get()
            if not find_text:
                info_label.config(text="")
                return
            
            count = 0
            korean_count = 0
            
            for resource in self.resources:
                for caption in resource['captions']:
                    text = caption['text']
                    
                    if case_sensitive_var.get():
                        if whole_word_var.get():
                            import re
                            if re.search(r'\b' + re.escape(find_text) + r'\b', text):
                                count += 1
                        else:
                            if find_text in text:
                                count += 1
                    else:
                        if whole_word_var.get():
                            import re
                            if re.search(r'\b' + re.escape(find_text) + r'\b', text, re.IGNORECASE):
                                count += 1
                        else:
                            if find_text.lower() in text.lower():
                                count += 1
                    
                    # Check if replacement will introduce Korean
                    replace_text = replace_entry.get()
                    if replace_text and any('\uac00' <= char <= '\ud7a3' for char in replace_text):
                        korean_count += 1
            
            if korean_count > 0:
                info_label.config(text=f"Will replace in {count} captions (Korean text detected)")
            else:
                info_label.config(text=f"Will replace in {count} captions")
        
        find_entry.bind('<KeyRelease>', lambda e: preview_replace())
        replace_entry.bind('<KeyRelease>', lambda e: preview_replace())
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        def do_replace():
            find_text = find_entry.get()
            replace_text = replace_entry.get()
            
            if not find_text:
                messagebox.showwarning("Warning", "Please enter text to find.")
                return
            
            # Check if replacement contains Korean
            has_korean = any('\uac00' <= char <= '\ud7a3' for char in replace_text)
            
            if has_korean:
                if not messagebox.askyesno("Korean Text Detected",
                                         "The replacement text contains Korean characters.\n"
                                         "This may work better with Unicode caption types.\n"
                                         "Continue with replacement?"):
                    return
            
            count = 0
            warnings = []
            
            for resource in self.resources:
                for caption in resource['captions']:
                    old_text = caption['text']
                    new_text = old_text
                    
                    # Perform replacement based on options
                    if case_sensitive_var.get():
                        if whole_word_var.get():
                            import re
                            pattern = r'\b' + re.escape(find_text) + r'\b'
                            new_text = re.sub(pattern, replace_text, old_text)
                        else:
                            new_text = old_text.replace(find_text, replace_text)
                    else:
                        if whole_word_var.get():
                            import re
                            pattern = r'\b' + re.escape(find_text) + r'\b'
                            new_text = re.sub(pattern, replace_text, old_text, flags=re.IGNORECASE)
                        else:
                            # Case-insensitive replace
                            import re
                            new_text = re.sub(re.escape(find_text), replace_text, old_text, flags=re.IGNORECASE)
                    
                    if new_text != old_text:
                        # Check if Korean text will fit
                        if has_korean and caption.get('type') == 'string':
                            # Check byte length
                            try:
                                byte_len = len(new_text.encode('cp949'))
                                if byte_len > 255:
                                    warnings.append(f"{resource['name']}: '{old_text[:20]}...' may be too long")
                            except:
                                pass
                        
                        if resource['name'] not in self.modifications:
                            self.modifications[resource['name']] = {}
                        self.modifications[resource['name']][old_text] = new_text
                        count += 1
            
            msg = f"Modified {count} captions."
            if warnings:
                msg += "\n\nWarnings:\n" + "\n".join(warnings[:5])
                if len(warnings) > 5:
                    msg += f"\n... and {len(warnings)-5} more"
            
            messagebox.showinfo("Success", msg)
            dialog.destroy()
            self.on_resource_select(None)
        
        ttk.Button(button_frame, text="Replace All", command=do_replace).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def clear_modifications(self):
        """Clear modifications"""
        if self.modifications:
            if messagebox.askyesno("Confirm", "Clear all modifications?"):
                self.modifications.clear()
                self.on_resource_select(None)
                self.status_var.set("Modifications cleared")
    
    def export_captions(self):
        """Export captions to CSV"""
        if not any(r['captions'] for r in self.resources):
            messagebox.showwarning("Warning", "No captions to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8-sig') as f:
                    if filename.endswith('.csv'):
                        # CSV format
                        f.write("Resource,Caption,Position,Length,Type\n")
                        
                        for resource in self.resources:
                            for caption in resource['captions']:
                                # Escape quotes in caption text
                                text = caption['text'].replace('"', '""')
                                f.write(f'"{resource["name"]}",')
                                f.write(f'"{text}",')
                                f.write(f'"0x{caption["position"]:04X}",')
                                f.write(f'"{caption["length"]}",')
                                f.write(f'"{caption.get("type", "unknown")}"\n')
                    else:
                        # Text format
                        f.write("Caption Extraction Report\n")
                        f.write("=" * 80 + "\n")
                        f.write(f"File: {self.file_path}\n")
                        f.write(f"Generated: {datetime.datetime.now()}\n")
                        f.write("=" * 80 + "\n\n")
                        
                        total_captions = 0
                        for resource in self.resources:
                            if resource['captions']:
                                f.write(f"\nResource: {resource['name']}\n")
                                f.write(f"Size: {resource['size']} bytes\n")
                                f.write(f"Caption Values: {len(resource['captions'])}\n")
                                f.write("-" * 40 + "\n")
                                
                                for i, caption in enumerate(resource['captions'], 1):
                                    f.write(f"\n  Caption #{i}:\n")
                                    f.write(f"    Text: {caption['text']}\n")
                                    f.write(f"    Position: 0x{caption['position']:04X}\n")
                                    f.write(f"    Length: {caption['length']} bytes\n")
                                    f.write(f"    Type: {caption.get('type', 'unknown')}\n")
                                    total_captions += 1
                        
                        f.write(f"\n\nTotal Caption Values: {total_captions}\n")
                
                messagebox.showinfo("Success", f"Exported {sum(len(r['captions']) for r in self.resources)} captions to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def set_api_key(self):
        """Set OpenAI API key"""
        dialog = tk.Toplevel(self.root)
        dialog.title("API Key Configuration")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (200 // 2)
        dialog.geometry(f"500x200+{x}+{y}")
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Instructions
        ttk.Label(main_frame, text="Enter your OpenAI API Key:").pack(anchor=tk.W, pady=(0, 10))
        
        # API Key entry
        api_key_var = tk.StringVar(value=self.api_key)
        api_entry = ttk.Entry(main_frame, textvariable=api_key_var, width=60, show="*")
        api_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Show/Hide button
        show_var = tk.BooleanVar(value=False)
        
        def toggle_show():
            if show_var.get():
                api_entry.config(show="")
            else:
                api_entry.config(show="*")
        
        ttk.Checkbutton(main_frame, text="Show API Key", variable=show_var, 
                       command=toggle_show).pack(anchor=tk.W)
        
        # Info label
        info_text = "API Key is stored in memory only (not saved to disk)"
        ttk.Label(main_frame, text=info_text, foreground="gray").pack(pady=(10, 0))
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)
        
        def save_key():
            self.api_key = api_key_var.get().strip()
            if self.api_key:
                # Test the API key
                if self.test_api_key():
                    messagebox.showinfo("Success", "API Key validated successfully!")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Invalid API Key. Please check and try again.")
            else:
                self.api_key = ""
                dialog.destroy()
        
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Save", command=save_key).pack(side=tk.RIGHT)
        
        api_entry.focus_set()
        dialog.bind('<Return>', lambda e: save_key())
    
    def test_api_key(self):
        """Test if the API key is valid"""
        if not self.api_key:
            return False
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Simple test request
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "Hi"}],
                "max_tokens": 5
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=5
            )
            
            return response.status_code == 200
        except:
            return False
    
    def api_translate_all(self):
        """Translate all captions using API"""
        if not self.api_key:
            if not messagebox.askyesno("No API Key", 
                                     "No API key configured.\n"
                                     "Would you like to set it now?"):
                return
            self.set_api_key()
            if not self.api_key:
                return
        
        if not self.resources:
            messagebox.showwarning("Warning", "No resources loaded.")
            return
        
        # Collect all unique captions
        all_captions = []
        caption_map = {}  # Track which resources have which captions
        
        for resource in self.resources:
            for caption in resource['captions']:
                text = caption['text']
                if text not in caption_map:
                    caption_map[text] = []
                caption_map[text].append({
                    'resource': resource['name'],
                    'caption': caption
                })
                all_captions.append(caption)
        
        unique_texts = list(caption_map.keys())
        
        if not unique_texts:
            messagebox.showinfo("Info", "No captions to translate.")
            return
        
        # Ask for confirmation
        msg = f"Translate {len(unique_texts)} unique captions?\n"
        msg += f"(Total instances: {len(all_captions)})\n\n"
        msg += "This will use your OpenAI API credits."
        
        if not messagebox.askyesno("Confirm Translation", msg):
            return
        
        # Create progress window
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Translation Progress")
        progress_window.geometry("500x200")
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        # Center the window
        progress_window.update_idletasks()
        x = (progress_window.winfo_screenwidth() // 2) - (500 // 2)
        y = (progress_window.winfo_screenheight() // 2) - (200 // 2)
        progress_window.geometry(f"500x200+{x}+{y}")
        
        # Progress UI
        main_frame = ttk.Frame(progress_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        status_label = ttk.Label(main_frame, text="Preparing translation...")
        status_label.pack(pady=(0, 10))
        
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(main_frame, variable=progress_var, 
                                      maximum=len(unique_texts), length=400)
        progress_bar.pack(fill=tk.X, pady=(0, 10))
        
        detail_label = ttk.Label(main_frame, text="", foreground="gray")
        detail_label.pack()
        
        stats_label = ttk.Label(main_frame, text="")
        stats_label.pack(pady=(10, 0))
        
        cancel_flag = [False]
        
        def cancel_translation():
            cancel_flag[0] = True
            
        cancel_btn = ttk.Button(progress_window, text="Cancel", command=cancel_translation)
        cancel_btn.pack(pady=10)
        
        # Translation thread
        def translate_worker():
            translations = {}
            completed = 0
            failed = 0
            cached = 0
            
            try:
                # First, use basic dictionary
                for text in unique_texts[:]:
                    if text in self.basic_translations:
                        translations[text] = self.basic_translations[text]
                        cached += 1
                        completed += 1
                        progress_var.set(completed)
                        unique_texts.remove(text)
                
                # Update status
                self.root.after(0, lambda: status_label.config(
                    text=f"Found {cached} translations in dictionary. Translating remaining {len(unique_texts)}..."
                ))
                
                # Batch translate remaining
                batch_size = 20
                for i in range(0, len(unique_texts), batch_size):
                    if cancel_flag[0]:
                        break
                    
                    batch = unique_texts[i:i+batch_size]
                    
                    # Update UI
                    self.root.after(0, lambda b=batch: detail_label.config(
                        text=f"Translating: {b[0][:30]}..." if b else ""
                    ))
                    
                    # Translate batch
                    try:
                        batch_translations = self.translate_batch(batch, caption_map)
                        translations.update(batch_translations)
                        completed += len(batch_translations)
                    except Exception as e:
                        print(f"Batch translation error: {e}")
                        failed += len(batch)
                        # Use fallback for failed batch
                        for text in batch:
                            translations[text] = text  # Keep original
                    
                    # Update progress
                    progress_var.set(completed + failed)
                    self.root.after(0, lambda c=completed, f=failed: stats_label.config(
                        text=f"Completed: {c} | Failed: {f} | Cached: {cached}"
                    ))
                
                # Apply translations
                if not cancel_flag[0]:
                    self.root.after(0, lambda: self.apply_translations(translations, caption_map))
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Translation Complete",
                        f"Successfully translated {len(translations)} captions.\n"
                        f"Cached: {cached}\n"
                        f"API Translated: {completed - cached}\n"
                        f"Failed: {failed}"
                    ))
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Translation Error",
                    f"An error occurred during translation:\n{str(e)}"
                ))
            finally:
                self.root.after(0, progress_window.destroy)
        
        # Start translation in background
        thread = threading.Thread(target=translate_worker, daemon=True)
        thread.start()
    
    def translate_batch(self, texts, caption_map):
        """Translate a batch of texts using OpenAI API"""
        # Prepare constraints for each text
        constraints = {}
        for text in texts:
            instances = caption_map[text]
            # Find most restrictive constraint
            min_length = min(inst['caption']['length'] for inst in instances)
            caption_type = instances[0]['caption'].get('type', 'unknown')
            
            constraints[text] = {
                'max_length': min_length,
                'type': caption_type
            }
        
        # Create prompt
        prompt = self.create_batch_prompt(texts, constraints)
        
        # Call API
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a professional UI translator. Translate English UI text to Korean. Keep translations short and suitable for buttons, menus, and labels."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 1000,
            "temperature": 0.3
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code != 200:
            raise Exception(f"API error: {response.status_code}")
        
        # Parse response
        result = response.json()
        content = result['choices'][0]['message']['content']
        
        # Extract translations
        translations = self.parse_translation_response(content, texts, constraints)
        
        return translations
    
    def create_batch_prompt(self, texts, constraints):
        """Create optimized prompt for batch translation"""
        prompt = "Translate the following UI texts to Korean. "
        prompt += "Follow the constraints for each text.\n"
        prompt += "Return ONLY a JSON object with original text as key and translation as value.\n\n"
        
        prompt += "Texts to translate:\n"
        for text in texts:
            const = constraints[text]
            prompt += f'"{text}" (max {const["max_length"]} bytes in CP949)\n'
        
        prompt += '\nExample format: {"About":"정보","File":"파일"}\n'
        prompt += "\nJSON:"
        
        return prompt
    
    def parse_translation_response(self, content, texts, constraints):
        """Parse API response and validate translations"""
        translations = {}
        
        try:
            # Try to parse as JSON
            json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                # Fallback parsing
                data = {}
                for line in content.split('\n'):
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            key = parts[0].strip(' "\'')
                            value = parts[1].strip(' "\',')
                            if key in texts:
                                data[key] = value
            
            # Validate and apply constraints
            for text in texts:
                if text in data:
                    translation = data[text]
                    const = constraints[text]
                    
                    # Check length constraint
                    validated = self.validate_translation(
                        text, translation, const['max_length'], const['type']
                    )
                    
                    translations[text] = validated
                else:
                    # Use fallback
                    translations[text] = text
                    
        except Exception as e:
            print(f"Parse error: {e}")
            # Return original texts as fallback
            for text in texts:
                translations[text] = text
        
        return translations
    
    def validate_translation(self, original, translation, max_length, caption_type):
        """Validate and adjust translation to fit constraints"""
        # For string type (Pascal string), must fit in exact bytes
        if caption_type == 'string':
            # Try different encodings
            for encoding in ['cp949', 'euc-kr']:
                try:
                    encoded = translation.encode(encoding)
                    if len(encoded) <= max_length:
                        return translation
                    
                    # Try to fit by padding adjustment
                    if len(encoded) < max_length + 10:
                        # Add spaces to match length
                        padded = translation + ' ' * (max_length - len(encoded))
                        if len(padded.encode(encoding)) <= max_length:
                            return padded
                except:
                    pass
            
            # If Korean doesn't fit, try shorter translation
            if len(original) <= max_length:
                return original  # Keep English
        
        # For other types, more flexible
        return translation
    
    def apply_translations(self, translations, caption_map):
        """Apply translations to all caption instances"""
        # Clear existing modifications
        if messagebox.askyesno("Apply Translations", 
                             "Clear existing modifications and apply translations?"):
            self.modifications.clear()
        
        # Apply translations
        applied_count = 0
        for text, instances in caption_map.items():
            if text in translations:
                translated = translations[text]
                if translated != text:  # Only if actually translated
                    for instance in instances:
                        resource_name = instance['resource']
                        if resource_name not in self.modifications:
                            self.modifications[resource_name] = {}
                        self.modifications[resource_name][text] = translated
                        applied_count += 1
        
        # Update cache
        self.translation_cache.update(translations)
        
        # Refresh display
        self.on_resource_select(None)
        self.status_var.set(f"Applied {applied_count} translations")
    
    def batch_modify(self):
        """Batch modify all captions with safety checks"""
        if not self.resources:
            messagebox.showwarning("Warning", "No resources loaded.")
            return
        
        total_captions = sum(len(r['captions']) for r in self.resources)
        if total_captions == 0:
            messagebox.showinfo("Info", "No captions found.")
            return
        
        options = [
            "1. Fill with 'a' (keep exact length)",
            "2. Add prefix/suffix",
            "3. Clear all (space fill)",
            "4. Smart Korean translation",
            "5. Cancel"
        ]
        
        choice = simpledialog.askstring(
            "Batch Modify",
            f"Modify all {total_captions} captions:\n\n" + "\n".join(options) + "\n\nChoice (1-5):",
            initialvalue="1"
        )
        
        if not choice or choice == "5":
            return
        
        # Apply to all captions
        modified_count = 0
        skipped_count = 0
        
        for resource in self.resources:
            if resource['name'] not in self.modifications:
                self.modifications[resource['name']] = {}
            
            for caption in resource['captions']:
                old_text = caption['text']
                original_length = caption['length']
                caption_type = caption.get('type', 'unknown')
                
                if choice == "1":
                    # Fill with 'a' keeping exact length
                    new_text = 'a' * len(old_text)
                    self.modifications[resource['name']][old_text] = new_text
                    modified_count += 1
                    
                elif choice == "2":
                    # Add prefix/suffix
                    prefix = simpledialog.askstring("Prefix", "Enter prefix (or leave empty):", initialvalue="[")
                    suffix = simpledialog.askstring("Suffix", "Enter suffix (or leave empty):", initialvalue="]")
                    if prefix is None and suffix is None:
                        continue
                    
                    prefix = prefix or ""
                    suffix = suffix or ""
                    new_text = prefix + old_text + suffix
                    
                    # Check if it fits
                    if caption_type == 'string':
                        test_len = len(new_text.encode('latin-1', errors='ignore'))
                        if test_len <= original_length:
                            self.modifications[resource['name']][old_text] = new_text
                            modified_count += 1
                        else:
                            skipped_count += 1
                    else:
                        self.modifications[resource['name']][old_text] = new_text
                        modified_count += 1
                        
                elif choice == "3":
                    # Clear with spaces (maintain structure)
                    if caption_type == 'string':
                        new_text = ' ' * len(old_text)
                    else:
                        new_text = ""
                    self.modifications[resource['name']][old_text] = new_text
                    modified_count += 1
                    
                elif choice == "4":
                    # Smart Korean translation (safe mode)
                    # Simple example translations
                    translations = {
                        'About': '정보',
                        'OK': '확인',
                        'Cancel': '취소',
                        'File': '파일',
                        'Edit': '편집',
                        'Help': '도움말',
                        'Open': '열기',
                        'Save': '저장',
                        'Close': '닫기',
                        'Exit': '종료',
                        'Yes': '예',
                        'No': '아니오'
                    }
                    
                    # Check if we have a translation
                    if old_text in translations:
                        new_text = translations[old_text]
                        
                        # Safety check for Korean text
                        if caption_type == 'string':
                            # Check if Korean fits in original space
                            safe = False
                            for encoding in ['cp949', 'euc-kr']:
                                try:
                                    test_bytes = new_text.encode(encoding)
                                    if len(test_bytes) <= original_length:
                                        safe = True
                                        break
                                except:
                                    pass
                            
                            if safe:
                                self.modifications[resource['name']][old_text] = new_text
                                modified_count += 1
                            else:
                                skipped_count += 1
                        else:
                            # Other types are more flexible
                            self.modifications[resource['name']][old_text] = new_text
                            modified_count += 1
                    
        msg = f"Modified {modified_count} captions."
        if skipped_count > 0:
            msg += f"\nSkipped {skipped_count} captions (safety check failed)."
        
        messagebox.showinfo("Batch Modify Complete", msg)
        self.on_resource_select(None)
    
    def create_modified_data(self, resource):
        """Create modified resource data with Korean support and safety checks"""
        if resource['name'] not in self.modifications:
            return resource['data']
        
        data = bytearray(resource['data'])
        changes = self.modifications[resource['name']]
        
        # Sort captions by position (reverse) to maintain offsets
        sorted_captions = sorted(resource['captions'], key=lambda x: x['position'], reverse=True)
        
        for caption in sorted_captions:
            if caption['text'] in changes:
                new_text = changes[caption['text']]
                
                pos = caption['position']
                length = caption['length']
                caption_type = caption.get('type', 'unknown')
                
                # Detect if new text contains Korean
                has_korean = any('\uac00' <= char <= '\ud7a3' for char in new_text)
                
                # Handle different string types
                if caption_type == 'string':
                    # Pascal string - special handling for length preservation
                    if pos > 0:
                        # Choose encoding based on content
                        if has_korean:
                            # For Korean text, try to maintain original length
                            success = False
                            for encoding in ['cp949', 'euc-kr']:
                                try:
                                    new_bytes = new_text.encode(encoding, errors='strict')
                                    
                                    # CRITICAL: Maintain exact original length for safety
                                    if len(new_bytes) < length:
                                        # Pad with spaces to maintain length
                                        padding_needed = length - len(new_bytes)
                                        new_bytes = new_bytes + b' ' * padding_needed
                                    elif len(new_bytes) > length:
                                        # Try adding spaces to Korean text to fit
                                        padded_text = new_text + ' ' * 10
                                        padded_bytes = padded_text.encode(encoding, errors='strict')
                                        if len(padded_bytes) >= length:
                                            # Truncate to exact length
                                            new_bytes = padded_bytes[:length]
                                        else:
                                            continue
                                    
                                    # Ensure we have exact length
                                    if len(new_bytes) == length:
                                        # Update length byte (keep original)
                                        data[pos - 1] = length
                                        # Update string content
                                        for i in range(length):
                                            data[pos + i] = new_bytes[i]
                                        success = True
                                        break
                                except:
                                    continue
                            
                            if not success:
                                # If Korean doesn't fit, try to use ASCII representation
                                ascii_text = ''.join(c if ord(c) < 128 else '?' for c in new_text)
                                new_bytes = ascii_text.encode('ascii', errors='ignore')
                                if len(new_bytes) < length:
                                    new_bytes = new_bytes + b' ' * (length - len(new_bytes))
                                else:
                                    new_bytes = new_bytes[:length]
                                
                                data[pos - 1] = length
                                for i in range(length):
                                    data[pos + i] = new_bytes[i]
                        else:
                            # ASCII text - easier to handle
                            new_bytes = new_text.encode('latin-1', errors='ignore')
                            
                            # Maintain original length
                            if len(new_bytes) < length:
                                new_bytes = new_bytes + b' ' * (length - len(new_bytes))
                            elif len(new_bytes) > length:
                                new_bytes = new_bytes[:length]
                            
                            if len(new_bytes) == length:
                                data[pos - 1] = length
                                for i in range(length):
                                    data[pos + i] = new_bytes[i]
                
                elif caption_type == 'lstring':
                    # Long string - more flexible but still maintain structure
                    if pos >= 4:
                        if has_korean:
                            # Try CP949 first for Korean Windows compatibility
                            for encoding in ['cp949', 'utf-8']:
                                try:
                                    new_bytes = new_text.encode(encoding, errors='strict')
                                    
                                    # Check if it fits in allocated space
                                    if len(new_bytes) <= length:
                                        # Update length field
                                        length_bytes = struct.pack('<I', len(new_bytes))
                                        data[pos-4:pos] = length_bytes
                                        # Update string content
                                        for i in range(length):
                                            if i < len(new_bytes):
                                                data[pos + i] = new_bytes[i]
                                            else:
                                                data[pos + i] = 0
                                        break
                                except:
                                    continue
                        else:
                            new_bytes = new_text.encode('latin-1', errors='ignore')
                            if len(new_bytes) <= length:
                                # Update length field
                                length_bytes = struct.pack('<I', len(new_bytes))
                                data[pos-4:pos] = length_bytes
                                # Update string content
                                for i in range(length):
                                    if i < len(new_bytes):
                                        data[pos + i] = new_bytes[i]
                                    else:
                                        data[pos + i] = 0
                
                elif caption_type == 'wstring':
                    # Wide string - best for Korean but must fit
                    if pos >= 4:
                        new_bytes = new_text.encode('utf-16-le', errors='ignore')
                        if len(new_bytes) <= length:
                            # Update length field (character count)
                            char_count = len(new_text)
                            length_bytes = struct.pack('<I', char_count)
                            data[pos-4:pos] = length_bytes
                            # Update string content
                            for i in range(length):
                                if i < len(new_bytes):
                                    data[pos + i] = new_bytes[i]
                                else:
                                    data[pos + i] = 0
                
                elif caption_type == 'utf8string':
                    # UTF-8 string - good for Korean
                    if pos >= 4:
                        new_bytes = new_text.encode('utf-8', errors='ignore')
                        if len(new_bytes) <= length:
                            # Update length field
                            length_bytes = struct.pack('<I', len(new_bytes))
                            data[pos-4:pos] = length_bytes
                            # Update string content
                            for i in range(length):
                                if i < len(new_bytes):
                                    data[pos + i] = new_bytes[i]
                                else:
                                    data[pos + i] = 0
                
                elif caption_type == 'direct':
                    # Direct string replacement - must maintain exact length
                    if has_korean:
                        # Try to fit Korean with padding
                        for encoding in ['cp949', 'euc-kr']:
                            try:
                                new_bytes = new_text.encode(encoding, errors='strict')
                                if len(new_bytes) <= length:
                                    # Pad to exact length
                                    for i in range(length):
                                        if i < len(new_bytes):
                                            data[pos + i] = new_bytes[i]
                                        else:
                                            data[pos + i] = 0x20  # Space padding
                                    break
                            except:
                                continue
                    else:
                        new_bytes = new_text.encode('latin-1', errors='ignore')
                        # Always maintain exact length
                        for i in range(length):
                            if i < len(new_bytes):
                                data[pos + i] = new_bytes[i]
                            else:
                                data[pos + i] = 0x20  # Space padding
        
        return bytes(data)
    
    def _try_convert_to_wstring(self, data: bytearray, type_pos: int, text: str, available_space: int) -> bool:
        """Try to convert a string to wide string format if space allows"""
        if type_pos < 0 or type_pos >= len(data):
            return False
        
        # Calculate required space for wide string
        wide_bytes = text.encode('utf-16-le', errors='ignore')
        required_space = 5 + len(wide_bytes)  # 1 type + 4 length + string bytes
        
        if required_space <= available_space:
            # Change type to wide string
            data[type_pos] = self.vaWString
            # Write length
            char_count = len(text)
            length_bytes = struct.pack('<I', char_count)
            data[type_pos+1:type_pos+5] = length_bytes
            # Write string
            start = type_pos + 5
            for i, b in enumerate(wide_bytes):
                if start + i < len(data):
                    data[start + i] = b
            # Clear remaining bytes
            for i in range(len(wide_bytes), available_space - 5):
                if start + i < len(data):
                    data[start + i] = 0
            return True
        
        return False
    
    def apply_modifications(self):
        """Apply modifications to the exe file"""
        if not self.modifications:
            messagebox.showinfo("Info", "No modifications to apply.")
            return
        
        total_changes = sum(len(changes) for changes in self.modifications.values())
        
        # Ask about backup preference
        backup_dialog = tk.Toplevel(self.root)
        backup_dialog.title("Backup Options")
        backup_dialog.geometry("400x200")
        backup_dialog.transient(self.root)
        backup_dialog.grab_set()
        
        # Center dialog
        backup_dialog.update_idletasks()
        x = (backup_dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (backup_dialog.winfo_screenheight() // 2) - (200 // 2)
        backup_dialog.geometry(f"400x200+{x}+{y}")
        
        frame = ttk.Frame(backup_dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=f"Apply {total_changes} modifications?").pack(pady=(0, 20))
        
        backup_var = tk.StringVar(value="single")
        
        ttk.Radiobutton(frame, text="Keep single backup (overwrite)", 
                       variable=backup_var, value="single").pack(anchor=tk.W, pady=2)
        ttk.Radiobutton(frame, text="Create timestamped backup", 
                       variable=backup_var, value="timestamp").pack(anchor=tk.W, pady=2)
        ttk.Radiobutton(frame, text="No backup (not recommended)", 
                       variable=backup_var, value="none").pack(anchor=tk.W, pady=2)
        
        result = [False]
        
        def apply():
            result[0] = True
            backup_dialog.destroy()
        
        def cancel():
            backup_dialog.destroy()
        
        button_frame = ttk.Frame(backup_dialog)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)
        
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Apply", command=apply).pack(side=tk.RIGHT)
        
        backup_dialog.wait_window()
        
        if not result[0]:
            return
        
        backup_type = backup_var.get()
        
        try:
            # Handle backup based on user choice
            if backup_type != "none":
                if backup_type == "single":
                    backup_path = f"{self.file_path}.backup"
                else:  # timestamp
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_path = f"{self.file_path}.backup_{timestamp}"
                
                self.status_var.set("Creating backup...")
                shutil.copy2(self.file_path, backup_path)
            
            # Close PE file if open
            if self.pe:
                self.pe.close()
                self.pe = None
            
            # Small delay to ensure file is released
            time.sleep(0.3)
            
            # Begin update
            self.status_var.set("Updating resources...")
            h_update = kernel32.BeginUpdateResourceW(self.file_path, False)
            if not h_update:
                error_code = kernel32.GetLastError()
                raise Exception(f"Failed to begin resource update. Error code: {error_code}")
            
            success_count = 0
            failed_count = 0
            
            # Update each modified resource
            for resource in self.resources:
                if resource['name'] in self.modifications:
                    try:
                        # Create modified data
                        modified_data = self.create_modified_data(resource)
                        
                        # Prepare resource name parameter
                        if resource['name'].startswith('ID_'):
                            # Numeric ID
                            resource_id = int(resource['name'][3:])
                            resource_param = MAKEINTRESOURCE(resource_id)
                        else:
                            # String name
                            resource_param = ctypes.c_wchar_p(resource['name'])
                        
                        # Get language ID
                        language = int(resource['language'][2:], 16)
                        
                        # Create data buffer
                        data_buffer = ctypes.create_string_buffer(modified_data)
                        
                        # Update resource
                        if kernel32.UpdateResourceW(
                            h_update,
                            MAKEINTRESOURCE(RT_RCDATA),
                            resource_param,
                            language,
                            data_buffer,
                            len(modified_data)
                        ):
                            success_count += 1
                        else:
                            failed_count += 1
                            error_code = kernel32.GetLastError()
                            print(f"Failed to update resource {resource['name']}: Error {error_code}")
                        
                    except Exception as e:
                        failed_count += 1
                        print(f"Error updating resource {resource['name']}: {str(e)}")
            
            # Commit changes
            self.status_var.set("Committing changes...")
            if not kernel32.EndUpdateResourceW(h_update, False):
                error_code = kernel32.GetLastError()
                raise Exception(f"Failed to commit resource updates. Error code: {error_code}")
            
            # Report results
            msg = f"Successfully modified {success_count} resources."
            if failed_count > 0:
                msg += f"\nFailed to modify {failed_count} resources."
            
            if backup_type != "none":
                msg += f"\n\nBackup saved as: {os.path.basename(backup_path)}"
            
            messagebox.showinfo("Success" if failed_count == 0 else "Partial Success", msg)
            
            # Clear modifications and reload
            self.modifications.clear()
            self.load_resources()
            
        except Exception as e:
            self.status_var.set("Error applying modifications")
            messagebox.showerror("Error", f"Failed to apply modifications:\n{str(e)}")
            
            # Try to reload PE file
            try:
                if not self.pe:
                    self.pe = pefile.PE(self.file_path)
            except:
                pass

if __name__ == "__main__":
    root = tk.Tk()
    app = ImprovedCaptionExtractorGUI(root)
    root.mainloop()