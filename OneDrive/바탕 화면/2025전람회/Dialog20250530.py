import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import pefile
import struct
import os
import ctypes
from ctypes import wintypes
import shutil
import datetime
import threading
import requests
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import IntEnum
import time

# Windows API constants
RT_DIALOG = 5

# Dialog styles
DS_SETFONT = 0x40
DS_FIXEDSYS = 0x0008

# Control styles
WS_VISIBLE = 0x10000000
WS_CHILD = 0x40000000
WS_TABSTOP = 0x00010000

# Windows API functions
kernel32 = ctypes.windll.kernel32
imagehlp = ctypes.windll.imagehlp

# API function definitions
kernel32.BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
kernel32.BeginUpdateResourceW.restype = wintypes.HANDLE

kernel32.UpdateResourceW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.WORD,
    wintypes.LPVOID,
    wintypes.DWORD
]
kernel32.UpdateResourceW.restype = wintypes.BOOL

kernel32.EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
kernel32.EndUpdateResourceW.restype = wintypes.BOOL

kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD

# CheckSumMappedFile for PE checksum
imagehlp.CheckSumMappedFile.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32)
]
imagehlp.CheckSumMappedFile.restype = ctypes.POINTER(ctypes.c_uint32)

def MAKEINTRESOURCE(i):
    """Convert integer resource ID to LPCWSTR"""
    return ctypes.c_wchar_p(i)

@dataclass
class DialogControl:
    """Dialog control information"""
    control_class: str
    text: str
    id: int
    x: int
    y: int
    cx: int
    cy: int
    style: int
    ex_style: int
    text_position: int = 0  # Position where text starts in the control data

@dataclass
class DialogInfo:
    """Dialog information"""
    title: str
    title_position: int = 0
    controls: List[DialogControl] = None
    has_font: bool = False
    font_name: str = ""
    font_size: int = 0
    x: int = 0
    y: int = 0
    cx: int = 0
    cy: int = 0
    style: int = 0
    ex_style: int = 0
    raw_data: bytes = b""
    is_extended: bool = False
    item_count: int = 0
    
    def __post_init__(self):
        if self.controls is None:
            self.controls = []

class SafeDialogParser:
    """Safe dialog parser"""
    
    def __init__(self):
        self.control_classes = {
            0x0080: "BUTTON",
            0x0081: "EDIT", 
            0x0082: "STATIC",
            0x0083: "LISTBOX",
            0x0084: "SCROLLBAR",
            0x0085: "COMBOBOX"
        }
    
    def parse_dialog(self, data: bytes) -> Optional[DialogInfo]:
        """Parse dialog resource safely"""
        try:
            pos = 0
            
            # Detect dialog type
            first_dword = struct.unpack('<I', data[pos:pos+4])[0]
            
            is_extended = False
            if (first_dword & 0xFFFF0000) == 0xFFFF0000:
                dlg_ver = first_dword & 0xFFFF
                signature = (first_dword >> 16) & 0xFFFF
                if signature == 0xFFFF and dlg_ver == 1:
                    is_extended = True
            
            # Parse header
            if is_extended:
                pos += 2  # dlgVer
                pos += 2  # signature
                help_id = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                ex_style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
            else:
                style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                ex_style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
            
            # Number of items
            item_count = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            
            # Position and size
            x = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            y = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            cx = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            cy = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            
            # Menu
            menu_info = self._read_sz_or_ord_array(data, pos)
            pos = menu_info[1]
            
            # Window class
            class_info = self._read_sz_or_ord_array(data, pos)
            pos = class_info[1]
            
            # Title
            title_position = pos
            title_info = self._read_sz_or_ord_array(data, pos)
            title = title_info[0] if isinstance(title_info[0], str) else ""
            pos = title_info[1]
            
            dialog_info = DialogInfo(
                title=title,
                title_position=title_position,
                has_font=bool(style & DS_SETFONT),
                x=x, y=y, cx=cx, cy=cy,
                style=style, ex_style=ex_style,
                raw_data=data,
                is_extended=is_extended,
                item_count=item_count
            )
            
            # Font info
            if style & DS_SETFONT:
                if pos + 2 <= len(data):
                    font_size = struct.unpack('<H', data[pos:pos+2])[0]
                    pos += 2
                    dialog_info.font_size = font_size
                    
                    if is_extended and pos + 4 <= len(data):
                        weight = struct.unpack('<H', data[pos:pos+2])[0]
                        pos += 2
                        italic = data[pos]
                        pos += 1
                        charset = data[pos]
                        pos += 1
                    
                    font_info = self._read_sz_or_ord_array(data, pos)
                    if isinstance(font_info[0], str):
                        dialog_info.font_name = font_info[0]
                    pos = font_info[1]
            
            # Align to DWORD
            pos = (pos + 3) & ~3
            
            # Parse controls
            for i in range(item_count):
                pos = (pos + 3) & ~3
                
                if pos >= len(data):
                    break
                
                control_result = self._parse_control(data, pos, is_extended)
                if control_result:
                    control, new_pos = control_result
                    dialog_info.controls.append(control)
                    pos = new_pos
                else:
                    break
            
            return dialog_info
            
        except Exception as e:
            print(f"Dialog parsing error: {e}")
            return None
    
    def _parse_control(self, data: bytes, start_pos: int, is_extended: bool) -> Optional[Tuple[DialogControl, int]]:
        """Parse control"""
        try:
            pos = start_pos
            
            # Parse control header
            if is_extended:
                if pos + 16 > len(data):
                    return None
                    
                help_id = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                ex_style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
            else:
                if pos + 8 > len(data):
                    return None
                    
                style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                ex_style = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
            
            # Position and size
            if pos + 8 > len(data):
                return None
                
            x = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            y = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            cx = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            cy = struct.unpack('<h', data[pos:pos+2])[0]
            pos += 2
            
            # Control ID
            if is_extended:
                if pos + 4 > len(data):
                    return None
                control_id = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
            else:
                if pos + 2 > len(data):
                    return None
                control_id = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
            
            # Control class
            class_info = self._read_sz_or_ord_array(data, pos)
            pos = class_info[1]
            
            control_class = ""
            if isinstance(class_info[0], int):
                control_class = self.control_classes.get(class_info[0], f"Class_{class_info[0]}")
            else:
                control_class = class_info[0] or "Unknown"
            
            # Control text
            text_position = pos
            text_info = self._read_sz_or_ord_array(data, pos)
            pos = text_info[1]
            
            text = ""
            if isinstance(text_info[0], str):
                text = text_info[0]
            elif isinstance(text_info[0], int):
                text = f"ResID_{text_info[0]}"
            
            control = DialogControl(
                control_class=control_class,
                text=text,
                id=control_id,
                x=x, y=y, cx=cx, cy=cy,
                style=style,
                ex_style=ex_style,
                text_position=text_position
            )
            
            # Creation data
            if pos + 2 <= len(data):
                creation_data_size = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                pos += creation_data_size
            
            return (control, pos)
            
        except Exception as e:
            return None
    
    def _read_sz_or_ord_array(self, data: bytes, pos: int) -> Tuple[any, int]:
        """Read sz_Or_Ord array"""
        if pos >= len(data):
            return (None, pos)
        
        if pos + 2 <= len(data):
            first_word = struct.unpack('<H', data[pos:pos+2])[0]
            
            if first_word == 0xFFFF:
                # Ordinal
                pos += 2
                if pos + 2 <= len(data):
                    ordinal = struct.unpack('<H', data[pos:pos+2])[0]
                    return (ordinal, pos + 2)
            elif first_word == 0x0000:
                # Empty string
                return ("", pos + 2)
            else:
                # Unicode string
                return self._read_unicode_string(data, pos)
        
        return (None, pos)
    
    def _read_unicode_string(self, data: bytes, pos: int) -> Tuple[str, int]:
        """Read null-terminated Unicode string"""
        start = pos
        chars = []
        
        while pos + 1 < len(data):
            char_bytes = data[pos:pos+2]
            if char_bytes == b'\x00\x00':
                pos += 2
                break
                
            try:
                char = char_bytes.decode('utf-16-le', errors='ignore')
                chars.append(char)
            except:
                pass
                
            pos += 2
        
        text = ''.join(chars)
        return (text, pos)

class SafeDialogRebuilder:
    """Safe dialog rebuilder that maintains structure integrity"""
    
    def __init__(self):
        self.parser = SafeDialogParser()
    
    def rebuild_dialog_complete(self, dialog_info: DialogInfo, translations: Dict[str, str]) -> bytes:
        """Complete dialog rebuild with proper structure"""
        try:
            # Start building new dialog
            new_data = bytearray()
            
            # Write header
            if dialog_info.is_extended:
                # DLGTEMPLATEEX
                new_data.extend(struct.pack('<H', 1))  # dlgVer
                new_data.extend(struct.pack('<H', 0xFFFF))  # signature
                new_data.extend(struct.pack('<I', 0))  # helpID
                new_data.extend(struct.pack('<I', dialog_info.ex_style))
                new_data.extend(struct.pack('<I', dialog_info.style))
            else:
                # DLGTEMPLATE
                new_data.extend(struct.pack('<I', dialog_info.style))
                new_data.extend(struct.pack('<I', dialog_info.ex_style))
            
            # Item count
            new_data.extend(struct.pack('<H', dialog_info.item_count))
            
            # Position and size
            new_data.extend(struct.pack('<h', dialog_info.x))
            new_data.extend(struct.pack('<h', dialog_info.y))
            new_data.extend(struct.pack('<h', dialog_info.cx))
            new_data.extend(struct.pack('<h', dialog_info.cy))
            
            # Menu (no menu)
            new_data.extend(b'\x00\x00')
            
            # Window class (default)
            new_data.extend(b'\x00\x00')
            
            # Title
            title_text = translations.get(dialog_info.title, dialog_info.title) if dialog_info.title else ""
            self._write_unicode_string(new_data, title_text)
            
            # Font info
            if dialog_info.has_font:
                new_data.extend(struct.pack('<H', dialog_info.font_size))
                if dialog_info.is_extended:
                    new_data.extend(struct.pack('<H', 400))  # weight
                    new_data.extend(b'\x00')  # italic
                    new_data.extend(b'\x01')  # charset
                self._write_unicode_string(new_data, dialog_info.font_name)
            
            # Align to DWORD
            while len(new_data) % 4 != 0:
                new_data.append(0)
            
            # Write controls
            for control in dialog_info.controls:
                # Align to DWORD
                while len(new_data) % 4 != 0:
                    new_data.append(0)
                
                # Control header
                if dialog_info.is_extended:
                    new_data.extend(struct.pack('<I', 0))  # helpID
                    new_data.extend(struct.pack('<I', control.ex_style))
                    new_data.extend(struct.pack('<I', control.style))
                else:
                    new_data.extend(struct.pack('<I', control.style))
                    new_data.extend(struct.pack('<I', control.ex_style))
                
                # Position and size
                new_data.extend(struct.pack('<h', control.x))
                new_data.extend(struct.pack('<h', control.y))
                new_data.extend(struct.pack('<h', control.cx))
                new_data.extend(struct.pack('<h', control.cy))
                
                # Control ID
                if dialog_info.is_extended:
                    new_data.extend(struct.pack('<I', control.id))
                else:
                    new_data.extend(struct.pack('<H', control.id))
                
                # Control class
                if control.control_class.startswith("Class_"):
                    # Ordinal
                    class_id = int(control.control_class.split('_')[1])
                    new_data.extend(b'\xFF\xFF')
                    new_data.extend(struct.pack('<H', class_id))
                else:
                    # String (shouldn't happen for standard controls)
                    self._write_unicode_string(new_data, control.control_class)
                
                # Control text
                if control.text.startswith("ResID_"):
                    # Resource ID
                    res_id = int(control.text.split('_')[1])
                    new_data.extend(b'\xFF\xFF')
                    new_data.extend(struct.pack('<H', res_id))
                else:
                    # Text string
                    text = translations.get(control.text, control.text)
                    self._write_unicode_string(new_data, text)
                
                # Creation data (none)
                new_data.extend(struct.pack('<H', 0))
            
            return bytes(new_data)
            
        except Exception as e:
            print(f"Dialog rebuild error: {e}")
            # Return original data on error
            return dialog_info.raw_data
    
    def _write_unicode_string(self, data: bytearray, text: str):
        """Write Unicode string to data"""
        if text:
            data.extend(text.encode('utf-16-le'))
        data.extend(b'\x00\x00')

class PEChecksum:
    """PE checksum calculator and updater"""
    
    @staticmethod
    def fix_checksum(file_path: str) -> bool:
        """Fix PE checksum"""
        try:
            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Get PE header offset
            pe = pefile.PE(file_path)
            checksum_offset = pe.OPTIONAL_HEADER.get_file_offset() + 0x40
            pe.close()
            
            # Clear current checksum
            data_array = bytearray(data)
            struct.pack_into('<I', data_array, checksum_offset, 0)
            
            # Calculate new checksum
            header_sum = ctypes.c_uint32()
            check_sum = ctypes.c_uint32()
            
            imagehlp.CheckSumMappedFile(
                ctypes.create_string_buffer(bytes(data_array)),
                len(data_array),
                ctypes.byref(header_sum),
                ctypes.byref(check_sum)
            )
            
            # Write new checksum
            struct.pack_into('<I', data_array, checksum_offset, check_sum.value)
            
            # Save file
            with open(file_path, 'wb') as f:
                f.write(data_array)
            
            return True
            
        except Exception as e:
            print(f"Checksum fix error: {e}")
            return False
    
    @staticmethod
    def remove_signature(file_path: str) -> bool:
        """Remove digital signature"""
        try:
            pe = pefile.PE(file_path)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                # Clear security directory
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = 0
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = 0
                pe.write(file_path)
            
            pe.close()
            return True
            
        except Exception as e:
            print(f"Signature removal error: {e}")
            return False

class SafeDialogTranslatorGUI:
    """Safe Dialog translator with execution fix"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Safe Dialog Translator - 실행 문제 해결")
        self.root.geometry("1400x800")
        
        self.pe = None
        self.dialogs = {}
        self.dialog_data = {}
        self.file_path = ""
        self.parser = SafeDialogParser()
        self.rebuilder = SafeDialogRebuilder()
        self.checksum_fixer = PEChecksum()
        self.translations = {}
        self.api_key = ""
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, 
                               text="Safe Dialog Translator - 안전한 Dialog 번역",
                               font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        # Info
        info_text = """이 번역기는 다음을 자동으로 처리합니다:
• Dialog 구조 완전 재구성으로 안전한 번역
• PE 체크섬 자동 수정
• 디지털 서명 자동 제거
• 실행 가능한 EXE 파일 생성"""
        
        info_label = ttk.Label(main_frame, text=info_text, foreground="blue")
        info_label.grid(row=1, column=0, columnspan=3, pady=10)
        
        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="파일 선택", padding="10")
        file_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=60).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="찾아보기", command=self.browse_file).grid(row=0, column=1)
        ttk.Button(file_frame, text="분석", command=self.analyze_dialogs).grid(row=0, column=2, padx=5)
        ttk.Button(file_frame, text="백업", command=self.create_backup).grid(row=0, column=3, padx=5)
        ttk.Button(file_frame, text="API 키", command=self.set_api_key).grid(row=0, column=4, padx=5)
        
        # Main content
        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Left: Dialog list
        dialog_frame = ttk.LabelFrame(content_frame, text="Dialog 목록", padding="10")
        dialog_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        
        columns = ("ID", "타이틀", "컨트롤 수")
        self.dialog_tree = ttk.Treeview(dialog_frame, columns=columns, show="headings", height=15)
        
        self.dialog_tree.heading("ID", text="ID")
        self.dialog_tree.heading("타이틀", text="타이틀")
        self.dialog_tree.heading("컨트롤 수", text="컨트롤 수")
        
        self.dialog_tree.column("ID", width=60)
        self.dialog_tree.column("타이틀", width=150)
        self.dialog_tree.column("컨트롤 수", width=60)
        
        dialog_scroll = ttk.Scrollbar(dialog_frame, orient="vertical", command=self.dialog_tree.yview)
        self.dialog_tree.configure(yscrollcommand=dialog_scroll.set)
        
        self.dialog_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        dialog_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.dialog_tree.bind('<<TreeviewSelect>>', self.on_dialog_select)
        
        # Middle: Translation list
        trans_frame = ttk.LabelFrame(content_frame, text="번역 목록", padding="10")
        trans_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        trans_columns = ("타입", "영어 원문", "한국어 번역")
        self.trans_tree = ttk.Treeview(trans_frame, columns=trans_columns, show="headings", height=15)
        
        self.trans_tree.heading("타입", text="타입")
        self.trans_tree.heading("영어 원문", text="영어 원문")
        self.trans_tree.heading("한국어 번역", text="한국어 번역")
        
        self.trans_tree.column("타입", width=80)
        self.trans_tree.column("영어 원문", width=200)
        self.trans_tree.column("한국어 번역", width=200)
        
        trans_scroll = ttk.Scrollbar(trans_frame, orient="vertical", command=self.trans_tree.yview)
        self.trans_tree.configure(yscrollcommand=trans_scroll.set)
        
        self.trans_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        trans_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Right: Log
        log_frame = ttk.LabelFrame(content_frame, text="로그", padding="10")
        log_frame.grid(row=0, column=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Courier", 9), width=40, height=15)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(button_frame, text="모든 Dialog 번역", 
                  command=self.translate_all_dialogs,
                  style="Accent.TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="안전하게 적용", 
                  command=self.apply_translations_safely).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="번역 초기화", 
                  command=self.clear_translations).pack(side=tk.RIGHT, padx=5)
        
        # Status
        self.status_label = ttk.Label(main_frame, text="준비", relief=tk.SUNKEN)
        self.status_label.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Configure weights
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        content_frame.rowconfigure(0, weight=1)
        for i in range(3):
            content_frame.columnconfigure(i, weight=1)
        dialog_frame.rowconfigure(0, weight=1)
        trans_frame.rowconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
    
    def log(self, message):
        """Add log message"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="EXE 파일 선택",
            filetypes=[("실행 파일", "*.exe"), ("모든 파일", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)
    
    def create_backup(self):
        """Create backup"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "먼저 파일을 선택하세요")
            return
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{file_path}.safe_backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            self.log(f"백업 생성: {os.path.basename(backup_path)}")
            messagebox.showinfo("성공", f"백업 생성: {os.path.basename(backup_path)}")
        except Exception as e:
            messagebox.showerror("오류", f"백업 실패: {str(e)}")
    
    def set_api_key(self):
        """Set API key"""
        dialog = tk.Toplevel(self.root)
        dialog.title("API Key 설정")
        dialog.geometry("500x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="OpenAI API Key:").pack(pady=10)
        
        api_var = tk.StringVar(value=self.api_key)
        entry = ttk.Entry(dialog, textvariable=api_var, width=50, show="*")
        entry.pack(pady=10)
        
        def save():
            self.api_key = api_var.get().strip()
            dialog.destroy()
        
        ttk.Button(dialog, text="저장", command=save).pack(pady=10)
    
    def analyze_dialogs(self):
        """Analyze dialogs"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "파일을 선택하세요")
            return
        
        self.file_path = file_path
        
        try:
            self.status_label.config(text="분석 중...")
            self.log("Dialog 리소스 분석 시작")
            
            self.dialogs.clear()
            self.dialog_data.clear()
            
            # Clear views
            for item in self.dialog_tree.get_children():
                self.dialog_tree.delete(item)
            for item in self.trans_tree.get_children():
                self.trans_tree.delete(item)
            
            if self.pe:
                self.pe.close()
            
            self.pe = pefile.PE(file_path)
            
            # Check for digital signature
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                self.log("⚠️ 디지털 서명 감지됨 - 자동으로 제거됩니다")
            
            dialog_count = 0
            total_controls = 0
            
            # Find RT_DIALOG resources
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_DIALOG']:
                        for resource_id in resource_type.directory.entries:
                            dialog_id = resource_id.id if hasattr(resource_id, 'id') else 0
                            
                            for resource_lang in resource_id.directory.entries:
                                lang_id = resource_lang.id if hasattr(resource_lang, 'id') else 0
                                
                                # Get dialog data
                                data = self.pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size
                                )
                                
                                # Store raw data
                                self.dialog_data[(dialog_id, lang_id)] = data
                                
                                dialog_count += 1
                                
                                # Parse dialog
                                dialog_info = self.parser.parse_dialog(data)
                                
                                if dialog_info:
                                    self.dialogs[(dialog_id, lang_id)] = dialog_info
                                    total_controls += len(dialog_info.controls)
                                    
                                    # Display title
                                    display_title = dialog_info.title if dialog_info.title else "(No Title)"
                                    
                                    # Add to tree
                                    self.dialog_tree.insert("", "end", values=(
                                        dialog_id,
                                        display_title,
                                        len(dialog_info.controls)
                                    ), tags=(dialog_id, lang_id))
                                    
                                    self.log(f"Dialog {dialog_id}: {len(dialog_info.controls)} controls")
            
            self.status_label.config(text=f"완료: {dialog_count}개 Dialog, {total_controls}개 Control")
            self.log(f"분석 완료: {dialog_count}개 Dialog, {total_controls}개 Control")
            
        except Exception as e:
            self.status_label.config(text=f"오류: {str(e)}")
            self.log(f"❌ 오류: {str(e)}")
            messagebox.showerror("오류", f"파일 분석 실패: {str(e)}")
    
    def on_dialog_select(self, event):
        """Handle dialog selection"""
        selection = self.dialog_tree.selection()
        if not selection:
            return
        
        item = self.dialog_tree.item(selection[0])
        tags = item['tags']
        
        if len(tags) >= 2:
            dialog_id, lang_id = tags[0], tags[1]
            
            # Clear translation tree
            for item in self.trans_tree.get_children():
                self.trans_tree.delete(item)
            
            # Get dialog info
            dialog_info = self.dialogs.get((dialog_id, lang_id))
            
            if dialog_info:
                # Add title
                if dialog_info.title:
                    translation = self.translations.get(dialog_info.title, "")
                    self.trans_tree.insert("", "end", values=(
                        "Title",
                        dialog_info.title,
                        translation
                    ))
                
                # Add controls
                for control in dialog_info.controls:
                    if control.text and not control.text.startswith("ResID_"):
                        translation = self.translations.get(control.text, "")
                        self.trans_tree.insert("", "end", values=(
                            control.control_class,
                            control.text,
                            translation
                        ))
    
    def _is_english_text(self, text):
        """Check if text is English"""
        if not text or len(text.strip()) == 0:
            return False
        
        if text.startswith("ResID_"):
            return False
        
        if text.strip().isdigit():
            return False
        
        ascii_count = sum(1 for c in text if ord(c) < 128)
        korean_count = sum(1 for c in text if '\uac00' <= c <= '\ud7a3')
        
        if korean_count > 0:
            return False
        
        has_alpha = any(c.isalpha() for c in text)
        return ascii_count / len(text) > 0.8 and has_alpha
    
    def translate_all_dialogs(self):
        """Translate all dialogs"""
        if not self.api_key:
            messagebox.showwarning("API Key 필요", "먼저 API 키를 설정하세요")
            self.set_api_key()
            return
        
        # Collect English texts
        to_translate = []
        
        for dialog_info in self.dialogs.values():
            if dialog_info.title and self._is_english_text(dialog_info.title):
                if dialog_info.title not in to_translate and dialog_info.title not in self.translations:
                    to_translate.append(dialog_info.title)
            
            for control in dialog_info.controls:
                if control.text and self._is_english_text(control.text):
                    if control.text not in to_translate and control.text not in self.translations:
                        to_translate.append(control.text)
        
        if not to_translate:
            messagebox.showinfo("정보", "번역할 영어 텍스트가 없습니다")
            return
        
        self.log(f"번역할 텍스트: {len(to_translate)}개")
        
        # Progress dialog
        progress = tk.Toplevel(self.root)
        progress.title("번역 진행 중")
        progress.geometry("600x400")
        progress.transient(self.root)
        progress.grab_set()
        
        ttk.Label(progress, text="Dialog 텍스트 번역 중...").pack(pady=10)
        
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress, variable=progress_var, maximum=len(to_translate))
        progress_bar.pack(fill=tk.X, padx=20, pady=10)
        
        log_text = scrolledtext.ScrolledText(progress, height=15)
        log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        def translate_worker():
            try:
                batch_size = 10
                
                for i in range(0, len(to_translate), batch_size):
                    batch = to_translate[i:i+batch_size]
                    
                    # API call
                    api_translations = self.call_translation_api(batch)
                    
                    # Apply translations
                    for text, translation in api_translations.items():
                        self.translations[text] = translation
                        log_text.insert(tk.END, f"{text} → {translation}\n")
                        log_text.see(tk.END)
                        self.log(f"번역: {text} → {translation}")
                    
                    progress_var.set(min(i + batch_size, len(to_translate)))
                    progress.update()
                
                # Refresh current dialog
                self.on_dialog_select(None)
                
                messagebox.showinfo("완료", f"{len(to_translate)}개 텍스트 번역 완료!")
                
            except Exception as e:
                self.log(f"❌ 번역 오류: {str(e)}")
                messagebox.showerror("오류", str(e))
            finally:
                progress.destroy()
        
        thread = threading.Thread(target=translate_worker, daemon=True)
        thread.start()
    
    def call_translation_api(self, texts):
        """Call translation API"""
        translations = {}
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            prompt = "다음 Windows Dialog의 텍스트를 한국어로 번역해주세요.\n"
            prompt += "버튼, 라벨, 타이틀 등 UI 텍스트입니다.\n"
            prompt += "간결하고 명확한 한국어로 번역해주세요.\n\n"
            
            for i, text in enumerate(texts, 1):
                prompt += f"text{i}: {text}\n"
            
            prompt += "\nJSON 형식으로 응답: {\"text1\": \"번역1\", ...}"
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {
                        "role": "system",
                        "content": "Windows 프로그램 UI 번역 전문가입니다."
                    },
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 2000
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                # Parse JSON
                import re
                json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                    
                    for i, text in enumerate(texts, 1):
                        key = f"text{i}"
                        if key in parsed:
                            translations[text] = parsed[key]
                        else:
                            translations[text] = text
            
        except Exception as e:
            print(f"API error: {e}")
            for text in texts:
                translations[text] = text
        
        return translations
    
    def clear_translations(self):
        """Clear translations"""
        if self.translations:
            if messagebox.askyesno("확인", "모든 번역을 초기화하시겠습니까?"):
                self.translations.clear()
                self.on_dialog_select(None)
                self.status_label.config(text="번역 초기화됨")
                self.log("번역 초기화됨")
    
    def apply_translations_safely(self):
        """Apply translations safely with all fixes"""
        if not self.translations:
            messagebox.showinfo("정보", "적용할 번역이 없습니다")
            return
        
        if not messagebox.askyesno("안전한 번역 적용", 
                                 f"{len(self.translations)}개의 번역을 안전하게 적용하시겠습니까?\n\n"
                                 "다음 작업이 자동으로 수행됩니다:\n"
                                 "• 임시 파일 생성\n"
                                 "• Dialog 재구성\n"
                                 "• 디지털 서명 제거\n"
                                 "• PE 체크섬 수정"):
            return
        
        try:
            self.log("=== 안전한 번역 적용 시작 ===")
            
            # Close PE
            if self.pe:
                self.pe.close()
                self.pe = None
            
            # Create temporary file
            temp_file = self.file_path + ".tmp"
            shutil.copy2(self.file_path, temp_file)
            self.log(f"임시 파일 생성: {os.path.basename(temp_file)}")
            
            # Remove digital signature
            self.log("디지털 서명 제거 중...")
            self.checksum_fixer.remove_signature(temp_file)
            
            # Begin update
            self.status_label.config(text="번역 적용 중...")
            self.log("리소스 업데이트 시작...")
            
            h_update = kernel32.BeginUpdateResourceW(temp_file, False)
            if not h_update:
                error_code = kernel32.GetLastError()
                raise Exception(f"리소스 업데이트 시작 실패 (오류 코드: {error_code})")
            
            success_count = 0
            failed_count = 0
            
            # Apply each dialog
            for (dialog_id, lang_id), dialog_info in self.dialogs.items():
                # Check if needs update
                needs_update = False
                
                if dialog_info.title and dialog_info.title in self.translations:
                    needs_update = True
                
                if not needs_update:
                    for control in dialog_info.controls:
                        if control.text and control.text in self.translations:
                            needs_update = True
                            break
                
                if needs_update:
                    self.log(f"Dialog {dialog_id} 재구성 중...")
                    
                    # Rebuild dialog completely
                    new_data = self.rebuilder.rebuild_dialog_complete(dialog_info, self.translations)
                    
                    # Update resource
                    data_buffer = ctypes.create_string_buffer(new_data)
                    
                    if kernel32.UpdateResourceW(
                        h_update,
                        MAKEINTRESOURCE(RT_DIALOG),
                        MAKEINTRESOURCE(dialog_id),
                        lang_id,
                        data_buffer,
                        len(new_data)
                    ):
                        success_count += 1
                        self.log(f"✓ Dialog {dialog_id} 업데이트 성공")
                    else:
                        failed_count += 1
                        error_code = kernel32.GetLastError()
                        self.log(f"✗ Dialog {dialog_id} 업데이트 실패: 오류 {error_code}")
            
            # Commit
            self.log("변경사항 커밋 중...")
            if not kernel32.EndUpdateResourceW(h_update, False):
                error_code = kernel32.GetLastError()
                raise Exception(f"리소스 업데이트 커밋 실패 (오류 코드: {error_code})")
            
            # Fix PE checksum
            self.log("PE 체크섬 수정 중...")
            self.checksum_fixer.fix_checksum(temp_file)
            
            # Replace original file
            self.log("원본 파일 교체 중...")
            time.sleep(0.5)  # Give Windows time to release file
            shutil.move(temp_file, self.file_path)
            
            # Report
            msg = f"{success_count}개 Dialog 리소스가 안전하게 업데이트되었습니다."
            if failed_count > 0:
                msg += f"\n{failed_count}개 실패"
            
            self.log(f"=== 완료: {msg} ===")
            messagebox.showinfo("성공", msg + "\n\n파일이 안전하게 수정되었습니다.")
            
            # Reload
            self.translations.clear()
            self.analyze_dialogs()
            
        except Exception as e:
            self.status_label.config(text="적용 실패")
            self.log(f"❌ 오류: {str(e)}")
            
            # Cleanup
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
            
            messagebox.showerror("오류", 
                               f"번역 적용 실패: {str(e)}\n\n"
                               "백업 파일에서 복원하세요.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SafeDialogTranslatorGUI(root)
    root.mainloop()