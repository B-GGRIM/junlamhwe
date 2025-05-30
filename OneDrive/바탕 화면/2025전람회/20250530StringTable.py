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

# Windows API constants
RT_STRING = 6

# Windows API functions
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

# Define Windows API function signatures
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

def MAKEINTRESOURCE(i):
    """Convert integer resource ID to LPCWSTR"""
    return ctypes.c_wchar_p(i)

class StringTableParser:
    """String Table 파서"""
    
    def __init__(self):
        self.strings = {}  # {string_id: string_text}
    
    def parse_string_table(self, data: bytes, block_id: int) -> Dict[int, str]:
        """String Table 블록 파싱
        
        String Table은 16개 문자열씩 블록으로 저장됨
        각 문자열: [길이(2바이트)][UTF-16LE 문자열]
        """
        strings = {}
        pos = 0
        
        # 각 블록은 16개의 문자열을 포함
        base_id = (block_id - 1) * 16
        
        for i in range(16):
            if pos + 2 > len(data):
                break
            
            # 문자열 길이 (문자 수, 바이트 수 아님)
            str_len = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            
            if str_len > 0:
                # UTF-16LE로 인코딩된 문자열
                byte_len = str_len * 2
                if pos + byte_len <= len(data):
                    string_bytes = data[pos:pos+byte_len]
                    try:
                        string_text = string_bytes.decode('utf-16-le', errors='ignore')
                        string_id = base_id + i
                        strings[string_id] = string_text
                    except:
                        pass
                    pos += byte_len
            # 빈 문자열인 경우 pos는 증가하지 않음
        
        return strings
    
    def build_string_table(self, strings: Dict[int, str], block_id: int) -> bytes:
        """String Table 블록 재구성"""
        data = bytearray()
        base_id = (block_id - 1) * 16
        
        # 16개 문자열 슬롯
        for i in range(16):
            string_id = base_id + i
            
            if string_id in strings:
                # 문자열이 있는 경우
                text = strings[string_id]
                encoded = text.encode('utf-16-le')
                str_len = len(text)  # 문자 수
                
                # 길이 쓰기 (2바이트)
                data.extend(struct.pack('<H', str_len))
                # 문자열 쓰기
                data.extend(encoded)
            else:
                # 빈 문자열
                data.extend(struct.pack('<H', 0))
        
        return bytes(data)

class StringTableTranslatorGUI:
    """String Table 번역 GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("String Table Translator - 문자열 테이블 번역기")
        self.root.geometry("1200x800")
        
        self.pe = None
        self.string_tables = {}  # {(block_id, lang_id): {string_id: string}}
        self.file_path = ""
        self.parser = StringTableParser()
        self.modifications = {}  # {string_id: translated_text}
        
        self.api_key = ""
        self.current_string_id = None
        self.current_item = None
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Info frame
        info_frame = ttk.LabelFrame(main_frame, text="String Table Translator", padding="10")
        info_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        info_label = ttk.Label(info_frame, 
                             text="Windows EXE 파일의 String Table을 영어에서 한국어로 번역합니다.\n"
                             "String Table은 프로그램의 메시지, 에러, 다이얼로그 텍스트 등을 저장합니다.",
                             foreground="blue")
        info_label.pack()
        
        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="파일 선택", padding="10")
        file_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=50).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="찾아보기", command=self.browse_file).grid(row=0, column=1)
        ttk.Button(file_frame, text="로드", command=self.load_string_tables).grid(row=0, column=2, padx=5)
        ttk.Button(file_frame, text="백업", command=self.create_backup).grid(row=0, column=3, padx=5)
        ttk.Button(file_frame, text="API 키", command=self.set_api_key).grid(row=0, column=4, padx=5)
        
        # Statistics
        self.stats_label = ttk.Label(file_frame, text="", foreground="green")
        self.stats_label.grid(row=1, column=0, columnspan=5, pady=5)
        
        # Main content - Paned window
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Left panel - String list
        left_frame = ttk.LabelFrame(paned, text="문자열 목록", padding="10")
        
        # String tree
        columns = ("ID", "영어 원문", "한국어 번역", "상태")
        self.string_tree = ttk.Treeview(left_frame, columns=columns, show="tree headings", height=20)
        
        self.string_tree.heading("#0", text="블록")
        self.string_tree.heading("ID", text="ID")
        self.string_tree.heading("영어 원문", text="영어 원문")
        self.string_tree.heading("한국어 번역", text="한국어 번역")
        self.string_tree.heading("상태", text="상태")
        
        self.string_tree.column("#0", width=100)
        self.string_tree.column("ID", width=60)
        self.string_tree.column("영어 원문", width=300)
        self.string_tree.column("한국어 번역", width=300)
        self.string_tree.column("상태", width=80)
        
        # Scrollbar
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.string_tree.yview)
        self.string_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.string_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Double click to edit
        self.string_tree.bind('<Double-Button-1>', self.on_string_double_click)
        
        # Right panel - Edit area
        right_frame = ttk.LabelFrame(paned, text="편집", padding="10")
        
        # Original text
        ttk.Label(right_frame, text="영어 원문:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.original_text = scrolledtext.ScrolledText(right_frame, height=5, wrap=tk.WORD)
        self.original_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        self.original_text.config(state='disabled')
        
        # Translated text
        ttk.Label(right_frame, text="한국어 번역:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.translated_text = scrolledtext.ScrolledText(right_frame, height=5, wrap=tk.WORD)
        self.translated_text.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Buttons
        button_frame = ttk.Frame(right_frame)
        button_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(button_frame, text="저장", command=self.save_current_translation).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="API 번역", command=self.translate_current).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="모두 번역", command=self.translate_all).pack(side=tk.LEFT, padx=5)
        
        # Add panels
        paned.add(left_frame, weight=3)
        paned.add(right_frame, weight=2)
        
        # Bottom buttons
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(bottom_frame, text="번역 적용", 
                  command=self.apply_translations,
                  style="Accent.TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(bottom_frame, text="초기화", 
                  command=self.clear_modifications).pack(side=tk.RIGHT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="준비")
        status_bar = ttk.Label(bottom_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Configure weights
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        left_frame.rowconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)
        right_frame.rowconfigure(3, weight=1)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="EXE 파일 선택",
            filetypes=[("실행 파일", "*.exe"), ("모든 파일", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)
    
    def create_backup(self):
        """백업 생성"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "먼저 파일을 선택하세요")
            return
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{file_path}.string_backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            messagebox.showinfo("성공", f"백업 생성: {os.path.basename(backup_path)}")
        except Exception as e:
            messagebox.showerror("오류", f"백업 실패: {str(e)}")
    
    def load_string_tables(self):
        """String Table 로드"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "파일을 선택하세요")
            return
        
        self.file_path = file_path
        
        try:
            self.status_var.set("String Table 로드 중...")
            self.string_tables.clear()
            self.modifications.clear()
            
            # Clear tree
            for item in self.string_tree.get_children():
                self.string_tree.delete(item)
            
            if self.pe:
                self.pe.close()
            
            self.pe = pefile.PE(file_path)
            
            total_strings = 0
            block_count = 0
            
            # Find RT_STRING resources
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_STRING']:
                        for resource_id in resource_type.directory.entries:
                            block_id = resource_id.id if hasattr(resource_id, 'id') else 0
                            
                            if block_id > 0:  # Valid block ID
                                block_count += 1
                                
                                # Create block node
                                block_node = self.string_tree.insert("", "end", 
                                                                   text=f"Block {block_id}",
                                                                   open=True)
                                
                                for resource_lang in resource_id.directory.entries:
                                    lang_id = resource_lang.id if hasattr(resource_lang, 'id') else 0
                                    
                                    # Get string table data
                                    data = self.pe.get_data(
                                        resource_lang.data.struct.OffsetToData,
                                        resource_lang.data.struct.Size
                                    )
                                    
                                    # Parse strings
                                    strings = self.parser.parse_string_table(data, block_id)
                                    
                                    if strings:
                                        self.string_tables[(block_id, lang_id)] = strings
                                        total_strings += len(strings)
                                        
                                        # Add to tree
                                        for string_id, text in sorted(strings.items()):
                                            self.string_tree.insert(block_node, "end",
                                                                  values=(
                                                                      string_id,
                                                                      text,
                                                                      "",  # 번역 (아직 없음)
                                                                      "원본"
                                                                  ),
                                                                  tags=(string_id,))
            
            # Update statistics
            self.stats_label.config(
                text=f"블록 {block_count}개, 문자열 {total_strings}개 로드됨"
            )
            self.status_var.set("로드 완료")
            
        except Exception as e:
            self.status_var.set("로드 실패")
            messagebox.showerror("오류", f"파일 로드 실패: {str(e)}")
    
    def on_string_double_click(self, event):
        """문자열 더블클릭 처리"""
        selection = self.string_tree.selection()
        if selection:
            item = self.string_tree.item(selection[0])
            if 'values' in item and item['values']:
                self.load_string_to_editor(item, selection[0])
    
    def load_string_to_editor(self, item, item_id):
        """선택된 문자열을 편집기에 로드"""
        values = item['values']
        if len(values) >= 2:
            string_id = values[0]
            original = values[1]
            
            # Load original text
            self.original_text.config(state='normal')
            self.original_text.delete(1.0, tk.END)
            self.original_text.insert(1.0, original)
            self.original_text.config(state='disabled')
            
            # Load translation if exists
            self.translated_text.delete(1.0, tk.END)
            if string_id in self.modifications:
                self.translated_text.insert(1.0, self.modifications[string_id])
            elif len(values) >= 3 and values[2]:
                self.translated_text.insert(1.0, values[2])
            
            # Store current string ID
            self.current_string_id = string_id
            self.current_item = item_id
    
    def save_current_translation(self):
        """현재 편집 중인 번역 저장"""
        if hasattr(self, 'current_string_id') and self.current_string_id is not None and self.current_item is not None:
            translation = self.translated_text.get(1.0, tk.END).strip()
            if translation:
                self.modifications[self.current_string_id] = translation
                
                # Update tree
                item = self.string_tree.item(self.current_item)
                values = list(item['values'])
                values[2] = translation
                values[3] = "번역됨"
                self.string_tree.item(self.current_item, values=values)
                
                self.status_var.set(f"String ID {self.current_string_id} 번역 저장됨")
        else:
            messagebox.showwarning("경고", "편집할 문자열을 먼저 선택하세요")
    
    def translate_current(self):
        """현재 선택된 문자열 API 번역"""
        if not self.api_key:
            messagebox.showwarning("API Key 필요", "먼저 API 키를 설정하세요")
            self.set_api_key()
            return
        
        if hasattr(self, 'current_string_id'):
            original = self.original_text.get(1.0, tk.END).strip()
            if original:
                # API 호출
                translations = self.call_translation_api([original])
                if original in translations:
                    self.translated_text.delete(1.0, tk.END)
                    self.translated_text.insert(1.0, translations[original])
                    self.save_current_translation()
    
    def translate_all(self):
        """모든 문자열 API 번역"""
        if not self.api_key:
            messagebox.showwarning("API Key 필요", "먼저 API 키를 설정하세요")
            self.set_api_key()
            return
        
        # Collect all English strings
        to_translate = []
        string_map = {}  # {text: [string_ids]}
        
        for (block_id, lang_id), strings in self.string_tables.items():
            for string_id, text in strings.items():
                if self._is_english_text(text) and string_id not in self.modifications:
                    if text not in string_map:
                        string_map[text] = []
                        to_translate.append(text)
                    string_map[text].append(string_id)
        
        if not to_translate:
            messagebox.showinfo("정보", "번역할 영어 문자열이 없습니다")
            return
        
        # Progress dialog
        progress = tk.Toplevel(self.root)
        progress.title("번역 진행 중")
        progress.geometry("500x300")
        progress.transient(self.root)
        progress.grab_set()
        
        ttk.Label(progress, text="String Table 번역 중...").pack(pady=10)
        
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress, variable=progress_var, maximum=len(to_translate))
        progress_bar.pack(fill=tk.X, padx=20, pady=10)
        
        log_text = scrolledtext.ScrolledText(progress, height=10)
        log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        def translate_worker():
            try:
                batch_size = 10
                
                for i in range(0, len(to_translate), batch_size):
                    batch = to_translate[i:i+batch_size]
                    
                    # API call
                    translations = self.call_translation_api(batch)
                    
                    # Apply translations
                    for text, translation in translations.items():
                        for string_id in string_map[text]:
                            self.modifications[string_id] = translation
                        
                        log_text.insert(tk.END, f"{text} → {translation}\n")
                        log_text.see(tk.END)
                    
                    progress_var.set(min(i + batch_size, len(to_translate)))
                    progress.update()
                
                # Update tree
                self.refresh_tree()
                
                messagebox.showinfo("완료", f"{len(to_translate)}개 문자열 번역 완료!")
                
            except Exception as e:
                messagebox.showerror("오류", str(e))
            finally:
                progress.destroy()
        
        thread = threading.Thread(target=translate_worker, daemon=True)
        thread.start()
    
    def _is_english_text(self, text):
        """영어 텍스트인지 확인"""
        if not text or len(text.strip()) == 0:
            return False
        
        # 숫자만 있는 경우 제외
        if text.strip().isdigit():
            return False
        
        ascii_count = sum(1 for c in text if ord(c) < 128)
        korean_count = sum(1 for c in text if '\uac00' <= c <= '\ud7a3')
        
        # 한글이 있으면 제외
        if korean_count > 0:
            return False
        
        # ASCII 비율이 높고 알파벳이 있으면 영어
        has_alpha = any(c.isalpha() for c in text)
        return ascii_count / len(text) > 0.8 and has_alpha
    
    def call_translation_api(self, texts):
        """ChatGPT API 호출"""
        translations = {}
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            prompt = "다음 Windows 프로그램의 String Table 텍스트를 한국어로 번역해주세요.\n"
            prompt += "메시지, 에러, 상태 텍스트 등이 포함되어 있습니다.\n"
            prompt += "자연스럽고 정확한 한국어로 번역해주세요.\n\n"
            
            for i, text in enumerate(texts, 1):
                prompt += f"text{i}: {text}\n"
            
            prompt += "\nJSON 형식으로 응답: {\"text1\": \"번역1\", ...}"
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {
                        "role": "system",
                        "content": "Windows 프로그램 UI/메시지 번역 전문가입니다."
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
    
    def set_api_key(self):
        """API 키 설정"""
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
    
    def refresh_tree(self):
        """트리 뷰 새로고침"""
        # Get current state
        expanded = []
        for item in self.string_tree.get_children():
            if self.string_tree.item(item, 'open'):
                expanded.append(self.string_tree.item(item, 'text'))
        
        # Clear and rebuild
        for item in self.string_tree.get_children():
            self.string_tree.delete(item)
        
        # Rebuild tree
        for (block_id, lang_id), strings in sorted(self.string_tables.items()):
            block_text = f"Block {block_id}"
            block_node = self.string_tree.insert("", "end", 
                                               text=block_text,
                                               open=block_text in expanded)
            
            for string_id, text in sorted(strings.items()):
                translation = self.modifications.get(string_id, "")
                status = "번역됨" if translation else "원본"
                
                self.string_tree.insert(block_node, "end",
                                      values=(string_id, text, translation, status),
                                      tags=(string_id,))
    
    def clear_modifications(self):
        """번역 초기화"""
        if self.modifications:
            if messagebox.askyesno("확인", "모든 번역을 초기화하시겠습니까?"):
                self.modifications.clear()
                self.refresh_tree()
                self.status_var.set("번역 초기화됨")
    
    def apply_translations(self):
        """번역 적용"""
        if not self.modifications:
            messagebox.showinfo("정보", "적용할 번역이 없습니다")
            return
        
        if not messagebox.askyesno("번역 적용", 
                                 f"{len(self.modifications)}개의 번역을 적용하시겠습니까?\n\n"
                                 "백업을 먼저 생성하는 것을 권장합니다."):
            return
        
        try:
            # Close PE
            if self.pe:
                self.pe.close()
                self.pe = None
            
            # Begin update
            self.status_var.set("번역 적용 중...")
            h_update = kernel32.BeginUpdateResourceW(self.file_path, False)
            if not h_update:
                raise Exception("리소스 업데이트 시작 실패")
            
            success_count = 0
            
            # Apply each string table block
            for (block_id, lang_id), strings in self.string_tables.items():
                # Build new string table with translations
                new_strings = {}
                modified = False
                
                for string_id, original in strings.items():
                    if string_id in self.modifications:
                        new_strings[string_id] = self.modifications[string_id]
                        modified = True
                    else:
                        new_strings[string_id] = original
                
                if modified:
                    # Build new string table data
                    new_data = self.parser.build_string_table(new_strings, block_id)
                    
                    # Update resource
                    data_buffer = ctypes.create_string_buffer(new_data)
                    
                    if kernel32.UpdateResourceW(
                        h_update,
                        MAKEINTRESOURCE(RT_STRING),
                        MAKEINTRESOURCE(block_id),
                        lang_id,
                        data_buffer,
                        len(new_data)
                    ):
                        success_count += 1
            
            # Commit
            if not kernel32.EndUpdateResourceW(h_update, False):
                raise Exception("리소스 업데이트 커밋 실패")
            
            messagebox.showinfo("성공", 
                              f"{success_count}개 String Table 블록이 업데이트되었습니다.")
            
            # Reload
            self.modifications.clear()
            self.load_string_tables()
            
        except Exception as e:
            self.status_var.set("적용 실패")
            messagebox.showerror("오류", f"번역 적용 실패: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = StringTableTranslatorGUI(root)
    root.mainloop()