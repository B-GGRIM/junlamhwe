import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import os
import sys
import importlib.util
import shutil
import datetime
import threading
import json
import gc
import tempfile
from typing import List, Dict, Any, Optional

# 현재 디렉토리를 Python 경로에 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# 플러그인 인터페이스 import
try:
    from plugin_interface import TranslatorPlugin
except ImportError:
    print("Error: plugin_interface.py 파일을 찾을 수 없습니다.")
    print(f"현재 디렉토리: {current_dir}")
    print("plugin_interface.py 파일이 같은 폴더에 있는지 확인하세요.")
    sys.exit(1)

class UnifiedTranslatorGUI:
    """통합 번역 클라이언트"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Universal EXE Translator - 통합 번역 시스템")
        self.root.geometry("1400x800")
        
        self.file_path = ""
        self.api_key = ""
        self.plugins: List[TranslatorPlugin] = []
        self.plugin_results = {}
        self.all_translations = {}
        
        self.setup_ui()
        self.load_plugins()
    
    def setup_ui(self):
        # Style
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, 
                               text="Universal EXE Translator",
                               style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        subtitle_label = ttk.Label(main_frame,
                                 text="Windows EXE 파일의 모든 리소스를 한번에 번역합니다",
                                 foreground="gray")
        subtitle_label.grid(row=1, column=0, columnspan=3, pady=(0, 20))
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="파일 선택", padding="10")
        file_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=60)
        file_entry.grid(row=0, column=0, padx=(0, 10))
        
        ttk.Button(file_frame, text="찾아보기", command=self.browse_file).grid(row=0, column=1)
        ttk.Button(file_frame, text="백업 생성", command=self.create_backup).grid(row=0, column=2, padx=(10, 0))
        ttk.Button(file_frame, text="백업 복원", command=self.restore_backup).grid(row=0, column=3, padx=(10, 0))
        
        # API Key button
        ttk.Button(file_frame, text="API 키 설정", command=self.set_api_key).grid(row=0, column=4, padx=(20, 0))
        
        # Main content - PanedWindow
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Left panel - Plugin list and status
        left_frame = ttk.Frame(paned)
        
        # Plugin list
        plugin_label = ttk.Label(left_frame, text="플러그인 상태", style='Header.TLabel')
        plugin_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        
        # Plugin tree
        columns = ("플러그인", "버전", "상태", "리소스 수", "번역 대상")
        self.plugin_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=10)
        
        self.plugin_tree.heading("플러그인", text="플러그인")
        self.plugin_tree.heading("버전", text="버전")
        self.plugin_tree.heading("상태", text="상태")
        self.plugin_tree.heading("리소스 수", text="리소스 수")
        self.plugin_tree.heading("번역 대상", text="번역 대상")
        
        self.plugin_tree.column("플러그인", width=150)
        self.plugin_tree.column("버전", width=60)
        self.plugin_tree.column("상태", width=80)
        self.plugin_tree.column("리소스 수", width=80)
        self.plugin_tree.column("번역 대상", width=80)
        
        # 더블클릭 이벤트 바인딩
        self.plugin_tree.bind("<Double-Button-1>", self.show_resource_details)
        
        plugin_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.plugin_tree.yview)
        self.plugin_tree.configure(yscrollcommand=plugin_scroll.set)
        
        self.plugin_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        plugin_scroll.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Plugin control buttons
        plugin_btn_frame = ttk.Frame(left_frame)
        plugin_btn_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Button(plugin_btn_frame, text="플러그인 새로고침", 
                  command=self.load_plugins).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(plugin_btn_frame, text="플러그인 폴더 열기", 
                  command=self.open_plugin_folder).pack(side=tk.LEFT)
        ttk.Button(plugin_btn_frame, text="리소스 상세보기", 
                  command=self.show_resource_details).pack(side=tk.LEFT, padx=(5, 0))
        
        # Progress frame
        progress_frame = ttk.LabelFrame(left_frame, text="진행 상황", padding="10")
        progress_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(20, 0))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        
        self.progress_label = ttk.Label(progress_frame, text="대기 중...")
        self.progress_label.pack()
        
        # Right panel - Log and summary
        right_frame = ttk.Frame(paned)
        
        # Summary
        summary_label = ttk.Label(right_frame, text="분석 결과", style='Header.TLabel')
        summary_label.pack(pady=(0, 10))
        
        # Summary text
        self.summary_text = scrolledtext.ScrolledText(right_frame, height=10, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Log
        log_label = ttk.Label(right_frame, text="실행 로그", style='Header.TLabel')
        log_label.pack(pady=(10, 5))
        
        # Log text
        self.log_text = scrolledtext.ScrolledText(right_frame, height=15, wrap=tk.WORD, font=("Courier", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Add panels
        paned.add(left_frame, weight=1)
        paned.add(right_frame, weight=2)
        
        # Bottom buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(20, 0))
        
        # Action buttons
        self.analyze_btn = ttk.Button(button_frame, text="1. 파일 분석", 
                                    command=self.analyze_file,
                                    state='disabled')
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.translate_btn = ttk.Button(button_frame, text="2. 자동 번역", 
                                      command=self.translate_all,
                                      state='disabled')
        self.translate_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.apply_btn = ttk.Button(button_frame, text="3. 번역 적용", 
                                  command=self.apply_translations,
                                  state='disabled')
        self.apply_btn.pack(side=tk.LEFT)
        
        # Right side buttons
        ttk.Button(button_frame, text="번역 내보내기", 
                  command=self.export_translations).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="번역 가져오기", 
                  command=self.import_translations).pack(side=tk.RIGHT)
        
        # Status bar
        self.status_var = tk.StringVar(value="준비")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Configure weights
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        left_frame.rowconfigure(1, weight=1)
    
    def show_resource_details(self, event=None):
        """리소스 상세 정보 표시"""
        selected = self.plugin_tree.selection()
        if not selected:
            return
        
        # 선택된 플러그인 찾기
        item = self.plugin_tree.item(selected[0])
        plugin_name = item['values'][0]
        
        # 해당 플러그인의 분석 결과 찾기
        if plugin_name not in self.plugin_results:
            messagebox.showinfo("정보", "먼저 파일을 분석하세요.")
            return
        
        result = self.plugin_results[plugin_name]
        if result['count'] == 0:
            messagebox.showinfo("정보", "이 플러그인에서 발견된 리소스가 없습니다.")
            return
        
        # 상세 정보 창 생성
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"{plugin_name} - 리소스 상세 정보")
        detail_window.geometry("800x600")
        detail_window.transient(self.root)
        
        # 요약 정보
        summary_frame = ttk.LabelFrame(detail_window, text="요약", padding="10")
        summary_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        ttk.Label(summary_frame, text=result['summary'], font=("Arial", 11)).pack(anchor=tk.W)
        
        # 리소스 목록
        list_frame = ttk.LabelFrame(detail_window, text="리소스 목록", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        
        # 플러그인별 상세 정보 표시
        if 'Dialog' in plugin_name:
            columns = ("Dialog ID", "제목", "컨트롤 수")
            tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
            tree.heading("Dialog ID", text="Dialog ID")
            tree.heading("제목", text="제목")
            tree.heading("컨트롤 수", text="컨트롤 수")
            
            for item in result.get('items', []):
                tree.insert("", "end", values=(
                    item.get('dialog_id', ''),
                    item.get('title', ''),
                    item.get('controls', 0)
                ))
                
        elif 'RCData' in plugin_name:
            columns = ("이름", "캡션 수", "크기")
            tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
            tree.heading("이름", text="리소스 이름")
            tree.heading("캡션 수", text="캡션 수")
            tree.heading("크기", text="크기 (bytes)")
            
            for item in result.get('items', []):
                tree.insert("", "end", values=(
                    item.get('name', ''),
                    item.get('captions', 0),
                    item.get('size', 0)
                ))
                
        elif 'String' in plugin_name:
            columns = ("Block ID", "문자열 수", "Language ID")
            tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
            tree.heading("Block ID", text="Block ID")
            tree.heading("문자열 수", text="문자열 수")
            tree.heading("Language ID", text="Language ID")
            
            for item in result.get('items', []):
                tree.insert("", "end", values=(
                    item.get('block_id', ''),
                    item.get('string_count', 0),
                    f"0x{item.get('lang_id', 0):04X}"
                ))
        
        # 스크롤바 추가
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 닫기 버튼
        ttk.Button(detail_window, text="닫기", command=detail_window.destroy).pack(pady=10)
    
    def log(self, message: str, level: str = "INFO"):
        """로그 메시지 추가"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        tag = None
        if level == "ERROR":
            tag = "error"
            self.log_text.tag_config("error", foreground="red")
        elif level == "SUCCESS":
            tag = "success"
            self.log_text.tag_config("success", foreground="green")
        elif level == "WARNING":
            tag = "warning"
            self.log_text.tag_config("warning", foreground="orange")
        
        self.log_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.log_text.tag_config("timestamp", foreground="gray")
        
        if tag:
            self.log_text.insert(tk.END, f"{message}\n", tag)
        else:
            self.log_text.insert(tk.END, f"{message}\n")
        
        self.log_text.see(tk.END)
        self.root.update()
    
    def load_plugins(self):
        """플러그인 로드"""
        self.plugins.clear()
        
        # Clear plugin tree
        for item in self.plugin_tree.get_children():
            self.plugin_tree.delete(item)
        
        plugin_dir = "plugins"
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir)
        
        # Load built-in plugins
        built_in_plugins = [
            ('plugin_rcdata', 'RCDataTranslatorPlugin'),
            ('plugin_stringtable', 'StringTableTranslatorPlugin'),
            ('plugin_dialog', 'DialogTranslatorPlugin')
        ]
        
        loaded_count = 0
        for module_name, class_name in built_in_plugins:
            try:
                # 동적으로 모듈 import
                module = importlib.import_module(module_name)
                plugin_class = getattr(module, class_name)
                plugin = plugin_class()
                self.plugins.append(plugin)
                loaded_count += 1
                self.log(f"{plugin.name} 로드 성공", "SUCCESS")
            except ImportError as e:
                self.log(f"{module_name}.py 파일을 찾을 수 없습니다: {str(e)}", "WARNING")
            except AttributeError as e:
                self.log(f"{module_name}에서 {class_name}을 찾을 수 없습니다: {str(e)}", "WARNING")
            except Exception as e:
                self.log(f"{module_name} 로드 실패: {str(e)}", "ERROR")
        
        if loaded_count > 0:
            self.log(f"기본 플러그인 {loaded_count}개 로드됨", "SUCCESS")
        else:
            self.log("기본 플러그인을 로드하지 못했습니다. 플러그인 파일들을 확인하세요.", "WARNING")
        
        # Load external plugins from plugins directory
        if os.path.exists(plugin_dir):
            for filename in os.listdir(plugin_dir):
                if filename.endswith('.py') and filename.startswith('plugin_'):
                    try:
                        # Dynamic import
                        module_name = filename[:-3]
                        file_path = os.path.join(plugin_dir, filename)
                        
                        spec = importlib.util.spec_from_file_location(module_name, file_path)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Find plugin class
                        for name in dir(module):
                            obj = getattr(module, name)
                            if (isinstance(obj, type) and 
                                issubclass(obj, TranslatorPlugin) and 
                                obj != TranslatorPlugin):
                                plugin = obj()
                                self.plugins.append(plugin)
                                self.log(f"외부 플러그인 로드: {plugin.name}", "SUCCESS")
                                break
                    
                    except Exception as e:
                        self.log(f"플러그인 {filename} 로드 실패: {str(e)}", "ERROR")
        
        # Sort plugins by priority
        self.plugins.sort(key=lambda p: p.priority)
        
        # Update plugin tree
        for plugin in self.plugins:
            info = plugin.get_info()
            self.plugin_tree.insert("", "end", values=(
                info['name'],
                info['version'],
                "준비",
                "-",
                "-"
            ))
        
        self.log(f"총 {len(self.plugins)}개 플러그인 로드됨")
    
    def browse_file(self):
        """파일 선택"""
        filename = filedialog.askopenfilename(
            title="EXE 파일 선택",
            filetypes=[("실행 파일", "*.exe"), ("모든 파일", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)
            self.file_path = filename
            
            # Enable analyze button
            self.analyze_btn.config(state='normal')
            
            # Clear previous results
            self.summary_text.delete(1.0, tk.END)
            self.plugin_results.clear()
            self.all_translations.clear()
            
            self.log(f"파일 선택: {os.path.basename(filename)}")
    
    def create_backup(self):
        """백업 생성"""
        if not self.file_path:
            messagebox.showwarning("경고", "먼저 파일을 선택하세요")
            return
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.file_path}.unified_backup_{timestamp}"
            
            shutil.copy2(self.file_path, backup_path)
            
            self.log(f"백업 생성: {os.path.basename(backup_path)}", "SUCCESS")
            messagebox.showinfo("성공", f"백업이 생성되었습니다:\n{os.path.basename(backup_path)}")
        except Exception as e:
            self.log(f"백업 생성 실패: {str(e)}", "ERROR")
            messagebox.showerror("오류", f"백업 생성 실패: {str(e)}")
    
    def restore_backup(self):
        """백업 복원"""
        if not self.file_path:
            messagebox.showwarning("경고", "먼저 파일을 선택하세요")
            return
        
        # Find backups
        directory = os.path.dirname(self.file_path)
        base_name = os.path.basename(self.file_path)
        
        backup_files = []
        for file in os.listdir(directory):
            if file.startswith(base_name) and 'backup' in file:
                backup_files.append(file)
        
        if not backup_files:
            messagebox.showerror("오류", "백업 파일을 찾을 수 없습니다!")
            return
        
        # Select backup dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("백업 선택")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="복원할 백업을 선택하세요:", font=("Arial", 12)).pack(pady=10)
        
        listbox = tk.Listbox(dialog, font=("Courier", 10))
        listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        
        # Sort by date
        backup_info = []
        for backup in backup_files:
            backup_path = os.path.join(directory, backup)
            mod_time = os.path.getmtime(backup_path)
            size = os.path.getsize(backup_path) / 1024 / 1024  # MB
            backup_info.append((backup, mod_time, size))
        
        backup_info.sort(key=lambda x: x[1], reverse=True)
        
        for backup, mod_time, size in backup_info:
            time_str = datetime.datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d %H:%M:%S")
            display = f"{backup} ({time_str}, {size:.1f} MB)"
            listbox.insert(tk.END, display)
        
        def restore():
            if listbox.curselection():
                idx = listbox.curselection()[0]
                selected = backup_info[idx][0]
                
                try:
                    backup_path = os.path.join(directory, selected)
                    shutil.copy2(backup_path, self.file_path)
                    
                    self.log(f"백업 복원 완료: {selected}", "SUCCESS")
                    messagebox.showinfo("성공", "백업에서 파일이 복원되었습니다!")
                    
                    dialog.destroy()
                    
                    # Reset state
                    self.plugin_results.clear()
                    self.all_translations.clear()
                    self.summary_text.delete(1.0, tk.END)
                    
                except Exception as e:
                    messagebox.showerror("오류", f"복원 실패: {str(e)}")
        
        ttk.Button(dialog, text="복원", command=restore).pack(pady=10)
    
    def set_api_key(self):
        """API 키 설정"""
        dialog = tk.Toplevel(self.root)
        dialog.title("API Key 설정")
        dialog.geometry("600x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - 300
        y = (dialog.winfo_screenheight() // 2) - 100
        dialog.geometry(f"600x200+{x}+{y}")
        
        ttk.Label(dialog, text="OpenAI API Key를 입력하세요:", font=("Arial", 12)).pack(pady=20)
        
        api_var = tk.StringVar(value=self.api_key)
        entry = ttk.Entry(dialog, textvariable=api_var, width=60, show="*", font=("Arial", 11))
        entry.pack(pady=10)
        
        def save():
            self.api_key = api_var.get().strip()
            if self.api_key:
                self.log("API 키 설정됨", "SUCCESS")
                messagebox.showinfo("성공", "API 키가 설정되었습니다")
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="저장", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="취소", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def open_plugin_folder(self):
        """플러그인 폴더 열기"""
        plugin_dir = "plugins"
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir)
        
        if sys.platform == "win32":
            os.startfile(plugin_dir)
        elif sys.platform == "darwin":
            os.system(f"open {plugin_dir}")
        else:
            os.system(f"xdg-open {plugin_dir}")
    
    def analyze_file(self):
        """파일 분석"""
        if not self.file_path:
            messagebox.showwarning("경고", "파일을 선택하세요")
            return
        
        if not self.plugins:
            messagebox.showwarning("경고", "로드된 플러그인이 없습니다.\n플러그인 파일들을 확인하세요.")
            return
        
        self.log("=== 파일 분석 시작 ===")
        self.summary_text.delete(1.0, tk.END)
        self.plugin_results.clear()
        
        # Disable buttons during analysis
        self.analyze_btn.config(state='disabled')
        self.translate_btn.config(state='disabled')
        self.apply_btn.config(state='disabled')
        
        def analyze_worker():
            try:
                total_resources = 0
                total_translatable = 0
                
                summary = f"파일: {os.path.basename(self.file_path)}\n"
                summary += f"크기: {os.path.getsize(self.file_path) / 1024 / 1024:.2f} MB\n"
                summary += "=" * 60 + "\n\n"
                
                for i, plugin in enumerate(self.plugins):
                    try:
                        self.progress_var.set((i / len(self.plugins)) * 100)
                        self.progress_label.config(text=f"{plugin.name} 분석 중...")
                        
                        # Update plugin tree
                        self.plugin_tree.item(self.plugin_tree.get_children()[i], 
                                            values=(plugin.name, plugin.version, "분석 중...", "-", "-"))
                        
                        # Analyze
                        result = plugin.analyze(self.file_path)
                        self.plugin_results[plugin.name] = result
                        
                        # Update tree
                        self.plugin_tree.item(self.plugin_tree.get_children()[i], 
                                            values=(plugin.name, plugin.version, "완료", 
                                                  result['count'], "-"))
                        
                        # Add to summary
                        summary += f"[{plugin.name}]\n"
                        summary += f"{result['summary']}\n\n"
                        
                        total_resources += result['count']
                        
                        self.log(f"{plugin.name}: {result['summary']}")
                        
                    except Exception as e:
                        self.log(f"{plugin.name} 분석 실패: {str(e)}", "ERROR")
                        self.plugin_tree.item(self.plugin_tree.get_children()[i], 
                                            values=(plugin.name, plugin.version, "실패", "0", "-"))
                
                # Update summary
                summary += f"\n총 리소스: {total_resources}개\n"
                self.summary_text.insert(1.0, summary)
                
                self.progress_var.set(100)
                self.progress_label.config(text="분석 완료")
                
                # Enable translate button if resources found
                if total_resources > 0:
                    self.translate_btn.config(state='normal')
                
                self.log("=== 파일 분석 완료 ===", "SUCCESS")
                
            except Exception as e:
                self.log(f"분석 중 오류: {str(e)}", "ERROR")
                messagebox.showerror("오류", f"파일 분석 실패: {str(e)}")
            finally:
                self.analyze_btn.config(state='normal')
        
        # Start in thread
        thread = threading.Thread(target=analyze_worker, daemon=True)
        thread.start()
    
    def translate_all(self):
        """모든 리소스 번역"""
        if not self.api_key:
            messagebox.showwarning("API Key 필요", "먼저 API 키를 설정하세요")
            self.set_api_key()
            if not self.api_key:
                return
        
        self.log("=== 자동 번역 시작 ===")
        
        # Disable buttons
        self.analyze_btn.config(state='disabled')
        self.translate_btn.config(state='disabled')
        self.apply_btn.config(state='disabled')
        
        def translate_worker():
            try:
                import concurrent.futures
                import time
                
                start_time = time.time()
                total_translated = 0
                total_failed = 0
                
                # 모든 플러그인의 번역 작업 수집
                plugin_tasks = []
                
                for i, plugin in enumerate(self.plugins):
                    if plugin.name not in self.plugin_results:
                        continue
                    
                    if self.plugin_results[plugin.name]['count'] == 0:
                        continue
                    
                    plugin_tasks.append((i, plugin))
                
                if not plugin_tasks:
                    self.log("번역할 리소스가 없습니다", "WARNING")
                    return
                
                self.log(f"{len(plugin_tasks)}개 플러그인에서 번역 작업 시작")
                
                # 병렬 처리를 위한 ThreadPoolExecutor
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                    future_to_plugin = {}
                    
                    # 각 플러그인에 대한 번역 작업 제출
                    for i, plugin in plugin_tasks:
                        self.plugin_tree.item(self.plugin_tree.get_children()[i], 
                                            values=(plugin.name, plugin.version, "대기 중...", 
                                                  self.plugin_results[plugin.name]['count'], "-"))
                        
                        # 최적화된 progress callback
                        def make_progress_callback(plugin_index, plugin_name):
                            def progress_callback(current, total, message):
                                # UI 업데이트 빈도 줄이기 (10% 단위로만 업데이트)
                                if current % max(1, total // 10) == 0 or current == total:
                                    progress = (plugin_index / len(self.plugins)) * 100 + (current / total) * (100 / len(self.plugins))
                                    self.progress_var.set(progress)
                                    self.progress_label.config(text=f"{plugin_name}: {message}")
                                    self.root.update()  # UI 업데이트
                            return progress_callback
                        
                        # 번역 작업 제출
                        future = executor.submit(
                            self._translate_plugin_optimized,
                            plugin,
                            i,
                            make_progress_callback(i, plugin.name)
                        )
                        future_to_plugin[future] = (i, plugin)
                    
                    # 결과 수집
                    for future in concurrent.futures.as_completed(future_to_plugin):
                        i, plugin = future_to_plugin[future]
                        
                        try:
                            result = future.result()
                            
                            if result['success']:
                                total_translated += result['translated']
                                total_failed += result['failed']
                                
                                # Update tree
                                self.plugin_tree.item(self.plugin_tree.get_children()[i], 
                                                    values=(plugin.name, plugin.version, "번역 완료", 
                                                          self.plugin_results[plugin.name]['count'],
                                                          result['translated']))
                                
                                self.log(f"{plugin.name}: {result['message']}", "SUCCESS")
                                
                                # Collect translations
                                plugin_translations = plugin.get_translations()
                                self.all_translations[plugin.name] = plugin_translations
                            else:
                                self.log(f"{plugin.name}: {result['message']}", "ERROR")
                                self.plugin_tree.item(self.plugin_tree.get_children()[i], 
                                                    values=(plugin.name, plugin.version, "번역 실패", 
                                                          self.plugin_results[plugin.name]['count'], "0"))
                        
                        except Exception as e:
                            self.log(f"{plugin.name} 번역 실패: {str(e)}", "ERROR")
                
                # Summary
                elapsed_time = time.time() - start_time
                self.progress_var.set(100)
                self.progress_label.config(text="번역 완료")
                
                summary = f"\n\n번역 결과:\n"
                summary += f"성공: {total_translated}개\n"
                summary += f"실패: {total_failed}개\n"
                summary += f"소요 시간: {elapsed_time:.1f}초"
                self.summary_text.insert(tk.END, summary)
                
                # Enable apply button if translations exist
                if total_translated > 0:
                    self.apply_btn.config(state='normal')
                
                self.log(f"=== 번역 완료: {total_translated}개 성공 ({elapsed_time:.1f}초) ===", "SUCCESS")
                
                if total_translated > 0:
                    messagebox.showinfo("번역 완료", 
                                      f"{total_translated}개의 텍스트가 번역되었습니다.\n"
                                      f"소요 시간: {elapsed_time:.1f}초\n\n"
                                      "이제 '번역 적용' 버튼을 클릭하여 파일에 적용할 수 있습니다.")
                
            except Exception as e:
                self.log(f"번역 중 오류: {str(e)}", "ERROR")
                messagebox.showerror("오류", f"번역 실패: {str(e)}")
            finally:
                self.analyze_btn.config(state='normal')
                self.translate_btn.config(state='normal')
        
        # Start in thread - 이 부분이 수정되었습니다!
        thread = threading.Thread(target=translate_worker, daemon=True)
        thread.start()
    
    def _translate_plugin_optimized(self, plugin, index, progress_callback):
        """플러그인 번역 (최적화 버전)"""
        try:
            # Update UI
            self.plugin_tree.item(self.plugin_tree.get_children()[index], 
                                values=(plugin.name, plugin.version, "번역 중...", 
                                      self.plugin_results[plugin.name]['count'], "-"))
            
            # 최적화된 번역 수행
            result = plugin.translate(self.file_path, self.api_key, progress_callback)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'translated': 0,
                'failed': 0,
                'message': str(e)
            }
    
    def apply_translations(self):
        """번역 적용"""
        if not self.all_translations:
            messagebox.showwarning("경고", "적용할 번역이 없습니다")
            return
        
        # Count total translations
        total_count = sum(len(trans) for trans in self.all_translations.values())
        
        if not messagebox.askyesno("번역 적용", 
                                 f"총 {total_count}개의 번역을 적용하시겠습니까?\n\n"
                                 "이 작업은 되돌릴 수 없으므로 백업을 권장합니다."):
            return
        
        self.log("=== 번역 적용 시작 ===")
        
        # Disable buttons
        self.analyze_btn.config(state='disabled')
        self.translate_btn.config(state='disabled')
        self.apply_btn.config(state='disabled')
        
        def apply_worker():
            try:
                import gc
                import time
                
                success_count = 0
                failed_count = 0
                
                # 모든 플러그인의 PE 핸들 정리
                self.log("리소스 정리 중...")
                for plugin in self.plugins:
                    try:
                        plugin.cleanup()
                    except:
                        pass
                
                # Garbage collection 강제 실행
                gc.collect()
                time.sleep(0.5)  # 파일 핸들 해제 대기
                
                # Create temporary file with unique name
                import tempfile
                temp_fd, temp_file = tempfile.mkstemp(suffix='.exe', dir=os.path.dirname(self.file_path))
                os.close(temp_fd)  # 파일 디스크립터 닫기
                
                try:
                    # 원본 파일을 임시 파일로 복사
                    shutil.copy2(self.file_path, temp_file)
                    self.log(f"임시 파일 생성: {os.path.basename(temp_file)}")
                    
                    # 각 플러그인에 번역 적용
                    for i, plugin in enumerate(self.plugins):
                        if plugin.name not in self.all_translations:
                            continue
                        
                        plugin_translations = self.all_translations[plugin.name]
                        if not plugin_translations:
                            continue
                        
                        try:
                            self.progress_var.set((i / len(self.plugins)) * 100)
                            self.progress_label.config(text=f"{plugin.name} 적용 중...")
                            
                            # 각 플러그인이 임시 파일에 적용
                            result = plugin.apply_translations(temp_file, plugin_translations)
                            
                            if result['success']:
                                success_count += 1
                                self.log(f"{plugin.name}: {result['message']}", "SUCCESS")
                            else:
                                failed_count += 1
                                self.log(f"{plugin.name}: {result['message']}", "ERROR")
                            
                            # 각 플러그인 적용 후 정리
                            try:
                                plugin.cleanup()
                            except:
                                pass
                            
                            # 잠시 대기
                            time.sleep(0.1)
                            
                        except Exception as e:
                            failed_count += 1
                            self.log(f"{plugin.name} 적용 실패: {str(e)}", "ERROR")
                    
                    # 모든 적용이 성공했으면 원본 파일 교체
                    if success_count > 0:
                        self.log("원본 파일 교체 중...")
                        
                        # 다시 한번 정리
                        gc.collect()
                        time.sleep(0.5)
                        
                        # 원본 파일 백업 (안전을 위해)
                        backup_path = self.file_path + ".bak"
                        if os.path.exists(backup_path):
                            os.remove(backup_path)
                        
                        # 파일 교체 시도
                        max_attempts = 3
                        for attempt in range(max_attempts):
                            try:
                                # 원본을 백업으로 이동
                                os.rename(self.file_path, backup_path)
                                # 임시 파일을 원본 위치로 이동
                                shutil.move(temp_file, self.file_path)
                                # 백업 파일 삭제
                                os.remove(backup_path)
                                break
                                
                            except OSError as e:
                                if "1224" in str(e.winerror) or "being used" in str(e):
                                    self.log(f"파일 교체 시도 {attempt + 1}/{max_attempts}: 파일이 사용 중", "WARNING")
                                    
                                    if attempt < max_attempts - 1:
                                        # 재시도 전 대기
                                        time.sleep(2.0)
                                        gc.collect()
                                        
                                        # 안티바이러스나 다른 프로그램이 파일을 검사 중일 수 있음
                                        self.log("파일이 다른 프로세스에 의해 사용 중입니다. 잠시 대기 중...", "WARNING")
                                    else:
                                        # 최종 시도: 복사 방식으로 교체
                                        self.log("복사 방식으로 파일 교체 시도", "WARNING")
                                        
                                        # 백업이 이미 만들어졌으면 삭제
                                        if os.path.exists(backup_path) and backup_path != self.file_path:
                                            try:
                                                os.remove(self.file_path)
                                            except:
                                                # 실패하면 덮어쓰기
                                                pass
                                        
                                        # 임시 파일을 원본으로 복사
                                        shutil.copy2(temp_file, self.file_path)
                                        
                                        # 임시 파일 삭제
                                        try:
                                            os.remove(temp_file)
                                        except:
                                            pass
                                        
                                        # 백업 삭제 시도
                                        if os.path.exists(backup_path):
                                            try:
                                                os.remove(backup_path)
                                            except:
                                                self.log(f"백업 파일 삭제 실패: {backup_path}", "WARNING")
                                        
                                        break
                                else:
                                    raise
                        
                        self.progress_var.set(100)
                        self.progress_label.config(text="적용 완료")
                        
                        self.log(f"=== 번역 적용 완료: {success_count}개 플러그인 성공 ===", "SUCCESS")
                        
                        messagebox.showinfo("성공", 
                                          f"번역이 성공적으로 적용되었습니다!\n\n"
                                          f"성공: {success_count}개 플러그인\n"
                                          f"실패: {failed_count}개 플러그인")
                    else:
                        # 실패 시 임시 파일 삭제
                        os.remove(temp_file)
                        messagebox.showerror("실패", "번역 적용에 실패했습니다")
                    
                except Exception as e:
                    # 오류 발생 시 임시 파일 정리
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass
                    raise e
                
            except Exception as e:
                self.log(f"적용 중 오류: {str(e)}", "ERROR")
                
                error_msg = f"번역 적용 실패: {str(e)}"
                
                # 특정 오류에 대한 사용자 친화적인 메시지
                if "1224" in str(e):
                    error_msg += "\n\n파일이 다른 프로그램에 의해 사용 중입니다.\n"
                    error_msg += "다음을 확인해주세요:\n"
                    error_msg += "• 안티바이러스 프로그램이 파일을 검사 중인지\n"
                    error_msg += "• 파일이 실행 중이거나 다른 프로그램에서 열려있는지\n"
                    error_msg += "• Windows 탐색기에서 파일을 미리보기 중인지\n\n"
                    error_msg += "해결 방법:\n"
                    error_msg += "1. 잠시 기다린 후 다시 시도\n"
                    error_msg += "2. 컴퓨터를 재시작 후 시도\n"
                    error_msg += "3. 안티바이러스를 일시적으로 비활성화"
                
                messagebox.showerror("오류", error_msg)
                        
            finally:
                # 최종 정리
                for plugin in self.plugins:
                    try:
                        plugin.cleanup()
                    except:
                        pass
                
                gc.collect()
                
                self.analyze_btn.config(state='normal')
                self.translate_btn.config(state='normal')
                self.apply_btn.config(state='normal')
        
        # Start in thread
        thread = threading.Thread(target=apply_worker, daemon=True)
        thread.start()
    
    def export_translations(self):
        """번역 내보내기"""
        if not self.all_translations:
            messagebox.showwarning("경고", "내보낼 번역이 없습니다")
            return
        
        filename = filedialog.asksaveasfilename(
            title="번역 저장",
            defaultextension=".json",
            filetypes=[("JSON 파일", "*.json"), ("모든 파일", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.all_translations, f, ensure_ascii=False, indent=2)
                
                self.log(f"번역 내보내기 완료: {os.path.basename(filename)}", "SUCCESS")
                messagebox.showinfo("성공", "번역이 저장되었습니다")
            except Exception as e:
                self.log(f"번역 내보내기 실패: {str(e)}", "ERROR")
                messagebox.showerror("오류", f"저장 실패: {str(e)}")
    
    def import_translations(self):
        """번역 가져오기"""
        filename = filedialog.askopenfilename(
            title="번역 불러오기",
            filetypes=[("JSON 파일", "*.json"), ("모든 파일", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    imported = json.load(f)
                
                self.all_translations = imported
                
                # Set translations to plugins
                for plugin in self.plugins:
                    if plugin.name in imported:
                        plugin.set_translations(imported[plugin.name])
                
                # Enable apply button
                self.apply_btn.config(state='normal')
                
                total_count = sum(len(trans) for trans in imported.values())
                self.log(f"번역 가져오기 완료: {total_count}개", "SUCCESS")
                messagebox.showinfo("성공", f"{total_count}개의 번역을 불러왔습니다")
                
            except Exception as e:
                self.log(f"번역 가져오기 실패: {str(e)}", "ERROR")
                messagebox.showerror("오류", f"불러오기 실패: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = UnifiedTranslatorGUI(root)
    root.mainloop()