import pefile
import struct
import ctypes
from ctypes import wintypes
import json
import requests
import gc
import time
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from plugin_interface import TranslatorPlugin

# 캐시 시스템 (선택사항)
CACHE_ENABLED = False
try:
    from translation_cache import get_translation_cache
    CACHE_ENABLED = True
except ImportError:
    # 캐시 없이도 정상 작동
    pass

# Windows API constants
RT_DIALOG = 5

# Dialog styles
DS_SETFONT = 0x40
DS_FIXEDSYS = 0x0008

# Windows API functions
kernel32 = ctypes.windll.kernel32
imagehlp = ctypes.windll.imagehlp

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
    text_position: int = 0

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

class DialogTranslatorPlugin(TranslatorPlugin):
    """Dialog 번역 플러그인"""
    
    def __init__(self):
        super().__init__()
        self.name = "Dialog Translator"
        self.version = "1.0"
        self.description = "Windows Dialog 리소스 번역"
        self.resource_type = "RT_DIALOG"
        self.priority = 300
        
        self.parser = SafeDialogParser()
        self.rebuilder = SafeDialogRebuilder()
        self.checksum_fixer = PEChecksum()
        self.dialogs = {}
        self.dialog_data = {}
        self.translations = {}
        self.pe = None
    
    def get_info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "resource_type": self.resource_type,
            "author": "System",
            "requirements": ["pefile"]
        }
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """파일 분석"""
        try:
            if self.pe:
                self.pe.close()
            
            self.pe = pefile.PE(file_path)
            self.dialogs.clear()
            self.dialog_data.clear()
            
            dialog_count = 0
            total_controls = 0
            english_texts = 0
            has_signature = hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY')
            
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
                                    
                                    # Count English texts
                                    if dialog_info.title and self._is_english_text(dialog_info.title):
                                        english_texts += 1
                                    
                                    for control in dialog_info.controls:
                                        if control.text and self._is_english_text(control.text):
                                            english_texts += 1
            
            summary = f"Dialog {dialog_count}개, Control {total_controls}개 (영어 텍스트 {english_texts}개)"
            if has_signature:
                summary += " [디지털 서명 있음]"
            
            return {
                "count": dialog_count,
                "items": [{
                    "dialog_id": dialog_id,
                    "title": dialog_info.title if dialog_info.title else "(No Title)",
                    "controls": len(dialog_info.controls)
                } for (dialog_id, lang_id), dialog_info in self.dialogs.items()],
                "summary": summary
            }
            
        except Exception as e:
            return {
                "count": 0,
                "items": [],
                "summary": f"분석 실패: {str(e)}"
            }
    
    def translate(self, file_path: str, api_key: str, progress_callback=None) -> Dict[str, Any]:
        """자동 번역 수행 (최적화 버전)"""
        try:
            # Collect English texts
            to_translate = []
            unique_texts = set()
            
            for dialog_info in self.dialogs.values():
                if dialog_info.title and self._is_english_text(dialog_info.title):
                    if dialog_info.title not in self.translations:
                        unique_texts.add(dialog_info.title)
                
                for control in dialog_info.controls:
                    if control.text and self._is_english_text(control.text):
                        if control.text not in self.translations:
                            unique_texts.add(control.text)
            
            to_translate = list(unique_texts)
            
            if not to_translate:
                return {
                    "success": True,
                    "translated": 0,
                    "failed": 0,
                    "message": "번역할 영어 텍스트가 없습니다"
                }
            
            # Translate in larger batches
            translated_count = 0
            failed_count = 0
            batch_size = 50  # 배치 크기 증가
            
            total_batches = (len(to_translate) + batch_size - 1) // batch_size
            
            for batch_num, i in enumerate(range(0, len(to_translate), batch_size)):
                batch = to_translate[i:i+batch_size]
                
                if progress_callback:
                    progress_callback(i, len(to_translate), 
                                    f"Dialog 번역 중... 배치 {batch_num + 1}/{total_batches}")
                
                # API call with retry
                max_retries = 3
                for retry in range(max_retries):
                    try:
                        api_translations = self._call_translation_api_optimized(batch, api_key)
                        
                        # Apply translations
                        for text, translation in api_translations.items():
                            self.translations[text] = translation
                            
                            if text != translation:
                                translated_count += 1
                            else:
                                failed_count += 1
                        
                        break
                        
                    except Exception as e:
                        if retry < max_retries - 1:
                            if progress_callback:
                                progress_callback(i, len(to_translate), f"재시도 중... ({retry + 1}/{max_retries})")
                            time.sleep(1)
                        else:
                            failed_count += len(batch)
            
            return {
                "success": True,
                "translated": translated_count,
                "failed": failed_count,
                "message": f"{translated_count}개 텍스트 번역 완료"
            }
            
        except Exception as e:
            return {
                "success": False,
                "translated": 0,
                "failed": 0,
                "message": f"번역 실패: {str(e)}"
            }
    
    def _call_translation_api_optimized(self, texts: List[str], api_key: str) -> Dict[str, str]:
        """최적화된 ChatGPT API 호출 (캐시 지원)"""
        # 캐시 확인
        if CACHE_ENABLED:
            cache = get_translation_cache()
            cached_translations = cache.get_batch(texts)
            
            texts_to_translate = [t for t in texts if t not in cached_translations]
            
            if not texts_to_translate:
                print(f"Dialog: 캐시에서 {len(cached_translations)}개 번역 로드")
                return cached_translations
        else:
            texts_to_translate = texts
            cached_translations = {}
        
        translations = {}
        
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # 간결한 프롬프트
            prompt = "Translate Windows dialog texts (buttons, labels, titles) to Korean. Keep it concise.\n\n"
            
            text_dict = {}
            for i, text in enumerate(texts_to_translate, 1):
                text_dict[i] = text
                prompt += f"{i}. {text}\n"
            
            prompt += "\nJSON: {\"1\": \"한국어1\", ...}"
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {
                        "role": "system",
                        "content": "Windows dialog UI translator. Translate to concise Korean."
                    },
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 4000
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                # Parse JSON
                import re
                json_match = re.search(r'\{[^{}]+\}', content, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                    
                    for num_str, translation in parsed.items():
                        try:
                            num = int(num_str)
                            if num in text_dict:
                                translations[text_dict[num]] = translation
                        except:
                            pass
                    
                    # 누락된 항목은 원본 유지
                    for i, text in text_dict.items():
                        if text not in translations:
                            translations[text] = text
                
                # 캐시에 저장
                if CACHE_ENABLED and translations:
                    cache.put_batch(translations)
                    cache.save_cache()
            
        except Exception as e:
            print(f"API error: {e}")
            for text in texts_to_translate:
                translations[text] = text
        
        # 캐시된 번역과 새로운 번역 병합
        final_translations = cached_translations.copy()
        final_translations.update(translations)
        
        # 원본 texts 리스트의 모든 항목이 포함되도록 보장
        for text in texts:
            if text not in final_translations:
                final_translations[text] = text
        
        return final_translations
    
    def apply_translations(self, file_path: str, translations: Dict[str, str]) -> Dict[str, Any]:
        """번역 적용"""
        try:
            import gc
            import time
            
            # Merge translations
            self.translations.update(translations)
            
            if not self.translations:
                return {
                    "success": False,
                    "message": "적용할 번역이 없습니다",
                    "details": {}
                }
            
            # Close PE if open
            if self.pe:
                try:
                    self.pe.close()
                except:
                    pass
                self.pe = None
            
            # Force garbage collection
            gc.collect()
            time.sleep(0.2)  # 파일 핸들 해제 대기
            
            # Remove digital signature first
            self.checksum_fixer.remove_signature(file_path)
            
            # Begin update
            h_update = kernel32.BeginUpdateResourceW(file_path, False)
            if not h_update:
                error_code = kernel32.GetLastError()
                raise Exception(f"리소스 업데이트 시작 실패 (오류 코드: {error_code})")
            
            success_count = 0
            failed_count = 0
            
            try:
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
                        else:
                            failed_count += 1
                            error_code = kernel32.GetLastError()
                            print(f"Dialog {dialog_id} update failed: error {error_code}")
                
                # Commit
                if not kernel32.EndUpdateResourceW(h_update, False):
                    error_code = kernel32.GetLastError()
                    raise Exception(f"리소스 업데이트 커밋 실패 (오류 코드: {error_code})")
                
            except Exception as e:
                # 오류 발생 시 업데이트 취소
                kernel32.EndUpdateResourceW(h_update, True)
                raise e
            
            # Fix PE checksum
            self.checksum_fixer.fix_checksum(file_path)
            
            return {
                "success": True,
                "message": f"{success_count}개 Dialog 업데이트 완료",
                "details": {
                    "updated": success_count,
                    "failed": failed_count,
                    "checksum_fixed": True,
                    "signature_removed": True
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"적용 실패: {str(e)}",
                "details": {}
            }
    
    def get_translations(self) -> Dict[str, str]:
        """현재 번역 데이터 반환"""
        return self.translations.copy()
    
    def set_translations(self, translations: Dict[str, str]):
        """번역 데이터 설정"""
        self.translations = translations.copy()
    
    def cleanup(self):
        """정리 작업"""
        if self.pe:
            try:
                self.pe.close()
            except:
                pass
            self.pe = None
        # 다이얼로그 데이터 정리
        self.dialogs.clear()
        self.dialog_data.clear()
        # 번역 데이터는 유지 (필요시 재사용)
    
    def _is_english_text(self, text):
        """영어 텍스트인지 확인"""
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
    
    def _call_translation_api(self, texts: List[str], api_key: str) -> Dict[str, str]:
        """ChatGPT API 호출"""
        translations = {}
        
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
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