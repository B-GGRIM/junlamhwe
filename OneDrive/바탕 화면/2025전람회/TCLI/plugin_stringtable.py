import pefile
import struct
import ctypes
from ctypes import wintypes
import json
import requests
from typing import List, Dict, Tuple, Optional, Any
from plugin_interface import TranslatorPlugin

# Windows API constants
RT_STRING = 6

# Windows API functions
kernel32 = ctypes.windll.kernel32

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
        self.strings = {}
    
    def parse_string_table(self, data: bytes, block_id: int) -> Dict[int, str]:
        """String Table 블록 파싱"""
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

class StringTableTranslatorPlugin(TranslatorPlugin):
    """String Table 번역 플러그인"""
    
    def __init__(self):
        super().__init__()
        self.name = "String Table Translator"
        self.version = "1.0"
        self.description = "Windows String Table 리소스 번역"
        self.resource_type = "RT_STRING"
        self.priority = 200
        
        self.parser = StringTableParser()
        self.string_tables = {}
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
            self.string_tables.clear()
            
            total_strings = 0
            block_count = 0
            english_strings = 0
            
            # Find RT_STRING resources
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_STRING']:
                        for resource_id in resource_type.directory.entries:
                            block_id = resource_id.id if hasattr(resource_id, 'id') else 0
                            
                            if block_id > 0:
                                block_count += 1
                                
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
                                        
                                        # Count English strings
                                        for string_id, text in strings.items():
                                            if self._is_english_text(text):
                                                english_strings += 1
            
            return {
                "count": block_count,
                "items": [{
                    "block_id": block_id,
                    "string_count": len(strings),
                    "lang_id": lang_id
                } for (block_id, lang_id), strings in self.string_tables.items()],
                "summary": f"String Table {block_count}개 블록, {total_strings}개 문자열 (영어 {english_strings}개)"
            }
            
        except Exception as e:
            return {
                "count": 0,
                "items": [],
                "summary": f"분석 실패: {str(e)}"
            }
    
    def translate(self, file_path: str, api_key: str, progress_callback=None) -> Dict[str, Any]:
        """자동 번역 수행"""
        try:
            # Collect English texts
            to_translate = []
            string_map = {}  # {text: [string_ids]}
            
            for (block_id, lang_id), strings in self.string_tables.items():
                for string_id, text in strings.items():
                    if self._is_english_text(text) and string_id not in self.translations:
                        if text not in string_map:
                            string_map[text] = []
                            to_translate.append(text)
                        string_map[text].append(string_id)
            
            if not to_translate:
                return {
                    "success": True,
                    "translated": 0,
                    "failed": 0,
                    "message": "번역할 영어 문자열이 없습니다"
                }
            
            # Translate in batches
            translated_count = 0
            failed_count = 0
            batch_size = 10
            
            for i in range(0, len(to_translate), batch_size):
                batch = to_translate[i:i+batch_size]
                
                if progress_callback:
                    progress_callback(i, len(to_translate), f"String Table 번역 중... {i}/{len(to_translate)}")
                
                # API call
                api_translations = self._call_translation_api(batch, api_key)
                
                # Apply translations
                for text, translation in api_translations.items():
                    for string_id in string_map[text]:
                        self.translations[string_id] = translation
                    
                    if text != translation:
                        translated_count += 1
                    else:
                        failed_count += 1
            
            return {
                "success": True,
                "translated": translated_count,
                "failed": failed_count,
                "message": f"{translated_count}개 문자열 번역 완료"
            }
            
        except Exception as e:
            return {
                "success": False,
                "translated": 0,
                "failed": 0,
                "message": f"번역 실패: {str(e)}"
            }
    
    def apply_translations(self, file_path: str, translations: Dict[str, str]) -> Dict[str, Any]:
        """번역 적용"""
        try:
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
                self.pe.close()
                self.pe = None
            
            # Begin update
            h_update = kernel32.BeginUpdateResourceW(file_path, False)
            if not h_update:
                raise Exception("리소스 업데이트 시작 실패")
            
            success_count = 0
            
            # Apply each string table block
            for (block_id, lang_id), strings in self.string_tables.items():
                # Build new string table with translations
                new_strings = {}
                modified = False
                
                for string_id, original in strings.items():
                    if string_id in self.translations:
                        new_strings[string_id] = self.translations[string_id]
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
            
            return {
                "success": True,
                "message": f"{success_count}개 String Table 블록 업데이트 완료",
                "details": {
                    "updated": success_count
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
        # Convert to text-based mapping for export
        text_translations = {}
        for (block_id, lang_id), strings in self.string_tables.items():
            for string_id, original in strings.items():
                if string_id in self.translations:
                    text_translations[original] = self.translations[string_id]
        return text_translations
    
    def set_translations(self, translations: Dict[str, str]):
        """번역 데이터 설정"""
        # Convert from text-based to ID-based mapping
        self.translations.clear()
        for (block_id, lang_id), strings in self.string_tables.items():
            for string_id, original in strings.items():
                if original in translations:
                    self.translations[string_id] = translations[original]
    
    def cleanup(self):
        """정리 작업"""
        if self.pe:
            self.pe.close()
            self.pe = None
    
    def _is_english_text(self, text):
        """영어 텍스트인지 확인"""
        if not text or len(text.strip()) == 0:
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