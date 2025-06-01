import pefile
import struct
import ctypes
from ctypes import wintypes
import json
import requests
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import IntEnum
from plugin_interface import TranslatorPlugin

# Windows API constants
RT_RCDATA = 10

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
    return ctypes.c_wchar_p(i)

class DFMValueType(IntEnum):
    vaNull = 0
    vaList = 1
    vaInt8 = 2
    vaInt16 = 3
    vaInt32 = 4
    vaExtended = 5
    vaString = 6
    vaIdent = 7
    vaFalse = 8
    vaTrue = 9
    vaBinary = 10
    vaSet = 11
    vaLString = 12
    vaNil = 13
    vaCollection = 14
    vaSingle = 15
    vaCurrency = 16
    vaDate = 17
    vaWString = 18
    vaInt64 = 19
    vaUTF8String = 20

@dataclass
class CaptionInfo:
    text: str
    position: int
    length: int
    value_type: str
    type_byte_pos: int = 0
    can_expand: bool = True

class ImprovedDFMParser:
    def __init__(self):
        self.debug = False
        self.encodings = ['utf-8', 'cp949', 'euc-kr', 'latin-1', 'cp1252']
        self.text_properties = [
            b'Caption', b'Text', b'Hint', b'Title', b'DisplayLabel',
            b'EditLabel', b'Category', b'Description', b'Value',
            b'DisplayName', b'FieldName', b'Filter', b'DefaultExt',
            b'FileName', b'StatusBar', b'SimpleText'
        ]
    
    def find_all_captions(self, data: bytes) -> List[CaptionInfo]:
        all_captions = []
        offset = 0
        if len(data) > 3 and data[0:3] == b'TPF':
            offset = 4
        
        pattern_captions = self._find_by_enhanced_pattern(data, offset)
        all_captions.extend(pattern_captions)
        
        struct_captions = self._parse_dfm_recursive(data, offset)
        collection_captions = self._find_collection_strings(data, offset)
        
        caption_map = {}
        for cap in all_captions + struct_captions + collection_captions:
            key = f"{cap.position}:{cap.text}"
            if key not in caption_map:
                caption_map[key] = cap
        
        captions = list(caption_map.values())
        captions = sorted(captions, key=lambda x: x.position)
        captions = [cap for cap in captions if self._is_valid_caption(cap.text)]
        
        return captions
    
    def _find_by_enhanced_pattern(self, data: bytes, start_offset: int) -> List[CaptionInfo]:
        captions = []
        
        for prop_name in self.text_properties:
            pos = start_offset
            prop_len = len(prop_name)
            
            while pos < len(data) - prop_len - 10:
                if pos < len(data) and data[pos] == prop_len:
                    if pos + prop_len + 1 <= len(data):
                        if data[pos+1:pos+1+prop_len] == prop_name:
                            value_pos = pos + 1 + prop_len
                            
                            while value_pos < len(data) and data[value_pos] in [0x20, 0x09, 0x3D]:
                                value_pos += 1
                            
                            if value_pos < len(data):
                                caption_info = self._extract_any_string_value(data, value_pos, prop_name.decode())
                                if caption_info:
                                    captions.append(caption_info)
                                    pos = value_pos + caption_info.length
                                else:
                                    pos += 1
                        else:
                            pos += 1
                    else:
                        pos += 1
                else:
                    pos += 1
        
        return captions
    
    def _parse_dfm_recursive(self, data: bytes, start_pos: int, depth: int = 0) -> List[CaptionInfo]:
        captions = []
        pos = start_pos
        
        while pos < len(data) - 10:
            if self._check_keyword(data, pos, b'object') or self._check_keyword(data, pos, b'inherited'):
                keyword_len = 6 if data[pos:pos+6] == b'object' else 9
                pos += keyword_len
                
                while pos < len(data) and data[pos] in [0x20, 0x09, 0x0A, 0x0D]:
                    pos += 1
                
                obj_end = self._find_object_end(data, pos)
                if obj_end > pos:
                    obj_captions = self._parse_object_properties(data, pos, obj_end)
                    captions.extend(obj_captions)
                    
                    nested = self._parse_dfm_recursive(data, pos, depth + 1)
                    captions.extend(nested)
                    
                    pos = obj_end
                else:
                    pos += 1
            
            elif self._check_keyword(data, pos, b'item'):
                pos += 4
                item_end = self._find_item_end(data, pos)
                if item_end > pos:
                    item_captions = self._parse_object_properties(data, pos, item_end)
                    captions.extend(item_captions)
                    pos = item_end
                else:
                    pos += 1
            else:
                pos += 1
        
        return captions
    
    def _find_collection_strings(self, data: bytes, start_offset: int) -> List[CaptionInfo]:
        captions = []
        collection_props = [b'Items.Strings', b'Lines.Strings', b'Tabs.Strings']
        
        for prop in collection_props:
            pos = start_offset
            while pos < len(data) - len(prop) - 10:
                if self._find_property(data, pos, prop):
                    pos += len(prop) + 1
                    
                    while pos < len(data) and data[pos] != ord('('):
                        pos += 1
                    pos += 1
                    
                    while pos < len(data) and data[pos] != ord(')'):
                        if data[pos] == ord("'"):
                            pos += 1
                            start = pos
                            while pos < len(data) and data[pos] != ord("'"):
                                if data[pos] == ord("'") and pos + 1 < len(data) and data[pos + 1] == ord("'"):
                                    pos += 2
                                else:
                                    pos += 1
                            
                            if pos < len(data):
                                text = data[start:pos].decode('latin-1', errors='ignore')
                                if text and self._is_valid_caption(text):
                                    captions.append(CaptionInfo(
                                        text=text,
                                        position=start,
                                        length=pos - start,
                                        value_type='collection',
                                        type_byte_pos=0,
                                        can_expand=False
                                    ))
                            pos += 1
                        else:
                            pos += 1
                else:
                    pos += 1
        
        return captions
    
    def _extract_any_string_value(self, data: bytes, pos: int, prop_name: str) -> Optional[CaptionInfo]:
        if pos >= len(data):
            return None
        
        result = self._extract_typed_value(data, pos)
        if result:
            return result
        
        if data[pos] == ord("'"):
            return self._extract_quoted_string(data, pos)
        
        if data[pos] == ord("#"):
            return self._extract_char_code_string(data, pos)
        
        if 0 < data[pos] < 255:
            return self._extract_direct_string(data, pos)
        
        return None
    
    def _extract_typed_value(self, data: bytes, pos: int) -> Optional[CaptionInfo]:
        if pos >= len(data):
            return None
        
        value_type = data[pos]
        type_pos = pos
        pos += 1
        
        if value_type == 6 and pos < len(data):
            str_len = data[pos]
            if 0 < str_len < 255 and pos + str_len + 1 <= len(data):
                string_bytes = data[pos + 1:pos + 1 + str_len]
                text = self._safe_decode(string_bytes)
                if text:
                    return CaptionInfo(
                        text=text,
                        position=pos + 1,
                        length=str_len,
                        value_type='string',
                        type_byte_pos=type_pos,
                        can_expand=True
                    )
        
        elif value_type == 12 and pos + 4 <= len(data):
            str_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            if 0 < str_len < 10000 and pos + str_len <= len(data):
                string_bytes = data[pos:pos + str_len]
                text = self._safe_decode(string_bytes)
                if text:
                    return CaptionInfo(
                        text=text,
                        position=pos,
                        length=str_len,
                        value_type='lstring',
                        type_byte_pos=type_pos,
                        can_expand=True
                    )
        
        elif value_type == 18 and pos + 4 <= len(data):
            char_count = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            byte_len = char_count * 2
            if 0 < byte_len < 20000 and pos + byte_len <= len(data):
                string_bytes = data[pos:pos + byte_len]
                try:
                    text = string_bytes.decode('utf-16-le', errors='ignore').strip('\x00')
                    if text:
                        return CaptionInfo(
                            text=text,
                            position=pos,
                            length=byte_len,
                            value_type='wstring',
                            type_byte_pos=type_pos,
                            can_expand=True
                        )
                except:
                    pass
        
        elif value_type == 20 and pos + 4 <= len(data):
            str_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            if 0 < str_len < 10000 and pos + str_len <= len(data):
                string_bytes = data[pos:pos + str_len]
                try:
                    text = string_bytes.decode('utf-8', errors='ignore')
                    if text:
                        return CaptionInfo(
                            text=text,
                            position=pos,
                            length=str_len,
                            value_type='utf8string',
                            type_byte_pos=type_pos,
                            can_expand=True
                        )
                except:
                    pass
        
        return None
    
    def _extract_quoted_string(self, data: bytes, pos: int) -> Optional[CaptionInfo]:
        if pos >= len(data) or data[pos] != ord("'"):
            return None
        
        start_pos = pos
        pos += 1
        text_start = pos
        
        text_parts = []
        while pos < len(data):
            if data[pos] == ord("'"):
                if pos + 1 < len(data) and data[pos + 1] == ord("'"):
                    text_parts.append(data[text_start:pos + 1])
                    pos += 2
                    text_start = pos
                else:
                    text_parts.append(data[text_start:pos])
                    break
            else:
                pos += 1
        
        if text_parts or text_start < pos:
            if text_start < pos:
                text_parts.append(data[text_start:pos])
            
            combined = b''.join(text_parts)
            text = self._safe_decode(combined).replace("''", "'")
            
            if text:
                return CaptionInfo(
                    text=text,
                    position=start_pos,
                    length=pos - start_pos + 1,
                    value_type='quoted',
                    type_byte_pos=0,
                    can_expand=False
                )
        
        return None
    
    def _extract_char_code_string(self, data: bytes, pos: int) -> Optional[CaptionInfo]:
        if pos >= len(data) or data[pos] != ord("#"):
            return None
        
        start_pos = pos
        chars = []
        
        while pos < len(data) and data[pos] == ord("#"):
            pos += 1
            num_start = pos
            
            while pos < len(data) and data[pos] in range(ord('0'), ord('9') + 1):
                pos += 1
            
            if pos > num_start:
                char_code = int(data[num_start:pos])
                if 0 < char_code < 65536:
                    chars.append(chr(char_code))
        
        if chars:
            text = ''.join(chars)
            if self._is_valid_caption(text):
                return CaptionInfo(
                    text=text,
                    position=start_pos,
                    length=pos - start_pos,
                    value_type='charcode',
                    type_byte_pos=0,
                    can_expand=False
                )
        
        return None
    
    def _extract_direct_string(self, data: bytes, pos: int) -> Optional[CaptionInfo]:
        if pos >= len(data):
            return None
        
        str_len = data[pos]
        if 0 < str_len < 255 and pos + str_len + 1 <= len(data):
            string_bytes = data[pos + 1:pos + 1 + str_len]
            if self._looks_like_text(string_bytes):
                text = self._safe_decode(string_bytes)
                if text:
                    return CaptionInfo(
                        text=text,
                        position=pos + 1,
                        length=str_len,
                        value_type='direct',
                        type_byte_pos=0,
                        can_expand=False
                    )
        
        return None
    
    def _check_keyword(self, data: bytes, pos: int, keyword: bytes) -> bool:
        return (pos + len(keyword) <= len(data) and 
                data[pos:pos+len(keyword)] == keyword)
    
    def _find_property(self, data: bytes, pos: int, prop_name: bytes) -> bool:
        return (pos + len(prop_name) <= len(data) and 
                data[pos:pos+len(prop_name)] == prop_name)
    
    def _find_object_end(self, data: bytes, start_pos: int) -> int:
        pos = start_pos
        depth = 1
        
        while pos < len(data) - 6:
            if self._check_keyword(data, pos, b'object') or self._check_keyword(data, pos, b'inherited'):
                depth += 1
                pos += 6
            elif self._check_keyword(data, pos, b'end'):
                depth -= 1
                if depth == 0:
                    return pos + 3
                pos += 3
            else:
                pos += 1
        
        return -1
    
    def _find_item_end(self, data: bytes, start_pos: int) -> int:
        pos = start_pos
        
        while pos < len(data) - 3:
            if self._check_keyword(data, pos, b'end'):
                return pos + 3
            elif self._check_keyword(data, pos, b'item'):
                return pos
            else:
                pos += 1
        
        return -1
    
    def _parse_object_properties(self, data: bytes, start_pos: int, end_pos: int) -> List[CaptionInfo]:
        captions = []
        pos = start_pos
        
        while pos < end_pos and pos < len(data) - 10:
            name_len = data[pos] if pos < len(data) else 0
            
            if 0 < name_len < 50 and pos + name_len + 1 <= len(data):
                name_bytes = data[pos + 1:pos + 1 + name_len]
                
                if name_bytes in self.text_properties:
                    value_pos = pos + 1 + name_len
                    
                    while value_pos < len(data) and data[value_pos] in [0x20, 0x09, 0x3D]:
                        value_pos += 1
                    
                    if value_pos < len(data):
                        caption_info = self._extract_any_string_value(data, value_pos, name_bytes.decode())
                        if caption_info:
                            captions.append(caption_info)
                            pos = value_pos + caption_info.length
                        else:
                            pos += 1
                else:
                    pos += 1
            else:
                pos += 1
        
        return captions
    
    def _looks_like_text(self, data: bytes) -> bool:
        if not data:
            return False
        
        printable = sum(1 for b in data if 32 <= b <= 126 or b >= 128)
        return printable >= len(data) * 0.7
    
    def _safe_decode(self, data: bytes) -> Optional[str]:
        if not data:
            return None
        
        has_high_bytes = any(b >= 128 for b in data)
        
        if has_high_bytes:
            encodings = ['cp949', 'euc-kr', 'utf-8', 'latin-1']
        else:
            encodings = ['ascii', 'utf-8', 'latin-1']
        
        for encoding in encodings:
            try:
                text = data.decode(encoding, errors='strict')
                text = text.replace('\x00', '').strip()
                if text:
                    return text
            except:
                continue
        
        return data.decode('latin-1', errors='replace').strip()
    
    def _is_valid_caption(self, text: str) -> bool:
        if not text or len(text) == 0:
            return False
        
        clean = text.strip()
        if not clean or len(clean) < 1 or len(clean) > 1000:
            return False
        
        excluded = {
            'True', 'False', 'nil', '0', '1', '-1',
            'clBtnFace', 'clWindow', 'clWindowText'
        }
        
        if clean in excluded:
            return False
        
        try:
            float(clean)
            return False
        except ValueError:
            pass
        
        if not any(c.isalnum() or c in ' .,!?-_()[]{}/@#$%&*+=:;\'"' for c in clean):
            return False
        
        return True

class DFMRestructurer:
    def __init__(self):
        self.parser = ImprovedDFMParser()
    
    def restructure_with_translations(self, data: bytes, translations: Dict[str, str]) -> bytes:
        captions = self.parser.find_all_captions(data)
        
        if not captions:
            return data
        
        captions_to_modify = []
        for cap in captions:
            if cap.text in translations:
                captions_to_modify.append((cap, translations[cap.text]))
        
        captions_to_modify.sort(key=lambda x: x[0].position, reverse=True)
        
        new_data = bytearray(data)
        size_change = 0
        
        for caption, new_text in captions_to_modify:
            if caption.can_expand and caption.value_type in ['string', 'lstring', 'wstring', 'utf8string']:
                new_data, change = self._replace_caption_expandable(new_data, caption, new_text)
                size_change += change
            else:
                self._replace_caption_fixed(new_data, caption, new_text)
        
        return bytes(new_data)
    
    def _replace_caption_expandable(self, data: bytearray, caption: CaptionInfo, new_text: str) -> Tuple[bytearray, int]:
        size_change = 0
        
        if caption.value_type == 'string':
            encoded = new_text.encode('cp949', errors='ignore')
            
            if len(encoded) > 255:
                if caption.type_byte_pos > 0:
                    data[caption.type_byte_pos] = DFMValueType.vaWString
                    
                    length_bytes = struct.pack('<I', len(new_text))
                    wide_bytes = new_text.encode('utf-16-le')
                    
                    old_size = 1 + caption.length
                    new_size = 4 + len(wide_bytes)
                    
                    if new_size > old_size:
                        extra = new_size - old_size
                        data[caption.position - 1:caption.position - 1] = bytes(extra)
                        size_change = extra
                    elif new_size < old_size:
                        remove = old_size - new_size
                        del data[caption.position - 1:caption.position - 1 + remove]
                        size_change = -remove
                    
                    data[caption.position - 1:caption.position + 3] = length_bytes
                    data[caption.position + 3:caption.position + 3 + len(wide_bytes)] = wide_bytes
            else:
                old_size = 1 + caption.length
                new_size = 1 + len(encoded)
                
                if new_size > old_size:
                    extra = new_size - old_size
                    data[caption.position:caption.position] = bytes(extra)
                    size_change = extra
                elif new_size < old_size:
                    remove = old_size - new_size
                    del data[caption.position + len(encoded):caption.position + len(encoded) + remove]
                    size_change = -remove
                
                data[caption.position - 1] = len(encoded)
                data[caption.position:caption.position + len(encoded)] = encoded
        
        elif caption.value_type in ['lstring', 'wstring', 'utf8string']:
            if caption.value_type == 'wstring':
                encoded = new_text.encode('utf-16-le')
                char_count = len(new_text)
            elif caption.value_type == 'utf8string':
                encoded = new_text.encode('utf-8')
                char_count = len(encoded)
            else:
                encoded = new_text.encode('cp949', errors='ignore')
                char_count = len(encoded)
            
            old_content_size = caption.length
            new_content_size = len(encoded)
            
            if new_content_size != old_content_size:
                diff = new_content_size - old_content_size
                
                if diff > 0:
                    data[caption.position + old_content_size:caption.position + old_content_size] = bytes(diff)
                else:
                    del data[caption.position + new_content_size:caption.position + old_content_size]
                
                size_change = diff
            
            if caption.value_type == 'wstring':
                length_bytes = struct.pack('<I', char_count)
            else:
                length_bytes = struct.pack('<I', len(encoded))
            
            data[caption.position - 4:caption.position] = length_bytes
            data[caption.position:caption.position + len(encoded)] = encoded
        
        return data, size_change
    
    def _replace_caption_fixed(self, data: bytearray, caption: CaptionInfo, new_text: str):
        if any('\uac00' <= c <= '\ud7a3' for c in new_text):
            encoded = new_text.encode('cp949', errors='ignore')
        else:
            encoded = new_text.encode('latin-1', errors='ignore')
        
        if len(encoded) > caption.length:
            encoded = self._truncate_safely(encoded, caption.length)
        
        for i in range(caption.length):
            if i < len(encoded):
                data[caption.position + i] = encoded[i]
            else:
                data[caption.position + i] = 0x00
        
        if caption.value_type in ['string', 'direct'] and caption.position > 0:
            data[caption.position - 1] = min(len(encoded), 255)
    
    def _truncate_safely(self, encoded: bytes, max_length: int) -> bytes:
        if len(encoded) <= max_length:
            return encoded
        
        for i in range(max_length, max(0, max_length - 3), -1):
            try:
                test = encoded[:i]
                test.decode('cp949')
                return test
            except:
                continue
        
        return encoded[:max_length]

class RCDataTranslatorPlugin(TranslatorPlugin):
    """RCData (DFM) 리소스 번역 플러그인"""
    
    def __init__(self):
        super().__init__()
        self.name = "RCData/DFM Translator"
        self.version = "1.0"
        self.description = "Delphi/C++ Builder DFM 리소스 번역"
        self.resource_type = "RT_RCDATA"
        self.priority = 100
        
        self.parser = ImprovedDFMParser()
        self.restructurer = DFMRestructurer()
        self.resources = []
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
            self.resources = []
            
            resource_count = 0
            total_captions = 0
            english_captions = 0
            
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
                        for resource_id in resource_type.directory.entries:
                            resource_name = self._get_resource_name(resource_id)
                            
                            if resource_name.startswith('T'):
                                resource_count += 1
                                
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(
                                        resource_lang.data.struct.OffsetToData,
                                        resource_lang.data.struct.Size
                                    )
                                    
                                    lang_id = resource_lang.id if hasattr(resource_lang, 'id') else 0
                                    
                                    captions = self.parser.find_all_captions(data)
                                    caption_count = len(captions)
                                    total_captions += caption_count
                                    
                                    # Count English captions
                                    for caption in captions:
                                        if self._is_english_text(caption.text):
                                            english_captions += 1
                                    
                                    resource_info = {
                                        'id': resource_id.id if hasattr(resource_id, 'id') else 'N/A',
                                        'name': resource_name,
                                        'size': len(data),
                                        'language': f"0x{lang_id:04X}",
                                        'data': data,
                                        'offset': resource_lang.data.struct.OffsetToData,
                                        'captions': captions,
                                        'status': '파싱됨'
                                    }
                                    
                                    self.resources.append(resource_info)
            
            return {
                "count": resource_count,
                "items": [{
                    "name": res['name'],
                    "captions": len(res['captions']),
                    "size": res['size']
                } for res in self.resources],
                "summary": f"DFM 리소스 {resource_count}개, 캡션 {total_captions}개 (영어 {english_captions}개)"
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
            caption_map = {}
            
            for resource in self.resources:
                for caption in resource['captions']:
                    if self._is_english_text(caption.text):
                        if caption.text not in self.translations:
                            if caption.text not in to_translate:
                                to_translate.append(caption.text)
                            
                            if caption.text not in caption_map:
                                caption_map[caption.text] = []
                            caption_map[caption.text].append(resource['name'])
            
            if not to_translate:
                return {
                    "success": True,
                    "translated": 0,
                    "failed": 0,
                    "message": "번역할 영어 텍스트가 없습니다"
                }
            
            # Translate in batches
            translated_count = 0
            failed_count = 0
            batch_size = 10
            
            for i in range(0, len(to_translate), batch_size):
                batch = to_translate[i:i+batch_size]
                
                if progress_callback:
                    progress_callback(i, len(to_translate), f"번역 중... {i}/{len(to_translate)}")
                
                # API call
                api_translations = self._call_translation_api(batch, api_key)
                
                # Apply translations
                for text, translation in api_translations.items():
                    if text != translation:
                        self.translations[text] = translation
                        translated_count += 1
                    else:
                        failed_count += 1
            
            return {
                "success": True,
                "translated": translated_count,
                "failed": failed_count,
                "message": f"{translated_count}개 번역 완료"
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
                error_code = kernel32.GetLastError()
                raise Exception(f"리소스 업데이트 시작 실패 (오류: {error_code})")
            
            success_count = 0
            failed_count = 0
            
            # Update each resource
            for resource in self.resources:
                # Build translation map for this resource
                resource_translations = {}
                
                for caption in resource['captions']:
                    if caption.text in self.translations:
                        resource_translations[caption.text] = self.translations[caption.text]
                
                if resource_translations:
                    # Restructure data
                    restructured_data = self.restructurer.restructure_with_translations(
                        resource['data'], 
                        resource_translations
                    )
                    
                    # Prepare parameters
                    if resource['name'].startswith('ID_'):
                        resource_id = int(resource['name'][3:])
                        resource_param = MAKEINTRESOURCE(resource_id)
                    else:
                        resource_param = ctypes.c_wchar_p(resource['name'])
                    
                    language = int(resource['language'][2:], 16)
                    
                    # Update
                    data_buffer = ctypes.create_string_buffer(restructured_data)
                    
                    if kernel32.UpdateResourceW(
                        h_update,
                        MAKEINTRESOURCE(RT_RCDATA),
                        resource_param,
                        language,
                        data_buffer,
                        len(restructured_data)
                    ):
                        success_count += 1
                    else:
                        failed_count += 1
            
            # Commit
            if not kernel32.EndUpdateResourceW(h_update, False):
                error_code = kernel32.GetLastError()
                raise Exception(f"리소스 업데이트 커밋 실패 (오류: {error_code})")
            
            return {
                "success": True,
                "message": f"{success_count}개 리소스 업데이트 성공",
                "details": {
                    "updated": success_count,
                    "failed": failed_count
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
            self.pe.close()
            self.pe = None
    
    def _get_resource_name(self, resource_id):
        """Get resource name"""
        if hasattr(resource_id, 'name') and resource_id.name:
            return str(resource_id.name)
        elif hasattr(resource_id, 'id') and resource_id.id is not None:
            return f"ID_{resource_id.id}"
        return "UNKNOWN"
    
    def _is_english_text(self, text):
        """텍스트가 영어인지 확인"""
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
            
            prompt = "다음 Windows 프로그램 UI 텍스트들을 자연스러운 한국어로 번역해주세요.\n"
            prompt += "각 텍스트는 메뉴, 버튼, 라벨 등의 UI 요소입니다.\n"
            prompt += "간결하고 명확한 한국어로 번역해주세요.\n\n"
            
            text_list = {}
            for i, text in enumerate(texts, 1):
                key = f"text{i}"
                text_list[key] = text
                prompt += f"{key}: {text}\n"
            
            prompt += "\n다음 JSON 형식으로 응답해주세요:\n"
            prompt += '{"text1": "번역1", "text2": "번역2", ...}'
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {
                        "role": "system", 
                        "content": "당신은 Windows 프로그램 UI 전문 번역가입니다. "
                                  "영어 UI 텍스트를 자연스럽고 표준적인 한국어로 번역합니다. "
                                  "Microsoft Windows의 한국어 번역 스타일을 따릅니다."
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
                
                # JSON 파싱
                try:
                    import re
                    json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
                    if json_match:
                        json_str = json_match.group()
                        parsed = json.loads(json_str)
                        
                        for i, text in enumerate(texts, 1):
                            key = f"text{i}"
                            if key in parsed:
                                translations[text] = parsed[key]
                            else:
                                translations[text] = text
                    else:
                        for text in texts:
                            translations[text] = text
                            
                except json.JSONDecodeError:
                    for text in texts:
                        translations[text] = text
                        
            elif response.status_code == 401:
                raise Exception("API 키가 유효하지 않습니다.")
            elif response.status_code == 429:
                raise Exception("API 요청 한도를 초과했습니다.")
            else:
                raise Exception(f"API 오류: {response.status_code}")
                
        except requests.exceptions.Timeout:
            for text in texts:
                translations[text] = text
                
        except Exception as e:
            print(f"API 오류: {e}")
            for text in texts:
                translations[text] = text
        
        return translations