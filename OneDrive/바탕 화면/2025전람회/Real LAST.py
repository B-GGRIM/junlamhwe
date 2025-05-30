import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import pefile
import struct
import os
import re
import ctypes
from ctypes import wintypes
import shutil
import time
import datetime
from typing import List, Dict, Tuple, Optional, Set, Any
import json
import threading
import requests
from dataclasses import dataclass, field
from enum import IntEnum

# Windows API constants
RT_STRING = 6
RT_RCDATA = 10

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

class DFMValueType(IntEnum):
    """DFM value types"""
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
    """Caption information"""
    text: str
    position: int
    length: int
    value_type: str
    type_byte_pos: int = 0
    can_expand: bool = True

class ImprovedDFMParser:
    """개선된 DFM 파서 - 모든 텍스트 속성 찾기"""
    
    def __init__(self):
        self.debug = False
        self.encodings = ['utf-8', 'cp949', 'euc-kr', 'latin-1', 'cp1252']
        # 찾을 텍스트 속성들 확장
        self.text_properties = [
            b'Caption', b'Text', b'Hint', b'Title', b'DisplayLabel',
            b'EditLabel', b'Category', b'Description', b'Value',
            b'DisplayName', b'FieldName', b'Filter', b'DefaultExt',
            b'FileName', b'StatusBar', b'SimpleText'
        ]
    
    def find_all_captions(self, data: bytes) -> List[CaptionInfo]:
        """모든 Caption과 텍스트 속성 찾기"""
        all_captions = []
        
        # Skip TPF header if present
        offset = 0
        if len(data) > 3 and data[0:3] == b'TPF':
            offset = 4
        
        # Method 1: 향상된 패턴 매칭
        pattern_captions = self._find_by_enhanced_pattern(data, offset)
        all_captions.extend(pattern_captions)
        
        # Method 2: 재귀적 구조 파싱
        struct_captions = self._parse_dfm_recursive(data, offset)
        
        # Method 3: Items/Lines 컬렉션 파싱
        collection_captions = self._find_collection_strings(data, offset)
        
        # 중복 제거하며 병합
        caption_map = {}
        for cap in all_captions + struct_captions + collection_captions:
            key = f"{cap.position}:{cap.text}"
            if key not in caption_map:
                caption_map[key] = cap
        
        # 정렬 및 필터링
        captions = list(caption_map.values())
        captions = sorted(captions, key=lambda x: x.position)
        captions = [cap for cap in captions if self._is_valid_caption(cap.text)]
        
        return captions
    
    def _find_by_enhanced_pattern(self, data: bytes, start_offset: int) -> List[CaptionInfo]:
        """향상된 패턴 매칭으로 모든 텍스트 속성 찾기"""
        captions = []
        
        for prop_name in self.text_properties:
            pos = start_offset
            prop_len = len(prop_name)
            
            while pos < len(data) - prop_len - 10:
                # 속성 이름 길이 확인
                if pos < len(data) and data[pos] == prop_len:
                    # 속성 이름 확인
                    if pos + prop_len + 1 <= len(data):
                        if data[pos+1:pos+1+prop_len] == prop_name:
                            # 속성 값 위치
                            value_pos = pos + 1 + prop_len
                            
                            # = 기호 건너뛰기
                            while value_pos < len(data) and data[value_pos] in [0x20, 0x09, 0x3D]:  # space, tab, =
                                value_pos += 1
                            
                            if value_pos < len(data):
                                # 값 추출
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
        """재귀적으로 DFM 구조 파싱"""
        captions = []
        pos = start_pos
        
        while pos < len(data) - 10:
            # object 또는 inherited 키워드 찾기
            if self._check_keyword(data, pos, b'object') or self._check_keyword(data, pos, b'inherited'):
                # 키워드 건너뛰기
                keyword_len = 6 if data[pos:pos+6] == b'object' else 9
                pos += keyword_len
                
                # 공백 건너뛰기
                while pos < len(data) and data[pos] in [0x20, 0x09, 0x0A, 0x0D]:
                    pos += 1
                
                # 객체 끝 찾기 (end 키워드)
                obj_end = self._find_object_end(data, pos)
                if obj_end > pos:
                    # 객체 내부 파싱
                    obj_captions = self._parse_object_properties(data, pos, obj_end)
                    captions.extend(obj_captions)
                    
                    # 중첩된 객체 찾기
                    nested = self._parse_dfm_recursive(data, pos, depth + 1)
                    captions.extend(nested)
                    
                    pos = obj_end
                else:
                    pos += 1
            
            # item 키워드 (컬렉션 아이템)
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
        """Items, Lines 등 컬렉션 내부 문자열 찾기"""
        captions = []
        collection_props = [b'Items.Strings', b'Lines.Strings', b'Tabs.Strings']
        
        for prop in collection_props:
            pos = start_offset
            while pos < len(data) - len(prop) - 10:
                # 컬렉션 속성 찾기
                if self._find_property(data, pos, prop):
                    pos += len(prop) + 1
                    
                    # ( 찾기
                    while pos < len(data) and data[pos] != ord('('):
                        pos += 1
                    pos += 1
                    
                    # ) 까지 문자열들 추출
                    while pos < len(data) and data[pos] != ord(')'):
                        # 문자열 추출
                        if data[pos] == ord("'"):  # 작은따옴표 시작
                            pos += 1
                            start = pos
                            # 닫는 따옴표 찾기
                            while pos < len(data) and data[pos] != ord("'"):
                                # 이스케이프된 따옴표 처리
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
        """다양한 형식의 문자열 값 추출"""
        if pos >= len(data):
            return None
        
        # 1. Type byte가 있는 경우
        result = self._extract_typed_value(data, pos)
        if result:
            return result
        
        # 2. 작은따옴표로 둘러싸인 문자열
        if data[pos] == ord("'"):
            return self._extract_quoted_string(data, pos)
        
        # 3. #으로 시작하는 문자 코드
        if data[pos] == ord("#"):
            return self._extract_char_code_string(data, pos)
        
        # 4. 직접 길이 바이트가 있는 경우
        if 0 < data[pos] < 255:
            return self._extract_direct_string(data, pos)
        
        return None
    
    def _extract_typed_value(self, data: bytes, pos: int) -> Optional[CaptionInfo]:
        """타입 바이트가 있는 값 추출"""
        if pos >= len(data):
            return None
        
        value_type = data[pos]
        type_pos = pos
        pos += 1
        
        # vaString (6)
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
        
        # vaLString (12)
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
        
        # vaWString (18)
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
        
        # vaUTF8String (20)
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
        """작은따옴표로 둘러싸인 문자열 추출"""
        if pos >= len(data) or data[pos] != ord("'"):
            return None
        
        start_pos = pos
        pos += 1  # 여는 따옴표 건너뛰기
        text_start = pos
        
        text_parts = []
        while pos < len(data):
            if data[pos] == ord("'"):
                # 이스케이프된 따옴표 확인
                if pos + 1 < len(data) and data[pos + 1] == ord("'"):
                    text_parts.append(data[text_start:pos + 1])
                    pos += 2
                    text_start = pos
                else:
                    # 닫는 따옴표
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
        """#로 시작하는 문자 코드 문자열 추출"""
        if pos >= len(data) or data[pos] != ord("#"):
            return None
        
        start_pos = pos
        chars = []
        
        while pos < len(data) and data[pos] == ord("#"):
            pos += 1
            num_start = pos
            
            # 숫자 읽기
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
        """직접 길이 바이트가 있는 문자열 추출"""
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
        """키워드 확인"""
        return (pos + len(keyword) <= len(data) and 
                data[pos:pos+len(keyword)] == keyword)
    
    def _find_property(self, data: bytes, pos: int, prop_name: bytes) -> bool:
        """속성 이름 찾기"""
        return (pos + len(prop_name) <= len(data) and 
                data[pos:pos+len(prop_name)] == prop_name)
    
    def _find_object_end(self, data: bytes, start_pos: int) -> int:
        """object의 end 위치 찾기"""
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
        """item의 end 위치 찾기"""
        pos = start_pos
        
        while pos < len(data) - 3:
            if self._check_keyword(data, pos, b'end'):
                return pos + 3
            elif self._check_keyword(data, pos, b'item'):
                # 다음 item 시작
                return pos
            else:
                pos += 1
        
        return -1
    
    def _parse_object_properties(self, data: bytes, start_pos: int, end_pos: int) -> List[CaptionInfo]:
        """객체 내부의 모든 속성 파싱"""
        captions = []
        pos = start_pos
        
        while pos < end_pos and pos < len(data) - 10:
            # 속성 이름 길이
            name_len = data[pos] if pos < len(data) else 0
            
            if 0 < name_len < 50 and pos + name_len + 1 <= len(data):
                name_bytes = data[pos + 1:pos + 1 + name_len]
                
                # 텍스트 속성인지 확인
                if name_bytes in self.text_properties:
                    value_pos = pos + 1 + name_len
                    
                    # = 건너뛰기
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
        """바이트가 텍스트처럼 보이는지 확인"""
        if not data:
            return False
        
        printable = sum(1 for b in data if 32 <= b <= 126 or b >= 128)
        return printable >= len(data) * 0.7
    
    def _safe_decode(self, data: bytes) -> Optional[str]:
        """안전하게 바이트 디코드"""
        if not data:
            return None
        
        # 인코딩 우선순위
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
        """유효한 캡션 텍스트인지 확인"""
        if not text or len(text) == 0:
            return False
        
        clean = text.strip()
        if not clean or len(clean) < 1 or len(clean) > 1000:
            return False
        
        # 시스템 값 제외 (축소)
        excluded = {
            'True', 'False', 'nil', '0', '1', '-1',
            'clBtnFace', 'clWindow', 'clWindowText'
        }
        
        if clean in excluded:
            return False
        
        # 숫자만 있는 경우 제외
        try:
            float(clean)
            return False
        except ValueError:
            pass
        
        # 최소한 하나의 의미있는 문자
        if not any(c.isalnum() or c in ' .,!?-_()[]{}/@#$%&*+=:;\'"' for c in clean):
            return False
        
        return True

class DFMRestructurer:
    """DFM 재구성 처리"""
    
    def __init__(self):
        self.parser = ImprovedDFMParser()
    
    def restructure_with_translations(self, data: bytes, translations: Dict[str, str]) -> bytes:
        """번역을 적용하여 DFM 재구성"""
        # Find all captions
        captions = self.parser.find_all_captions(data)
        
        if not captions:
            return data
        
        # Sort by position (reverse) to maintain offsets
        captions_to_modify = []
        for cap in captions:
            if cap.text in translations:
                captions_to_modify.append((cap, translations[cap.text]))
        
        captions_to_modify.sort(key=lambda x: x[0].position, reverse=True)
        
        # Create new data
        new_data = bytearray(data)
        size_change = 0
        
        # Process each caption
        for caption, new_text in captions_to_modify:
            if caption.can_expand and caption.value_type in ['string', 'lstring', 'wstring', 'utf8string']:
                # Calculate new size
                new_data, change = self._replace_caption_expandable(new_data, caption, new_text)
                size_change += change
            else:
                # Replace without expansion
                self._replace_caption_fixed(new_data, caption, new_text)
        
        return bytes(new_data)
    
    def _replace_caption_expandable(self, data: bytearray, caption: CaptionInfo, new_text: str) -> Tuple[bytearray, int]:
        """확장 가능한 Caption 교체"""
        size_change = 0
        
        if caption.value_type == 'string':  # Pascal string
            # Encode new text
            encoded = new_text.encode('cp949', errors='ignore')
            
            if len(encoded) > 255:
                # Convert to wide string
                if caption.type_byte_pos > 0:
                    # Change type to wide string
                    data[caption.type_byte_pos] = DFMValueType.vaWString
                    
                    # Insert space for 4-byte length
                    length_bytes = struct.pack('<I', len(new_text))
                    wide_bytes = new_text.encode('utf-16-le')
                    
                    # Calculate space needed
                    old_size = 1 + caption.length  # 1 byte length + string
                    new_size = 4 + len(wide_bytes)  # 4 byte length + wide string
                    
                    # Expand/shrink data
                    if new_size > old_size:
                        # Need more space
                        extra = new_size - old_size
                        data[caption.position - 1:caption.position - 1] = bytes(extra)
                        size_change = extra
                    elif new_size < old_size:
                        # Remove extra space
                        remove = old_size - new_size
                        del data[caption.position - 1:caption.position - 1 + remove]
                        size_change = -remove
                    
                    # Write new data
                    data[caption.position - 1:caption.position + 3] = length_bytes
                    data[caption.position + 3:caption.position + 3 + len(wide_bytes)] = wide_bytes
            else:
                # Normal pascal string replacement
                old_size = 1 + caption.length
                new_size = 1 + len(encoded)
                
                if new_size > old_size:
                    # Expand
                    extra = new_size - old_size
                    data[caption.position:caption.position] = bytes(extra)
                    size_change = extra
                elif new_size < old_size:
                    # Shrink
                    remove = old_size - new_size
                    del data[caption.position + len(encoded):caption.position + len(encoded) + remove]
                    size_change = -remove
                
                # Update length and content
                data[caption.position - 1] = len(encoded)
                data[caption.position:caption.position + len(encoded)] = encoded
        
        elif caption.value_type in ['lstring', 'wstring', 'utf8string']:
            # These types already support variable length
            if caption.value_type == 'wstring':
                encoded = new_text.encode('utf-16-le')
                char_count = len(new_text)
            elif caption.value_type == 'utf8string':
                encoded = new_text.encode('utf-8')
                char_count = len(encoded)
            else:  # lstring
                encoded = new_text.encode('cp949', errors='ignore')
                char_count = len(encoded)
            
            # Calculate size difference
            old_content_size = caption.length
            new_content_size = len(encoded)
            
            if new_content_size != old_content_size:
                diff = new_content_size - old_content_size
                
                if diff > 0:
                    # Expand
                    data[caption.position + old_content_size:caption.position + old_content_size] = bytes(diff)
                else:
                    # Shrink
                    del data[caption.position + new_content_size:caption.position + old_content_size]
                
                size_change = diff
            
            # Update length field
            if caption.value_type == 'wstring':
                length_bytes = struct.pack('<I', char_count)
            else:
                length_bytes = struct.pack('<I', len(encoded))
            
            data[caption.position - 4:caption.position] = length_bytes
            
            # Update content
            data[caption.position:caption.position + len(encoded)] = encoded
        
        return data, size_change
    
    def _replace_caption_fixed(self, data: bytearray, caption: CaptionInfo, new_text: str):
        """고정 크기 Caption 교체"""
        # Encode with appropriate encoding
        if any('\uac00' <= c <= '\ud7a3' for c in new_text):
            encoded = new_text.encode('cp949', errors='ignore')
        else:
            encoded = new_text.encode('latin-1', errors='ignore')
        
        # Fit to current size
        if len(encoded) > caption.length:
            encoded = self._truncate_safely(encoded, caption.length)
        
        # Replace in place
        for i in range(caption.length):
            if i < len(encoded):
                data[caption.position + i] = encoded[i]
            else:
                data[caption.position + i] = 0x00
        
        # Update length byte if applicable
        if caption.value_type in ['string', 'direct'] and caption.position > 0:
            data[caption.position - 1] = min(len(encoded), 255)
    
    def _truncate_safely(self, encoded: bytes, max_length: int) -> bytes:
        """안전하게 멀티바이트 문자열 자르기"""
        if len(encoded) <= max_length:
            return encoded
        
        # Try to avoid breaking multibyte characters
        for i in range(max_length, max(0, max_length - 3), -1):
            try:
                test = encoded[:i]
                test.decode('cp949')  # Test if valid
                return test
            except:
                continue
        
        return encoded[:max_length]

class UniversalResourceTranslatorGUI:
    """통합 리소스 번역 GUI - String Table + RCData"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Universal Resource Translator - 통합 리소스 번역기")
        self.root.geometry("1400x900")
        
        self.pe = None
        self.string_tables = {}  # {(block_id, lang_id): {string_id: string}}
        self.rcdata_resources = []  # DFM resources
        self.file_path = ""
        self.string_parser = StringTableParser()
        self.dfm_parser = ImprovedDFMParser()
        self.dfm_restructurer = DFMRestructurer()
        self.string_modifications = {}  # {string_id: translated_text}
        self.rcdata_modifications = {}  # {resource_name: {original: translated}}
        
        self.api_key = ""
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title frame
        title_frame = ttk.LabelFrame(main_frame, text="Universal Resource Translator", padding="10")
        title_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        title_label = ttk.Label(title_frame, 
                               text="Windows EXE 파일의 String Table과 DFM 리소스를 한번에 번역합니다.\n"
                               "• String Table: 프로그램 메시지, 에러, 상태 텍스트\n"
                               "• DFM 리소스: 폼, 다이얼로그, UI 컴포넌트의 Caption\n"
                               "• ChatGPT API를 사용한 정확한 한국어 번역\n"
                               "• 한 번의 클릭으로 모든 리소스 번역",
                               foreground="blue")
        title_label.pack()
        
        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="파일 선택", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=60).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="찾아보기", command=self.browse_file).grid(row=0, column=1)
        ttk.Button(file_frame, text="리소스 로드", command=self.load_all_resources).grid(row=0, column=2, padx=5)
        ttk.Button(file_frame, text="백업 생성", command=self.create_backup).grid(row=0, column=3, padx=5)
        ttk.Button(file_frame, text="백업 복원", command=self.restore_backup).grid(row=0, column=4, padx=5)
        ttk.Button(file_frame, text="API 키", command=self.set_api_key).grid(row=0, column=5, padx=5)
        
        # Statistics
        self.stats_label = ttk.Label(file_frame, text="", foreground="green")
        self.stats_label.grid(row=1, column=0, columnspan=6, pady=5)
        
        # Main content - Notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Tab 1: String Table
        string_frame = ttk.Frame(self.notebook)
        self.notebook.add(string_frame, text="String Table")
        self.setup_string_table_tab(string_frame)
        
        # Tab 2: DFM Resources
        dfm_frame = ttk.Frame(self.notebook)
        self.notebook.add(dfm_frame, text="DFM Resources")
        self.setup_dfm_resources_tab(dfm_frame)
        
        # Tab 3: Translation Summary
        summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(summary_frame, text="번역 요약")
        self.setup_summary_tab(summary_frame)
        
        # Bottom buttons
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Translation button
        translate_button = ttk.Button(bottom_frame, 
                                    text="전체 번역 (String Table + DFM)", 
                                    command=self.translate_all_resources,
                                    style="Accent.TButton")
        translate_button.pack(side=tk.RIGHT, padx=5)
        
        # Apply button
        apply_button = ttk.Button(bottom_frame, 
                                text="번역 적용", 
                                command=self.apply_all_translations)
        apply_button.pack(side=tk.RIGHT, padx=5)
        
        # Clear button
        ttk.Button(bottom_frame, text="초기화", command=self.clear_all_modifications).pack(side=tk.RIGHT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="준비")
        status_bar = ttk.Label(bottom_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Configure weights
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.columnconfigure(0, weight=1)
    
    def setup_string_table_tab(self, parent):
        """String Table 탭 설정"""
        # String tree
        columns = ("ID", "영어 원문", "한국어 번역", "상태")
        self.string_tree = ttk.Treeview(parent, columns=columns, show="tree headings", height=20)
        
        self.string_tree.heading("#0", text="블록")
        self.string_tree.heading("ID", text="ID")
        self.string_tree.heading("영어 원문", text="영어 원문")
        self.string_tree.heading("한국어 번역", text="한국어 번역")
        self.string_tree.heading("상태", text="상태")
        
        self.string_tree.column("#0", width=100)
        self.string_tree.column("ID", width=60)
        self.string_tree.column("영어 원문", width=350)
        self.string_tree.column("한국어 번역", width=350)
        self.string_tree.column("상태", width=80)
        
        # Scrollbar
        string_scroll = ttk.Scrollbar(parent, orient="vertical", command=self.string_tree.yview)
        self.string_tree.configure(yscrollcommand=string_scroll.set)
        
        self.string_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        string_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
    
    def setup_dfm_resources_tab(self, parent):
        """DFM Resources 탭 설정"""
        # Paned window
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Left: Resource list
        left_frame = ttk.Frame(paned)
        
        columns = ("리소스", "크기", "캡션 수", "상태")
        self.resource_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=20)
        
        self.resource_tree.heading("리소스", text="리소스")
        self.resource_tree.heading("크기", text="크기")
        self.resource_tree.heading("캡션 수", text="캡션 수")
        self.resource_tree.heading("상태", text="상태")
        
        self.resource_tree.column("리소스", width=150)
        self.resource_tree.column("크기", width=80)
        self.resource_tree.column("캡션 수", width=60)
        self.resource_tree.column("상태", width=80)
        
        resource_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.resource_tree.yview)
        self.resource_tree.configure(yscrollcommand=resource_scroll.set)
        
        self.resource_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        resource_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.resource_tree.bind('<<TreeviewSelect>>', self.on_resource_select)
        
        # Right: Caption list
        right_frame = ttk.Frame(paned)
        
        caption_columns = ("원본", "번역", "타입")
        self.caption_tree = ttk.Treeview(right_frame, columns=caption_columns, show="headings", height=20)
        
        self.caption_tree.heading("원본", text="원본")
        self.caption_tree.heading("번역", text="번역")
        self.caption_tree.heading("타입", text="타입")
        
        self.caption_tree.column("원본", width=250)
        self.caption_tree.column("번역", width=250)
        self.caption_tree.column("타입", width=80)
        
        caption_scroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.caption_tree.yview)
        self.caption_tree.configure(yscrollcommand=caption_scroll.set)
        
        self.caption_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        caption_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        paned.add(left_frame, weight=1)
        paned.add(right_frame, weight=2)
        
        left_frame.rowconfigure(0, weight=1)
        left_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)
        right_frame.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
    
    def setup_summary_tab(self, parent):
        """번역 요약 탭 설정"""
        self.summary_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=("Courier", 10))
        self.summary_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
    
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
            backup_path = f"{file_path}.unified_backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            messagebox.showinfo("성공", f"백업 생성: {os.path.basename(backup_path)}")
        except Exception as e:
            messagebox.showerror("오류", f"백업 실패: {str(e)}")
    
    def restore_backup(self):
        """백업 복원"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "먼저 파일을 선택하세요")
            return
        
        directory = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)
        
        backup_files = []
        for file in os.listdir(directory):
            if file.startswith(base_name + ".") and "backup" in file:
                backup_files.append(file)
        
        if not backup_files:
            messagebox.showerror("오류", "백업 파일을 찾을 수 없습니다!")
            return
        
        # Selection dialog
        if len(backup_files) == 1:
            selected = backup_files[0]
        else:
            dialog = tk.Toplevel(self.root)
            dialog.title("백업 선택")
            dialog.geometry("600x400")
            dialog.transient(self.root)
            dialog.grab_set()
            
            ttk.Label(dialog, text="복원할 백업을 선택하세요:").pack(pady=10)
            
            listbox = tk.Listbox(dialog)
            listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            for backup in sorted(backup_files, reverse=True):
                listbox.insert(tk.END, backup)
            
            selected = [None]
            
            def restore():
                if listbox.curselection():
                    idx = listbox.curselection()[0]
                    selected[0] = backup_files[idx]
                    dialog.destroy()
            
            ttk.Button(dialog, text="복원", command=restore).pack(pady=10)
            dialog.wait_window()
            
            if not selected[0]:
                return
            
            selected = selected[0]
        
        if messagebox.askyesno("복원 확인", f"{selected}에서 복원하시겠습니까?"):
            try:
                backup_path = os.path.join(directory, selected)
                shutil.copy2(backup_path, file_path)
                messagebox.showinfo("성공", "백업에서 파일이 복원되었습니다!")
                self.clear_all_modifications()
                self.load_all_resources()
            except Exception as e:
                messagebox.showerror("오류", f"복원 실패: {str(e)}")
    
    def load_all_resources(self):
        """모든 리소스 로드"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "먼저 EXE 파일을 선택하세요.")
            return
        
        self.file_path = file_path
        
        try:
            self.status_var.set("리소스 로드 중...")
            self.string_tables.clear()
            self.rcdata_resources.clear()
            self.string_modifications.clear()
            self.rcdata_modifications.clear()
            
            # Clear UI
            for item in self.string_tree.get_children():
                self.string_tree.delete(item)
            for item in self.resource_tree.get_children():
                self.resource_tree.delete(item)
            for item in self.caption_tree.get_children():
                self.caption_tree.delete(item)
            
            if self.pe:
                self.pe.close()
            
            self.pe = pefile.PE(file_path)
            
            string_count = 0
            string_block_count = 0
            rcdata_count = 0
            caption_count = 0
            
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    # String Table
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_STRING']:
                        for resource_id in resource_type.directory.entries:
                            block_id = resource_id.id if hasattr(resource_id, 'id') else 0
                            
                            if block_id > 0:
                                string_block_count += 1
                                
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
                                    strings = self.string_parser.parse_string_table(data, block_id)
                                    
                                    if strings:
                                        self.string_tables[(block_id, lang_id)] = strings
                                        string_count += len(strings)
                                        
                                        # Add to tree
                                        for string_id, text in sorted(strings.items()):
                                            self.string_tree.insert(block_node, "end",
                                                                  values=(
                                                                      string_id,
                                                                      text,
                                                                      "",  # 번역
                                                                      "원본"
                                                                  ),
                                                                  tags=(string_id,))
                    
                    # RCData (DFM)
                    elif resource_type.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
                        for resource_id in resource_type.directory.entries:
                            resource_name = self.get_resource_name(resource_id)
                            
                            # Filter DFM resources (T-prefix)
                            if resource_name.startswith('T'):
                                rcdata_count += 1
                                
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(
                                        resource_lang.data.struct.OffsetToData,
                                        resource_lang.data.struct.Size
                                    )
                                    
                                    lang_id = resource_lang.id if hasattr(resource_lang, 'id') else 0
                                    
                                    # Parse captions
                                    captions = self.dfm_parser.find_all_captions(data)
                                    caption_count += len(captions)
                                    
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
                                    
                                    self.rcdata_resources.append(resource_info)
                                    
                                    # Add to tree
                                    self.resource_tree.insert("", "end", values=(
                                        resource_info['name'],
                                        f"{resource_info['size']} 바이트",
                                        len(captions),
                                        resource_info['status']
                                    ))
            
            # Update statistics
            self.stats_label.config(
                text=f"String Table: {string_block_count}개 블록, {string_count}개 문자열 | "
                f"DFM 리소스: {rcdata_count}개, {caption_count}개 캡션"
            )
            self.status_var.set("리소스 로드 완료")
            
            # Update summary
            self.update_summary()
            
        except Exception as e:
            self.status_var.set("파일 로드 오류")
            messagebox.showerror("오류", f"파일 로드 중 오류 발생: {str(e)}")
    
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
        
        # Clear caption tree
        for item in self.caption_tree.get_children():
            self.caption_tree.delete(item)
        
        # Find selected resource
        for resource in self.rcdata_resources:
            if str(resource['name']) == str(values[0]):
                # Display captions
                for caption in resource['captions']:
                    translation = caption.text
                    if resource['name'] in self.rcdata_modifications:
                        if caption.text in self.rcdata_modifications[resource['name']]:
                            translation = self.rcdata_modifications[resource['name']][caption.text]
                    
                    self.caption_tree.insert("", "end", values=(
                        caption.text,
                        translation,
                        caption.value_type
                    ))
                break
    
    def _is_english_text(self, text):
        """텍스트가 영어인지 확인"""
        if not text or len(text.strip()) == 0:
            return False
        
        # 숫자만 있는 경우 제외
        if text.strip().isdigit():
            return False
        
        ascii_count = sum(1 for c in text if ord(c) < 128)
        korean_count = sum(1 for c in text if '\uac00' <= c <= '\ud7a3')
        
        # 한글이 있으면 번역된 것
        if korean_count > 0:
            return False
        
        # ASCII 비율이 80% 이상이고 알파벳이 포함되어 있으면 영어
        has_alpha = any(c.isalpha() for c in text)
        return ascii_count / len(text) > 0.8 and has_alpha
    
    def translate_all_resources(self):
        """모든 리소스 번역 - String Table + DFM"""
        if not self.api_key:
            messagebox.showwarning("API Key 필요", "먼저 API 키를 설정해주세요.")
            self.set_api_key()
            if not self.api_key:
                return
        
        # 번역할 텍스트 수집
        to_translate = []
        text_map = {}  # {text: [(type, id)]}
        
        # String Table 텍스트 수집
        for (block_id, lang_id), strings in self.string_tables.items():
            for string_id, text in strings.items():
                if self._is_english_text(text) and string_id not in self.string_modifications:
                    if text not in to_translate:
                        to_translate.append(text)
                    if text not in text_map:
                        text_map[text] = []
                    text_map[text].append(('string', string_id))
        
        # DFM 캡션 수집
        for resource in self.rcdata_resources:
            for caption in resource['captions']:
                if self._is_english_text(caption.text):
                    already_translated = False
                    if resource['name'] in self.rcdata_modifications:
                        if caption.text in self.rcdata_modifications[resource['name']]:
                            already_translated = True
                    
                    if not already_translated:
                        if caption.text not in to_translate:
                            to_translate.append(caption.text)
                        if caption.text not in text_map:
                            text_map[caption.text] = []
                        text_map[caption.text].append(('dfm', resource['name']))
        
        if not to_translate:
            messagebox.showinfo("정보", "번역할 영어 텍스트가 없습니다.")
            return
        
        # 확인 대화상자
        if messagebox.askyesno("번역 확인", 
                             f"총 {len(to_translate)}개의 영어 텍스트를 발견했습니다.\n\n"
                             f"String Table: {sum(1 for t in text_map.values() for item in t if item[0] == 'string')}개\n"
                             f"DFM Caption: {sum(1 for t in text_map.values() for item in t if item[0] == 'dfm')}개\n\n"
                             "API를 사용하여 모두 한국어로 번역하시겠습니까?"):
            
            # Progress dialog
            progress = tk.Toplevel(self.root)
            progress.title("통합 번역 진행 중")
            progress.geometry("600x400")
            progress.transient(self.root)
            progress.grab_set()
            
            ttk.Label(progress, text="String Table과 DFM 리소스를 번역 중...").pack(pady=10)
            
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(progress, variable=progress_var, maximum=len(to_translate))
            progress_bar.pack(fill=tk.X, padx=20, pady=10)
            
            log_text = scrolledtext.ScrolledText(progress, height=15)
            log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            def translate_worker():
                try:
                    # Batch translate
                    batch_size = 10
                    string_translated = 0
                    dfm_translated = 0
                    
                    for i in range(0, len(to_translate), batch_size):
                        batch = to_translate[i:i+batch_size]
                        
                        # API call
                        translations = self.call_translation_api(batch)
                        
                        # Apply translations
                        for text, translation in translations.items():
                            if text in text_map:
                                for type_name, id_val in text_map[text]:
                                    if type_name == 'string':
                                        self.string_modifications[id_val] = translation
                                        string_translated += 1
                                        log_text.insert(tk.END, f"[String {id_val}] {text} → {translation}\n")
                                    elif type_name == 'dfm':
                                        if id_val not in self.rcdata_modifications:
                                            self.rcdata_modifications[id_val] = {}
                                        self.rcdata_modifications[id_val][text] = translation
                                        dfm_translated += 1
                                        log_text.insert(tk.END, f"[DFM {id_val}] {text} → {translation}\n")
                            
                            log_text.see(tk.END)
                        
                        progress_var.set(min(i + batch_size, len(to_translate)))
                        progress.update()
                    
                    messagebox.showinfo("번역 완료", 
                                      f"번역이 완료되었습니다!\n\n"
                                      f"String Table: {string_translated}개 번역됨\n"
                                      f"DFM Caption: {dfm_translated}개 번역됨\n"
                                      f"총 {string_translated + dfm_translated}개 항목 번역")
                    
                except Exception as e:
                    messagebox.showerror("오류", str(e))
                finally:
                    progress.destroy()
                    self.refresh_all_views()
                    self.update_summary()
            
            # Start translation
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
            
            prompt = "다음 Windows 프로그램의 텍스트들을 자연스러운 한국어로 번역해주세요.\n"
            prompt += "String Table 메시지와 UI Caption이 섞여 있습니다.\n"
            prompt += "간결하고 명확한 한국어로 번역해주세요.\n\n"
            
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
        """Set API key"""
        dialog = tk.Toplevel(self.root)
        dialog.title("API 키 설정")
        dialog.geometry("500x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="OpenAI API 키:").pack(pady=10)
        
        api_var = tk.StringVar(value=self.api_key)
        entry = ttk.Entry(dialog, textvariable=api_var, width=50, show="*")
        entry.pack(pady=10)
        
        def save():
            self.api_key = api_var.get().strip()
            dialog.destroy()
        
        ttk.Button(dialog, text="저장", command=save).pack(pady=10)
    
    def refresh_all_views(self):
        """모든 뷰 새로고침"""
        # Refresh String Table tree
        for item in self.string_tree.get_children():
            block_node = item
            for child in self.string_tree.get_children(block_node):
                values = self.string_tree.item(child)['values']
                tags = self.string_tree.item(child)['tags']
                if tags:
                    string_id = tags[0]
                    if string_id in self.string_modifications:
                        new_values = list(values)
                        new_values[2] = self.string_modifications[string_id]
                        new_values[3] = "번역됨"
                        self.string_tree.item(child, values=new_values)
        
        # Refresh caption view if selected
        self.on_resource_select(None)
    
    def update_summary(self):
        """번역 요약 업데이트"""
        self.summary_text.delete(1.0, tk.END)
        
        summary = "통합 번역 요약\n"
        summary += "=" * 80 + "\n\n"
        
        # String Table 요약
        summary += "[ String Table ]\n"
        summary += "-" * 40 + "\n"
        total_strings = sum(len(strings) for strings in self.string_tables.values())
        translated_strings = len(self.string_modifications)
        summary += f"총 문자열: {total_strings}개\n"
        summary += f"번역된 문자열: {translated_strings}개\n"
        summary += f"번역률: {translated_strings/total_strings*100:.1f}%\n\n" if total_strings > 0 else "\n"
        
        # 번역 예시
        if self.string_modifications:
            summary += "번역 예시:\n"
            for i, (string_id, translation) in enumerate(list(self.string_modifications.items())[:5]):
                # Find original
                original = ""
                for strings in self.string_tables.values():
                    if string_id in strings:
                        original = strings[string_id]
                        break
                summary += f"  {original} → {translation}\n"
            summary += "\n"
        
        # DFM Resources 요약
        summary += "[ DFM Resources ]\n"
        summary += "-" * 40 + "\n"
        total_captions = sum(len(r['captions']) for r in self.rcdata_resources)
        translated_captions = sum(len(mods) for mods in self.rcdata_modifications.values())
        summary += f"총 리소스: {len(self.rcdata_resources)}개\n"
        summary += f"총 캡션: {total_captions}개\n"
        summary += f"번역된 캡션: {translated_captions}개\n"
        summary += f"번역률: {translated_captions/total_captions*100:.1f}%\n\n" if total_captions > 0 else "\n"
        
        # 번역 예시
        if self.rcdata_modifications:
            summary += "번역 예시:\n"
            count = 0
            for resource_name, translations in self.rcdata_modifications.items():
                for original, translated in list(translations.items())[:5]:
                    summary += f"  [{resource_name}] {original} → {translated}\n"
                    count += 1
                    if count >= 5:
                        break
                if count >= 5:
                    break
        
        self.summary_text.insert(1.0, summary)
    
    def clear_all_modifications(self):
        """모든 번역 초기화"""
        if self.string_modifications or self.rcdata_modifications:
            if messagebox.askyesno("확인", "모든 번역을 초기화하시겠습니까?"):
                self.string_modifications.clear()
                self.rcdata_modifications.clear()
                self.refresh_all_views()
                self.update_summary()
                self.status_var.set("번역 초기화됨")
    
    def apply_all_translations(self):
        """모든 번역 적용"""
        if not self.string_modifications and not self.rcdata_modifications:
            messagebox.showinfo("정보", "적용할 번역이 없습니다.")
            return
        
        total_changes = len(self.string_modifications) + sum(len(m) for m in self.rcdata_modifications.values())
        
        if not messagebox.askyesno("번역 적용", 
                                 f"총 {total_changes}개의 번역을 적용하시겠습니까?\n\n"
                                 f"String Table: {len(self.string_modifications)}개\n"
                                 f"DFM Caption: {sum(len(m) for m in self.rcdata_modifications.values())}개\n\n"
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
            
            # Apply String Table modifications
            for (block_id, lang_id), strings in self.string_tables.items():
                # Build new string table with translations
                new_strings = {}
                modified = False
                
                for string_id, original in strings.items():
                    if string_id in self.string_modifications:
                        new_strings[string_id] = self.string_modifications[string_id]
                        modified = True
                    else:
                        new_strings[string_id] = original
                
                if modified:
                    # Build new string table data
                    new_data = self.string_parser.build_string_table(new_strings, block_id)
                    
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
            
            # Apply DFM modifications
            for resource in self.rcdata_resources:
                if resource['name'] in self.rcdata_modifications:
                    # Build translation map
                    translations = self.rcdata_modifications[resource['name']]
                    
                    # Create restructured data
                    if translations:
                        self.status_var.set(f"{resource['name']} 재구성 중...")
                        restructured_data = self.dfm_restructurer.restructure_with_translations(
                            resource['data'], 
                            translations
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
            
            # Commit
            if not kernel32.EndUpdateResourceW(h_update, False):
                raise Exception("리소스 업데이트 커밋 실패")
            
            messagebox.showinfo("성공", 
                              f"{success_count}개 리소스가 업데이트되었습니다.\n\n"
                              "번역이 성공적으로 적용되었습니다.")
            
            # Reload
            self.string_modifications.clear()
            self.rcdata_modifications.clear()
            self.load_all_resources()
            
        except Exception as e:
            self.status_var.set("적용 실패")
            messagebox.showerror("오류", f"번역 적용 실패: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = UniversalResourceTranslatorGUI(root)
    root.mainloop()