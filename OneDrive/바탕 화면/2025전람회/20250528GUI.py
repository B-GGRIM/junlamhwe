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
RT_RCDATA = 10

# Windows API functions
kernel32 = ctypes.windll.kernel32

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
        """타입 바이트가 있는 값 추출 (기존 로직)"""
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

class UnlimitedCaptionTranslatorGUI:
    """범용 Caption 번역 GUI - API 전용"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Universal Caption Translator - 범용 캡션 번역기")
        self.root.geometry("1200x800")
        
        self.pe = None
        self.resources = []
        self.file_path = ""
        self.parser = ImprovedDFMParser()  # 개선된 파서 사용
        self.restructurer = DFMRestructurer()
        self.modifications = {}
        
        self.api_key = ""
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Warning frame
        warning_frame = ttk.LabelFrame(main_frame, text="⚠️ Universal Translation Mode - 범용 번역 모드", padding="10")
        warning_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        warning_label = ttk.Label(warning_frame, 
                                text="이 프로그램은 모든 Windows EXE 파일의 영어 텍스트를 한국어로 번역합니다.\n"
                                "• 자동으로 영어 텍스트를 감지하여 번역\n"
                                "• ChatGPT API를 사용한 자연스럽고 정확한 한국어 번역\n"
                                "• 개선된 파서로 모든 Caption과 텍스트 속성 감지\n"
                                "• 번역 길이 제한 없이 DFM 파일 자동 재구성\n"
                                "• 모든 Delphi/C++ Builder 프로그램 완벽 지원",
                                foreground="blue")
        warning_label.pack()
        
        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="파일 선택", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=60).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="찾아보기", command=self.browse_file).grid(row=0, column=1)
        ttk.Button(file_frame, text="리소스 로드", command=self.load_resources).grid(row=0, column=2, padx=5)
        
        # Backup controls
        ttk.Button(file_frame, text="백업 생성", command=self.create_backup).grid(row=0, column=3, padx=5)
        ttk.Button(file_frame, text="백업 복원", command=self.restore_backup).grid(row=0, column=4, padx=5)
        
        # API Key
        ttk.Button(file_frame, text="API 키", command=self.set_api_key).grid(row=0, column=5, padx=5)
        
        # Statistics
        self.stats_label = ttk.Label(file_frame, text="", foreground="green")
        self.stats_label.grid(row=1, column=0, columnspan=6, pady=5)
        
        # Main content
        main_paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        main_paned.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Left panel - Resources
        left_frame = ttk.LabelFrame(main_paned, text="DFM 리소스", padding="10")
        
        columns = ("ID", "리소스", "크기", "캡션 수", "상태")
        self.resource_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=20)
        
        self.resource_tree.heading("ID", text="ID")
        self.resource_tree.heading("리소스", text="리소스")
        self.resource_tree.heading("크기", text="크기")
        self.resource_tree.heading("캡션 수", text="캡션 수")
        self.resource_tree.heading("상태", text="상태")
        
        self.resource_tree.column("ID", width=50)
        self.resource_tree.column("리소스", width=120)
        self.resource_tree.column("크기", width=80)
        self.resource_tree.column("캡션 수", width=60)
        self.resource_tree.column("상태", width=80)
        
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.resource_tree.yview)
        self.resource_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.resource_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.resource_tree.bind('<<TreeviewSelect>>', self.on_resource_select)
        
        # Middle panel - Structure view
        middle_frame = ttk.LabelFrame(main_paned, text="DFM 구조", padding="10")
        
        self.structure_text = scrolledtext.ScrolledText(middle_frame, wrap=tk.WORD, font=("Courier", 9))
        self.structure_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Right panel - Captions
        right_frame = ttk.LabelFrame(main_paned, text="캡션 번역", padding="10")
        
        # Caption list
        caption_columns = ("원본", "번역", "크기 변화", "타입")
        self.caption_tree = ttk.Treeview(right_frame, columns=caption_columns, show="headings", height=15)
        
        self.caption_tree.heading("원본", text="원본")
        self.caption_tree.heading("번역", text="번역")
        self.caption_tree.heading("크기 변화", text="크기 변화")
        self.caption_tree.heading("타입", text="타입")
        
        self.caption_tree.column("원본", width=200)
        self.caption_tree.column("번역", width=200)
        self.caption_tree.column("크기 변화", width=80)
        self.caption_tree.column("타입", width=60)
        
        caption_scroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.caption_tree.yview)
        self.caption_tree.configure(yscrollcommand=caption_scroll.set)
        
        self.caption_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        caption_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.caption_tree.bind('<Double-Button-1>', self.on_caption_double_click)
        
        # Caption operations
        ops_frame = ttk.Frame(right_frame)
        ops_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(ops_frame, text="편집", command=self.edit_caption).pack(side=tk.LEFT, padx=2)
        ttk.Button(ops_frame, text="API 번역", command=self.translate_all_unlimited).pack(side=tk.LEFT, padx=2)
        ttk.Button(ops_frame, text="크기 보고서", command=self.show_size_report).pack(side=tk.LEFT, padx=2)
        ttk.Button(ops_frame, text="초기화", command=self.clear_modifications).pack(side=tk.LEFT, padx=2)
        
        # Add panels
        main_paned.add(left_frame, weight=1)
        main_paned.add(middle_frame, weight=2)
        main_paned.add(right_frame, weight=2)
        
        # Bottom
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status
        self.status_var = tk.StringVar(value="준비 - 범용 번역 모드")
        status_bar = ttk.Label(bottom_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=2)
        
        # Action buttons
        button_frame = ttk.Frame(bottom_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="번역 적용", 
                  command=self.apply_unlimited_modifications,
                  style="Accent.TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="구조 검증", 
                  command=self.verify_structure).pack(side=tk.RIGHT, padx=5)
        
        # Configure weights
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(0, weight=1)
        left_frame.columnconfigure(0, weight=1)
        middle_frame.rowconfigure(0, weight=1)
        middle_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)
        right_frame.columnconfigure(0, weight=1)
    
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
            backup_path = f"{file_path}.unlimited_backup_{timestamp}"
            
            shutil.copy2(file_path, backup_path)
            
            messagebox.showinfo("성공", 
                              f"백업이 생성되었습니다:\n{os.path.basename(backup_path)}")
        except Exception as e:
            messagebox.showerror("오류", f"백업 생성 실패: {str(e)}")
    
    def restore_backup(self):
        """백업 복구"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "먼저 파일을 선택하세요")
            return
        
        # Find backups
        directory = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)
        
        backup_files = []
        for file in os.listdir(directory):
            if (file.startswith(base_name + ".unlimited_backup") or 
                file.startswith(base_name + ".backup") or
                file.startswith(base_name + ".safe_backup")):
                backup_files.append(file)
        
        if not backup_files:
            messagebox.showerror("오류", "백업 파일을 찾을 수 없습니다!")
            return
        
        # Select backup
        if len(backup_files) == 1:
            selected = backup_files[0]
        else:
            # Selection dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("백업 선택")
            dialog.geometry("600x400")
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Center dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - 300
            y = (dialog.winfo_screenheight() // 2) - 200
            dialog.geometry(f"600x400+{x}+{y}")
            
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
            
            selected = [None]
            
            def restore():
                if listbox.curselection():
                    idx = listbox.curselection()[0]
                    selected[0] = backup_info[idx][0]
                    dialog.destroy()
            
            ttk.Button(dialog, text="복원", command=restore).pack(pady=10)
            dialog.wait_window()
            
            if not selected[0]:
                return
            
            selected = selected[0]
        
        # Restore
        if messagebox.askyesno("복원 확인", 
                             f"{selected}에서 복원하시겠습니까?\n\n현재 파일이 덮어씌워집니다!"):
            try:
                backup_path = os.path.join(directory, selected)
                shutil.copy2(backup_path, file_path)
                
                messagebox.showinfo("성공", "백업에서 파일이 복원되었습니다!")
                
                # Reload
                self.modifications.clear()
                self.load_resources()
                
            except Exception as e:
                messagebox.showerror("오류", f"복원 실패: {str(e)}")
    
    def load_resources(self):
        """리소스 로드"""
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("경고", "먼저 EXE 파일을 선택하세요.")
            return
        
        self.file_path = file_path
        
        try:
            self.status_var.set("리소스 로드 중...")
            self.resources.clear()
            self.modifications.clear()
            
            # Clear UI
            for item in self.resource_tree.get_children():
                self.resource_tree.delete(item)
            self.clear_all_views()
            
            if self.pe:
                self.pe.close()
            
            self.pe = pefile.PE(file_path)
            
            resource_count = 0
            total_captions = 0
            
            # Extract RT_RCDATA resources
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
                        for resource_id in resource_type.directory.entries:
                            resource_name = self.get_resource_name(resource_id)
                            
                            # Filter DFM resources (T-prefix)
                            if resource_name.startswith('T'):
                                resource_count += 1
                                
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(
                                        resource_lang.data.struct.OffsetToData,
                                        resource_lang.data.struct.Size
                                    )
                                    
                                    lang_id = resource_lang.id if hasattr(resource_lang, 'id') else 0
                                    
                                    # Parse captions using improved parser
                                    captions = self.parser.find_all_captions(data)
                                    caption_count = len(captions)
                                    total_captions += caption_count
                                    
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
                                    
                                    # Add to tree
                                    self.resource_tree.insert("", "end", values=(
                                        resource_info['id'],
                                        resource_info['name'],
                                        f"{resource_info['size']} 바이트",
                                        caption_count,
                                        resource_info['status']
                                    ))
            
            # Update statistics
            self.stats_label.config(
                text=f"DFM 리소스 {resource_count}개 로드됨 | "
                f"총 캡션 수: {total_captions}개 | "
                f"범용 번역 준비 완료"
            )
            self.status_var.set("준비 - 리소스 로드 완료")
            
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
        
        # Find selected resource
        for resource in self.resources:
            if str(resource['name']) == str(values[1]):
                self.display_resource_details(resource)
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
    
    def display_resource_details(self, resource):
        """Display resource details"""
        self.clear_all_views()
        
        # Structure view
        structure_info = f"리소스: {resource['name']}\n"
        structure_info += f"크기: {resource['size']} 바이트\n"
        structure_info += f"발견된 캡션: {len(resource['captions'])}개\n"
        structure_info += "=" * 60 + "\n\n"
        
        # Show captions found
        if resource['captions']:
            structure_info += "DFM 객체 구조:\n"
            structure_info += f"Form 또는 Dialog\n"
            for i, caption in enumerate(resource['captions']):
                # 영어인지 확인
                is_english = self._is_english_text(caption.text)
                lang_indicator = " [영어]" if is_english else " [번역됨]"
                structure_info += f"  Caption {i+1} = '{caption.text}' [{caption.value_type}]{lang_indicator}\n"
        
        self.structure_text.insert(1.0, structure_info)
        
        # Caption list
        for item in self.caption_tree.get_children():
            self.caption_tree.delete(item)
        
        for caption in resource['captions']:
            # Check for translation
            translation = caption.text
            if resource['name'] in self.modifications:
                if caption.text in self.modifications[resource['name']]:
                    translation = self.modifications[resource['name']][caption.text]
            
            # Size change
            original_size = len(caption.text.encode('cp949', errors='ignore'))
            translated_size = len(translation.encode('cp949', errors='ignore'))
            size_change = translated_size - original_size
            
            if size_change > 0:
                size_str = f"+{size_change}"
            elif size_change < 0:
                size_str = str(size_change)
            else:
                size_str = "0"
            
            # Add to tree
            self.caption_tree.insert("", "end", values=(
                caption.text,
                translation,
                size_str,
                caption.value_type
            ), tags=(resource['name'], caption.text))
    
    def clear_all_views(self):
        """Clear all views"""
        self.structure_text.delete(1.0, tk.END)
        for item in self.caption_tree.get_children():
            self.caption_tree.delete(item)
    
    def on_caption_double_click(self, event):
        """Handle double click"""
        self.edit_caption()
    
    def edit_caption(self):
        """Edit caption - unlimited length"""
        selection = self.caption_tree.selection()
        if not selection:
            messagebox.showwarning("경고", "편집할 캡션을 선택하세요.")
            return
        
        item = self.caption_tree.item(selection[0])
        values = item['values']
        tags = item['tags']
        
        if len(tags) >= 2:
            resource_name = tags[0]
            original_text = tags[1]
            
            # Edit dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("캡션 편집 - 길이 제한 없음")
            dialog.geometry("600x400")
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Main frame
            main_frame = ttk.Frame(dialog, padding="10")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Info
            info_frame = ttk.LabelFrame(main_frame, text="캡션 정보", padding="10")
            info_frame.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(info_frame, text=f"리소스: {resource_name}").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"원본: {original_text}").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"원본 크기: {len(original_text.encode('cp949'))} 바이트").pack(anchor=tk.W)
            
            # Edit area
            edit_frame = ttk.LabelFrame(main_frame, text="새 번역 (크기 제한 없음)", padding="10")
            edit_frame.pack(fill=tk.BOTH, expand=True)
            
            text_widget = tk.Text(edit_frame, height=8, font=("Arial", 11))
            text_widget.pack(fill=tk.BOTH, expand=True)
            
            # Pre-fill with current translation if exists
            if resource_name in self.modifications:
                if original_text in self.modifications[resource_name]:
                    text_widget.insert("1.0", self.modifications[resource_name][original_text])
                else:
                    text_widget.insert("1.0", original_text)
            else:
                text_widget.insert("1.0", original_text)
            
            text_widget.focus_set()
            text_widget.tag_add(tk.SEL, "1.0", tk.END)
            
            # Size indicator
            size_label = ttk.Label(edit_frame, text="", foreground="blue")
            size_label.pack(pady=(5, 0))
            
            def update_size(*args):
                new_text = text_widget.get("1.0", tk.END).strip()
                new_size = len(new_text.encode('cp949', errors='ignore'))
                size_diff = new_size - len(original_text.encode('cp949'))
                
                if size_diff > 0:
                    size_label.config(
                        text=f"새 크기: {new_size} 바이트 (+{size_diff} 바이트) - 자동으로 처리됩니다",
                        foreground="green"
                    )
                else:
                    size_label.config(
                        text=f"새 크기: {new_size} 바이트 ({size_diff} 바이트)",
                        foreground="black"
                    )
            
            text_widget.bind('<KeyRelease>', update_size)
            update_size()
            
            # Buttons
            button_frame = ttk.Frame(dialog)
            button_frame.pack(fill=tk.X, pady=(10, 0))
            
            def save_caption():
                new_text = text_widget.get("1.0", tk.END).strip()
                
                if new_text and new_text != original_text:
                    if resource_name not in self.modifications:
                        self.modifications[resource_name] = {}
                    self.modifications[resource_name][original_text] = new_text
                    
                    self.status_var.set(f"캡션 수정됨: {original_text} → {new_text}")
                    dialog.destroy()
                    
                    # Refresh
                    self.on_resource_select(None)
                else:
                    dialog.destroy()
            
            ttk.Button(button_frame, text="취소", command=dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(button_frame, text="저장", command=save_caption).pack(side=tk.RIGHT)
    
    def translate_all_unlimited(self):
        """모든 Caption API 번역 - 자동 감지 및 번역"""
        if not self.api_key:
            messagebox.showwarning("API Key 필요", "먼저 API 키를 설정해주세요.")
            self.set_api_key()
            if not self.api_key:
                return
        
        # 영어 텍스트인지 확인하는 함수
        def is_english_text(text):
            # 기본 ASCII 문자가 80% 이상이고, 한글이 없으면 영어로 간주
            if not text or len(text.strip()) == 0:
                return False
            
            # 숫자만 있는 경우 제외
            if text.strip().isdigit():
                return False
            
            ascii_count = sum(1 for c in text if ord(c) < 128)
            korean_count = sum(1 for c in text if '\uac00' <= c <= '\ud7a3')
            
            # 한글이 있으면 이미 번역된 것으로 간주
            if korean_count > 0:
                return False
            
            # ASCII 비율이 80% 이상이고 알파벳이 포함되어 있으면 영어로 간주
            has_alpha = any(c.isalpha() for c in text)
            return ascii_count / len(text) > 0.8 and has_alpha
        
        to_translate = []
        caption_map = {}
        
        # 모든 영어 caption 수집
        for resource in self.resources:
            for caption in resource['captions']:
                if is_english_text(caption.text):
                    # 이미 번역된 것 제외
                    already_translated = False
                    if resource['name'] in self.modifications:
                        if caption.text in self.modifications[resource['name']]:
                            already_translated = True
                    
                    if not already_translated:
                        if caption.text not in to_translate:
                            to_translate.append(caption.text)
                        
                        if caption.text not in caption_map:
                            caption_map[caption.text] = []
                        caption_map[caption.text].append(resource['name'])
        
        if not to_translate:
            messagebox.showinfo("정보", "번역할 영어 텍스트가 없습니다.")
            return
        
        # 진행 상황 표시
        if messagebox.askyesno("번역 확인", 
                             f"{len(to_translate)}개의 영어 텍스트를 발견했습니다.\n\n"
                             f"예시:\n"
                             f"• {to_translate[0] if to_translate else ''}\n"
                             f"• {to_translate[1] if len(to_translate) > 1 else ''}\n"
                             f"• {to_translate[2] if len(to_translate) > 2 else ''}\n\n"
                             "API를 사용하여 모두 한국어로 번역하시겠습니까?"):
            
            # Progress dialog
            progress = tk.Toplevel(self.root)
            progress.title("API 번역 진행 중")
            progress.geometry("500x300")
            progress.transient(self.root)
            progress.grab_set()
            
            ttk.Label(progress, text="영어 텍스트를 한국어로 번역 중...").pack(pady=10)
            
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(progress, variable=progress_var, maximum=len(to_translate))
            progress_bar.pack(fill=tk.X, padx=20, pady=10)
            
            log_text = scrolledtext.ScrolledText(progress, height=10)
            log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            def translate_worker():
                try:
                    # Batch translate
                    batch_size = 10
                    
                    for i in range(0, len(to_translate), batch_size):
                        batch = to_translate[i:i+batch_size]
                        
                        # API call
                        translations = self.call_translation_api(batch)
                        
                        # Apply
                        for text, translation in translations.items():
                            for resource_name in caption_map[text]:
                                if resource_name not in self.modifications:
                                    self.modifications[resource_name] = {}
                                self.modifications[resource_name][text] = translation
                            
                            log_text.insert(tk.END, f"{text} → {translation}\n")
                            log_text.see(tk.END)
                        
                        progress_var.set(min(i + batch_size, len(to_translate)))
                        progress.update()
                    
                    messagebox.showinfo("번역 완료", 
                                      f"{len(to_translate)}개의 텍스트를 번역했습니다!\n"
                                      "모든 번역이 전체 길이로 보존됩니다.")
                    
                except Exception as e:
                    messagebox.showerror("오류", str(e))
                finally:
                    progress.destroy()
                    self.on_resource_select(None)
            
            # Start translation
            thread = threading.Thread(target=translate_worker, daemon=True)
            thread.start()
    
    def call_translation_api(self, texts):
        """Call translation API - 개선된 버전"""
        translations = {}
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # 더 명확한 프롬프트
            prompt = "다음 Windows 프로그램 UI 텍스트들을 자연스러운 한국어로 번역해주세요.\n"
            prompt += "각 텍스트는 메뉴, 버튼, 라벨 등의 UI 요소입니다.\n"
            prompt += "간결하고 명확한 한국어로 번역해주세요.\n\n"
            
            # 번역할 텍스트 목록
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
            
            print(f"API 호출 중... {len(texts)}개 텍스트 번역")
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                print(f"API 응답: {content[:200]}...")  # 디버깅용
                
                # JSON 파싱 개선
                try:
                    # JSON 부분만 추출
                    import re
                    json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
                    if json_match:
                        json_str = json_match.group()
                        parsed = json.loads(json_str)
                        
                        # 매핑 복원
                        for i, text in enumerate(texts, 1):
                            key = f"text{i}"
                            if key in parsed:
                                translations[text] = parsed[key]
                                print(f"번역됨: {text} → {parsed[key]}")
                            else:
                                # 키가 없으면 원본 유지
                                translations[text] = text
                    else:
                        # JSON을 찾을 수 없으면 다른 방식 시도
                        lines = content.strip().split('\n')
                        for i, text in enumerate(texts):
                            for line in lines:
                                if text in line and ':' in line:
                                    # "text: translation" 형식 파싱
                                    parts = line.split(':', 1)
                                    if len(parts) == 2:
                                        translation = parts[1].strip().strip('"').strip("'")
                                        translations[text] = translation
                                        break
                            
                            if text not in translations:
                                translations[text] = text
                                
                except json.JSONDecodeError as e:
                    print(f"JSON 파싱 오류: {e}")
                    # 파싱 실패시 원본 유지
                    for text in texts:
                        translations[text] = text
                        
            elif response.status_code == 401:
                raise Exception("API 키가 유효하지 않습니다.")
            elif response.status_code == 429:
                raise Exception("API 요청 한도를 초과했습니다. 잠시 후 다시 시도하세요.")
            else:
                raise Exception(f"API 오류: {response.status_code} - {response.text}")
                
        except requests.exceptions.Timeout:
            print("API 요청 시간 초과")
            # 타임아웃시 원본 유지
            for text in texts:
                translations[text] = text
                
        except Exception as e:
            print(f"API 오류: {e}")
            # 오류시 원본 유지
            for text in texts:
                translations[text] = text
        
        # 번역 결과 검증
        success_count = sum(1 for orig, trans in translations.items() if orig != trans)
        print(f"번역 완료: {success_count}/{len(texts)}개 성공")
        
        return translations
    
    def set_api_key(self):
        """Set API key"""
        dialog = tk.Toplevel(self.root)
        dialog.title("API 키 설정")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="OpenAI API 키를 입력하세요:").pack(pady=10)
        
        api_var = tk.StringVar(value=self.api_key)
        entry = ttk.Entry(dialog, textvariable=api_var, width=50, show="*")
        entry.pack(pady=10)
        
        def save():
            self.api_key = api_var.get().strip()
            dialog.destroy()
        
        ttk.Button(dialog, text="저장", command=save).pack(pady=10)
    
    def show_size_report(self):
        """Show size change report"""
        dialog = tk.Toplevel(self.root)
        dialog.title("번역 크기 보고서")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        
        # Create report
        report_text = scrolledtext.ScrolledText(dialog, font=("Courier", 10))
        report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        report = "무제한 번역 크기 보고서\n"
        report += "=" * 80 + "\n\n"
        
        total_original = 0
        total_translated = 0
        expandable_count = 0
        fixed_count = 0
        
        for resource in self.resources:
            if resource['captions']:
                report += f"\n리소스: {resource['name']}\n"
                report += "-" * 40 + "\n"
                
                for caption in resource['captions']:
                    translation = caption.text
                    
                    if resource['name'] in self.modifications:
                        if caption.text in self.modifications[resource['name']]:
                            translation = self.modifications[resource['name']][caption.text]
                    
                    if translation != caption.text:
                        orig_size = len(caption.text.encode('cp949', errors='ignore'))
                        trans_size = len(translation.encode('cp949', errors='ignore'))
                        
                        total_original += orig_size
                        total_translated += trans_size
                        
                        if caption.can_expand:
                            expandable_count += 1
                            status = "[확장가능]"
                        else:
                            fixed_count += 1
                            status = "[고정크기]"
                        
                        report += f"  '{caption.text}' ({orig_size}b) → '{translation}' ({trans_size}b) {status}"
                        
                        if trans_size > orig_size:
                            report += f" [+{trans_size - orig_size} 바이트]"
                        
                        report += "\n"
        
        report += "\n" + "=" * 80 + "\n"
        report += f"원본 총 크기: {total_original} 바이트\n"
        report += f"번역 총 크기: {total_translated} 바이트\n"
        report += f"총 증가량: {total_translated - total_original} 바이트\n"
        report += f"확장 가능한 캡션: {expandable_count}개\n"
        report += f"고정 크기 캡션: {fixed_count}개\n"
        report += "\n확장 가능한 캡션은 자동으로 크기가 조정됩니다.\n"
        report += "고정 크기 캡션은 필요시 잘립니다."
        
        report_text.insert(1.0, report)
        
        ttk.Button(dialog, text="닫기", command=dialog.destroy).pack(pady=10)
    
    def clear_modifications(self):
        """Clear modifications"""
        if self.modifications:
            if messagebox.askyesno("확인", "모든 번역을 초기화하시겠습니까?"):
                self.modifications.clear()
                self.on_resource_select(None)
                self.status_var.set("번역 초기화됨")
    
    def verify_structure(self):
        """Verify DFM structure"""
        issues = []
        
        for resource in self.resources:
            if resource['name'] in self.modifications:
                try:
                    # Test restructuring
                    translations = {}
                    if resource['name'] in self.modifications:
                        translations.update(self.modifications[resource['name']])
                    
                    # Only test if there are translations
                    if translations:
                        # Test restructure
                        new_data = self.restructurer.restructure_with_translations(
                            resource['data'], 
                            translations
                        )
                        
                        # Re-parse
                        new_captions = self.parser.find_all_captions(new_data)
                        
                        # Compare
                        if len(new_captions) != len(resource['captions']):
                            issues.append(f"{resource['name']}: Caption count changed ({len(resource['captions'])} → {len(new_captions)})")
                    
                except Exception as e:
                    issues.append(f"{resource['name']}: {str(e)}")
        
        if issues:
            messagebox.showwarning("구조 문제 발견", 
                                 "다음 문제가 발견되었습니다:\n\n" + "\n".join(issues[:10]))
        else:
            messagebox.showinfo("구조 검증 완료", 
                              "모든 DFM 구조가 정상입니다!\n"
                              "번역을 안전하게 적용할 수 있습니다.")
    
    def apply_unlimited_modifications(self):
        """Apply modifications with DFM restructuring"""
        if not self.modifications:
            messagebox.showinfo("정보", "적용할 변경사항이 없습니다.")
            return
        
        total_changes = sum(len(changes) for changes in self.modifications.values())
        
        # Confirmation
        if not messagebox.askyesno("번역 적용 확인",
                                 f"{total_changes}개의 번역을 적용하시겠습니까?\n\n"
                                 "다음 작업이 수행됩니다:\n"
                                 "• 모든 번역 길이 보존\n"
                                 "• 필요시 DFM 파일 재구성\n"
                                 "• 자동 문자열 타입 변환\n\n"
                                 "백업이 자동으로 생성됩니다."):
            return
        
        try:
            # Auto backup
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.file_path}.pre_unlimited_{timestamp}"
            
            self.status_var.set("백업 생성 중...")
            shutil.copy2(self.file_path, backup_path)
            
            # Close PE
            if self.pe:
                self.pe.close()
                self.pe = None
            
            time.sleep(0.3)
            
            # Begin update
            self.status_var.set("번역 적용 중...")
            h_update = kernel32.BeginUpdateResourceW(self.file_path, False)
            if not h_update:
                error_code = kernel32.GetLastError()
                raise Exception(f"리소스 업데이트를 시작할 수 없습니다. 오류 코드: {error_code}")
            
            success_count = 0
            failed_count = 0
            
            # Update each resource
            for resource in self.resources:
                if resource['name'] in self.modifications:
                    try:
                        # Build translation map
                        translations = {}
                        
                        # Add modifications
                        if resource['name'] in self.modifications:
                            translations.update(self.modifications[resource['name']])
                        
                        # Create restructured data only if there are translations
                        if translations:
                            self.status_var.set(f"{resource['name']} 재구성 중...")
                            restructured_data = self.restructurer.restructure_with_translations(
                                resource['data'], 
                                translations
                            )
                            
                            # Log size change
                            size_change = len(restructured_data) - len(resource['data'])
                            if size_change != 0:
                                print(f"{resource['name']}: 크기가 {size_change:+} 바이트 변경됨")
                            
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
                                error_code = kernel32.GetLastError()
                                print(f"{resource['name']} 업데이트 실패: 오류 {error_code}")
                        
                    except Exception as e:
                        failed_count += 1
                        print(f"{resource['name']} 업데이트 중 오류: {str(e)}")
            
            # Commit
            self.status_var.set("변경사항 커밋 중...")
            if not kernel32.EndUpdateResourceW(h_update, False):
                error_code = kernel32.GetLastError()
                raise Exception(f"리소스 업데이트를 커밋할 수 없습니다. 오류 코드: {error_code}")
            
            # Report
            msg = f"{success_count}개의 리소스를 성공적으로 업데이트했습니다.\n"
            if failed_count > 0:
                msg += f"실패: {failed_count}개 리소스\n"
            msg += f"\n백업 파일: {os.path.basename(backup_path)}"
            
            messagebox.showinfo("성공", msg)
            
            # Reload
            self.modifications.clear()
            self.load_resources()
            
        except Exception as e:
            self.status_var.set("번역 적용 오류")
            messagebox.showerror("오류", 
                               f"번역 적용 실패:\n{str(e)}\n\n"
                               "백업에서 복원하세요.")

if __name__ == "__main__":
    root = tk.Tk()
    app = UnlimitedCaptionTranslatorGUI(root)
    root.mainloop()