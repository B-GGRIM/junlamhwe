import os
import shutil
from typing import List, Tuple, Dict, Set, Optional
import struct
import re
import json
from datetime import datetime
import hashlib

class SafeExePatcher:
    def __init__(self, exe_path: str):
        """
        안전한 EXE 파일 패처 - UI 번역에 특화
        
        Args:
            exe_path: 수정할 exe 파일 경로
        """
        self.exe_path = exe_path
        self.backup_path = exe_path + ".backup"
        self.log_path = exe_path + "_patch_log.json"
        self.patch_history = []
        self.pe_sections = {}
        self.ui_strings = []
        
    def create_backup(self) -> bool:
        """원본 파일 백업 생성 및 무결성 검증"""
        try:
            if not os.path.exists(self.backup_path):
                shutil.copy2(self.exe_path, self.backup_path)
                # 파일 해시 저장 (무결성 검증용)
                original_hash = self._calculate_file_hash(self.exe_path)
                backup_hash = self._calculate_file_hash(self.backup_path)
                
                if original_hash != backup_hash:
                    print("경고: 백업 파일 무결성 검증 실패")
                    return False
                    
                print(f"백업 파일 생성: {self.backup_path}")
                print(f"파일 해시: {original_hash}")
            return True
        except Exception as e:
            print(f"백업 생성 실패: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """파일 SHA256 해시 계산"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def analyze_pe_structure(self) -> bool:
        """PE 파일 구조 분석"""
        try:
            with open(self.exe_path, 'rb') as f:
                # DOS 헤더 확인
                dos_signature = f.read(2)
                if dos_signature != b'MZ':
                    print("경고: 유효한 PE 파일이 아닙니다.")
                    return False
                
                # PE 헤더 위치 찾기
                f.seek(0x3C)
                pe_offset = struct.unpack('<L', f.read(4))[0]
                
                # PE 서명 확인
                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    print("경고: PE 서명이 올바르지 않습니다.")
                    return False
                
                # COFF 헤더 읽기
                machine = struct.unpack('<H', f.read(2))[0]
                num_sections = struct.unpack('<H', f.read(2))[0]
                
                print(f"PE 파일 분석 완료 - 섹션 수: {num_sections}")
                self.pe_sections['num_sections'] = num_sections
                self.pe_sections['pe_offset'] = pe_offset
                
                return True
                
        except Exception as e:
            print(f"PE 구조 분석 실패: {e}")
            return False
    
    def find_ui_strings(self, min_length: int = 3) -> List[Dict]:
        """UI 관련 문자열들을 스마트하게 찾기"""
        ui_patterns = [
            # 일반적인 UI 텍스트 패턴
            r'\b(File|Edit|View|Tools|Help|Options|Settings|Cancel|OK|Yes|No|Apply|Close|Exit|Save|Open|New|Copy|Paste|Cut|Delete|Undo|Redo)\b',
            r'\b(Menu|Dialog|Button|Window|Tab|Panel|Group|Label|Text|Input|Output|Error|Warning|Info|Success)\b',
            r'\b(Start|Stop|Pause|Resume|Play|Record|Load|Unload|Install|Uninstall|Update|Refresh|Search|Find|Replace)\b',
            # 대화상자나 메시지 패턴
            r'^[A-Z][a-zA-Z\s]{2,30}[.!?:]?$',
            # 파일 확장자나 타입
            r'\*\.\w{2,4}',
            # 키보드 단축키
            r'Ctrl\+\w|Alt\+\w|Shift\+\w|F\d+',
        ]
        
        all_strings = self.extract_all_strings(min_length=min_length, max_length=100)
        ui_candidates = []
        
        for encoding, strings in all_strings.items():
            for string_val, pos, length in strings:
                # UI 문자열 가능성 점수 계산
                ui_score = 0
                
                # 패턴 매칭 점수
                for pattern in ui_patterns:
                    if re.search(pattern, string_val, re.IGNORECASE):
                        ui_score += 10
                
                # 길이 점수 (너무 길거나 짧으면 감점)
                if 3 <= len(string_val) <= 50:
                    ui_score += 5
                elif len(string_val) > 100:
                    ui_score -= 5
                
                # printable 문자 비율 점수
                printable_ratio = sum(1 for c in string_val if c.isprintable()) / len(string_val)
                ui_score += int(printable_ratio * 10)
                
                # 대문자로 시작하는 경우 점수 추가
                if string_val and string_val[0].isupper():
                    ui_score += 3
                
                # 특수문자나 숫자만 있는 경우 감점
                if re.match(r'^[^a-zA-Z]*$', string_val):
                    ui_score -= 10
                
                if ui_score >= 8:  # 임계값
                    ui_candidates.append({
                        'string': string_val,
                        'position': pos,
                        'length': length,
                        'encoding': encoding,
                        'ui_score': ui_score,
                        'category': self._categorize_ui_string(string_val)
                    })
        
        # 점수순으로 정렬
        ui_candidates.sort(key=lambda x: x['ui_score'], reverse=True)
        self.ui_strings = ui_candidates
        
        return ui_candidates
    
    def _categorize_ui_string(self, string_val: str) -> str:
        """UI 문자열 카테고리 분류"""
        string_lower = string_val.lower()
        
        if any(word in string_lower for word in ['file', 'open', 'save', 'new', 'exit']):
            return 'menu'
        elif any(word in string_lower for word in ['ok', 'cancel', 'yes', 'no', 'apply', 'close']):
            return 'button'
        elif any(word in string_lower for word in ['error', 'warning', 'info', 'success']):
            return 'message'
        elif any(word in string_lower for word in ['options', 'settings', 'preferences', 'config']):
            return 'settings'
        elif re.search(r'ctrl\+|alt\+|shift\+|f\d+', string_lower):
            return 'shortcut'
        else:
            return 'general'
    
    def safe_replace_string(self, original: str, replacement: str, encoding: str = 'utf-8', 
                          dry_run: bool = False) -> Dict:
        """안전한 문자열 교체 (길이 검증, 롤백 기능 포함)"""
        result = {
            'success': False,
            'positions_found': 0,
            'positions_replaced': 0,
            'warnings': [],
            'errors': []
        }
        
        try:
            positions = self.find_string_positions(original, encoding)
            result['positions_found'] = len(positions)
            
            if not positions:
                result['errors'].append(f"문자열 '{original}'을 찾을 수 없습니다.")
                return result
            
            # 한국어 문자열 길이 검증
            korean_char_count = sum(1 for c in replacement if ord(c) > 127)
            if korean_char_count > 0:
                # 한국어는 보통 2-3바이트이므로 더 엄격하게 검증
                max_allowed_length = min(pos[1] for pos in positions) // 3
                if len(replacement) > max_allowed_length:
                    result['warnings'].append(f"한국어 문자열이 너무 길 수 있습니다. (권장: {max_allowed_length}자 이하)")
            
            if dry_run:
                result['success'] = True
                result['positions_replaced'] = len(positions)
                return result
            
            # 실제 교체 수행
            with open(self.exe_path, 'r+b') as f:
                content = f.read()
                content_array = bytearray(content)
                replacements_made = 0
                
                # 위치를 역순으로 정렬 (뒤에서부터 교체)
                positions.sort(key=lambda x: x[0], reverse=True)
                
                for pos, orig_length, detected_encoding, has_null in positions:
                    try:
                        replacement_bytes = replacement.encode(detected_encoding)
                        
                        # Null terminator 처리
                        if has_null:
                            replacement_bytes += b'\x00'
                        
                        if len(replacement_bytes) <= orig_length:
                            # 남는 공간을 null로 채움
                            replacement_bytes = replacement_bytes.ljust(orig_length, b'\x00')
                            content_array[pos:pos + orig_length] = replacement_bytes
                            replacements_made += 1
                        else:
                            result['warnings'].append(f"위치 {pos}에서 교체 문자열이 너무 깁니다.")
                    
                    except UnicodeEncodeError as e:
                        result['errors'].append(f"인코딩 오류 (위치 {pos}): {e}")
                
                if replacements_made > 0:
                    f.seek(0)
                    f.write(content_array)
                    f.truncate()
                    
                    # 패치 로그 저장
                    self._log_patch(original, replacement, encoding, replacements_made)
                    
                    result['success'] = True
                    result['positions_replaced'] = replacements_made
                
        except Exception as e:
            result['errors'].append(f"교체 중 오류: {e}")
        
        return result
    
    def smart_korean_translation(self, translations_dict: Dict[str, str], 
                               target_categories: List[str] = None) -> Dict:
        """스마트 한국어 번역 (UI 카테고리별 처리)"""
        if not self.ui_strings:
            self.find_ui_strings()
        
        results = {
            'total_found': 0,
            'total_replaced': 0,
            'category_results': {},
            'failed_replacements': []
        }
        
        for ui_item in self.ui_strings:
            string_val = ui_item['string']
            category = ui_item['category']
            
            # 카테고리 필터링
            if target_categories and category not in target_categories:
                continue
            
            # 번역 사전에서 찾기
            korean_translation = None
            for english, korean in translations_dict.items():
                if english.lower() == string_val.lower() or english == string_val:
                    korean_translation = korean
                    break
            
            if korean_translation:
                results['total_found'] += 1
                
                # 안전한 교체 시도
                replace_result = self.safe_replace_string(
                    string_val, korean_translation, ui_item['encoding']
                )
                
                if replace_result['success']:
                    results['total_replaced'] += replace_result['positions_replaced']
                    
                    if category not in results['category_results']:
                        results['category_results'][category] = 0
                    results['category_results'][category] += 1
                    
                    print(f"✓ {category}: '{string_val}' → '{korean_translation}'")
                else:
                    results['failed_replacements'].append({
                        'original': string_val,
                        'translation': korean_translation,
                        'errors': replace_result['errors']
                    })
                    print(f"✗ 실패: '{string_val}' → '{korean_translation}' ({replace_result['errors']})")
        
        return results
    
    def _log_patch(self, original: str, replacement: str, encoding: str, count: int):
        """패치 기록 저장"""
        patch_info = {
            'timestamp': datetime.now().isoformat(),
            'original': original,
            'replacement': replacement,
            'encoding': encoding,
            'positions_replaced': count
        }
        
        self.patch_history.append(patch_info)
        
        # JSON 파일로 저장
        try:
            with open(self.log_path, 'w', encoding='utf-8') as f:
                json.dump(self.patch_history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"로그 저장 실패: {e}")
    
    def verify_exe_integrity(self) -> bool:
        """수정된 EXE 파일의 무결성 검증"""
        try:
            # 기본 PE 구조 검증
            if not self.analyze_pe_structure():
                return False
            
            # 파일 크기 검증 (너무 많이 변경되었는지 확인)
            original_size = os.path.getsize(self.backup_path)
            modified_size = os.path.getsize(self.exe_path)
            
            size_diff_ratio = abs(modified_size - original_size) / original_size
            if size_diff_ratio > 0.1:  # 10% 이상 크기 변화시 경고
                print(f"경고: 파일 크기가 {size_diff_ratio*100:.1f}% 변경되었습니다.")
                return False
            
            print("EXE 파일 무결성 검증 통과")
            return True
            
        except Exception as e:
            print(f"무결성 검증 실패: {e}")
            return False
    
    def create_translation_template(self) -> Dict[str, str]:
        """번역 템플릿 생성 (일반적인 UI 문자열들)"""
        common_ui_translations = {
            # 메뉴
            "File": "파일",
            "Edit": "편집",
            "View": "보기",
            "Tools": "도구",
            "Help": "도움말",
            "Window": "창",
            
            # 버튼
            "OK": "확인",
            "Cancel": "취소",
            "Yes": "예",
            "No": "아니오",
            "Apply": "적용",
            "Close": "닫기",
            "Exit": "종료",
            "Save": "저장",
            "Open": "열기",
            "New": "새로 만들기",
            "Copy": "복사",
            "Paste": "붙여넣기",
            "Cut": "잘라내기",
            "Delete": "삭제",
            "Undo": "실행 취소",
            "Redo": "다시 실행",
            
            # 일반
            "Error": "오류",
            "Warning": "경고",
            "Information": "정보",
            "Settings": "설정",
            "Options": "옵션",
            "Preferences": "환경설정",
            "About": "정보",
            "Search": "검색",
            "Find": "찾기",
            "Replace": "바꾸기",
            "Print": "인쇄",
            "Properties": "속성",
            "Start": "시작",
            "Stop": "중지",
            "Pause": "일시중지",
            "Resume": "계속",
            
            # 상태
            "Ready": "준비",
            "Loading": "로딩 중",
            "Complete": "완료",
            "Failed": "실패",
            "Success": "성공",
        }
        
        return common_ui_translations
    
    # 기존 메서드들은 그대로 유지 (find_string_positions, extract_all_strings 등)
    def find_string_positions(self, target_string: str, encoding: str = 'utf-8') -> List[Tuple[int, int, str, bool]]:
        """문자열의 위치를 찾습니다"""
        positions = []
        
        try:
            with open(self.exe_path, 'rb') as f:
                content = f.read()
                
            # 다양한 인코딩으로 시도
            encodings_to_try = [encoding, 'utf-8', 'cp949', 'utf-16le']
            encodings_to_try = list(dict.fromkeys(encodings_to_try))  # 중복 제거
            
            for enc in encodings_to_try:
                try:
                    target_bytes = target_string.encode(enc)
                    target_bytes_null = target_bytes + b'\x00'
                    
                    # 일반 문자열 찾기
                    start = 0
                    while True:
                        pos = content.find(target_bytes, start)
                        if pos == -1:
                            break
                        positions.append((pos, len(target_bytes), enc, False))
                        start = pos + 1
                    
                    # Null terminator 포함된 문자열 찾기
                    start = 0
                    while True:
                        pos = content.find(target_bytes_null, start)
                        if pos == -1:
                            break
                        positions.append((pos, len(target_bytes_null), enc, True))
                        start = pos + 1
                        
                except UnicodeEncodeError:
                    continue
                    
        except Exception as e:
            print(f"파일 읽기 오류: {e}")
            
        return positions
    
    def extract_all_strings(self, min_length: int = 4, max_length: int = 200, 
                          encodings: List[str] = None) -> Dict[str, List[Tuple[str, int, int]]]:
        """exe 파일에서 모든 문자열을 추출합니다"""
        if encodings is None:
            encodings = ['utf-8', 'cp949', 'utf-16le', 'ascii']
        
        all_strings = {}
        
        try:
            with open(self.exe_path, 'rb') as f:
                content = f.read()
                
            for encoding in encodings:
                strings_found = []
                processed_positions = set()
                
                try:
                    if encoding == 'utf-16le':
                        # UTF-16LE 처리
                        for i in range(0, len(content) - 1, 2):
                            if i in processed_positions:
                                continue
                            
                            end_pos = i
                            decoded_chars = []
                            
                            while end_pos < len(content) - 1:
                                char_bytes = content[end_pos:end_pos + 2]
                                if len(char_bytes) < 2:
                                    break
                                
                                try:
                                    char = char_bytes.decode('utf-16le')
                                    if char.isprintable() and ord(char) > 31:
                                        decoded_chars.append(char)
                                        end_pos += 2
                                    else:
                                        break
                                except:
                                    break
                            
                            if len(decoded_chars) >= min_length and len(decoded_chars) <= max_length:
                                string_value = ''.join(decoded_chars)
                                strings_found.append((string_value, i, end_pos - i))
                                for pos in range(i, end_pos, 2):
                                    processed_positions.add(pos)
                    
                    else:
                        # 다른 인코딩 처리
                        for i in range(len(content)):
                            if i in processed_positions:
                                continue
                            
                            end_pos = i
                            while end_pos < len(content):
                                byte_val = content[end_pos]
                                if 32 <= byte_val <= 126 or (encoding != 'ascii' and byte_val >= 128):
                                    end_pos += 1
                                else:
                                    break
                            
                            if end_pos > i + min_length:
                                try:
                                    potential_string = content[i:end_pos].decode(encoding, errors='ignore')
                                    clean_string = ''.join(c for c in potential_string if c.isprintable())
                                    
                                    if (min_length <= len(clean_string) <= max_length and
                                        len(clean_string) / len(potential_string) > 0.7):
                                        
                                        strings_found.append((clean_string, i, end_pos - i))
                                        for pos in range(i, end_pos):
                                            processed_positions.add(pos)
                                except:
                                    continue
                    
                    # 중복 제거
                    unique_strings = []
                    for string_val, pos, length in strings_found:
                        is_duplicate = False
                        for existing_string, existing_pos, _ in unique_strings:
                            if string_val == existing_string and abs(pos - existing_pos) < 10:
                                is_duplicate = True
                                break
                        if not is_duplicate:
                            unique_strings.append((string_val, pos, length))
                    
                    if unique_strings:
                        all_strings[encoding] = unique_strings
                        
                except Exception as e:
                    continue
        
        except Exception as e:
            print(f"문자열 추출 중 오류: {e}")
        
        return all_strings
    
    def restore_backup(self) -> bool:
        """백업에서 원본 파일 복원"""
        try:
            if os.path.exists(self.backup_path):
                shutil.copy2(self.backup_path, self.exe_path)
                print(f"백업에서 복원 완료: {self.exe_path}")
                return True
            else:
                print("백업 파일이 존재하지 않습니다.")
                return False
        except Exception as e:
            print(f"복원 실패: {e}")
            return False


def main():
    """향상된 UI 번역 도구 메인 함수"""
    print("=== 향상된 EXE UI 번역 도구 ===")
    
    exe_file = input("EXE 파일 경로를 입력하세요: ").strip().strip('"')
    
    if not os.path.exists(exe_file):
        print("파일이 존재하지 않습니다.")
        return
    
    patcher = SafeExePatcher(exe_file)
    
    # 백업 및 초기 분석
    if not patcher.create_backup():
        print("백업 생성에 실패했습니다. 작업을 중단합니다.")
        return
    
    if not patcher.analyze_pe_structure():
        print("PE 파일 분석에 실패했습니다.")
        return
    
    while True:
        print("\n=== 향상된 EXE UI 번역 도구 ===")
        print("1. UI 문자열 자동 탐지")
        print("2. 스마트 한국어 번역 (자동)")
        print("3. 커스텀 번역")
        print("4. 번역 템플릿 생성")
        print("5. 무결성 검증")
        print("6. 백업에서 복원")
        print("7. 종료")
        
        choice = input("\n선택하세요 (1-7): ").strip()
        
        if choice == '1':
            print("\nUI 문자열 탐지 중...")
            ui_strings = patcher.find_ui_strings()
            
            if ui_strings:
                print(f"\n총 {len(ui_strings)}개의 UI 문자열 후보를 발견했습니다:")
                
                # 카테고리별로 그룹화
                categories = {}
                for item in ui_strings[:50]:  # 상위 50개만 표시
                    category = item['category']
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(item)
                
                for category, items in categories.items():
                    print(f"\n[{category.upper()}] ({len(items)}개)")
                    for i, item in enumerate(items[:10], 1):  # 카테고리당 10개까지
                        print(f"  {i}. {item['string']} (점수: {item['ui_score']})")
                    if len(items) > 10:
                        print(f"  ... 외 {len(items) - 10}개 더")
            else:
                print("UI 문자열을 찾을 수 없습니다.")
        
        elif choice == '2':
            print("\n자동 한국어 번역 시작...")
            
            # 기본 번역 사전 로드
            translations = patcher.create_translation_template()
            
            # 사용자 추가 번역 입력
            print("\n추가 번역을 입력하시겠습니까? (y/n)")
            if input().lower() == 'y':
                print("추가 번역을 입력하세요 (빈 줄 입력시 종료):")
                while True:
                    original = input("영어: ").strip()
                    if not original:
                        break
                    korean = input("한국어: ").strip()
                    if korean:
                        translations[original] = korean
            
            # 번역 실행
            results = patcher.smart_korean_translation(translations)
            
            print(f"\n번역 완료!")
            print(f"- 발견된 문자열: {results['total_found']}개")
            print(f"- 성공적으로 번역된 문자열: {results['total_replaced']}개")
            
            if results['category_results']:
                print("\n카테고리별 번역 결과:")
                for category, count in results['category_results'].items():
                    print(f"  - {category}: {count}개")
            
            if results['failed_replacements']:
                print(f"\n실패한 번역: {len(results['failed_replacements'])}개")
                for failure in results['failed_replacements'][:5]:
                    print(f"  - {failure['original']}: {failure['errors']}")
        
        elif choice == '3':
            original = input("원본 문자열: ")
            replacement = input("교체할 문자열: ")
            encoding = input("인코딩 (기본값: utf-8): ").strip() or 'utf-8'
            
            # 미리 보기
            print("\n미리 보기 실행 중...")
            dry_result = patcher.safe_replace_string(original, replacement, encoding, dry_run=True)
            
            if dry_result['success']:
                print(f"교체 가능한 위치: {dry_result['positions_replaced']}개")
                if dry_result['warnings']:
                    print("경고사항:")
                    for warning in dry_result['warnings']:
                        print(f"  - {warning}")
                
                if input("실제로 교체하시겠습니까? (y/n): ").lower() == 'y':
                    result = patcher.safe_replace_string(original, replacement, encoding)
                    if result['success']:
                        print(f"성공적으로 {result['positions_replaced']}개 위치에서 교체되었습니다.")
                    else:
                        print("교체 실패:")
                        for error in result['errors']:
                            print(f"  - {error}")
            else:
                print("교체 불가능:")
                for error in dry_result['errors']:
                    print(f"  - {error}")
        
        elif choice == '4':
            template = patcher.create_translation_template()
            template_file = patcher.exe_path + "_translation_template.json"
            
            with open(template_file, 'w', encoding='utf-8') as f:
                json.dump(template, f, ensure_ascii=False, indent=2)
            
            print(f"번역 템플릿이 저장되었습니다: {template_file}")
            print(f"총 {len(template)}개의 기본 번역이 포함되어 있습니다.")
            print("이 파일을 수정하여 추가 번역을 정의할 수 있습니다.")
        
        elif choice == '5':
            print("\nEXE 파일 무결성 검증 중...")
            if patcher.verify_exe_integrity():
                print("✓ 무결성 검증 통과 - 파일이 정상적으로 수정되었습니다.")
                
                # 추가 실행 가능성 테스트 제안
                test_run = input("테스트 실행을 해보시겠습니까? (y/n): ").lower()
                if test_run == 'y':
                    import subprocess
                    try:
                        print("프로그램을 테스트 실행합니다... (5초 후 자동 종료)")
                        process = subprocess.Popen([patcher.exe_path], 
                                                 stdout=subprocess.PIPE, 
                                                 stderr=subprocess.PIPE)
                        
                        import time
                        time.sleep(5)
                        
                        if process.poll() is None:
                            process.terminate()
                            print("✓ 프로그램이 정상적으로 실행되었습니다.")
                        else:
                            print("⚠ 프로그램이 예상보다 빨리 종료되었습니다.")
                            
                    except Exception as e:
                        print(f"테스트 실행 실패: {e}")
            else:
                print("✗ 무결성 검증 실패 - 파일이 손상되었을 수 있습니다.")
                restore = input("백업에서 복원하시겠습니까? (y/n): ").lower()
                if restore == 'y':
                    patcher.restore_backup()
        
        elif choice == '6':
            patcher.restore_backup()
        
        elif choice == '7':
            print("프로그램을 종료합니다.")
            break
        
        else:
            print("잘못된 선택입니다.")


class BatchTranslator:
    """일괄 번역을 위한 추가 클래스"""
    
    def __init__(self, patcher: SafeExePatcher):
        self.patcher = patcher
        
    def load_translation_file(self, file_path: str) -> Dict[str, str]:
        """JSON 번역 파일 로드"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"번역 파일 로드 실패: {e}")
            return {}
    
    def auto_detect_language(self, text: str) -> str:
        """텍스트 언어 자동 감지 (간단한 휴리스틱)"""
        # 영어 패턴
        english_patterns = [
            r'\b(the|and|or|for|with|by|from|to|of|in|on|at)\b',
            r'^[A-Z][a-z]+',
        ]
        
        # 일본어 패턴 (일본 소프트웨어의 경우)
        japanese_patterns = [
            r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]',
        ]
        
        # 중국어 패턴
        chinese_patterns = [
            r'[\u4E00-\u9FFF]',
        ]
        
        for pattern in english_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 'english'
        
        for pattern in japanese_patterns:
            if re.search(pattern, text):
                return 'japanese'
        
        for pattern in chinese_patterns:
            if re.search(pattern, text):
                return 'chinese'
        
        return 'unknown'
    
    def create_comprehensive_translation_dict(self) -> Dict[str, str]:
        """포괄적인 번역 사전 생성"""
        translations = {
            # 파일 메뉴
            "File": "파일", "New": "새로 만들기", "Open": "열기", "Save": "저장",
            "Save As": "다른 이름으로 저장", "Close": "닫기", "Exit": "종료",
            "Print": "인쇄", "Print Preview": "인쇄 미리보기",
            
            # 편집 메뉴
            "Edit": "편집", "Undo": "실행 취소", "Redo": "다시 실행",
            "Cut": "잘라내기", "Copy": "복사", "Paste": "붙여넣기",
            "Delete": "삭제", "Select All": "모두 선택", "Find": "찾기",
            "Replace": "바꾸기", "Find Next": "다음 찾기",
            
            # 보기 메뉴
            "View": "보기", "Zoom": "확대/축소", "Fullscreen": "전체 화면",
            "Status Bar": "상태 표시줄", "Toolbar": "도구 모음",
            
            # 도구 메뉴
            "Tools": "도구", "Options": "옵션", "Settings": "설정",
            "Preferences": "환경설정", "Configuration": "구성",
            
            # 도움말 메뉴
            "Help": "도움말", "About": "정보", "Manual": "설명서",
            "Tutorial": "자습서", "Support": "지원",
            
            # 대화상자 버튼
            "OK": "확인", "Cancel": "취소", "Apply": "적용", "Yes": "예",
            "No": "아니오", "Retry": "다시 시도", "Ignore": "무시",
            "Abort": "중단", "Continue": "계속",
            
            # 일반적인 UI 요소
            "Button": "버튼", "Menu": "메뉴", "Window": "창", "Dialog": "대화상자",
            "Tab": "탭", "Panel": "패널", "Group": "그룹", "Label": "레이블",
            "Text": "텍스트", "Input": "입력", "Output": "출력",
            
            # 상태 메시지
            "Ready": "준비", "Loading": "로딩 중", "Processing": "처리 중",
            "Complete": "완료", "Failed": "실패", "Success": "성공",
            "Error": "오류", "Warning": "경고", "Information": "정보",
            
            # 동작
            "Start": "시작", "Stop": "중지", "Pause": "일시중지",
            "Resume": "계속", "Reset": "재설정", "Refresh": "새로 고침",
            "Update": "업데이트", "Download": "다운로드", "Upload": "업로드",
            "Install": "설치", "Uninstall": "제거", "Browse": "찾아보기",
            
            # 속성 및 상태
            "Properties": "속성", "Details": "자세히", "Advanced": "고급",
            "Basic": "기본", "Custom": "사용자 지정", "Automatic": "자동",
            "Manual": "수동", "Enable": "사용", "Disable": "사용 안 함",
            "Show": "표시", "Hide": "숨기기",
            
            # 파일 관련
            "Folder": "폴더", "Directory": "디렉터리", "Path": "경로",
            "Extension": "확장명", "Size": "크기", "Date": "날짜",
            "Modified": "수정됨", "Created": "만들어짐",
            
            # 네트워크/연결
            "Connect": "연결", "Disconnect": "연결 끊기", "Network": "네트워크",
            "Internet": "인터넷", "Server": "서버", "Client": "클라이언트",
            "Login": "로그인", "Logout": "로그아웃", "Username": "사용자 이름",
            "Password": "비밀번호",
            
            # 시간 관련
            "Today": "오늘", "Yesterday": "어제", "Tomorrow": "내일",
            "Now": "지금", "Never": "안 함", "Always": "항상",
            "Hour": "시간", "Minute": "분", "Second": "초",
            
            # 일반적인 형용사/부사
            "New": "새로운", "Old": "이전", "Current": "현재", "Default": "기본값",
            "Maximum": "최대", "Minimum": "최소", "Average": "평균",
            "Total": "전체", "Partial": "부분", "All": "모든", "None": "없음",
            
            # 특수한 경우들
            "Untitled": "제목 없음", "Unknown": "알 수 없음", "N/A": "해당 없음",
            "Version": "버전", "Build": "빌드", "Release": "릴리스",
        }
        
        return translations
    
    def smart_fuzzy_match(self, target: str, translation_dict: Dict[str, str], 
                         threshold: float = 0.8) -> Optional[str]:
        """퍼지 매칭을 통한 스마트 번역 찾기"""
        target_lower = target.lower().strip()
        
        # 정확한 매치 우선
        for english, korean in translation_dict.items():
            if english.lower() == target_lower:
                return korean
        
        # 부분 매치 (단어 포함)
        for english, korean in translation_dict.items():
            if target_lower in english.lower() or english.lower() in target_lower:
                if len(target_lower) >= 3:  # 너무 짧은 문자열은 제외
                    return korean
        
        # 레벤슈타인 거리 기반 유사도 (간단한 구현)
        def levenshtein_similarity(s1: str, s2: str) -> float:
            if len(s1) < len(s2):
                return levenshtein_similarity(s2, s1)
            
            if len(s2) == 0:
                return 0.0
            
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return 1.0 - (previous_row[-1] / len(s1))
        
        best_match = None
        best_similarity = 0.0
        
        for english, korean in translation_dict.items():
            similarity = levenshtein_similarity(target_lower, english.lower())
            if similarity > best_similarity and similarity >= threshold:
                best_similarity = similarity
                best_match = korean
        
        return best_match


def create_gui_version():
    """GUI 버전 생성을 위한 함수 (tkinter 사용)"""
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox, scrolledtext
        
        class ExePatcherGUI:
            def __init__(self, root):
                self.root = root
                self.root.title("EXE UI 번역 도구")
                self.root.geometry("800x600")
                
                self.patcher = None
                self.setup_ui()
            
            def setup_ui(self):
                # 파일 선택 프레임
                file_frame = ttk.Frame(self.root)
                file_frame.pack(fill='x', padx=10, pady=5)
                
                ttk.Label(file_frame, text="EXE 파일:").pack(side='left')
                self.file_path_var = tk.StringVar()
                ttk.Entry(file_frame, textvariable=self.file_path_var, width=50).pack(side='left', padx=5)
                ttk.Button(file_frame, text="찾아보기", command=self.browse_file).pack(side='left')
                ttk.Button(file_frame, text="분석", command=self.analyze_file).pack(side='left', padx=5)
                
                # 탭 컨트롤
                self.notebook = ttk.Notebook(self.root)
                self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
                
                # UI 문자열 탭
                self.ui_frame = ttk.Frame(self.notebook)
                self.notebook.add(self.ui_frame, text="UI 문자열")
                
                # 트리뷰 (UI 문자열 목록)
                self.ui_tree = ttk.Treeview(self.ui_frame, columns=('category', 'score', 'encoding'), show='tree headings')
                self.ui_tree.heading('#0', text='문자열')
                self.ui_tree.heading('category', text='카테고리')
                self.ui_tree.heading('score', text='점수')
                self.ui_tree.heading('encoding', text='인코딩')
                self.ui_tree.pack(fill='both', expand=True)
                
                # 번역 입력 프레임
                trans_frame = ttk.Frame(self.ui_frame)
                trans_frame.pack(fill='x', pady=5)
                
                ttk.Label(trans_frame, text="한국어 번역:").pack(side='left')
                self.translation_var = tk.StringVar()
                ttk.Entry(trans_frame, textvariable=self.translation_var, width=30).pack(side='left', padx=5)
                ttk.Button(trans_frame, text="번역 적용", command=self.apply_translation).pack(side='left')
                
                # 일괄 번역 탭
                self.batch_frame = ttk.Frame(self.notebook)
                self.notebook.add(self.batch_frame, text="일괄 번역")
                
                # 번역 사전 텍스트 영역
                ttk.Label(self.batch_frame, text="번역 사전 (JSON 형식):").pack(anchor='w')
                self.dict_text = scrolledtext.ScrolledText(self.batch_frame, height=15)
                self.dict_text.pack(fill='both', expand=True, pady=5)
                
                # 일괄 번역 버튼
                batch_btn_frame = ttk.Frame(self.batch_frame)
                batch_btn_frame.pack(fill='x')
                
                ttk.Button(batch_btn_frame, text="템플릿 로드", command=self.load_template).pack(side='left')
                ttk.Button(batch_btn_frame, text="일괄 번역 실행", command=self.batch_translate).pack(side='left', padx=5)
                
                # 로그 탭
                self.log_frame = ttk.Frame(self.notebook)
                self.notebook.add(self.log_frame, text="로그")
                
                self.log_text = scrolledtext.ScrolledText(self.log_frame)
                self.log_text.pack(fill='both', expand=True)
                
                # 하단 버튼들
                bottom_frame = ttk.Frame(self.root)
                bottom_frame.pack(fill='x', padx=10, pady=5)
                
                ttk.Button(bottom_frame, text="무결성 검증", command=self.verify_integrity).pack(side='left')
                ttk.Button(bottom_frame, text="백업 복원", command=self.restore_backup).pack(side='left', padx=5)
                ttk.Button(bottom_frame, text="종료", command=self.root.quit).pack(side='right')
            
            def browse_file(self):
                file_path = filedialog.askopenfilename(
                    title="EXE 파일 선택",
                    filetypes=[("실행 파일", "*.exe"), ("모든 파일", "*.*")]
                )
                if file_path:
                    self.file_path_var.set(file_path)
            
            def analyze_file(self):
                file_path = self.file_path_var.get()
                if not file_path or not os.path.exists(file_path):
                    messagebox.showerror("오류", "올바른 파일을 선택해주세요.")
                    return
                
                try:
                    self.patcher = SafeExePatcher(file_path)
                    if not self.patcher.create_backup():
                        messagebox.showerror("오류", "백업 생성에 실패했습니다.")
                        return
                    
                    if not self.patcher.analyze_pe_structure():
                        messagebox.showerror("오류", "PE 파일 분석에 실패했습니다.")
                        return
                    
                    # UI 문자열 탐지
                    ui_strings = self.patcher.find_ui_strings()
                    
                    # 트리뷰에 추가
                    for item in self.ui_tree.get_children():
                        self.ui_tree.delete(item)
                    
                    for ui_item in ui_strings[:100]:  # 상위 100개만 표시
                        self.ui_tree.insert('', 'end', 
                                          text=ui_item['string'],
                                          values=(ui_item['category'], 
                                                ui_item['ui_score'],
                                                ui_item['encoding']))
                    
                    self.log_message(f"분석 완료: {len(ui_strings)}개 UI 문자열 발견")
                    
                except Exception as e:
                    messagebox.showerror("오류", f"파일 분석 중 오류: {e}")
            
            def apply_translation(self):
                selection = self.ui_tree.selection()
                if not selection or not self.patcher:
                    messagebox.showwarning("경고", "문자열을 선택하고 파일을 분석해주세요.")
                    return
                
                item = self.ui_tree.item(selection[0])
                original = item['text']
                translation = self.translation_var.get()
                
                if not translation:
                    messagebox.showwarning("경고", "번역을 입력해주세요.")
                    return
                
                try:
                    result = self.patcher.safe_replace_string(original, translation)
                    if result['success']:
                        self.log_message(f"번역 성공: '{original}' → '{translation}'")
                        messagebox.showinfo("성공", f"{result['positions_replaced']}개 위치에서 번역되었습니다.")
                    else:
                        error_msg = '\n'.join(result['errors'])
                        messagebox.showerror("실패", f"번역 실패:\n{error_msg}")
                        
                except Exception as e:
                    messagebox.showerror("오류", f"번역 중 오류: {e}")
            
            def load_template(self):
                if not self.patcher:
                    messagebox.showwarning("경고", "먼저 파일을 분석해주세요.")
                    return
                
                template = self.patcher.create_translation_template()
                self.dict_text.delete(1.0, tk.END)
                self.dict_text.insert(1.0, json.dumps(template, ensure_ascii=False, indent=2))
            
            def batch_translate(self):
                if not self.patcher:
                    messagebox.showwarning("경고", "먼저 파일을 분석해주세요.")
                    return
                
                try:
                    translation_dict = json.loads(self.dict_text.get(1.0, tk.END))
                    results = self.patcher.smart_korean_translation(translation_dict)
                    
                    result_msg = f"""일괄 번역 완료!
발견된 문자열: {results['total_found']}개
번역된 문자열: {results['total_replaced']}개
실패한 문자열: {len(results['failed_replacements'])}개"""
                    
                    messagebox.showinfo("완료", result_msg)
                    self.log_message(result_msg.replace('\n', ' / '))
                    
                except json.JSONDecodeError:
                    messagebox.showerror("오류", "올바른 JSON 형식이 아닙니다.")
                except Exception as e:
                    messagebox.showerror("오류", f"일괄 번역 중 오류: {e}")
            
            def verify_integrity(self):
                if not self.patcher:
                    messagebox.showwarning("경고", "먼저 파일을 분석해주세요.")
                    return
                
                if self.patcher.verify_exe_integrity():
                    messagebox.showinfo("성공", "무결성 검증 통과!")
                else:
                    messagebox.showerror("실패", "무결성 검증 실패!")
            
            def restore_backup(self):
                if not self.patcher:
                    messagebox.showwarning("경고", "먼저 파일을 분석해주세요.")
                    return
                
                if messagebox.askyesno("확인", "백업에서 복원하시겠습니까?"):
                    if self.patcher.restore_backup():
                        messagebox.showinfo("성공", "백업에서 복원되었습니다.")
                    else:
                        messagebox.showerror("실패", "복원에 실패했습니다.")
            
            def log_message(self, message):
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
                self.log_text.see(tk.END)
        
        # GUI 실행
        if __name__ == "__main__":
            root = tk.Tk()
            app = ExePatcherGUI(root)
            root.mainloop()
            
    except ImportError:
        print("GUI 모드를 사용하려면 tkinter가 필요합니다.")
        print("콘솔 모드로 실행하세요.")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        create_gui_version()
    else:
        main()