import os
import shutil
from typing import List, Tuple, Dict, Set
import struct
import re

class ExePatcher:
    def __init__(self, exe_path: str):
        """
        EXE 파일 패처 초기화
        
        Args:
            exe_path: 수정할 exe 파일 경로
        """
        self.exe_path = exe_path
        self.backup_path = exe_path + ".backup"
        
    def create_backup(self) -> bool:
        """
        원본 파일 백업 생성
        
        Returns:
            백업 성공 여부
        """
        try:
            if not os.path.exists(self.backup_path):
                shutil.copy2(self.exe_path, self.backup_path)
                print(f"백업 파일 생성: {self.backup_path}")
            return True
        except Exception as e:
            print(f"백업 생성 실패: {e}")
            return False
    
    def find_string_positions(self, target_string: str, encoding: str = 'utf-8') -> List[int]:
        """
        문자열의 위치를 찾습니다
        
        Args:
            target_string: 찾을 문자열
            encoding: 문자열 인코딩 (utf-8, cp949, utf-16le 등)
            
        Returns:
            문자열이 발견된 위치들의 리스트
        """
        positions = []
        
        try:
            with open(self.exe_path, 'rb') as f:
                content = f.read()
                
            # 다양한 인코딩으로 시도
            encodings_to_try = [encoding]
            if encoding != 'utf-8':
                encodings_to_try.append('utf-8')
            if encoding != 'cp949':
                encodings_to_try.append('cp949')
            if encoding != 'utf-16le':
                encodings_to_try.append('utf-16le')
            
            for enc in encodings_to_try:
                try:
                    target_bytes = target_string.encode(enc)
                    # Null terminator 포함된 버전도 찾기
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
    
    def replace_string(self, original: str, replacement: str, encoding: str = 'utf-8') -> bool:
        """
        문자열을 교체합니다
        
        Args:
            original: 원본 문자열
            replacement: 교체할 문자열
            encoding: 문자열 인코딩
            
        Returns:
            교체 성공 여부
        """
        try:
            positions = self.find_string_positions(original, encoding)
            
            if not positions:
                print(f"문자열 '{original}'을 찾을 수 없습니다.")
                return False
            
            with open(self.exe_path, 'r+b') as f:
                content = f.read()
                
                replacements_made = 0
                
                # 위치를 역순으로 정렬하여 뒤에서부터 교체 (인덱스 변화 방지)
                positions.sort(key=lambda x: x[0], reverse=True)
                
                for pos, orig_length, detected_encoding, has_null in positions:
                    try:
                        # 교체할 문자열을 해당 인코딩으로 변환
                        replacement_bytes = replacement.encode(detected_encoding)
                        
                        # Null terminator가 있었다면 추가
                        if has_null:
                            replacement_bytes += b'\x00'
                        
                        # 길이 체크
                        if len(replacement_bytes) <= orig_length:
                            # 교체할 바이트가 더 짧으면 남는 공간을 null로 채움
                            replacement_bytes = replacement_bytes.ljust(orig_length, b'\x00')
                            
                            # 바이트 배열로 변환하여 수정
                            content_array = bytearray(content)
                            content_array[pos:pos + orig_length] = replacement_bytes
                            content = bytes(content_array)
                            
                            replacements_made += 1
                            print(f"위치 {pos}에서 교체 완료 ({detected_encoding})")
                        else:
                            print(f"경고: 교체할 문자열이 너무 깁니다. 위치 {pos} 건너뜀")
                            
                    except UnicodeEncodeError as e:
                        print(f"인코딩 오류 (위치 {pos}): {e}")
                        continue
                
                if replacements_made > 0:
                    # 파일에 변경사항 쓰기
                    f.seek(0)
                    f.write(content)
                    f.truncate()
                    print(f"총 {replacements_made}개 위치에서 교체 완료")
                    return True
                else:
                    print("교체된 문자열이 없습니다.")
                    return False
                    
        except Exception as e:
            print(f"문자열 교체 오류: {e}")
            return False
    
    def batch_replace(self, replacements: Dict[str, str], encoding: str = 'utf-8') -> int:
        """
        여러 문자열을 한번에 교체합니다
        
        Args:
            replacements: {원본문자열: 교체문자열} 딕셔너리
            encoding: 문자열 인코딩
            
        Returns:
            성공적으로 교체된 문자열 개수
        """
        success_count = 0
        
        for original, replacement in replacements.items():
            print(f"\n'{original}' -> '{replacement}' 교체 중...")
            if self.replace_string(original, replacement, encoding):
                success_count += 1
                
        return success_count
    
    def extract_all_strings(self, min_length: int = 4, max_length: int = 200, 
                          encodings: List[str] = None, save_to_file: bool = False) -> Dict[str, List[Tuple[str, int, str]]]:
        """
        exe 파일에서 모든 문자열을 추출합니다
        
        Args:
            min_length: 최소 문자열 길이
            max_length: 최대 문자열 길이
            encodings: 사용할 인코딩 리스트
            save_to_file: 파일로 저장할지 여부
            
        Returns:
            {인코딩: [(문자열, 위치, 길이), ...]} 형태의 딕셔너리
        """
        if encodings is None:
            encodings = ['utf-8', 'cp949', 'utf-16le', 'ascii', 'latin1']
        
        all_strings = {}
        
        try:
            with open(self.exe_path, 'rb') as f:
                content = f.read()
                
            print("문자열 추출 중...")
            
            for encoding in encodings:
                strings_found = []
                processed_positions = set()
                
                try:
                    if encoding == 'utf-16le':
                        # UTF-16LE는 2바이트씩 처리
                        for i in range(0, len(content) - 1, 2):
                            if i in processed_positions:
                                continue
                                
                            try:
                                # 연속된 UTF-16 문자들 찾기
                                end_pos = i
                                decoded_chars = []
                                
                                while end_pos < len(content) - 1:
                                    char_bytes = content[end_pos:end_pos + 2]
                                    if len(char_bytes) < 2:
                                        break
                                        
                                    try:
                                        char = char_bytes.decode('utf-16le')
                                        if char.isprintable() and char not in '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f':
                                            decoded_chars.append(char)
                                            end_pos += 2
                                        else:
                                            break
                                    except:
                                        break
                                
                                if len(decoded_chars) >= min_length:
                                    string_value = ''.join(decoded_chars)
                                    if len(string_value) <= max_length:
                                        strings_found.append((string_value, i, end_pos - i))
                                        for pos in range(i, end_pos, 2):
                                            processed_positions.add(pos)
                                            
                            except:
                                continue
                    
                    else:
                        # 다른 인코딩은 1바이트씩 처리
                        for i in range(len(content)):
                            if i in processed_positions:
                                continue
                                
                            try:
                                # 연속된 printable 문자들 찾기
                                end_pos = i
                                
                                while end_pos < len(content):
                                    byte_val = content[end_pos]
                                    
                                    # ASCII 범위나 확장 ASCII 체크
                                    if encoding == 'ascii':
                                        if 32 <= byte_val <= 126:  # printable ASCII
                                            end_pos += 1
                                        else:
                                            break
                                    elif encoding == 'cp949':
                                        # CP949는 복잡하므로 더 관대하게 처리
                                        if (32 <= byte_val <= 126) or (128 <= byte_val <= 255):
                                            end_pos += 1
                                        else:
                                            break
                                    else:
                                        # UTF-8 등
                                        if 32 <= byte_val <= 126:
                                            end_pos += 1
                                        elif byte_val >= 128:
                                            end_pos += 1
                                        else:
                                            break
                                
                                if end_pos > i + min_length:
                                    try:
                                        potential_string = content[i:end_pos].decode(encoding, errors='ignore')
                                        # 깨끗한 문자열인지 확인
                                        clean_string = ''.join(c for c in potential_string if c.isprintable())
                                        
                                        if (len(clean_string) >= min_length and 
                                            len(clean_string) <= max_length and
                                            len(clean_string) / len(potential_string) > 0.7):  # 70% 이상이 printable
                                            
                                            strings_found.append((clean_string, i, end_pos - i))
                                            for pos in range(i, end_pos):
                                                processed_positions.add(pos)
                                                
                                    except:
                                        continue
                                        
                            except:
                                continue
                    
                    # 중복 제거 (같은 문자열, 비슷한 위치)
                    unique_strings = []
                    for string_val, pos, length in strings_found:
                        is_duplicate = False
                        for existing_string, existing_pos, _ in unique_strings:
                            if (string_val == existing_string and abs(pos - existing_pos) < 10):
                                is_duplicate = True
                                break
                        if not is_duplicate:
                            unique_strings.append((string_val, pos, length))
                    
                    if unique_strings:
                        all_strings[encoding] = unique_strings
                        print(f"{encoding}: {len(unique_strings)}개 문자열 발견")
                        
                except Exception as e:
                    print(f"{encoding} 처리 중 오류: {e}")
                    continue
            
            # 파일로 저장
            if save_to_file:
                output_file = self.exe_path + "_strings.txt"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== {os.path.basename(self.exe_path)} 문자열 추출 결과 ===\n\n")
                    
                    for encoding, strings in all_strings.items():
                        f.write(f"\n[{encoding.upper()} 인코딩 - {len(strings)}개]\n")
                        f.write("-" * 80 + "\n")
                        
                        for i, (string_val, pos, length) in enumerate(strings, 1):
                            f.write(f"{i:4d}. 위치: 0x{pos:08X} ({pos:8d}) | 길이: {length:3d} | {repr(string_val)}\n")
                
                print(f"\n문자열 목록이 파일로 저장되었습니다: {output_file}")
            
            return all_strings
            
        except Exception as e:
            print(f"문자열 추출 중 오류: {e}")
            return {}
    
    def search_strings(self, pattern: str, case_sensitive: bool = True) -> Dict[str, List[Tuple[str, int, int]]]:
        """
        추출된 문자열에서 패턴 검색
        
        Args:
            pattern: 검색할 패턴 (정규식 지원)
            case_sensitive: 대소문자 구분 여부
            
        Returns:
            검색 결과
        """
        all_strings = self.extract_all_strings()
        results = {}
        
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
            
            for encoding, strings in all_strings.items():
                matches = []
                for string_val, pos, length in strings:
                    if regex.search(string_val):
                        matches.append((string_val, pos, length))
                
                if matches:
                    results[encoding] = matches
                    
        except re.error as e:
            print(f"정규식 오류: {e}")
            
        return results
    
    def restore_backup(self) -> bool:
        """
        백업에서 원본 파일 복원
        
        Returns:
            복원 성공 여부
        """
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
    """
    사용 예제
    """
    # exe 파일 경로 설정
    exe_file = input("EXE 파일 경로를 입력하세요: ").strip().strip('"')
    
    if not os.path.exists(exe_file):
        print("파일이 존재하지 않습니다.")
        return
    
    # 패처 객체 생성
    patcher = ExePatcher(exe_file)
    
    # 백업 생성
    if not patcher.create_backup():
        print("백업 생성에 실패했습니다. 작업을 중단합니다.")
        return
    
    while True:
        print("\n=== EXE 번역 패치 도구 ===")
        print("1. 단일 문자열 교체")
        print("2. 일괄 문자열 교체")
        print("3. 문자열 찾기")
        print("4. 모든 문자열 추출")
        print("5. 문자열 패턴 검색")
        print("6. 백업에서 복원")
        print("7. 종료")
        
        choice = input("\n선택하세요 (1-7): ").strip()
        
        if choice == '1':
            original = input("원본 문자열: ")
            replacement = input("교체할 문자열: ")
            encoding = input("인코딩 (기본값: utf-8): ").strip() or 'utf-8'
            
            patcher.replace_string(original, replacement, encoding)
            
        elif choice == '2':
            print("일괄 교체할 문자열들을 입력하세요 (빈 줄 입력시 종료):")
            replacements = {}
            
            while True:
                original = input("원본 문자열 (빈 줄로 종료): ").strip()
                if not original:
                    break
                replacement = input(f"'{original}'을 교체할 문자열: ")
                replacements[original] = replacement
            
            if replacements:
                encoding = input("인코딩 (기본값: utf-8): ").strip() or 'utf-8'
                success_count = patcher.batch_replace(replacements, encoding)
                print(f"\n총 {success_count}개 문자열이 성공적으로 교체되었습니다.")
            
        elif choice == '3':
            search_string = input("찾을 문자열: ")
            encoding = input("인코딩 (기본값: utf-8): ").strip() or 'utf-8'
            
            positions = patcher.find_string_positions(search_string, encoding)
            if positions:
                print(f"\n'{search_string}' 발견된 위치:")
                for pos, length, enc, has_null in positions:
                    null_info = " (null 종료)" if has_null else ""
                    print(f"  위치: {pos}, 길이: {length}, 인코딩: {enc}{null_info}")
            else:
                print(f"'{search_string}'을 찾을 수 없습니다.")
                
        elif choice == '4':
            print("\n=== 모든 문자열 추출 ===")
            min_len = input("최소 문자열 길이 (기본값: 4): ").strip()
            min_len = int(min_len) if min_len.isdigit() else 4
            
            max_len = input("최대 문자열 길이 (기본값: 200): ").strip()
            max_len = int(max_len) if max_len.isdigit() else 200
            
            save_file = input("파일로 저장하시겠습니까? (y/n, 기본값: y): ").strip().lower()
            save_file = save_file != 'n'
            
            # 인코딩 선택
            print("\n사용할 인코딩을 선택하세요:")
            print("1. 모든 인코딩 (utf-8, cp949, utf-16le, ascii, latin1)")
            print("2. 한글 중심 (utf-8, cp949)")
            print("3. 영문 중심 (ascii, latin1, utf-8)")
            print("4. 직접 입력")
            
            enc_choice = input("선택 (1-4, 기본값: 1): ").strip() or '1'
            
            if enc_choice == '1':
                encodings = ['utf-8', 'cp949', 'utf-16le', 'ascii', 'latin1']
            elif enc_choice == '2':
                encodings = ['utf-8', 'cp949']
            elif enc_choice == '3':
                encodings = ['ascii', 'latin1', 'utf-8']
            else:
                enc_input = input("인코딩들을 쉼표로 구분하여 입력: ")
                encodings = [enc.strip() for enc in enc_input.split(',')]
            
            all_strings = patcher.extract_all_strings(min_len, max_len, encodings, save_file)
            
            # 콘솔 출력
            if all_strings:
                display_all = input("\n모든 문자열을 콘솔에 출력하시겠습니까? (y/n): ").strip().lower() == 'y'
                
                for encoding, strings in all_strings.items():
                    print(f"\n[{encoding.upper()} - {len(strings)}개 문자열]")
                    print("-" * 60)
                    
                    display_count = min(20, len(strings)) if not display_all else len(strings)
                    
                    for i, (string_val, pos, length) in enumerate(strings[:display_count], 1):
                        # 너무 긴 문자열은 잘라서 표시
                        display_string = string_val if len(string_val) <= 50 else string_val[:47] + "..."
                        print(f"{i:3d}. [0x{pos:06X}] {repr(display_string)}")
                    
                    if not display_all and len(strings) > 20:
                        print(f"... 외 {len(strings) - 20}개 더 (파일에서 전체 확인 가능)")
            else:
                print("추출된 문자열이 없습니다.")
                
        elif choice == '5':
            pattern = input("검색할 패턴 (정규식 지원): ")
            case_sensitive = input("대소문자 구분? (y/n, 기본값: n): ").strip().lower() != 'y'
            
            results = patcher.search_strings(pattern, not case_sensitive)
            
            if results:
                print(f"\n패턴 '{pattern}' 검색 결과:")
                for encoding, matches in results.items():
                    print(f"\n[{encoding.upper()} - {len(matches)}개 발견]")
                    for i, (string_val, pos, length) in enumerate(matches, 1):
                        display_string = string_val if len(string_val) <= 50 else string_val[:47] + "..."
                        print(f"  {i}. [0x{pos:06X}] {repr(display_string)}")
            else:
                print(f"패턴 '{pattern}'과 일치하는 문자열이 없습니다.")
                
        elif choice == '6':
            patcher.restore_backup()
            
        elif choice == '7':
            print("프로그램을 종료합니다.")
            break
            
        else:
            print("잘못된 선택입니다.")

if __name__ == "__main__":
    main()