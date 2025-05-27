import os
import shutil
from typing import List, Tuple, Dict, Set
import struct
import re
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# OpenAI 라이브러리 버전 호환성 처리
try:
    from openai import OpenAI
    OPENAI_V1 = True
except ImportError:
    try:
        import openai
        OPENAI_V1 = False
    except ImportError:
        print("OpenAI 라이브러리가 설치되지 않았습니다.")
        print("다음 명령어로 설치하세요: pip install openai")
        exit(1)

class AIExeTranslator:
    def __init__(self, exe_path: str, api_key: str):
        """
        AI 기반 EXE 번역기 초기화
        
        Args:
            exe_path: 수정할 exe 파일 경로
            api_key: OpenAI API 키
        """
        self.exe_path = exe_path
        self.backup_path = exe_path + ".backup"
        
        # OpenAI 클라이언트 초기화 (버전별 호환성)
        if OPENAI_V1:
            self.client = OpenAI(api_key=api_key)
        else:
            openai.api_key = api_key
            self.client = None
            
        self.translation_cache = {}
        self.cache_file = exe_path + "_translation_cache.json"
        self.load_cache()
        
        # UI 관련 키워드들 (번역 우선순위가 높은 문자열들)
        self.ui_keywords = [
            'file', 'edit', 'view', 'tools', 'help', 'window', 'options', 'settings',
            'open', 'save', 'close', 'exit', 'new', 'copy', 'paste', 'cut', 'undo',
            'redo', 'find', 'replace', 'print', 'about', 'preferences', 'configure',
            'import', 'export', 'load', 'reload', 'refresh', 'update', 'install',
            'uninstall', 'start', 'stop', 'pause', 'resume', 'cancel', 'ok', 'yes',
            'no', 'apply', 'reset', 'default', 'browse', 'search', 'filter', 'sort',
            'error', 'warning', 'information', 'confirm', 'success', 'failed',
            'loading', 'please wait', 'processing', 'connecting', 'connected',
            'disconnected', 'network', 'internet', 'download', 'upload'
        ]
        
    def load_cache(self):
        """번역 캐시 로드"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.translation_cache = json.load(f)
                print(f"번역 캐시 로드됨: {len(self.translation_cache)}개 항목")
        except Exception as e:
            print(f"캐시 로드 실패: {e}")
            self.translation_cache = {}
    
    def save_cache(self):
        """번역 캐시 저장"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.translation_cache, f, ensure_ascii=False, indent=2)
            print(f"번역 캐시 저장됨: {len(self.translation_cache)}개 항목")
        except Exception as e:
            print(f"캐시 저장 실패: {e}")
    
    def is_likely_ui_text(self, text: str) -> bool:
        """UI 텍스트일 가능성이 높은지 판단"""
        text_lower = text.lower()
        
        # UI 키워드 포함 여부
        for keyword in self.ui_keywords:
            if keyword in text_lower:
                return True
        
        # 특정 패턴들
        patterns = [
            r'&\w+',  # 단축키 (&File 등)
            r'\w+\.\.\.',  # 메뉴 항목 (Save...)
            r'ctrl\+\w+',  # 단축키 (Ctrl+S)
            r'alt\+\w+',   # 단축키 (Alt+F)
            r'f\d+',       # 함수키 (F1, F2)
            r'\[.*\]',     # 대괄호 텍스트
            r'^\w+:$',     # 라벨 (Name:)
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        # 짧은 문장이면서 영어인 경우
        if len(text.split()) <= 5 and re.match(r'^[a-zA-Z\s\.\!\?\-\_\&\(\)]+$', text):
            return True
        
        return False
    
    def should_translate(self, text: str) -> bool:
        """번역해야 할 텍스트인지 판단"""
        # 너무 짧거나 긴 텍스트 제외
        if len(text) < 2 or len(text) > 200:
            return False
        
        # 숫자만 있는 경우 제외
        if text.isdigit():
            return False
        
        # 파일 경로나 URL 같은 것들 제외
        if any(pattern in text.lower() for pattern in ['.exe', '.dll', '.txt', '.log', 'http', 'www', 'c:\\', 'd:\\']):
            return False
        
        # 특수문자만 있는 경우 제외  
        if re.match(r'^[^\w\s]+$', text):
            return False
        
        # 이미 한글이 포함된 경우 제외
        if re.search(r'[가-힣]', text):
            return False
        
        # 영어가 포함되어 있고, UI 텍스트일 가능성이 높은 경우
        if re.search(r'[a-zA-Z]', text) and self.is_likely_ui_text(text):
            return True
        
        return False
    
    def translate_text(self, text: str, max_retries: int = 3) -> str:
        """텍스트를 한국어로 번역"""
        # 캐시 확인
        if text in self.translation_cache:
            return self.translation_cache[text]
        
        if not self.should_translate(text):
            return text
        
        for attempt in range(max_retries):
            try:
                system_message = """당신은 소프트웨어 UI 번역 전문가입니다. 다음 규칙을 따라 번역해주세요:

1. 소프트웨어 UI에서 사용되는 텍스트를 자연스러운 한국어로 번역
2. 메뉴, 버튼, 대화상자 텍스트에 적합한 번역
3. 단축키 표시(&)는 유지: &File → &파일
4. 생략부호(...)는 유지: Save... → 저장...
5. 기술적 용어는 널리 사용되는 한국어 용어 사용
6. 번역만 출력하고 다른 설명은 하지 마세요
7. 번역이 불가능하거나 부적절한 경우 원문 그대로 출력"""

                user_message = f"다음 UI 텍스트를 한국어로 번역해주세요: {text}"
                
                if OPENAI_V1:
                    # OpenAI v1.0+ 방식
                    response = self.client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[
                            {"role": "system", "content": system_message},
                            {"role": "user", "content": user_message}
                        ],
                        max_tokens=100,
                        temperature=0.3
                    )
                    translation = response.choices[0].message.content.strip()
                else:
                    # OpenAI v0.x 방식
                    response = openai.ChatCompletion.create(
                        model="gpt-3.5-turbo",
                        messages=[
                            {"role": "system", "content": system_message},
                            {"role": "user", "content": user_message}
                        ],
                        max_tokens=100,
                        temperature=0.3
                    )
                    translation = response.choices[0].message.content.strip()
                
                # 번역 결과 검증
                if translation and translation != text:
                    # 길이 체크 (원본의 3배를 넘으면 번역 실패로 간주)
                    if len(translation) <= len(text) * 3:
                        self.translation_cache[text] = translation
                        return translation
                
                # 번역 실패시 원문 반환
                return text
                
            except Exception as e:
                print(f"번역 오류 (시도 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    return text
        
        return text
    
    def translate_batch(self, texts: List[str], max_workers: int = 5) -> Dict[str, str]:
        """여러 텍스트를 병렬로 번역"""
        translations = {}
        
        # 번역이 필요한 텍스트만 필터링
        texts_to_translate = []
        for text in texts:
            if text in self.translation_cache:
                translations[text] = self.translation_cache[text]
            elif self.should_translate(text):
                texts_to_translate.append(text)
            else:
                translations[text] = text
        
        if not texts_to_translate:
            return translations
        
        print(f"번역 중: {len(texts_to_translate)}개 텍스트...")
        
        # 병렬 번역 처리
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_text = {
                executor.submit(self.translate_text, text): text 
                for text in texts_to_translate
            }
            
            completed = 0
            for future in as_completed(future_to_text):
                text = future_to_text[future]
                try:
                    translation = future.result()
                    translations[text] = translation
                    completed += 1
                    
                    if completed % 10 == 0:
                        print(f"진행률: {completed}/{len(texts_to_translate)}")
                        
                except Exception as e:
                    print(f"'{text}' 번역 실패: {e}")
                    translations[text] = text
        
        # 캐시 저장
        self.save_cache()
        return translations
    
    def create_backup(self) -> bool:
        """원본 파일 백업 생성"""
        try:
            if not os.path.exists(self.backup_path):
                shutil.copy2(self.exe_path, self.backup_path)
                print(f"백업 파일 생성: {self.backup_path}")
            return True
        except Exception as e:
            print(f"백업 생성 실패: {e}")
            return False
    
    def find_string_positions(self, target_string: str, encoding: str = 'utf-8') -> List[Tuple[int, int, str, bool]]:
        """문자열의 위치를 찾습니다"""
        positions = []
        
        try:
            with open(self.exe_path, 'rb') as f:
                content = f.read()
                
            encodings_to_try = [encoding, 'utf-8', 'cp949', 'utf-16le']
            
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
    
    def replace_string_safe(self, original: str, replacement: str, encoding: str = 'utf-8') -> bool:
        """문자열을 안전하게 교체 (길이 제한 고려)"""
        try:
            positions = self.find_string_positions(original, encoding)
            
            if not positions:
                return False
            
            with open(self.exe_path, 'r+b') as f:
                content = f.read()
                
                replacements_made = 0
                positions.sort(key=lambda x: x[0], reverse=True)
                
                for pos, orig_length, detected_encoding, has_null in positions:
                    try:
                        replacement_bytes = replacement.encode(detected_encoding)
                        
                        if has_null:
                            replacement_bytes += b'\x00'
                        
                        # 길이 체크 - 교체할 문자열이 더 짧거나 같아야 함
                        if len(replacement_bytes) <= orig_length:
                            replacement_bytes = replacement_bytes.ljust(orig_length, b'\x00')
                            
                            content_array = bytearray(content)
                            content_array[pos:pos + orig_length] = replacement_bytes
                            content = bytes(content_array)
                            
                            replacements_made += 1
                            
                    except UnicodeEncodeError:
                        continue
                
                if replacements_made > 0:
                    f.seek(0)
                    f.write(content)
                    f.truncate()
                    return True
                    
        except Exception as e:
            print(f"문자열 교체 오류: {e}")
            
        return False
    
    def extract_ui_strings(self, min_length: int = 2, max_length: int = 100) -> List[Tuple[str, int, str]]:
        """UI 관련 문자열들을 추출"""
        all_strings = []
        encodings = ['utf-8', 'ascii', 'cp949', 'utf-16le']
        
        try:
            with open(self.exe_path, 'rb') as f:
                content = f.read()
            
            print("UI 문자열 추출 중...")
            
            for encoding in encodings:
                try:
                    if encoding == 'utf-16le':
                        # UTF-16LE 처리
                        for i in range(0, len(content) - 1, 2):
                            try:
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
                                
                                if len(decoded_chars) >= min_length:
                                    string_value = ''.join(decoded_chars)
                                    if (len(string_value) <= max_length and 
                                        self.should_translate(string_value)):
                                        all_strings.append((string_value, i, encoding))
                                        
                            except:
                                continue
                    else:
                        # 다른 인코딩 처리
                        for i in range(len(content)):
                            try:
                                end_pos = i
                                
                                while end_pos < len(content):
                                    byte_val = content[end_pos]
                                    if 32 <= byte_val <= 126:  # printable ASCII
                                        end_pos += 1
                                    elif encoding != 'ascii' and byte_val >= 128:
                                        end_pos += 1
                                    else:
                                        break
                                
                                if end_pos > i + min_length:
                                    try:
                                        potential_string = content[i:end_pos].decode(encoding, errors='ignore')
                                        clean_string = ''.join(c for c in potential_string if c.isprintable())
                                        
                                        if (len(clean_string) >= min_length and 
                                            len(clean_string) <= max_length and
                                            self.should_translate(clean_string)):
                                            all_strings.append((clean_string, i, encoding))
                                            
                                    except:
                                        continue
                                        
                            except:
                                continue
                                
                except Exception as e:
                    continue
            
            # 중복 제거 및 정렬
            unique_strings = []
            seen = set()
            
            # UI 키워드가 포함된 문자열을 우선순위로 정렬
            all_strings.sort(key=lambda x: (
                -sum(1 for keyword in self.ui_keywords if keyword in x[0].lower()),
                len(x[0])
            ))
            
            for string_val, pos, enc in all_strings:
                if string_val not in seen:
                    seen.add(string_val)
                    unique_strings.append((string_val, pos, enc))
            
            print(f"번역 대상 UI 문자열 {len(unique_strings)}개 발견")
            return unique_strings
            
        except Exception as e:
            print(f"문자열 추출 오류: {e}")
            return []
    
    def auto_translate_exe(self, preview_mode: bool = True) -> Dict[str, str]:
        """EXE 파일을 자동으로 번역"""
        if not os.path.exists(self.exe_path):
            print("EXE 파일이 존재하지 않습니다.")
            return {}
        
        # UI 문자열 추출
        ui_strings = self.extract_ui_strings()
        
        if not ui_strings:
            print("번역할 UI 문자열을 찾을 수 없습니다.")
            return {}
        
        print(f"번역 대상: {len(ui_strings)}개 문자열")
        
        # 미리보기 모드
        if preview_mode:
            print("\n=== 번역 미리보기 (상위 20개) ===")
            preview_strings = [s[0] for s in ui_strings[:20]]
            translations = self.translate_batch(preview_strings)
            
            changes = {}
            for original in preview_strings:
                translation = translations[original]
                if translation != original:
                    changes[original] = translation
                    print(f"'{original}' → '{translation}'")
            
            if not changes:
                print("번역할 문자열이 없습니다.")
                return {}
            
            # 사용자 확인
            confirm = input(f"\n{len(changes)}개 문자열을 번역하시겠습니까? (y/n): ").strip().lower()
            if confirm != 'y':
                return changes
        
        # 전체 번역
        all_text = [s[0] for s in ui_strings]
        print("\n전체 문자열 번역 중...")
        translations = self.translate_batch(all_text)
        
        # 실제 파일 수정
        if not preview_mode:
            print("\nEXE 파일에 번역 적용 중...")
            success_count = 0
            
            for original, translation in translations.items():
                if original != translation:
                    # 인코딩별로 시도
                    replaced = False
                    for encoding in ['utf-8', 'ascii', 'cp949', 'utf-16le']:
                        if self.replace_string_safe(original, translation, encoding):
                            print(f"✓ '{original}' → '{translation}'")
                            success_count += 1
                            replaced = True
                            break
                    
                    if not replaced:
                        print(f"✗ '{original}' 교체 실패 (길이 제한 또는 인코딩 문제)")
            
            print(f"\n번역 완료: {success_count}개 문자열 교체됨")
        
        return translations
    
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
    """메인 함수"""
    print("=== AI 기반 EXE 한국어 번역 도구 ===")
    
    # OpenAI API 키 입력
    api_key = input("OpenAI API 키를 입력하세요: ").strip()
    if not api_key:
        print("API 키가 필요합니다.")
        return
    
    # EXE 파일 경로 입력
    exe_file = input("번역할 EXE 파일 경로를 입력하세요: ").strip().strip('"')
    
    if not os.path.exists(exe_file):
        print("파일이 존재하지 않습니다.")
        return
    
    # 번역기 객체 생성
    translator = AIExeTranslator(exe_file, api_key)
    
    # 백업 생성
    if not translator.create_backup():
        print("백업 생성에 실패했습니다. 작업을 중단합니다.")
        return
    
    while True:
        print("\n=== 메뉴 ===")
        print("1. AI 자동 번역 (미리보기)")
        print("2. AI 자동 번역 (실제 적용)")
        print("3. UI 문자열 추출 및 확인")
        print("4. 수동 문자열 교체")
        print("5. 번역 캐시 관리")
        print("6. 백업에서 복원")
        print("7. 종료")
        
        choice = input("\n선택하세요 (1-7): ").strip()
        
        if choice == '1':
            translations = translator.auto_translate_exe(preview_mode=True)
            if translations:
                print(f"\n미리보기 완료: {len(translations)}개 번역 결과")
        
        elif choice == '2':
            print("⚠️  실제 EXE 파일이 수정됩니다. 백업이 생성되었는지 확인하세요.")
            confirm = input("계속하시겠습니까? (y/n): ").strip().lower()
            if confirm == 'y':
                translator.auto_translate_exe(preview_mode=False)
        
        elif choice == '3':
            ui_strings = translator.extract_ui_strings()
            print(f"\n발견된 UI 문자열: {len(ui_strings)}개")
            
            show_all = input("모든 문자열을 출력하시겠습니까? (y/n): ").strip().lower() == 'y'
            display_count = len(ui_strings) if show_all else min(30, len(ui_strings))
            
            for i, (text, pos, enc) in enumerate(ui_strings[:display_count], 1):
                print(f"{i:3d}. [{enc}] {repr(text)}")
            
            if not show_all and len(ui_strings) > 30:
                print(f"... 외 {len(ui_strings) - 30}개 더")
        
        elif choice == '4':
            original = input("원본 문자열: ")
            replacement = input("교체할 문자열: ")
            
            if translator.replace_string_safe(original, replacement):
                print("교체 완료")
            else:
                print("교체 실패")
        
        elif choice == '5':
            print(f"현재 캐시: {len(translator.translation_cache)}개 번역")
            print("1. 캐시 내용 보기")
            print("2. 캐시 삭제")
            
            cache_choice = input("선택 (1-2): ").strip()
            
            if cache_choice == '1':
                for original, translation in list(translator.translation_cache.items())[:20]:
                    print(f"'{original}' → '{translation}'")
                if len(translator.translation_cache) > 20:
                    print(f"... 외 {len(translator.translation_cache) - 20}개 더")
            
            elif cache_choice == '2':
                if input("정말로 캐시를 삭제하시겠습니까? (y/n): ").strip().lower() == 'y':
                    translator.translation_cache = {}
                    if os.path.exists(translator.cache_file):
                        os.remove(translator.cache_file)
                    print("캐시 삭제 완료")
        
        elif choice == '6':
            translator.restore_backup()
        
        elif choice == '7':
            # 종료 전 캐시 저장
            translator.save_cache()
            print("프로그램을 종료합니다.")
            break
        
        else:
            print("잘못된 선택입니다.")

if __name__ == "__main__":
    main()