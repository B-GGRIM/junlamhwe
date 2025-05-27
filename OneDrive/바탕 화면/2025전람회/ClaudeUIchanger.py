# exe_ui_string_patcher_improved.py — 개선된 UI 문자열 패처
"""
정확한 UI 문자열 패처 (STRINGTABLE + DIALOG + MENU + 버전정보)
============================================================
* UI 관련 문자열만 정확히 추출 (노이즈 최소화)
* STRINGTABLE, DIALOG 컨트롤, MENU, 버전정보 지원
* UTF-16/ANSI 자동 판별, 길이 초과 방지
* 개선된 인터랙티브 편집 인터페이스

필수 패키지:
    pip install pefile rich prompt_toolkit
"""
from __future__ import annotations
import argparse
import struct
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional

import pefile
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import confirm

console = Console()

class UiString:
    """UI 문자열을 나타내는 클래스"""
    
    def __init__(self, idx: int, category: str, context: str, offset: int, 
                 raw_data: bytes, encoding: str, description: str = ""):
        self.idx = idx
        self.category = category  # STR, DLG, MENU, VER
        self.context = context    # 상세 컨텍스트 (예: "Dialog Title", "Button Text")
        self.offset = offset
        self.raw_data = raw_data
        self.encoding = encoding
        self.description = description
        self.new_data: Optional[bytes] = None
        self.is_modified = False

    def get_text(self, data: Optional[bytes] = None) -> str:
        """텍스트 추출"""
        target_data = data if data is not None else self.raw_data
        if not target_data:
            return ""
        
        try:
            if self.encoding == 'utf16':
                return target_data.decode('utf-16le', errors='replace').rstrip('\0')
            else:
                return target_data.decode('cp1252', errors='replace').rstrip('\0')
        except:
            return "<디코딩 오류>"

    def set_new_text(self, new_text: str) -> bool:
        """새 텍스트 설정"""
        if not new_text.strip():
            self.new_data = None
            self.is_modified = False
            return True
        
        try:
            if self.encoding == 'utf16':
                encoded = new_text.encode('utf-16le', errors='replace')
            else:
                encoded = new_text.encode('cp1252', errors='replace')
            
            # 패딩을 포함한 원본 크기 확인
            max_size = len(self.raw_data)
            if len(encoded) > max_size:
                return False
            
            # NULL 패딩으로 원본 크기에 맞춤
            self.new_data = encoded.ljust(max_size, b'\0')
            self.is_modified = True
            return True
        except:
            return False


class ResourceExtractor:
    """리소스 추출 클래스"""
    
    def __init__(self, pe: pefile.PE):
        self.pe = pe
        self.strings: List[UiString] = []
        self.string_counter = 1

    def extract_all(self) -> List[UiString]:
        """모든 UI 관련 문자열 추출"""
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            self._extract_stringtable()
            self._extract_dialogs()
            self._extract_menus()
            self._extract_version_info()
        
        # 중복 제거 및 정렬
        self._remove_duplicates()
        self._sort_strings()
        
        return self.strings

    def _extract_stringtable(self):
        """STRINGTABLE 리소스 추출"""
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if (entry.id or 0) != 6:  # RT_STRING
                continue
            
            for leaf in self._walk_resource_tree(entry):
                if not hasattr(leaf, 'data'):
                    continue
                
                try:
                    rva = leaf.data.struct.OffsetToData
                    size = leaf.data.struct.Size
                    if size < 2:
                        continue
                    
                    offset = self.pe.get_offset_from_rva(rva)
                    data = self.pe.__data__[offset:offset + size]
                    
                    self._parse_stringtable_block(offset, data)
                except:
                    continue

    def _parse_stringtable_block(self, base_offset: int, data: bytes):
        """STRINGTABLE 블록 파싱"""
        pos = 0
        string_id = 0
        
        while pos + 2 <= len(data):
            str_len = struct.unpack_from('<H', data, pos)[0]
            pos += 2
            
            if str_len > 0:
                end_pos = pos + str_len * 2
                if end_pos <= len(data):
                    string_data = data[pos:end_pos]
                    text = string_data.decode('utf-16le', errors='replace')
                    
                    # UI 관련 문자열 필터링
                    if self._is_ui_relevant_string(text):
                        ui_str = UiString(
                            idx=self.string_counter,
                            category="STR",
                            context=f"String #{string_id}",
                            offset=base_offset + pos,
                            raw_data=string_data,
                            encoding="utf16",
                            description=self._get_string_description(text)
                        )
                        self.strings.append(ui_str)
                        self.string_counter += 1
                
                pos = end_pos
            else:
                pos += str_len * 2
            
            string_id += 1

    def _extract_dialogs(self):
        """DIALOG 리소스 추출"""
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if (entry.id or 0) != 5:  # RT_DIALOG
                continue
            
            for leaf in self._walk_resource_tree(entry):
                if not hasattr(leaf, 'data'):
                    continue
                
                try:
                    rva = leaf.data.struct.OffsetToData
                    size = leaf.data.struct.Size
                    dialog_data = self.pe.get_memory_mapped_image()[rva:rva + size]
                    
                    self._parse_dialog(rva, dialog_data)
                except:
                    continue

    def _parse_dialog(self, base_rva: int, data: bytes):
        """DIALOG 구조 파싱"""
        if len(data) < 18:  # 최소 헤더 크기
            return
        
        # 다이얼로그 헤더 건너뛰기
        pos = 18
        
        # Menu, Class, Title 건너뛰기
        for field_name in ["Menu", "Class", "Title"]:
            if pos + 2 > len(data):
                return
            
            if data[pos:pos + 2] == b'\x00\x00':
                pos += 2
            elif data[pos:pos + 2] == b'\xff\xff':
                pos += 4
            else:
                # 문자열 찾기
                str_start = pos
                while pos + 2 <= len(data) and data[pos:pos + 2] != b'\x00\x00':
                    pos += 2
                
                if field_name == "Title" and pos > str_start:
                    title_data = data[str_start:pos]
                    if self._is_meaningful_dialog_text(title_data):
                        ui_str = UiString(
                            idx=self.string_counter,
                            category="DLG",
                            context="Dialog Title",
                            offset=base_rva + str_start,
                            raw_data=title_data,
                            encoding="utf16",
                            description="다이얼로그 제목"
                        )
                        self.strings.append(ui_str)
                        self.string_counter += 1
                
                pos += 2  # NULL 종료자

        # 다이얼로그 컨트롤들 스캔
        self._scan_dialog_controls(base_rva, data, pos)

    def _scan_dialog_controls(self, base_rva: int, data: bytes, start_pos: int):
        """다이얼로그 컨트롤 텍스트 스캔"""
        pos = start_pos
        
        while pos + 10 < len(data):  # 최소 컨트롤 크기
            # UTF-16 문자열 패턴 찾기
            if self._is_utf16_string_start(data, pos):
                str_start = pos
                str_end = self._find_utf16_string_end(data, pos)
                
                if str_end > str_start:
                    string_data = data[str_start:str_end]
                    if self._is_meaningful_dialog_text(string_data):
                        text = string_data.decode('utf-16le', errors='replace')
                        context = self._identify_control_type(text)
                        
                        ui_str = UiString(
                            idx=self.string_counter,
                            category="DLG",
                            context=context,
                            offset=base_rva + str_start,
                            raw_data=string_data,
                            encoding="utf16",
                            description=self._get_control_description(text)
                        )
                        self.strings.append(ui_str)
                        self.string_counter += 1
                    
                    pos = str_end
                else:
                    pos += 2
            else:
                pos += 2

    def _extract_menus(self):
        """MENU 리소스 추출"""
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if (entry.id or 0) != 4:  # RT_MENU
                continue
            
            for leaf in self._walk_resource_tree(entry):
                if not hasattr(leaf, 'data'):
                    continue
                
                try:
                    rva = leaf.data.struct.OffsetToData
                    size = leaf.data.struct.Size
                    menu_data = self.pe.get_memory_mapped_image()[rva:rva + size]
                    
                    self._parse_menu(rva, menu_data)
                except:
                    continue

    def _parse_menu(self, base_rva: int, data: bytes):
        """메뉴 구조 파싱"""
        pos = 4  # 메뉴 헤더 건너뛰기
        
        while pos + 4 < len(data):
            # 메뉴 아이템 플래그와 ID
            flags = struct.unpack_from('<H', data, pos)[0] if pos + 2 <= len(data) else 0
            pos += 2
            
            if not (flags & 0x10):  # MF_POPUP이 아닌 경우
                pos += 2  # ID 건너뛰기
            
            # 메뉴 텍스트
            str_start = pos
            while pos + 2 <= len(data) and data[pos:pos + 2] != b'\x00\x00':
                pos += 2
            
            if pos > str_start:
                menu_text = data[str_start:pos]
                if self._is_meaningful_menu_text(menu_text):
                    ui_str = UiString(
                        idx=self.string_counter,
                        category="MENU",
                        context="Menu Item",
                        offset=base_rva + str_start,
                        raw_data=menu_text,
                        encoding="utf16",
                        description="메뉴 항목"
                    )
                    self.strings.append(ui_str)
                    self.string_counter += 1
            
            pos += 2  # NULL 종료자
            
            if flags & 0x80:  # MF_END
                break

    def _extract_version_info(self):
        """버전 정보 추출"""
        for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if (entry.id or 0) != 16:  # RT_VERSION
                continue
            
            for leaf in self._walk_resource_tree(entry):
                if not hasattr(leaf, 'data'):
                    continue
                
                try:
                    rva = leaf.data.struct.OffsetToData
                    size = leaf.data.struct.Size
                    version_data = self.pe.get_memory_mapped_image()[rva:rva + size]
                    
                    self._parse_version_info(rva, version_data)
                except:
                    continue

    def _parse_version_info(self, base_rva: int, data: bytes):
        """버전 정보 파싱 (간단화)"""
        # 주요 버전 정보 필드들을 UTF-16으로 스캔
        version_fields = [
            "FileDescription", "ProductName", "CompanyName", 
            "FileVersion", "ProductVersion", "LegalCopyright"
        ]
        
        pos = 0
        while pos + 20 < len(data):
            # UTF-16 문자열 찾기
            if self._is_utf16_string_start(data, pos):
                str_start = pos
                str_end = self._find_utf16_string_end(data, pos)
                
                if str_end > str_start:
                    string_data = data[str_start:str_end]
                    text = string_data.decode('utf-16le', errors='replace')
                    
                    if len(text.strip()) > 3 and any(field in text for field in version_fields):
                        ui_str = UiString(
                            idx=self.string_counter,
                            category="VER",
                            context="Version Info",
                            offset=base_rva + str_start,
                            raw_data=string_data,
                            encoding="utf16",
                            description="버전 정보"
                        )
                        self.strings.append(ui_str)
                        self.string_counter += 1
                    
                    pos = str_end
                else:
                    pos += 2
            else:
                pos += 2

    # 유틸리티 메서드들
    def _walk_resource_tree(self, entry):
        """리소스 트리 순회"""
        if hasattr(entry, 'directory'):
            for sub_entry in entry.directory.entries:
                yield from self._walk_resource_tree(sub_entry)
        else:
            yield entry

    def _is_ui_relevant_string(self, text: str) -> bool:
        """UI 관련 문자열인지 판단"""
        text = text.strip()
        if len(text) < 2:
            return False
        
        # 파일 경로, 확장자, 기술적 문자열 제외
        excluded_patterns = [
            r'^[A-Z]:\\',  # 파일 경로
            r'\.(exe|dll|sys|log|tmp|dat)$',  # 파일 확장자
            r'^[0-9a-fA-F]{8,}$',  # 16진수 문자열
            r'^\d+\.\d+\.\d+',  # 버전 번호 패턴
            r'^[A-Z][a-z]*\.[A-Z]',  # 네임스페이스 패턴
        ]
        
        for pattern in excluded_patterns:
            if re.match(pattern, text):
                return False
        
        # UI 관련 키워드 포함 여부
        ui_keywords = [
            'OK', 'Cancel', 'Yes', 'No', 'Apply', 'Close', 'Exit', 'Help',
            'File', 'Edit', 'View', 'Tools', 'Window', 'Options', 'Settings',
            'Error', 'Warning', 'Information', 'Question', 'About',
            '확인', '취소', '적용', '닫기', '종료', '도움말', '파일', '편집',
            '보기', '도구', '창', '옵션', '설정', '오류', '경고', '정보'
        ]
        
        return any(keyword.lower() in text.lower() for keyword in ui_keywords) or len(text) >= 3

    def _is_meaningful_dialog_text(self, data: bytes) -> bool:
        """의미있는 다이얼로그 텍스트인지 판단"""
        try:
            text = data.decode('utf-16le', errors='replace').strip()
            return len(text) >= 1 and not text.isspace() and '\x00' not in text
        except:
            return False

    def _is_meaningful_menu_text(self, data: bytes) -> bool:
        """의미있는 메뉴 텍스트인지 판단"""
        try:
            text = data.decode('utf-16le', errors='replace').strip()
            return len(text) >= 1 and text != "-" and not text.startswith('\t')
        except:
            return False

    def _is_utf16_string_start(self, data: bytes, pos: int) -> bool:
        """UTF-16 문자열 시작점인지 확인"""
        if pos + 2 > len(data):
            return False
        
        char = data[pos:pos + 2]
        if char == b'\x00\x00':
            return False
        
        # 일반적인 ASCII 범위의 UTF-16 문자
        if 32 <= char[0] <= 126 and char[1] == 0:
            return True
        
        return False

    def _find_utf16_string_end(self, data: bytes, start: int) -> int:
        """UTF-16 문자열 끝점 찾기"""
        pos = start
        while pos + 2 <= len(data):
            if data[pos:pos + 2] == b'\x00\x00':
                return pos
            pos += 2
        return pos

    def _identify_control_type(self, text: str) -> str:
        """컨트롤 타입 식별"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['ok', '확인', 'yes', '예']):
            return "OK Button"
        elif any(word in text_lower for word in ['cancel', '취소', 'no', '아니오']):
            return "Cancel Button"
        elif any(word in text_lower for word in ['apply', '적용']):
            return "Apply Button"
        elif any(word in text_lower for word in ['close', '닫기']):
            return "Close Button"
        elif any(word in text_lower for word in ['help', '도움말']):
            return "Help Button"
        elif '&' in text:
            return "Menu/Button"
        else:
            return "Control Text"

    def _get_string_description(self, text: str) -> str:
        """문자열 설명 생성"""
        if len(text) > 50:
            return f"긴 텍스트: {text[:47]}..."
        return f"텍스트: {text}"

    def _get_control_description(self, text: str) -> str:
        """컨트롤 설명 생성"""
        return f"컨트롤: {text}"

    def _remove_duplicates(self):
        """중복 문자열 제거"""
        seen = set()
        unique_strings = []
        
        for ui_str in self.strings:
            text = ui_str.get_text()
            key = (text, ui_str.category)
            
            if key not in seen:
                seen.add(key)
                unique_strings.append(ui_str)
        
        self.strings = unique_strings

    def _sort_strings(self):
        """문자열 정렬 (카테고리별, 오프셋별)"""
        category_order = {"STR": 0, "DLG": 1, "MENU": 2, "VER": 3}
        
        self.strings.sort(key=lambda s: (
            category_order.get(s.category, 99),
            s.offset
        ))
        
        # 인덱스 재할당
        for i, ui_str in enumerate(self.strings, 1):
            ui_str.idx = i


class UiPatcher:
    """UI 패처 메인 클래스"""
    
    def __init__(self, exe_path: Path):
        self.exe_path = exe_path
        self.backup_path = exe_path.with_suffix('.bak')
        self.strings: List[UiString] = []
        
        # 백업 생성
        if not self.backup_path.exists():
            self.backup_path.write_bytes(exe_path.read_bytes())
            console.print(f"[green]백업 파일 생성: {self.backup_path.name}[/]")

    def load_strings(self):
        """문자열 로드"""
        try:
            pe = pefile.PE(str(self.exe_path))
            extractor = ResourceExtractor(pe)
            self.strings = extractor.extract_all()
            
            console.print(f"[green]총 {len(self.strings)}개의 UI 문자열을 찾았습니다.[/]")
        except Exception as e:
            console.print(f"[red]파일 로드 오류: {e}[/]")
            return False
        
        return True

    def show_strings_table(self):
        """문자열 테이블 표시"""
        if not self.strings:
            console.print("[yellow]표시할 문자열이 없습니다.[/]")
            return
        
        table = Table(title="🔤 UI 문자열 목록", show_header=True, header_style="bold blue")
        table.add_column("No", justify="right", style="cyan", width=4)
        table.add_column("분류", justify="center", style="magenta", width=6)
        table.add_column("컨텍스트", style="yellow", width=15)
        table.add_column("현재 텍스트", style="white", width=30)
        table.add_column("새 텍스트", style="green", width=30)
        table.add_column("상태", justify="center", width=6)
        
        for ui_str in self.strings:
            current_text = ui_str.get_text()
            new_text = ui_str.get_text(ui_str.new_data) if ui_str.new_data else ""
            status = "✏️" if ui_str.is_modified else ""
            
            # 텍스트 길이 제한
            if len(current_text) > 28:
                current_text = current_text[:25] + "..."
            if len(new_text) > 28:
                new_text = new_text[:25] + "..."
            
            table.add_row(
                str(ui_str.idx),
                ui_str.category,
                ui_str.context,
                current_text,
                new_text,
                status
            )
        
        console.print(table)

    def edit_string(self, idx: int) -> bool:
        """문자열 편집"""
        target = next((s for s in self.strings if s.idx == idx), None)
        if not target:
            console.print(f"[red]번호 {idx}를 찾을 수 없습니다.[/]")
            return False
        
        # 현재 정보 표시
        panel_content = [
            f"[bold]분류:[/] {target.category}",
            f"[bold]컨텍스트:[/] {target.context}",
            f"[bold]현재 텍스트:[/] {target.get_text()}",
            f"[bold]최대 길이:[/] {len(target.raw_data)} 바이트",
            "",
            "[dim]새 텍스트를 입력하세요 (빈 입력시 취소):[/]"
        ]
        
        console.print(Panel(
            "\n".join(panel_content),
            title=f"📝 문자열 편집 - #{idx}",
            border_style="blue"
        ))
        
        try:
            new_text = prompt("새 텍스트: ").strip()
            
            if not new_text:
                console.print("[yellow]편집이 취소되었습니다.[/]")
                return False
            
            if target.set_new_text(new_text):
                console.print(f"[green]✅ 문자열이 성공적으로 수정되었습니다![/]")
                return True
            else:
                console.print(f"[red]❌ 텍스트가 너무 깁니다! 최대 {len(target.raw_data)} 바이트까지 가능합니다.[/]")
                return False
                
        except KeyboardInterrupt:
            console.print("\n[yellow]편집이 취소되었습니다.[/]")
            return False

    def save_changes(self):
        """변경사항 저장"""
        modified_count = sum(1 for s in self.strings if s.is_modified)
        
        if modified_count == 0:
            console.print("[yellow]변경된 문자열이 없습니다.[/]")
            return
        
        console.print(f"[cyan]{modified_count}개의 문자열이 수정되었습니다.[/]")
        
        # 출력 파일명 입력
        default_name = self.exe_path.with_stem(self.exe_path.stem + "_patched")
        
        try:
            output_name = prompt(
                f"저장할 파일명 (Enter={default_name.name}): "
            ).strip()
            
            if not output_name:
                output_path = default_name
            else:
                output_path = self.exe_path.parent / output_name
                if not output_path.suffix:
                    output_path = output_path.with_suffix('.exe')
            
            # 파일 저장
            file_data = bytearray(self.exe_path.read_bytes())
            
            for ui_str in self.strings:
                if ui_str.is_modified and ui_str.new_data:
                    file_data[ui_str.offset:ui_str.offset + len(ui_str.new_data)] = ui_str.new_data
            
            output_path.write_bytes(file_data)
            console.print(f"[green]✅ 파일이 성공적으로 저장되었습니다: {output_path.name}[/]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]저장이 취소되었습니다.[/]")
        except Exception as e:
            console.print(f"[red]저장 오류: {e}[/]")

    def run_interactive(self):
        """인터랙티브 모드 실행"""
        if not self.load_strings():
            return
        
        console.print(Panel(
            "[bold blue]🔧 EXE UI 문자열 패처[/]\n\n"
            "명령어:\n"
            "• [bold]숫자[/]: 해당 번호의 문자열 편집\n"
            "• [bold]s[/]: 변경사항 저장\n"
            "• [bold]r[/]: 문자열 목록 새로고침\n"
            "• [bold]q[/]: 종료",
            title="사용법",
            border_style="green"
        ))
        
        while True:
            try:
                console.print("\n" + "="*80)
                self.show_strings_table()
                console.print("="*80)
                
                command = prompt("\n🔸 명령 입력 (숫자/s/r/q): ").strip().lower()
                
                if command == 'q':
                    if any(s.is_modified for s in self.strings):
                        if confirm("변경사항이 있습니다. 저장하지 않고 종료하시겠습니까?"):
                            break
                    else:
                        break
                
                elif command == 's':
                    self.save_changes()
                
                elif command == 'r':
                    console.clear()
                    console.print("[green]문자열 목록을 새로고침했습니다.[/]")
                
                elif command.isdigit():
                    idx = int(command)
                    self.edit_string(idx)
                
                else:
                    console.print("[red]올바른 명령을 입력하세요.[/]")
            
            except KeyboardInterrupt:
                console.print("\n[yellow]종료합니다.[/]")
                break
            except Exception as e:
                console.print(f"[red]오류가 발생했습니다: {e}[/]")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description="EXE 파일의 UI 문자열을 추출하고 편집하는 도구"
    )
    parser.add_argument("exe_file", help="편집할 EXE 파일 경로")
    
    args = parser