# -*- coding: utf-8 -*-
"""
ui_translate_patcher.py  (한국어 자동 번역·패치 도구)
-------------------------------------------------
• EXE의 UI 리소스(STRING‧DIALOG‧MENU 등)만 추출 → ChatGPT로 한국어 번역 → 길이 맞으면 즉시 패치
• 백업/복원, 중복 방지, 길이 초과 시 스킵 로직 포함
• 사용법 (PowerShell 예시)
    python ui_translate_patcher.py --exe "C:\Program Files\foo\bar.exe" --api-key sk-xxx --model gpt-4o-mini
필요 패키지:   pip install pefile openai tqdm
"""

from __future__ import annotations
import os, sys, argparse, shutil, re, time
from typing import List, Tuple, Dict, Set

import pefile               # PE 분석용
import openai               # ChatGPT 호출용
from tqdm import tqdm        # 진행률 표시 (선택)

# ───────────────────────────────────────────────────────────────
#  PE 리소스 유틸
# ───────────────────────────────────────────────────────────────
_UI_RESOURCE_IDS: Set[int] = {4, 5, 6, 9, 12}   # MENU, DIALOG, STRING, ACCELERATOR, GROUP_CURSOR


def build_ui_ranges(pe: pefile.PE) -> List[Tuple[int, int]]:
    """UI 관련 리소스 블록의 (파일 오프셋 시작, 끝) 리스트 반환"""
    ranges: List[Tuple[int, int]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return ranges

    def walk(entry, root_id=None):
        top_id = entry.id if entry.id is not None else root_id
        if hasattr(entry, "data"):
            if top_id in _UI_RESOURCE_IDS:
                data_entry = entry.data
                offset = pe.get_offset_from_rva(data_entry.struct.OffsetToData)
                size = data_entry.struct.Size
                ranges.append((offset, offset + size))
        elif hasattr(entry, "directory"):
            for child in entry.directory.entries:
                walk(child, top_id)

    for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        walk(e)
    return ranges


def offset_in_ranges(offset: int, ranges: List[Tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in ranges)


# ───────────────────────────────────────────────────────────────
#  EXE 패처 (UI 전용)
# ───────────────────────────────────────────────────────────────
class UiExePatcher:
    def __init__(self, exe_path: str):
        self.exe_path = exe_path
        self.backup_path = exe_path + ".backup"
        self.pe = pefile.PE(exe_path, fast_load=True)
        self.pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
        )
        self.ui_ranges = build_ui_ranges(self.pe)

    # ── 백업/복원 ──────────────────────────
    def create_backup(self) -> None:
        if not os.path.exists(self.backup_path):
            shutil.copy2(self.exe_path, self.backup_path)
            print(f"[+] 백업 생성 → {self.backup_path}")

    def restore_backup(self) -> None:
        if os.path.exists(self.backup_path):
            shutil.copy2(self.backup_path, self.exe_path)
            print("[+] 백업에서 복원 완료")

    # ── 오프셋이 UI 영역인가? ─────────────────
    def _is_ui_offset(self, offset: int) -> bool:
        return offset_in_ranges(offset, self.ui_ranges)

    # ── UI 문자열 추출 ─────────────────────────
    def extract_ui_strings(self, min_len=4, max_len=200) -> List[Tuple[str, int, str]]:
        """(문자열, 오프셋, 인코딩) 리스트 반환"""
        blob = open(self.exe_path, 'rb').read()
        results: List[Tuple[str, int, str]] = []

        def meaningful(s):
            return re.search(r'[가-힣A-Za-z]', s) is not None

        # UTF‑16LE 먼저 (RT_STRING 주력)
        for i in range(0, len(blob) - 1, 2):
            if not self._is_ui_offset(i):
                continue
            j = i
            chars = []
            while j < len(blob) - 1:
                piece = blob[j:j + 2]
                if piece == b'\x00\x00':
                    break
                try:
                    c = piece.decode('utf-16le')
                except UnicodeDecodeError:
                    break
                if c.isprintable():
                    chars.append(c)
                    j += 2
                else:
                    break
            if len(chars) >= min_len:
                s = ''.join(chars)
                if len(s) <= max_len and meaningful(s):
                    results.append((s, i, 'utf-16le'))
            if j > i:
                i = j

        # UTF‑8 / CP949 (메뉴·다이얼로그 제목 등)
        for i in range(len(blob)):
            if not self._is_ui_offset(i):
                continue
            if not (32 <= blob[i] <= 126 or blob[i] >= 128):
                continue
            j = i
            while j < len(blob):
                b = blob[j]
                if 32 <= b <= 126 or b >= 128:
                    j += 1
                else:
                    break
            if j - i >= min_len:
                segment = blob[i:j]
                for enc in ('utf-8', 'cp949'):
                    try:
                        s = segment.decode(enc)
                    except UnicodeDecodeError:
                        continue
                    if len(s) <= max_len and meaningful(s):
                        results.append((s, i, enc))
                        break
            i = j
        return results

    # ── 문자열 교체 ────────────────────────────
    def replace_string(self, pos: int, original_len: int, enc: str, new_text: str, data: bytearray) -> bool:
        try:
            new_bytes = new_text.encode(enc)
        except UnicodeEncodeError:
            return False
        if len(new_bytes) > original_len:
            return False  # 길이 초과 → 스킵
        if enc == 'utf-16le':
            # null‑종료 보장
            new_bytes += b'\x00\x00'
        else:
            new_bytes += b'\x00'
        data[pos:pos + len(new_bytes)] = new_bytes.ljust(original_len, b'\x00')
        return True

    # ── 전체 자동 번역 & 패치 ──────────────────
    def auto_translate_and_patch(self, api_key: str, model: str = 'gpt-4o-mini', temperature: float = 0.3,
                                 batch_size: int = 20, dry_run: bool = False) -> None:
        openai.api_key = api_key
        ui_strs = self.extract_ui_strings()
        unique: Dict[str, List[Tuple[int, int, str]]] = {}
        for txt, pos, enc in ui_strs:
            unique.setdefault(txt, []).append((pos, len(txt.encode(enc)) + (2 if enc == 'utf-16le' else 1), enc))

        print(f"[+] 번역 대상 UI 문자열: {len(unique)}개")

        # ▼ 번역 수행 (배치)
        translations: Dict[str, str] = {}
        items = list(unique.keys())
        for i in tqdm(range(0, len(items), batch_size), desc="번역 진행"):
            chunk = items[i:i + batch_size]
            prompt = "다음 UI 텍스트들을 자연스러운 한국어로 번역하세요. 줄 순서를 유지하고, 각 줄마다 번역만 출력하세요.\n\n" + "\n".join(chunk)
            try:
                resp = openai.ChatCompletion.create(
                    model=model,
                    temperature=temperature,
                    messages=[
                        {"role": "system", "content": "You are a professional software localizer."},
                        {"role": "user", "content": prompt}
                    ]
                )
                kr_lines = resp.choices[0].message.content.strip().splitlines()
                if len(kr_lines) != len(chunk):
                    print("[!] 줄 수 불일치 → 원문 유지")
                    continue
                for orig, kr in zip(chunk, kr_lines):
                    translations[orig] = kr.strip()
            except Exception as e:
                print(f"[!] 번역 실패: {e}")

        print(f"[+] 번역 완료 / 실제 패치 시작 …")
        # ▼ 패치
        with open(self.exe_path, 'rb') as f:
            bin_data = bytearray(f.read())

        patched = 0
        for src, tgt in translations.items():
            for pos, orig_len, enc in unique[src]:
                if self.replace_string(pos, orig_len, enc, tgt, bin_data):
                    patched += 1

        if not dry_run and patched:
            with open(self.exe_path, 'wb') as f:
                f.write(bin_data)
            print(f"[+] 총 {patched}개 위치에 번역 적용 완료")
        else:
            print("[!] 패치된 위치가 없습니다 (길이 제한으로 모두 스킵되었을 수 있음)")


# ───────────────────────────────────────────────────────────────
#  CLI 파서
# ───────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="EXE UI 한글화 자동 패처 (ChatGPT 사용)")
    p.add_argument("--exe", required=True, help="대상 EXE 경로")
    p.add_argument("--api-key", required=True, help="OpenAI API 키")
    p.add_argument("--model", default="gpt-4o-mini", help="사용할 모델 (기본: gpt-4o-mini)")
    p.add_argument("--dry-run", action="store_true", help="실제 파일 수정 없이 동작 테스트만 수행")
    return p.parse_args()


# ───────────────────────────────────────────────────────────────
#  Entry
# ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = parse_args()
    if not os.path.exists(args.exe):
        print("[!] EXE 파일을 찾을 수 없습니다.")
        sys.exit(1)

    patcher = UiExePatcher(args.exe)
    patcher.create_backup()

    t0 = time.time()
    patcher.auto_translate_and_patch(
        api_key=args.api_key,
        model=args.model,
        dry_run=args.dry_run,
    )
    print(f"[✓] 작업 완료 (경과 {time.time() - t0:.1f}초)")
