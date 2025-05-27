# exe_ui_string_patcher.py — DIALOG 캡션 지원 완전판 (오류 수정)
"""python
정적 UI 문자열 패처 (STRINGTABLE + DIALOG)
=========================================
* STRINGTABLE, DIALOG 의 LTEXT/PUSHBUTTON, 그리고 .rdata ASCII(≥8) 추출
* UTF‑16/ANSI 자동 판별, 길이 초과 방지(패딩)
* rich 테이블 인터랙티브 편집 → 패치 저장

필수 패키지
------------
    pip install pefile rich prompt_toolkit
"""
from __future__ import annotations
import argparse, struct
from pathlib import Path
from typing import List

import pefile
from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt
from rich.console import Console
from rich.table import Table
from prompt_toolkit import prompt

console = Console()

class UiStr:
    def __init__(self, idx: int, sec: str, off: int, raw: bytes, enc: str):
        self.idx, self.sec, self.off, self.raw, self.enc = idx, sec, off, raw, enc
        self.new: bytes | None = None

    def txt(self, data: bytes | None = None) -> str:
        b = data if data is not None else self.raw
        codec = 'utf-16le' if self.enc == 'utf16' else 'cp1252'
        return b.decode(codec, errors='replace')

# ───────────────────────── 리소스 트리 재귀 ─────────────────────────

def _walk(entry):
    if hasattr(entry, 'directory'):
        for e in entry.directory.entries:  # type: ignore[attr-defined]
            yield from _walk(e)
    else:
        yield entry

# ───────────────────────── STRINGTABLE ────────────────────────────

def collect_stringtable(pe: pefile.PE):
    res: list[tuple[int, bytes, str]] = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return res
    for top in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if (top.id or 0) != 6:  # RT_STRING
            continue
        for leaf in _walk(top):
            if not hasattr(leaf, 'data'):
                continue
            rva = leaf.data.struct.OffsetToData  # type: ignore[attr-defined]
            size = leaf.data.struct.Size  # type: ignore[attr-defined]
            if size < 2:
                continue
            off = pe.get_offset_from_rva(rva)
            blk = pe.__data__[off : off + size]
            cur = 0
            while cur + 2 <= len(blk):
                strlen = struct.unpack_from('<H', blk, cur)[0]
                cur += 2
                if strlen:
                    end = cur + strlen * 2
                    if end > len(blk):
                        break
                    res.append((off + cur, blk[cur:end], 'utf16'))
                cur += strlen * 2
    return res

# ───────────────────────── DIALOG 캡션 ────────────────────────────
DIALOG_HDR = '<IIIIHHHHHH'
HDR_SIZE = struct.calcsize(DIALOG_HDR)

def collect_dialog(pe: pefile.PE):
    out = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return out
    for top in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if (top.id or 0) != 5:  # RT_DIALOG
            continue
        for leaf in _walk(top):
            if not hasattr(leaf, 'data'):
                continue
            rva = leaf.data.struct.OffsetToData  # type: ignore[attr-defined]
            size = leaf.data.struct.Size  # type: ignore[attr-defined]
            raw = pe.get_memory_mapped_image()[rva : rva + size]
            if len(raw) < HDR_SIZE:
                continue
            off = HDR_SIZE  # skip header

            # skip menu, class, title prefix
            for _ in range(3):
                if raw[off : off + 2] == b'\x00\x00':
                    off += 2
                elif raw[off : off + 2] == b'\xff\xff':  # ordinal
                    off += 4
                else:
                    while raw[off : off + 2] != b'\x00\x00':
                        off += 2
                    off += 2

            # dialog title
            title_start = off
            while off + 2 <= len(raw) and raw[off : off + 2] != b'\x00\x00':
                off += 2
            if off > title_start:
                out.append((rva + title_start, raw[title_start:off], 'utf16'))
            off += 2  # skip NULL

            # scan remaining bytes for UTF‑16 strings (LTEXT, PUSHBUTTON)
            i = off
            while i + 2 < len(raw):
                if raw[i : i + 2] == b'\x00\x00':
                    i += 2
                    continue
                if 32 <= raw[i] <= 126 and raw[i + 1] == 0:
                    j = i
                    while j + 2 < len(raw) and 32 <= raw[j] <= 126 and raw[j + 1] == 0:
                        j += 2
                    if j - i >= 8:
                        out.append((rva + i, raw[i:j], 'utf16'))
                    i = j
                else:
                    i += 2
    return out

# ───────────────────────── .rdata ASCII ───────────────────────────

def collect_rdata_ascii(pe: pefile.PE):
    res = []
    for s in pe.sections:
        if s.Name.rstrip(b'\0') != b'.rdata':
            continue
        data = s.get_data(); base = s.PointerToRawData
        i = 0
        while i < len(data):
            if 32 <= data[i] <= 126:
                st = i
                while i < len(data) and 32 <= data[i] <= 126:
                    i += 1
                if i - st >= 8:
                    res.append((base + st, data[st:i], 'ansi'))
            else:
                i += 1
    return res

# ───────────────────────── 테이블 빌드 ────────────────────────────

def build_table(items: List[UiStr]):
    tbl = Table(title='UI 문자열')
    tbl.add_column('No', justify='right')
    tbl.add_column('Sec')
    tbl.add_column('Off')
    tbl.add_column('Current')
    tbl.add_column('New')
    for it in items:
        tbl.add_row(str(it.idx), it.sec, hex(it.off), it.txt(), it.txt(it.new) if it.new else '')
    return tbl

# ───────────────────────── 인터랙션 ───────────────────────────────

def interactive(target: Path):
    bak = target.with_suffix('.bak')
    if not bak.exists():
        bak.write_bytes(target.read_bytes())
    pe = pefile.PE(str(target))
    st = collect_stringtable(pe)
    dlg = collect_dialog(pe)
    asc = collect_rdata_ascii(pe)
    items: List[UiStr] = []
    for idx, (off, raw, enc) in enumerate(st + dlg + asc, 1):
        sec = 'STR' if idx <= len(st) else 'DLG' if idx <= len(st) + len(dlg) else 'RD'
        items.append(UiStr(idx, sec, off, raw, enc))

    while True:
        console.clear(); console.print(build_table(items))
        cmd = input('번호 / S=저장 / Q=종료 > ').strip().lower()
        if cmd == 'q':
            break
        if cmd == 's':
            _save(target, items)
            continue
        if not cmd.isdigit():
            continue
        sel = int(cmd)
        tgt = next((x for x in items if x.idx == sel), None)
        if not tgt:
            continue
        console.print(f'현재: [yellow]{tgt.txt()}[/]')
        new = prompt('새 문자열 (엔터 취소): ').strip()
        if not new:
            continue
        nb = new.encode('utf-16le' if tgt.enc == 'utf16' else 'cp1252', errors='replace')
        if len(nb) > len(tgt.raw):
            console.print('[red]길이가 길어 저장 불가!')
            continue
        tgt.new = nb.ljust(len(tgt.raw), b'\0')


def _save(path: Path, items: List[UiStr]):
    """패치 바이트를 새 파일로 저장한다. 원본은 보존."""
    buf = bytearray(path.read_bytes())
    for u in items:
        if u.new:
            buf[u.off : u.off + len(u.new)] = u.new

    default_file = path.with_stem(path.stem + '_patched').with_suffix('.exe')
    console.print(f"[cyan]새 EXE 파일명을 입력하세요[/] (Enter = {default_file.name})")
    user_input = input('> ').strip()
    out_file = (path.parent / user_input) if user_input else default_file

    if out_file.exists():
        console.print('[yellow]기존 파일을 덮어씁니다…')

    out_file.write_bytes(buf)
    console.print(f'[green]{out_file.name} 저장 완료')
    console.print(f'[green]{out_file.name} 저장 완료')
    console.print(f'[green]{out_file.name} 저장 완료')

# ───────────────────────── main ─────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('exe')
    args = parser.parse_args()
    interactive(Path(args.exe).expanduser().resolve())
