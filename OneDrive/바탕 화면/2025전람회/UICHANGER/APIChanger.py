# auto_korean_localizer.py – GPT-powered EXE UI 한글화 자동 패처 (OpenAI Python v1 호환)
"""
기능 개요
~~~~~~~~
* EXE/DLL 내부의 STRINGTABLE, DIALOG 텍스트를 수집
* OpenAI Chat API 호출로 한국어 번역 (포맷 토큰 유지, 길이 제한)
* 번역된 문자열을 바이너리에 패치하여 `<원본>_ko.exe` 저장

환경 준비
~~~~~~~~
1. Python ≥ 3.10
2. 의존 패키지 설치
   ```bash
   pip install pefile openai rich python-dotenv
   ```
3. API 키 설정
   - `.env` 파일 또는
   - 시스템 환경변수 `OPENAI_API_KEY`

사용 예
~~~~~~
```bash
python auto_korean_localizer.py AutoClick.exe
```
"""
from __future__ import annotations
import argparse, os, struct, json
from pathlib import Path
from typing import List, Tuple

import pefile
import openai
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# ───────────────── 환경 로드 ─────────────────
load_dotenv()  # .env 파일 불러오기
console = Console()
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    console.print("[red]환경 변수 OPENAI_API_KEY가 설정되지 않았습니다.")
    raise SystemExit(1)

# ───────────────── 리소스 수집 ─────────────────

def _walk(entry):
    if hasattr(entry, 'directory'):
        for e in entry.directory.entries:  # type: ignore
            yield from _walk(e)
    else:
        yield entry


def collect_texts(pe: pefile.PE) -> List[Tuple[int, bytes]]:
    items: list[Tuple[int, bytes]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for res_id in (6, 5):  # RT_STRING, RT_DIALOG
            for top in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if (top.id or 0) != res_id:
                    continue
                for leaf in _walk(top):
                    if not hasattr(leaf, 'data'):
                        continue
                    rva = leaf.data.struct.OffsetToData  # type: ignore
                    size = leaf.data.struct.Size  # type: ignore
                    raw = pe.get_memory_mapped_image()[rva : rva + size]
                    off = pe.get_offset_from_rva(rva)
                    if res_id == 6:
                        # STRINGTABLE UTF-16 blocks
                        blk = pe.__data__[off : off + size]
                        cur = 0
                        while cur + 2 <= len(blk):
                            slen = struct.unpack_from('<H', blk, cur)[0]
                            cur += 2
                            if slen:
                                items.append((off + cur, blk[cur : cur + slen * 2]))
                            cur += slen * 2
                    else:
                        # DIALOG captions heuristic
                        i = 0
                        while i + 8 < len(raw):
                            if 32 <= raw[i] <= 126 and raw[i+1] == 0:
                                j = i
                                while j + 2 < len(raw) and 32 <= raw[j] <= 126 and raw[j+1] == 0:
                                    j += 2
                                if j - i >= 8:
                                    items.append((off + i, raw[i:j]))
                                i = j
                            else:
                                i += 2
    return items

# ───────────────── 번역 ─────────────────
BATCH = 40

SYSTEM_PROMPT = (
    "당신은 소프트웨어 UI 로컬라이저입니다."
    "주어진 문자열을 한국어로 번역하되, %d, %s 같은 토큰은 그대로 두고,"
    "번역 결과 길이는 원문의 1.5배 내로 유지하세요."
)


def translate_all(src: List[str]) -> List[str]:
    results: List[str] = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}")) as prog:
        task = prog.add_task("번역 중…", total=len(src))
        for i in range(0, len(src), BATCH):
            batch = src[i : i + BATCH]
            # Chat API 호출
            resp = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(batch, ensure_ascii=False)}
                ],
                temperature=0.2
            )
            out = json.loads(resp.choices[0].message.content)
            results.extend(out)
            prog.update(task, advance=len(batch))
    return results

# ──────────────────── 패치 ────────────────────

def patch_exe(exe_path: Path):
    console.print(f"[cyan]Analyzing:[/] {exe_path.name}")
    pe = pefile.PE(str(exe_path))
    items = collect_texts(pe)
    if not items:
        console.print("[red]변환할 UI 문자열을 찾을 수 없습니다.")
        return
    srcs = [b.decode('utf-16le') for _, b in items]
    kos = translate_all(srcs)

    buf = bytearray(exe_path.read_bytes())
    for (off, raw), ko in zip(items, kos):
        nb = ko.encode('utf-16le')[: len(raw)]
        buf[off : off + len(raw)] = nb.ljust(len(raw), b'\x00')

    out = exe_path.with_stem(exe_path.stem + '_ko').with_suffix('.exe')
    out.write_bytes(buf)
    console.print(f"[green]완료! 새 파일:[/] {out.name}")

# ──────────────────── main ────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GPT 기반 EXE UI 한글화')
    parser.add_argument('exe', help='대상 실행 파일')
    args = parser.parse_args()
    patch_exe(Path(args.exe).expanduser().resolve())