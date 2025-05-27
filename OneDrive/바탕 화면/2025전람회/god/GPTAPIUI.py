#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import struct
import shutil
import threading
import itertools
import ctypes
from ctypes import wintypes, c_void_p, create_string_buffer, cast

import pefile
import openai
import win32api
import win32con
from openai.error import ServiceUnavailableError, RateLimitError

# Win32 API 함수 로드
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
kernel32.BeginUpdateResourceW.restype  = wintypes.HANDLE
kernel32.UpdateResourceW.argtypes = [
    wintypes.HANDLE,    # hUpdate
    wintypes.LPCWSTR,   # lpType
    wintypes.LPCWSTR,   # lpName
    wintypes.WORD,      # wLanguage
    wintypes.LPVOID,    # lpData
    wintypes.DWORD      # cbData
]
kernel32.UpdateResourceW.restype  = wintypes.BOOL
kernel32.EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
kernel32.EndUpdateResourceW.restype  = wintypes.BOOL

# 스피너(로딩 아이콘)
class Spinner:
    def __init__(self, message="Processing"):
        self.message = message
        self.stop_flag = threading.Event()
        self.thread    = threading.Thread(target=self._spin)
    def _spin(self):
        for c in itertools.cycle(['|','/','-','\\']):
            if self.stop_flag.is_set(): break
            sys.stdout.write(f"\r{self.message}... {c}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " "*(len(self.message)+5) + "\r")
    def start(self): self.thread.start()
    def stop(self):
        self.stop_flag.set()
        self.thread.join()

# MAKEINTRESOURCEW 구현
def MAKEINTRESOURCEW(i: int) -> wintypes.LPCWSTR:
    return cast(c_void_p(i & 0xFFFF), wintypes.LPCWSTR)

class ExeUIPatcher:
    def __init__(self, exe_path: str, api_key: str):
        self.exe_path = os.path.abspath(exe_path)
        openai.api_key = api_key

    def run(self):
        if not os.path.exists(self.exe_path):
            print(f"[-] 대상 파일이 없습니다: {self.exe_path}")
            return

        # 백업 생성
        backup = self.exe_path + ".backup"
        shutil.copy2(self.exe_path, backup)
        print(f"[+] 백업 생성: {backup}")

        # RT_STRING 스트링 블록 추출
        blocks = self.extract_blocks()
        print(f"[+] 추출된 블록 수: {len(blocks)}개")

        # 번역
        spinner = Spinner("UI 문자열 번역 중")
        spinner.start()
        translations = self.translate_blocks(blocks)
        spinner.stop()
        print("[+] 번역 완료")

        # 패치 (크기 검증 없이, 16 슬롯 모두 채움)
        if self.patch_blocks(blocks, translations):
            print("[+] RT_STRING 블록 전체 패치 완료")
        else:
            print("[-] 일부 블록 패치 실패")

    def extract_blocks(self):
        pe = pefile.PE(self.exe_path)
        blocks = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if res_type.id != pefile.RESOURCE_TYPE['RT_STRING']:
                    continue
                for entry in res_type.directory.entries:
                    block_id   = entry.id
                    lang_entry = entry.directory.entries[0]
                    d          = lang_entry.data.struct
                    raw        = pe.get_data(d.OffsetToData, d.Size)
                    # 16개의 문자열 슬롯으로 분리
                    strs, p = [], 0
                    for _ in range(16):
                        if p+2 > len(raw): break
                        ln = struct.unpack_from('<H', raw, p)[0]; p += 2
                        if ln > 0:
                            txt = raw[p:p+ln*2].decode('utf-16le', errors='ignore')
                        else:
                            txt = ""
                        p += ln*2
                        strs.append(txt)
                    langid = (lang_entry.data.sublang << 10) | lang_entry.data.lang
                    blocks[block_id] = {'strings': strs, 'langid': langid}
        pe.close()
        return blocks

    def translate_blocks(self, blocks):
        trans = {}
        for block_id, info in blocks.items():
            for idx, src in enumerate(info['strings']):
                if not src:
                    continue
                for attempt in range(5):
                    try:
                        resp = openai.ChatCompletion.create(
                            model='gpt-3.5-turbo',
                            messages=[
                                {'role':'system','content':'Translate this UI string to concise Korean without quotes.'},
                                {'role':'user','content': src}
                            ],
                            temperature=0
                        )
                        tgt = resp.choices[0].message.content.strip()
                        trans.setdefault(block_id, {})[idx] = tgt
                        break
                    except ServiceUnavailableError:
                        time.sleep(2**attempt)
                    except RateLimitError:
                        print("❌ API 쿼타 소진 또는 속도 제한")
                        sys.exit(1)
                    except Exception as e:
                        print(f"❌ 번역 오류: {e}")
                        sys.exit(1)
        return trans

    def patch_blocks(self, blocks, translations):
        hUpd = kernel32.BeginUpdateResourceW(self.exe_path, False)
        if not hUpd:
            print("[-] BeginUpdateResource 실패 (관리자 권한 확인)")
            return False

        for block_id, info in blocks.items():
            # 16 슬롯 모두 채워서 재패킹
            data = b""
            for idx in range(16):
                txt = translations.get(block_id, {}).get(idx, info['strings'][idx])
                if txt:
                    data += struct.pack('<H', len(txt)) + txt.encode('utf-16le')
                else:
                    data += struct.pack('<H', 0)

            buf = create_string_buffer(data)
            ok = kernel32.UpdateResourceW(
                hUpd,
                MAKEINTRESOURCEW(win32con.RT_STRING),
                MAKEINTRESOURCEW(block_id),
                info['langid'],
                cast(buf, c_void_p),
                len(data)
            )
            if not ok:
                err = ctypes.get_last_error()
                print(f"[-] 블록 {block_id} 패치 실패: Win32Error {err}")

        if not kernel32.EndUpdateResourceW(hUpd, False):
            err = ctypes.get_last_error()
            print(f"[-] EndUpdateResource 실패: Win32Error {err}")
            return False

        return True

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python GPTAPIUI.py <target.exe> <YOUR_OPENAI_API_KEY>")
        sys.exit(1)
    ExeUIPatcher(sys.argv[1], sys.argv[2]).run()
