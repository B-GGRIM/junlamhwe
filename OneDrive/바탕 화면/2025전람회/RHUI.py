#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import re
import subprocess
import openai

from openai.error import ServiceUnavailableError, RateLimitError

# 기본 설정: 스크립트 폴더에 ResourceHacker.exe 있어야 합니다.
RH_NAME = 'ResourceHacker.exe'


def extract_rc(rh_path: str, exe_path: str, out_rc: str):
    subprocess.run([rh_path, '-open', exe_path, '-save', out_rc, '-action', 'extractall'], check=True)


def translate_rc(in_rc: str, out_rc: str, api_key: str):
    openai.api_key = api_key
    pattern = re.compile(r'"(.*?)"', re.DOTALL)

    def repl(m):
        txt = m.group(1)
        if not txt.strip():
            return '""'
        for i in range(5):
            try:
                resp = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role":"system","content":"Translate this UI text to concise Korean without quotes."},
                        {"role":"user","content":txt}
                    ],
                    temperature=0
                )
                return f'"{resp.choices[0].message.content.strip()}"'
            except ServiceUnavailableError:
                time.sleep(2**i)
            except RateLimitError:
                print("❌ API 쿼타 소진 또는 속도 제한")
                sys.exit(1)
        print("❌ 번역 실패")
        sys.exit(1)

    content = open(in_rc, 'r', encoding='utf-8', errors='ignore').read()
    translated = pattern.sub(repl, content)
    with open(out_rc, 'w', encoding='utf-8') as f:
        f.write(translated)


def rebuild_exe(rh_path: str, exe_path: str, rc_file: str, out_exe: str):
    subprocess.run([
        rh_path,
        '-open', exe_path,
        '-save', out_exe,
        '-action', 'addoverwrite',
        '-script', rc_file
    ], check=True)


def main():
    # 사용법: python RHUI.py <target.exe> <API_KEY>
    if len(sys.argv) != 3:
        print("Usage: python RHUI.py <target.exe> <OPENAI_API_KEY>")
        sys.exit(1)

    target_exe = os.path.abspath(sys.argv[1])
    api_key    = sys.argv[2].strip()

    # ResourceHacker 경로
    cwd      = os.path.dirname(os.path.abspath(__file__))
    rh_path  = os.path.join(cwd, RH_NAME)
    if not os.path.isfile(rh_path):
        print(f"Error: {RH_NAME} not found in script directory: {rh_path}")
        sys.exit(1)
    if not os.path.isfile(target_exe):
        print(f"Error: target exe not found: {target_exe}")
        sys.exit(1)

    base      = os.path.splitext(os.path.basename(target_exe))[0]
    rc1       = f"{base}.rc"
    rc2       = f"{base}_ko.rc"
    out_exe   = f"{base}_ko.exe"

    print(f"[*] Extracting RC -> {rc1}")
    extract_rc(rh_path, target_exe, rc1)

    print(f"[*] Translating RC -> {rc2}")
    translate_rc(rc1, rc2, api_key)

    print(f"[*] Rebuilding EXE -> {out_exe}")
    rebuild_exe(rh_path, target_exe, rc2, out_exe)

    print(f"✅ Completed: {out_exe}")


if __name__ == '__main__':
    main()
