#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
번역 캐시 시스템
이전에 번역한 내용을 저장하여 재사용
"""

import json
import os
import hashlib
from typing import Dict, Optional

class TranslationCache:
    """번역 캐시 관리"""
    
    def __init__(self, cache_file: str = "translation_cache.json"):
        self.cache_file = cache_file
        self.cache: Dict[str, str] = {}
        self.load_cache()
    
    def load_cache(self):
        """캐시 파일 로드"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
            except:
                self.cache = {}
    
    def save_cache(self):
        """캐시 파일 저장"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except:
            pass
    
    def get(self, text: str) -> Optional[str]:
        """캐시에서 번역 가져오기"""
        # 텍스트 정규화
        normalized = text.strip()
        return self.cache.get(normalized)
    
    def put(self, text: str, translation: str):
        """캐시에 번역 저장"""
        normalized = text.strip()
        if normalized and translation:
            self.cache[normalized] = translation
    
    def get_batch(self, texts: list) -> Dict[str, str]:
        """여러 텍스트의 캐시된 번역 가져오기"""
        cached = {}
        for text in texts:
            translation = self.get(text)
            if translation:
                cached[text] = translation
        return cached
    
    def put_batch(self, translations: Dict[str, str]):
        """여러 번역을 캐시에 저장"""
        for text, translation in translations.items():
            self.put(text, translation)
        self.save_cache()
    
    def get_stats(self) -> Dict[str, int]:
        """캐시 통계"""
        return {
            "total_entries": len(self.cache),
            "cache_size_kb": len(json.dumps(self.cache).encode('utf-8')) / 1024
        }
    
    def clear(self):
        """캐시 초기화"""
        self.cache.clear()
        self.save_cache()


# 전역 캐시 인스턴스
_global_cache = None

def get_translation_cache() -> TranslationCache:
    """전역 캐시 인스턴스 가져오기"""
    global _global_cache
    if _global_cache is None:
        _global_cache = TranslationCache()
    return _global_cache


def cached_translate(texts: list, translate_func, *args, **kwargs) -> Dict[str, str]:
    """캐시를 사용한 번역
    
    Args:
        texts: 번역할 텍스트 리스트
        translate_func: 실제 번역 함수
        *args, **kwargs: 번역 함수에 전달할 인자
    
    Returns:
        번역 결과 딕셔너리
    """
    cache = get_translation_cache()
    
    # 캐시에서 찾기
    cached_translations = cache.get_batch(texts)
    
    # 캐시에 없는 텍스트만 번역
    texts_to_translate = [t for t in texts if t not in cached_translations]
    
    if texts_to_translate:
        # 실제 번역 수행
        new_translations = translate_func(texts_to_translate, *args, **kwargs)
        
        # 캐시에 저장
        cache.put_batch(new_translations)
        
        # 결과 병합
        cached_translations.update(new_translations)
    
    return cached_translations