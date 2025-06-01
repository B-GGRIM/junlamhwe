from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional, Any
import tkinter as tk
from tkinter import ttk

class TranslatorPlugin(ABC):
    """번역 플러그인 기본 인터페이스"""
    
    def __init__(self):
        self.name = "Unknown Plugin"
        self.version = "1.0"
        self.description = "No description"
        self.resource_type = "UNKNOWN"
        self.enabled = True
        self.priority = 100  # 실행 순서 (낮을수록 먼저 실행)
        
    @abstractmethod
    def get_info(self) -> Dict[str, str]:
        """플러그인 정보 반환"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "resource_type": self.resource_type,
            "author": "",
            "requirements": []
        }
    
    @abstractmethod
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """파일 분석 - 번역 가능한 리소스 찾기
        Returns: {
            "count": int,  # 찾은 리소스 수
            "items": List[Dict],  # 리소스 정보
            "summary": str  # 요약 정보
        }
        """
        pass
    
    @abstractmethod
    def translate(self, file_path: str, api_key: str, progress_callback=None) -> Dict[str, Any]:
        """자동 번역 수행
        Returns: {
            "success": bool,
            "translated": int,  # 번역된 항목 수
            "failed": int,  # 실패한 항목 수
            "message": str
        }
        """
        pass
    
    @abstractmethod
    def apply_translations(self, file_path: str, translations: Dict[str, str]) -> Dict[str, Any]:
        """번역 적용
        Returns: {
            "success": bool,
            "message": str,
            "details": Dict
        }
        """
        pass
    
    @abstractmethod
    def get_translations(self) -> Dict[str, str]:
        """현재 번역 데이터 반환"""
        pass
    
    @abstractmethod
    def set_translations(self, translations: Dict[str, str]):
        """번역 데이터 설정"""
        pass
    
    def create_ui_panel(self, parent: tk.Widget) -> Optional[tk.Widget]:
        """플러그인 전용 UI 패널 생성 (선택적)"""
        return None
    
    def validate_file(self, file_path: str) -> bool:
        """파일 유효성 검사"""
        return True
    
    def cleanup(self):
        """정리 작업"""
        pass