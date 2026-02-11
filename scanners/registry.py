"""
Scanner Registry — Central registry for all dataset scanners
=============================================================

The registry automatically detects file types and routes them to
the appropriate scanner. Scanners register themselves on import.

Usage:
    from scanners import scan_file, get_scanner
    
    # Auto-detect and scan
    result = scan_file("data.csv")
    
    # Get specific scanner
    scanner = get_scanner("csv")
    result = scanner.scan("data.csv")
"""

from __future__ import annotations
from typing import Dict, Type, Optional, List, Set
import os
import mimetypes

from .base import BaseScanner, ScanResult


class ScannerRegistry:
    """
    Central registry for all dataset scanners.
    
    Provides automatic format detection and scanner routing.
    """
    
    _instance: Optional['ScannerRegistry'] = None
    _scanners: Dict[str, Type[BaseScanner]] = {}
    _categories: Dict[str, List[str]] = {}  # category -> list of extensions
    
    def __new__(cls) -> 'ScannerRegistry':
        """Singleton pattern"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._scanners = {}
            cls._instance._categories = {}
        return cls._instance
    
    @classmethod
    def register(cls, scanner_class: Type[BaseScanner]) -> Type[BaseScanner]:
        """
        Register a scanner class for its supported extensions.
        
        Can be used as a decorator:
            @ScannerRegistry.register
            class MyScanner(BaseScanner):
                SUPPORTED_EXTENSIONS = {'xyz'}
                ...
        
        Args:
            scanner_class: Scanner class to register
            
        Returns:
            The scanner class (for decorator use)
        """
        registry = cls()
        
        for ext in scanner_class.SUPPORTED_EXTENSIONS:
            ext = ext.lower().lstrip('.')
            registry._scanners[ext] = scanner_class
            
            # Track by category
            category = scanner_class.CATEGORY
            if category not in registry._categories:
                registry._categories[category] = []
            if ext not in registry._categories[category]:
                registry._categories[category].append(ext)
        
        return scanner_class
    
    @classmethod
    def get_scanner(cls, extension: str) -> Optional[BaseScanner]:
        """
        Get a scanner instance for the given file extension.
        
        Args:
            extension: File extension (with or without dot)
            
        Returns:
            Scanner instance or None if not supported
        """
        registry = cls()
        ext = extension.lower().lstrip('.')
        
        scanner_class = registry._scanners.get(ext)
        if scanner_class:
            return scanner_class()
        return None
    
    @classmethod
    def get_scanner_for_file(cls, filepath: str) -> Optional[BaseScanner]:
        """
        Get a scanner instance for the given file path.
        Uses extension-based detection with MIME type fallback.
        
        Args:
            filepath: Path to the file
            
        Returns:
            Scanner instance or None if not supported
        """
        # Try extension first
        ext = cls._get_extension(filepath)
        scanner = cls.get_scanner(ext)
        if scanner:
            return scanner
        
        # Fallback to MIME type detection
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type:
            ext_from_mime = cls._mime_to_extension(mime_type)
            if ext_from_mime:
                return cls.get_scanner(ext_from_mime)
        
        return None
    
    @classmethod
    def _get_extension(cls, filepath: str) -> str:
        """Extract lowercase extension without dot"""
        _, ext = os.path.splitext(filepath)
        return ext.lower().lstrip('.')
    
    @classmethod
    def _mime_to_extension(cls, mime_type: str) -> Optional[str]:
        """Convert MIME type to file extension"""
        mime_map = {
            'text/csv': 'csv',
            'application/json': 'json',
            'image/png': 'png',
            'image/jpeg': 'jpg',
            'image/gif': 'gif',
            'image/bmp': 'bmp',
            'image/webp': 'webp',
            'image/tiff': 'tiff',
            'audio/wav': 'wav',
            'audio/mpeg': 'mp3',
            'audio/flac': 'flac',
            'audio/ogg': 'ogg',
            'video/mp4': 'mp4',
            'video/webm': 'webm',
            'video/x-msvideo': 'avi',
            'application/x-hdf5': 'hdf5',
            'application/x-parquet': 'parquet',
        }
        return mime_map.get(mime_type)
    
    @classmethod
    def scan_file(cls, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Scan a file using the appropriate scanner.
        
        Args:
            filepath: Path to the file to scan
            max_findings: Maximum number of anomalies to return
            
        Returns:
            ScanResult containing detected anomalies
            
        Raises:
            ValueError: If file format is not supported
            FileNotFoundError: If file doesn't exist
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        scanner = cls.get_scanner_for_file(filepath)
        if scanner is None:
            ext = cls._get_extension(filepath)
            supported = cls.get_supported_extensions()
            raise ValueError(
                f"Unsupported file format: .{ext}\n"
                f"Supported formats: {', '.join(sorted(supported))}"
            )
        
        return scanner.scan(filepath, max_findings)
    
    @classmethod
    def get_supported_extensions(cls) -> Set[str]:
        """Get all supported file extensions"""
        registry = cls()
        return set(registry._scanners.keys())
    
    @classmethod
    def get_categories(cls) -> Dict[str, List[str]]:
        """Get all categories and their supported extensions"""
        registry = cls()
        return dict(registry._categories)
    
    @classmethod
    def get_scanners_info(cls) -> List[Dict]:
        """Get information about all registered scanners"""
        registry = cls()
        seen = set()
        info = []
        
        for ext, scanner_class in registry._scanners.items():
            name = scanner_class.NAME
            if name not in seen:
                seen.add(name)
                info.append({
                    'name': name,
                    'category': scanner_class.CATEGORY,
                    'extensions': list(scanner_class.SUPPORTED_EXTENSIONS),
                })
        
        return sorted(info, key=lambda x: x['category'])
    
    @classmethod
    def is_supported(cls, filepath: str) -> bool:
        """Check if a file format is supported"""
        return cls.get_scanner_for_file(filepath) is not None


# Convenience functions
def get_scanner(extension: str) -> Optional[BaseScanner]:
    """Get a scanner instance for the given file extension"""
    return ScannerRegistry.get_scanner(extension)


def scan_file(filepath: str, max_findings: int = 100) -> ScanResult:
    """Scan a file using the appropriate scanner"""
    return ScannerRegistry.scan_file(filepath, max_findings)


def get_supported_extensions() -> Set[str]:
    """Get all supported file extensions"""
    return ScannerRegistry.get_supported_extensions()


def is_supported(filepath: str) -> bool:
    """Check if a file format is supported"""
    return ScannerRegistry.is_supported(filepath)
