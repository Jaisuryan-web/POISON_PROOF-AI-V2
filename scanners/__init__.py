"""
PoisonProof AI — Universal Dataset Scanners
============================================

This module contains specialized scanners for different dataset types:
- Tabular data (CSV, Excel, Parquet, JSON)
- Image data (PNG, JPG, TIFF, WebP, etc.)
- Text/NLP data (TXT, JSONL, etc.)
- Vector/Embeddings (NPY, HDF5, FAISS, etc.)
- Audio data (WAV, MP3, FLAC, etc.)
- Video data (MP4, AVI, WebM, etc.)
- And more...

Each scanner inherits from BaseScanner and implements the detect() method.
"""

from .base import BaseScanner, ScanResult, Anomaly, Severity
from .registry import ScannerRegistry, get_scanner, scan_file, get_supported_extensions, is_supported

# Import scanners to register them with the registry
from .tabular_scanner import TabularScanner
from .image_scanner import ImageScanner
from .text_scanner import TextNLPScanner
from .vector_scanner import VectorScanner
from .audio_scanner import AudioScanner

__all__ = [
    # Base classes
    'BaseScanner',
    'ScanResult', 
    'Anomaly',
    'Severity',
    # Registry
    'ScannerRegistry',
    'get_scanner',
    'scan_file',
    'get_supported_extensions',
    'is_supported',
    # Scanners
    'TabularScanner',
    'ImageScanner',
    'TextNLPScanner',
    'VectorScanner',
    'AudioScanner',
]
