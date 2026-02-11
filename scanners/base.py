"""
Base Scanner — Abstract base class for all dataset scanners
============================================================

All scanners inherit from BaseScanner and implement:
- SUPPORTED_EXTENSIONS: list of file extensions this scanner handles
- CATEGORY: human-readable category name
- detect(filepath) -> ScanResult: main detection method
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
import os


class Severity(Enum):
    """Severity levels for detected anomalies"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    
    def __str__(self):
        return self.value
    
    @property
    def priority(self) -> int:
        """Return numeric priority for sorting (higher = more severe)"""
        return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[self.value]


@dataclass
class Anomaly:
    """Represents a single detected anomaly"""
    type: str                          # e.g., "SQL Injection", "Statistical Outlier"
    location: str                      # e.g., "Row 15, Column 'name'"
    severity: Severity                 # LOW, MEDIUM, HIGH, CRITICAL
    description: str                   # Human-readable description
    confidence: float                  # 0.0 to 1.0
    category: str = ""                 # e.g., "Injection", "Statistical", "Integrity"
    details: Dict[str, Any] = field(default_factory=dict)  # Additional metadata
    remediation: str = ""              # Suggested fix
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'type': self.type,
            'location': self.location,
            'severity': str(self.severity),
            'description': self.description,
            'confidence': round(self.confidence * 100, 1),  # As percentage
            'category': self.category,
            'details': self.details,
            'remediation': self.remediation,
        }


@dataclass
class ScanResult:
    """Result of scanning a file"""
    filepath: str
    filename: str
    file_type: str                     # e.g., "csv", "png", "npy"
    category: str                      # e.g., "Tabular", "Image", "Vector"
    scanner_name: str                  # e.g., "TabularScanner"
    anomalies: List[Anomaly] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)  # File metadata
    scan_duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    @property
    def total_anomalies(self) -> int:
        return len(self.anomalies)
    
    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count anomalies by severity"""
        counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for a in self.anomalies:
            counts[str(a.severity)] += 1
        return counts
    
    @property
    def has_critical(self) -> bool:
        return any(a.severity == Severity.CRITICAL for a in self.anomalies)
    
    @property
    def has_high_or_critical(self) -> bool:
        return any(a.severity in (Severity.HIGH, Severity.CRITICAL) for a in self.anomalies)
    
    @property
    def max_severity(self) -> Optional[Severity]:
        """Return the highest severity level found"""
        if not self.anomalies:
            return None
        return max(self.anomalies, key=lambda a: a.severity.priority).severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'filepath': self.filepath,
            'filename': self.filename,
            'file_type': self.file_type,
            'category': self.category,
            'scanner_name': self.scanner_name,
            'total_anomalies': self.total_anomalies,
            'severity_counts': self.severity_counts,
            'max_severity': str(self.max_severity) if self.max_severity else None,
            'anomalies': [a.to_dict() for a in self.anomalies],
            'metadata': self.metadata,
            'scan_duration_ms': round(self.scan_duration_ms, 2),
            'timestamp': self.timestamp,
        }
    
    def get_anomalies_by_severity(self, severity: Severity) -> List[Anomaly]:
        """Filter anomalies by severity level"""
        return [a for a in self.anomalies if a.severity == severity]
    
    def get_high_severity_rows(self) -> Set[int]:
        """Extract row indices from High/Critical anomalies (for tabular data)"""
        rows = set()
        for a in self.anomalies:
            if a.severity in (Severity.HIGH, Severity.CRITICAL):
                # Parse row from location like "Row 15, Column 'name'"
                loc = a.location
                if 'Row' in loc:
                    try:
                        row_part = loc.split(',')[0].replace('Row', '').strip()
                        rows.add(int(row_part) - 1)  # Convert to 0-indexed
                    except (ValueError, IndexError):
                        pass
        return rows


class BaseScanner(ABC):
    """
    Abstract base class for all dataset scanners.
    
    Subclasses must implement:
    - SUPPORTED_EXTENSIONS: Set of file extensions (lowercase, without dot)
    - CATEGORY: Human-readable category name
    - detect(filepath) -> ScanResult: Main detection logic
    
    Optional overrides:
    - validate(filepath) -> bool: Pre-scan validation
    - get_metadata(filepath) -> Dict: Extract file metadata
    """
    
    # Subclasses must define these
    SUPPORTED_EXTENSIONS: Set[str] = set()
    CATEGORY: str = "Unknown"
    NAME: str = "BaseScanner"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize scanner with optional configuration.
        
        Args:
            config: Optional dictionary with scanner-specific settings
        """
        self.config = config or {}
        self._setup()
    
    def _setup(self) -> None:
        """
        Optional setup hook called after __init__.
        Override this to initialize resources, compile patterns, etc.
        """
        pass
    
    def can_handle(self, filepath: str) -> bool:
        """
        Check if this scanner can handle the given file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            True if this scanner supports the file format
        """
        ext = self._get_extension(filepath)
        return ext in self.SUPPORTED_EXTENSIONS
    
    def _get_extension(self, filepath: str) -> str:
        """Extract lowercase extension without dot"""
        _, ext = os.path.splitext(filepath)
        return ext.lower().lstrip('.')
    
    def validate(self, filepath: str) -> bool:
        """
        Validate that the file exists and is readable.
        Override for format-specific validation.
        
        Args:
            filepath: Path to the file
            
        Returns:
            True if file is valid and can be scanned
        """
        if not os.path.exists(filepath):
            return False
        if not os.path.isfile(filepath):
            return False
        if os.path.getsize(filepath) == 0:
            return False
        return True
    
    def get_metadata(self, filepath: str) -> Dict[str, Any]:
        """
        Extract file metadata.
        Override for format-specific metadata extraction.
        
        Args:
            filepath: Path to the file
            
        Returns:
            Dictionary of metadata
        """
        stat = os.stat(filepath)
        return {
            'filename': os.path.basename(filepath),
            'size_bytes': stat.st_size,
            'size_human': self._format_size(stat.st_size),
            'modified': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            'extension': self._get_extension(filepath),
        }
    
    def _format_size(self, size_bytes: int) -> str:
        """Format byte size to human-readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
    
    @abstractmethod
    def detect(self, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Perform anomaly detection on the file.
        
        Args:
            filepath: Path to the file to scan
            max_findings: Maximum number of anomalies to return
            
        Returns:
            ScanResult containing all detected anomalies
        """
        pass
    
    def scan(self, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Full scan pipeline: validate → get metadata → detect.
        
        Args:
            filepath: Path to the file to scan
            max_findings: Maximum number of anomalies to return
            
        Returns:
            ScanResult containing all detected anomalies
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is not supported
        """
        import time
        
        if not self.validate(filepath):
            raise FileNotFoundError(f"File not found or invalid: {filepath}")
        
        if not self.can_handle(filepath):
            raise ValueError(f"Unsupported file format for {self.NAME}: {filepath}")
        
        start_time = time.perf_counter()
        
        # Get metadata first
        metadata = self.get_metadata(filepath)
        
        # Run detection
        result = self.detect(filepath, max_findings)
        
        # Update result with metadata and timing
        result.metadata.update(metadata)
        result.scan_duration_ms = (time.perf_counter() - start_time) * 1000
        
        return result
    
    def __repr__(self) -> str:
        return f"{self.NAME}(extensions={self.SUPPORTED_EXTENSIONS})"
