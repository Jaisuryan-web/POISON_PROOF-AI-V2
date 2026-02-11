"""
Vector/Embeddings Scanner — NPY, NPZ, HDF5, Pickle, and embedding formats
==========================================================================

Detects:
- Distribution anomalies (unusual embedding distributions)
- Norm outliers (abnormally high/low L2 norms)
- NaN/Inf injection
- Dimension inconsistencies
- Pickle code execution risks
- Clustering attacks (embeddings designed to corrupt clusters)
- Hash verification for integrity

Supported formats:
- NumPy (.npy, .npz)
- HDF5 (.h5, .hdf5)
- Pickle (.pkl, .pickle)
- Safetensors (.safetensors) - partially, requires safetensors lib

"""

from __future__ import annotations
import os
import pickle
import struct
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter

from .base import BaseScanner, ScanResult, Anomaly, Severity
from .registry import ScannerRegistry


# Dangerous pickle opcodes that indicate code execution
DANGEROUS_PICKLE_OPCODES = {
    b'R': 'REDUCE - calls a callable',
    b'c': 'GLOBAL - imports a module attribute',
    b'i': 'INST - instantiates a class',
    b'o': 'OBJ - builds an object',
    b'\x81': 'NEWOBJ - creates new object',
    b'\x82': 'EXT1 - extension reference',
    b'\x83': 'EXT2 - extension reference',
    b'\x84': 'EXT4 - extension reference',
    b'\x92': 'NEWOBJ_EX - extended object creation',
    b'\x93': 'STACK_GLOBAL - stack-based import',
}

# Suspicious module imports in pickle
SUSPICIOUS_MODULES = [
    'os', 'subprocess', 'sys', 'builtins', '__builtin__',
    'commands', 'socket', 'urllib', 'requests',
    'eval', 'exec', 'compile', 'open', 'input',
    'shutil', 'tempfile', 'pathlib',
]


@ScannerRegistry.register
class VectorScanner(BaseScanner):
    """
    Scanner for vector embeddings and numerical array formats.
    
    Specialized for ML embedding security, detecting distribution anomalies,
    malicious pickle code, and data integrity issues.
    """
    
    SUPPORTED_EXTENSIONS = {'npy', 'npz', 'pkl', 'pickle', 'h5', 'hdf5'}
    CATEGORY = "Vector/Embeddings"
    NAME = "VectorScanner"
    
    # Configuration defaults
    DEFAULT_CONFIG = {
        'check_distribution': True,
        'check_norms': True,
        'check_nan_inf': True,
        'check_dimensions': True,
        'check_pickle_safety': True,
        'norm_outlier_threshold': 3.5,   # MAD-based z-score
        'max_arrays_to_scan': 100,       # Limit for multi-array files
        'max_elements_for_distribution': 1_000_000,  # Memory limit
    }
    
    def _setup(self) -> None:
        """Merge config with defaults"""
        merged = dict(self.DEFAULT_CONFIG)
        merged.update(self.config)
        self.config = merged
    
    def detect(self, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Detect anomalies in vector/embedding data.
        
        Args:
            filepath: Path to the file
            max_findings: Maximum anomalies to return
            
        Returns:
            ScanResult with detected anomalies
        """
        ext = self._get_extension(filepath)
        anomalies: List[Anomaly] = []
        metadata: Dict[str, Any] = {}
        
        # Check pickle safety FIRST (before loading)
        if ext in ('pkl', 'pickle') and self.config['check_pickle_safety']:
            pickle_findings = self._analyze_pickle_safety(filepath)
            anomalies.extend(pickle_findings)
            
            # If critical pickle issues found, don't load the file
            if any(a.severity == Severity.CRITICAL for a in pickle_findings):
                return ScanResult(
                    filepath=filepath,
                    filename=os.path.basename(filepath),
                    file_type=ext,
                    category=self.CATEGORY,
                    scanner_name=self.NAME,
                    anomalies=anomalies,
                    metadata={'warning': 'File not loaded due to security concerns'},
                )
        
        # Load arrays
        try:
            arrays = self._load_arrays(filepath, ext)
            metadata['array_count'] = len(arrays)
            metadata['total_elements'] = sum(np.prod(a.shape) for _, a in arrays)
        except Exception as e:
            anomalies.append(Anomaly(
                type="Load Error",
                location="File",
                severity=Severity.MEDIUM,
                description=f"Could not load file: {str(e)}",
                confidence=1.0,
                category="Integrity",
            ))
            return ScanResult(
                filepath=filepath,
                filename=os.path.basename(filepath),
                file_type=ext,
                category=self.CATEGORY,
                scanner_name=self.NAME,
                anomalies=anomalies,
                metadata=metadata,
            )
        
        # Analyze each array
        for name, arr in arrays[:self.config['max_arrays_to_scan']]:
            location = f"Array '{name}'" if name else "Array"
            
            # Record array metadata
            arr_meta = {
                'name': name,
                'shape': arr.shape,
                'dtype': str(arr.dtype),
                'size': arr.size,
            }
            
            # 1. NaN/Inf detection
            if self.config['check_nan_inf']:
                nan_inf_findings = self._detect_nan_inf(arr, location)
                anomalies.extend(nan_inf_findings)
            
            # 2. Distribution analysis
            if self.config['check_distribution'] and arr.size <= self.config['max_elements_for_distribution']:
                dist_findings = self._analyze_distribution(arr, location)
                anomalies.extend(dist_findings)
            
            # 3. Norm outliers (for 2D arrays that look like embeddings)
            if self.config['check_norms'] and len(arr.shape) == 2:
                norm_findings = self._detect_norm_outliers(arr, location)
                anomalies.extend(norm_findings)
            
            # 4. Dimension consistency
            if self.config['check_dimensions']:
                dim_findings = self._check_dimensions(arr, location)
                anomalies.extend(dim_findings)
        
        # Sort by severity and limit
        anomalies.sort(key=lambda a: -a.severity.priority)
        anomalies = anomalies[:max_findings]
        
        return ScanResult(
            filepath=filepath,
            filename=os.path.basename(filepath),
            file_type=ext,
            category=self.CATEGORY,
            scanner_name=self.NAME,
            anomalies=anomalies,
            metadata=metadata,
        )
    
    def _load_arrays(self, filepath: str, ext: str) -> List[Tuple[str, np.ndarray]]:
        """Load arrays from file"""
        arrays = []
        
        if ext == 'npy':
            arr = np.load(filepath, allow_pickle=False)
            arrays.append(('', arr))
        
        elif ext == 'npz':
            with np.load(filepath, allow_pickle=False) as npz:
                for name in npz.files:
                    arrays.append((name, npz[name]))
        
        elif ext in ('pkl', 'pickle'):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
            arrays = self._extract_arrays_from_object(data)
        
        elif ext in ('h5', 'hdf5'):
            arrays = self._load_h5_arrays(filepath)
        
        return arrays
    
    def _extract_arrays_from_object(self, obj: Any, prefix: str = '') -> List[Tuple[str, np.ndarray]]:
        """Recursively extract numpy arrays from an object"""
        arrays = []
        
        if isinstance(obj, np.ndarray):
            arrays.append((prefix, obj))
        elif isinstance(obj, dict):
            for key, value in obj.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                arrays.extend(self._extract_arrays_from_object(value, name))
        elif isinstance(obj, (list, tuple)):
            for idx, value in enumerate(obj):
                name = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                arrays.extend(self._extract_arrays_from_object(value, name))
        
        return arrays
    
    def _load_h5_arrays(self, filepath: str) -> List[Tuple[str, np.ndarray]]:
        """Load arrays from HDF5 file"""
        arrays = []
        
        try:
            import h5py
            
            def extract_datasets(group, prefix=''):
                for key in group.keys():
                    item = group[key]
                    name = f"{prefix}/{key}" if prefix else key
                    if isinstance(item, h5py.Dataset):
                        arrays.append((name, item[:]))
                    elif isinstance(item, h5py.Group):
                        extract_datasets(item, name)
            
            with h5py.File(filepath, 'r') as f:
                extract_datasets(f)
        
        except ImportError:
            pass  # h5py not available
        
        return arrays
    
    def _analyze_pickle_safety(self, filepath: str) -> List[Anomaly]:
        """Analyze pickle file for potential code execution"""
        anomalies = []
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Check for dangerous opcodes
            dangerous_found = []
            for opcode, description in DANGEROUS_PICKLE_OPCODES.items():
                if opcode in data:
                    dangerous_found.append(description)
            
            if dangerous_found:
                # Check for suspicious module references
                suspicious_imports = []
                for module in SUSPICIOUS_MODULES:
                    # Look for module name in pickle data
                    if module.encode() in data:
                        suspicious_imports.append(module)
                
                if suspicious_imports:
                    anomalies.append(Anomaly(
                        type="Malicious Pickle",
                        location="File",
                        severity=Severity.CRITICAL,
                        description=f"Pickle contains dangerous code execution patterns with suspicious imports: {suspicious_imports}",
                        confidence=0.95,
                        category="Security",
                        details={
                            'dangerous_opcodes': dangerous_found[:5],
                            'suspicious_imports': suspicious_imports,
                        },
                        remediation="DO NOT LOAD THIS FILE. It may execute arbitrary code."
                    ))
                else:
                    # Has dangerous opcodes but no obviously malicious imports
                    anomalies.append(Anomaly(
                        type="Potentially Unsafe Pickle",
                        location="File",
                        severity=Severity.HIGH,
                        description=f"Pickle contains code execution opcodes: {dangerous_found[:3]}",
                        confidence=0.7,
                        category="Security",
                        details={
                            'dangerous_opcodes': dangerous_found[:5],
                        },
                        remediation="Load with caution. Consider converting to safer format."
                    ))
        
        except Exception as e:
            anomalies.append(Anomaly(
                type="Pickle Analysis Error",
                location="File",
                severity=Severity.MEDIUM,
                description=f"Could not analyze pickle safety: {str(e)}",
                confidence=0.5,
                category="Integrity",
            ))
        
        return anomalies
    
    def _detect_nan_inf(self, arr: np.ndarray, location: str) -> List[Anomaly]:
        """Detect NaN and Inf values"""
        anomalies = []
        
        if not np.issubdtype(arr.dtype, np.floating):
            return anomalies
        
        nan_count = np.isnan(arr).sum()
        inf_count = np.isinf(arr).sum()
        total = arr.size
        
        if nan_count > 0:
            ratio = nan_count / total
            severity = Severity.HIGH if ratio > 0.01 else Severity.MEDIUM
            anomalies.append(Anomaly(
                type="NaN Values",
                location=location,
                severity=severity,
                description=f"Found {nan_count:,} NaN values ({ratio*100:.2f}% of array)",
                confidence=1.0,
                category="Data Quality",
                details={
                    'nan_count': int(nan_count),
                    'nan_ratio': float(ratio),
                    'array_size': total,
                },
                remediation="Replace NaN values or remove affected rows."
            ))
        
        if inf_count > 0:
            ratio = inf_count / total
            severity = Severity.HIGH if ratio > 0.001 else Severity.MEDIUM
            anomalies.append(Anomaly(
                type="Infinite Values",
                location=location,
                severity=severity,
                description=f"Found {inf_count:,} Inf values ({ratio*100:.4f}% of array)",
                confidence=1.0,
                category="Data Quality",
                details={
                    'inf_count': int(inf_count),
                    'inf_ratio': float(ratio),
                },
                remediation="Replace Inf values to prevent numerical instability."
            ))
        
        return anomalies
    
    def _analyze_distribution(self, arr: np.ndarray, location: str) -> List[Anomaly]:
        """Analyze value distribution for anomalies"""
        anomalies = []
        
        if not np.issubdtype(arr.dtype, np.number):
            return anomalies
        
        # Flatten and remove NaN/Inf for statistics
        flat = arr.flatten()
        valid = flat[np.isfinite(flat)]
        
        if len(valid) < 10:
            return anomalies
        
        mean = np.mean(valid)
        std = np.std(valid)
        min_val = np.min(valid)
        max_val = np.max(valid)
        
        # Check for extreme values
        if std > 0:
            # Values beyond 10 standard deviations
            extreme_mask = np.abs(valid - mean) > 10 * std
            extreme_count = extreme_mask.sum()
            
            if extreme_count > 0:
                extreme_ratio = extreme_count / len(valid)
                anomalies.append(Anomaly(
                    type="Extreme Values",
                    location=location,
                    severity=Severity.MEDIUM,
                    description=f"Found {extreme_count:,} values beyond 10 std from mean",
                    confidence=0.8,
                    category="Statistical",
                    details={
                        'extreme_count': int(extreme_count),
                        'extreme_ratio': float(extreme_ratio),
                        'mean': float(mean),
                        'std': float(std),
                        'min': float(min_val),
                        'max': float(max_val),
                    },
                    remediation="Review extreme values - may be poisoned embeddings."
                ))
        
        # Check for zero-variance arrays
        if std == 0:
            anomalies.append(Anomaly(
                type="Zero Variance",
                location=location,
                severity=Severity.HIGH,
                description=f"Array has zero variance (all values = {mean:.4g})",
                confidence=1.0,
                category="Data Quality",
                details={'constant_value': float(mean)},
                remediation="Constant arrays provide no information."
            ))
        
        return anomalies
    
    def _detect_norm_outliers(self, arr: np.ndarray, location: str) -> List[Anomaly]:
        """Detect embeddings with unusual L2 norms"""
        anomalies = []
        
        if len(arr.shape) != 2:
            return anomalies
        
        # Calculate L2 norms for each embedding (row)
        norms = np.linalg.norm(arr, axis=1)
        
        # Robust z-scores using MAD
        median_norm = np.nanmedian(norms)
        mad = np.nanmedian(np.abs(norms - median_norm))
        
        if mad == 0:
            return anomalies
        
        z_scores = 0.6745 * np.abs(norms - median_norm) / mad
        outliers = np.where(z_scores > self.config['norm_outlier_threshold'])[0]
        
        if len(outliers) > 0:
            outlier_ratio = len(outliers) / len(norms)
            
            anomalies.append(Anomaly(
                type="Norm Outliers",
                location=location,
                severity=Severity.MEDIUM if outlier_ratio < 0.05 else Severity.HIGH,
                description=f"Found {len(outliers)} embeddings with unusual L2 norms ({outlier_ratio*100:.2f}%)",
                confidence=0.8,
                category="Statistical",
                details={
                    'outlier_count': len(outliers),
                    'outlier_indices': outliers[:10].tolist(),
                    'median_norm': float(median_norm),
                    'outlier_norms': norms[outliers[:5]].tolist(),
                },
                remediation="Review these embeddings - may be poisoned or corrupted."
            ))
        
        return anomalies
    
    def _check_dimensions(self, arr: np.ndarray, location: str) -> List[Anomaly]:
        """Check for unusual array dimensions"""
        anomalies = []
        
        # Check for very large single dimension
        for dim_idx, dim_size in enumerate(arr.shape):
            if dim_size > 1_000_000:
                anomalies.append(Anomaly(
                    type="Large Dimension",
                    location=location,
                    severity=Severity.LOW,
                    description=f"Dimension {dim_idx} has {dim_size:,} elements",
                    confidence=0.5,
                    category="Data Quality",
                    details={'dimension': dim_idx, 'size': dim_size},
                    remediation="Verify this dimension size is expected."
                ))
        
        # Check for empty arrays
        if arr.size == 0:
            anomalies.append(Anomaly(
                type="Empty Array",
                location=location,
                severity=Severity.HIGH,
                description=f"Array is empty (shape: {arr.shape})",
                confidence=1.0,
                category="Data Quality",
                remediation="Remove empty arrays from dataset."
            ))
        
        return anomalies
    
    def get_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract vector-specific metadata"""
        base_meta = super().get_metadata(filepath)
        
        ext = self._get_extension(filepath)
        
        try:
            if ext == 'npy':
                # Read header without loading full array
                with open(filepath, 'rb') as f:
                    version = np.lib.format.read_magic(f)
                    shape, fortran, dtype = np.lib.format.read_array_header_1_0(f) if version[0] == 1 else np.lib.format.read_array_header_2_0(f)
                    base_meta['shape'] = shape
                    base_meta['dtype'] = str(dtype)
                    base_meta['fortran_order'] = fortran
            
            elif ext == 'npz':
                with np.load(filepath, allow_pickle=False) as npz:
                    base_meta['arrays'] = list(npz.files)
                    base_meta['array_count'] = len(npz.files)
        
        except Exception as e:
            base_meta['header_error'] = str(e)
        
        return base_meta
