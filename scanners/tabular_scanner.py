"""
Tabular Scanner — CSV, Excel, Parquet, JSON, and other tabular formats
=======================================================================

Detects:
- Injection patterns (SQL, XSS, Command, Path Traversal, LDAP, NoSQL)
- Statistical outliers (MAD, IQR methods)
- Label anomalies and inconsistencies
- Schema violations and type attacks
- Duplicate poisoning
- Null injection patterns
- Cardinality attacks

Supported formats:
- CSV (.csv)
- Excel (.xlsx, .xls)
- Parquet (.parquet)
- JSON (.json)
- Feather (.feather)

"""

from __future__ import annotations
import re
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import Counter

from .base import BaseScanner, ScanResult, Anomaly, Severity
from .registry import ScannerRegistry


# Detection patterns (expanded from original 40+ patterns)
INJECTION_PATTERNS = {
    'XSS': [
        (r"<script[\s>]", "Script tag injection"),
        (r"onerror\s*=", "Event handler injection (onerror)"),
        (r"onload\s*=", "Event handler injection (onload)"),
        (r"onclick\s*=", "Event handler injection (onclick)"),
        (r"onmouseover\s*=", "Event handler injection (onmouseover)"),
        (r"alert\s*\(", "Alert function call"),
        (r"document\.cookie", "Cookie access attempt"),
        (r"javascript:", "JavaScript protocol"),
        (r"<iframe", "Iframe injection"),
        (r"<img[^>]+onerror", "Image error handler"),
        (r"eval\s*\(", "Eval function call"),
        (r"<svg[^>]*onload", "SVG onload handler"),
        (r"expression\s*\(", "CSS expression"),
        (r"vbscript:", "VBScript protocol"),
        (r"data:text/html", "Data URI injection"),
    ],
    'SQL': [
        (r"drop\s+table", "DROP TABLE statement"),
        (r"drop\s+database", "DROP DATABASE statement"),
        (r"union\s+select", "UNION SELECT injection"),
        (r"union\s+all\s+select", "UNION ALL SELECT injection"),
        (r"insert\s+into", "INSERT INTO statement"),
        (r"delete\s+from", "DELETE FROM statement"),
        (r"update\s+.+set", "UPDATE SET statement"),
        (r"exec\s*\(", "EXEC function call"),
        (r"execute\s+immediate", "EXECUTE IMMEDIATE"),
        (r"'\s*or\s*'1'\s*=\s*'1", "OR '1'='1' injection"),
        (r"'\s*or\s*1\s*=\s*1", "OR 1=1 injection"),
        (r"--\s*$", "SQL comment injection"),
        (r";--", "Statement terminator with comment"),
        (r"'\s*;\s*--", "Quote-semicolon-comment pattern"),
        (r"waitfor\s+delay", "WAITFOR DELAY (timing attack)"),
        (r"benchmark\s*\(", "BENCHMARK function (timing)"),
        (r"sleep\s*\(", "SLEEP function (timing)"),
        (r"information_schema", "Schema enumeration"),
        (r"sys\.tables", "System table access"),
        (r"@@version", "Version disclosure"),
    ],
    'Command': [
        (r";\s*rm\s+-rf", "rm -rf command"),
        (r";\s*cat\s+", "cat command"),
        (r"\|\s*nc\s+", "Netcat pipe"),
        (r"&\s*whoami", "whoami command"),
        (r">\s*/dev/null", "Output redirection"),
        (r"\$\(.*\)", "Command substitution"),
        (r"`.*`", "Backtick execution"),
        (r";\s*wget\s+", "wget command"),
        (r";\s*curl\s+", "curl command"),
        (r";\s*chmod\s+", "chmod command"),
        (r";\s*chown\s+", "chown command"),
        (r"\|\s*bash", "Bash pipe"),
        (r"\|\s*sh\s", "Shell pipe"),
        (r"powershell", "PowerShell execution"),
        (r"cmd\.exe", "Windows cmd execution"),
        (r"\/bin\/sh", "/bin/sh execution"),
        (r"\/bin\/bash", "/bin/bash execution"),
    ],
    'PathTraversal': [
        (r"\.\./", "Path traversal (../)"),
        (r"\.\.\\", "Path traversal (..\\)"),
        (r"\.\.%2f", "URL-encoded traversal"),
        (r"\.\.%5c", "URL-encoded backslash traversal"),
        (r"/etc/passwd", "/etc/passwd access"),
        (r"/etc/shadow", "/etc/shadow access"),
        (r"c:\\windows", "Windows directory access"),
        (r"c:/windows", "Windows directory access (forward slash)"),
        (r"/proc/self", "Proc filesystem access"),
        (r"boot\.ini", "boot.ini access"),
        (r"win\.ini", "win.ini access"),
    ],
    'LDAP': [
        (r"\*\)\s*\(", "LDAP wildcard injection"),
        (r"\(\|", "LDAP OR injection"),
        (r"\)\(.*\)=\*", "LDAP pattern injection"),
        (r"\(\&", "LDAP AND injection"),
        (r"\x00", "Null byte injection"),
    ],
    'NoSQL': [
        (r"\$ne\s*:", "MongoDB $ne operator"),
        (r"\$gt\s*:", "MongoDB $gt operator"),
        (r"\$lt\s*:", "MongoDB $lt operator"),
        (r"\$where\s*:", "MongoDB $where operator"),
        (r"\$regex\s*:", "MongoDB $regex operator"),
        (r"\$nin\s*:", "MongoDB $nin operator"),
        (r"{\s*['\"]?\$", "MongoDB operator injection"),
    ],
    'Template': [
        (r"\{\{.*\}\}", "Template injection (Jinja/Handlebars)"),
        (r"\${.*}", "Template injection (expression)"),
        (r"<%.*%>", "Template injection (EJS/ERB)"),
        (r"#\{.*\}", "Template injection (Ruby)"),
    ],
}

# Compile patterns for performance
COMPILED_PATTERNS: List[Tuple[re.Pattern, str, str]] = []
for category, patterns in INJECTION_PATTERNS.items():
    for pattern, description in patterns:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            COMPILED_PATTERNS.append((compiled, category, description))
        except re.error:
            pass  # Skip invalid patterns


@ScannerRegistry.register
class TabularScanner(BaseScanner):
    """
    Scanner for tabular data formats (CSV, Excel, Parquet, JSON).
    
    Detects injection patterns, statistical outliers, and data quality issues.
    """
    
    SUPPORTED_EXTENSIONS = {'csv', 'xlsx', 'xls', 'parquet', 'json', 'feather'}
    CATEGORY = "Tabular"
    NAME = "TabularScanner"
    
    # Configuration defaults
    DEFAULT_CONFIG = {
        'mad_threshold': 3.5,      # Robust z-score threshold
        'iqr_factor': 1.5,         # IQR fence multiplier
        'high_severity_zscore': 5.0,  # Z-score for High severity
        'check_injections': True,
        'check_statistical': True,
        'check_duplicates': True,
        'check_nulls': True,
        'check_cardinality': True,
        'max_cardinality_ratio': 0.9,  # Flag if unique/total > 0.9 for categoricals
    }
    
    def _setup(self) -> None:
        """Merge config with defaults"""
        merged = dict(self.DEFAULT_CONFIG)
        merged.update(self.config)
        self.config = merged
    
    def detect(self, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Detect anomalies in tabular data.
        
        Args:
            filepath: Path to the file
            max_findings: Maximum anomalies to return
            
        Returns:
            ScanResult with detected anomalies
        """
        # Load data
        df = self._load_dataframe(filepath)
        ext = self._get_extension(filepath)
        
        anomalies: List[Anomaly] = []
        
        # 1. Injection pattern detection
        if self.config['check_injections']:
            injection_findings = self._detect_injections(df)
            anomalies.extend(injection_findings)
        
        # 2. Statistical outlier detection
        if self.config['check_statistical']:
            statistical_findings = self._detect_statistical_outliers(df)
            anomalies.extend(statistical_findings)
        
        # 3. Duplicate detection
        if self.config['check_duplicates']:
            duplicate_findings = self._detect_duplicates(df)
            anomalies.extend(duplicate_findings)
        
        # 4. Null pattern detection
        if self.config['check_nulls']:
            null_findings = self._detect_null_patterns(df)
            anomalies.extend(null_findings)
        
        # 5. Cardinality analysis
        if self.config['check_cardinality']:
            cardinality_findings = self._detect_cardinality_issues(df)
            anomalies.extend(cardinality_findings)
        
        # Sort by severity (highest first) and limit findings
        anomalies.sort(key=lambda a: -a.severity.priority)
        anomalies = anomalies[:max_findings]
        
        # Build result
        return ScanResult(
            filepath=filepath,
            filename=self._get_filename(filepath),
            file_type=ext,
            category=self.CATEGORY,
            scanner_name=self.NAME,
            anomalies=anomalies,
            metadata={
                'rows': len(df),
                'columns': len(df.columns),
                'column_names': list(df.columns),
                'dtypes': {col: str(dtype) for col, dtype in df.dtypes.items()},
            }
        )
    
    def _get_filename(self, filepath: str) -> str:
        """Extract filename from path"""
        import os
        return os.path.basename(filepath)
    
    def _load_dataframe(self, filepath: str) -> pd.DataFrame:
        """Load file into pandas DataFrame"""
        ext = self._get_extension(filepath)
        
        if ext == 'csv':
            return pd.read_csv(filepath)
        elif ext in ('xlsx', 'xls'):
            return pd.read_excel(filepath)
        elif ext == 'parquet':
            return pd.read_parquet(filepath)
        elif ext == 'json':
            return pd.read_json(filepath)
        elif ext == 'feather':
            return pd.read_feather(filepath)
        else:
            raise ValueError(f"Unsupported format: {ext}")
    
    def _detect_injections(self, df: pd.DataFrame) -> List[Anomaly]:
        """Detect injection patterns in text columns"""
        anomalies = []
        
        # Get text/object columns
        text_cols = df.select_dtypes(include=['object', 'string']).columns
        
        for col in text_cols:
            for idx, value in df[col].dropna().items():
                if not isinstance(value, str):
                    value = str(value)
                
                # Check all patterns
                for pattern, category, description in COMPILED_PATTERNS:
                    if pattern.search(value):
                        anomalies.append(Anomaly(
                            type=f"{category} Injection",
                            location=f"Row {idx + 1}, Column '{col}'",
                            severity=Severity.HIGH,
                            description=f"{description}: {value[:100]}{'...' if len(value) > 100 else ''}",
                            confidence=0.95,
                            category="Injection",
                            details={
                                'pattern_category': category,
                                'pattern_description': description,
                                'row': idx + 1,
                                'column': col,
                                'value_preview': value[:200],
                            },
                            remediation="Remove or sanitize this row before training."
                        ))
                        break  # One match per cell is enough
        
        return anomalies
    
    def _detect_statistical_outliers(self, df: pd.DataFrame) -> List[Anomaly]:
        """Detect statistical outliers using MAD and IQR"""
        anomalies = []
        
        # Get numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            series = df[col].dropna()
            if len(series) < 10:  # Need enough data for statistics
                continue
            
            # Calculate robust z-scores (MAD-based)
            median = np.nanmedian(series)
            mad = np.nanmedian(np.abs(series - median))
            
            if mad == 0:
                continue  # Can't calculate z-scores
            
            z_scores = 0.6745 * (series - median) / mad
            
            # Calculate IQR bounds
            q1 = np.nanpercentile(series, 25)
            q3 = np.nanpercentile(series, 75)
            iqr = q3 - q1
            lower_bound = q1 - self.config['iqr_factor'] * iqr
            upper_bound = q3 + self.config['iqr_factor'] * iqr
            
            # Find outliers
            for idx, (value, z) in enumerate(zip(series, z_scores)):
                abs_z = abs(z)
                original_idx = series.index[idx]  # Get original DataFrame index
                
                is_outlier = False
                severity = Severity.LOW
                confidence = 0.0
                
                # Check z-score threshold
                if abs_z > self.config['high_severity_zscore']:
                    is_outlier = True
                    severity = Severity.HIGH
                    confidence = min(0.95, 0.7 + abs_z * 0.05)
                elif abs_z > self.config['mad_threshold']:
                    is_outlier = True
                    severity = Severity.MEDIUM
                    confidence = min(0.85, 0.5 + abs_z * 0.1)
                
                # Check IQR bounds
                if value < lower_bound or value > upper_bound:
                    if not is_outlier:
                        is_outlier = True
                        severity = Severity.MEDIUM
                        confidence = 0.75
                    else:
                        # Both methods agree - increase confidence
                        confidence = min(0.98, confidence + 0.1)
                
                if is_outlier:
                    direction = "above" if value > median else "below"
                    anomalies.append(Anomaly(
                        type="Statistical Outlier",
                        location=f"Row {original_idx + 1}, Column '{col}'",
                        severity=severity,
                        description=f"Value {value:.4g} is {abs_z:.1f} standard deviations {direction} median ({median:.4g})",
                        confidence=confidence,
                        category="Statistical",
                        details={
                            'row': original_idx + 1,
                            'column': col,
                            'value': float(value),
                            'z_score': float(abs_z),
                            'median': float(median),
                            'mad': float(mad),
                            'iqr_lower': float(lower_bound),
                            'iqr_upper': float(upper_bound),
                        },
                        remediation="Review this value - it may be a data entry error or legitimate edge case."
                    ))
        
        return anomalies
    
    def _detect_duplicates(self, df: pd.DataFrame) -> List[Anomaly]:
        """Detect duplicate rows that might indicate data poisoning"""
        anomalies = []
        
        # Find exact duplicates
        duplicates = df[df.duplicated(keep=False)]
        if len(duplicates) == 0:
            return anomalies
        
        # Group by duplicate content
        duplicate_groups = duplicates.groupby(list(df.columns)).apply(lambda x: list(x.index))
        
        for _, indices in duplicate_groups.items():
            if len(indices) > 1:
                # Determine severity based on number of duplicates
                n_dupes = len(indices)
                if n_dupes >= 10:
                    severity = Severity.HIGH
                    confidence = 0.9
                elif n_dupes >= 5:
                    severity = Severity.MEDIUM
                    confidence = 0.75
                else:
                    severity = Severity.LOW
                    confidence = 0.6
                
                anomalies.append(Anomaly(
                    type="Duplicate Rows",
                    location=f"Rows {', '.join(str(i + 1) for i in indices[:5])}{'...' if n_dupes > 5 else ''}",
                    severity=severity,
                    description=f"Found {n_dupes} identical rows - possible data poisoning or collection error",
                    confidence=confidence,
                    category="Data Quality",
                    details={
                        'duplicate_count': n_dupes,
                        'row_indices': [i + 1 for i in indices],
                    },
                    remediation="Review duplicates - keep one or remove all if suspicious."
                ))
        
        return anomalies
    
    def _detect_null_patterns(self, df: pd.DataFrame) -> List[Anomaly]:
        """Detect suspicious null/missing data patterns"""
        anomalies = []
        
        # Check columns with high null rates
        null_rates = df.isnull().mean()
        
        for col, rate in null_rates.items():
            if rate > 0.5 and rate < 1.0:  # 50%+ but not all null
                anomalies.append(Anomaly(
                    type="High Null Rate",
                    location=f"Column '{col}'",
                    severity=Severity.MEDIUM if rate > 0.7 else Severity.LOW,
                    description=f"Column has {rate*100:.1f}% missing values",
                    confidence=0.8,
                    category="Data Quality",
                    details={
                        'column': col,
                        'null_rate': float(rate),
                        'null_count': int(df[col].isnull().sum()),
                    },
                    remediation="Consider imputation or removing this column."
                ))
        
        # Check for rows with many nulls
        row_null_rates = df.isnull().mean(axis=1)
        high_null_rows = row_null_rates[row_null_rates > 0.5]
        
        if len(high_null_rows) > 0 and len(high_null_rows) < len(df) * 0.1:
            # Only flag if it's a small subset (might be strategic nulls)
            anomalies.append(Anomaly(
                type="Strategic Null Pattern",
                location=f"{len(high_null_rows)} rows with >50% missing values",
                severity=Severity.MEDIUM,
                description=f"Found {len(high_null_rows)} rows with mostly null values",
                confidence=0.7,
                category="Data Quality",
                details={
                    'affected_row_count': len(high_null_rows),
                    'row_indices': [i + 1 for i in high_null_rows.index[:10].tolist()],
                },
                remediation="Review these sparse rows - they may be incomplete or intentionally poisoned."
            ))
        
        return anomalies
    
    def _detect_cardinality_issues(self, df: pd.DataFrame) -> List[Anomaly]:
        """Detect cardinality attacks on categorical columns"""
        anomalies = []
        
        # Check object/string columns
        cat_cols = df.select_dtypes(include=['object', 'string']).columns
        
        for col in cat_cols:
            series = df[col].dropna()
            if len(series) == 0:
                continue
            
            n_unique = series.nunique()
            n_total = len(series)
            ratio = n_unique / n_total
            
            # Flag if almost all values are unique (category explosion)
            if ratio > self.config['max_cardinality_ratio'] and n_unique > 50:
                anomalies.append(Anomaly(
                    type="Cardinality Anomaly",
                    location=f"Column '{col}'",
                    severity=Severity.MEDIUM,
                    description=f"Column has {n_unique} unique values out of {n_total} ({ratio*100:.1f}% unique) - possible ID column or cardinality attack",
                    confidence=0.7,
                    category="Schema",
                    details={
                        'column': col,
                        'unique_count': n_unique,
                        'total_count': n_total,
                        'unique_ratio': float(ratio),
                    },
                    remediation="Verify this is not an identifier column used as a feature."
                ))
            
            # Check for suspicious value distribution
            value_counts = series.value_counts()
            if len(value_counts) > 1:
                top_freq = value_counts.iloc[0]
                second_freq = value_counts.iloc[1]
                
                # Flag if one category dominates (possible label poisoning)
                if top_freq > n_total * 0.9 and n_unique > 2:
                    anomalies.append(Anomaly(
                        type="Category Imbalance",
                        location=f"Column '{col}'",
                        severity=Severity.LOW,
                        description=f"One category dominates: '{value_counts.index[0]}' appears {top_freq} times ({top_freq/n_total*100:.1f}%)",
                        confidence=0.6,
                        category="Data Quality",
                        details={
                            'column': col,
                            'dominant_value': str(value_counts.index[0]),
                            'dominant_count': int(top_freq),
                            'dominant_ratio': float(top_freq / n_total),
                        },
                        remediation="Check if this extreme imbalance is expected or indicates data issues."
                    ))
        
        return anomalies
    
    def get_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract tabular-specific metadata"""
        base_meta = super().get_metadata(filepath)
        
        try:
            df = self._load_dataframe(filepath)
            base_meta.update({
                'rows': len(df),
                'columns': len(df.columns),
                'column_names': list(df.columns),
                'memory_usage_mb': df.memory_usage(deep=True).sum() / (1024 * 1024),
            })
        except Exception as e:
            base_meta['load_error'] = str(e)
        
        return base_meta
