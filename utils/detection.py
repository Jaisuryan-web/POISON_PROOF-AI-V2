from __future__ import annotations
import numpy as np
import pandas as pd
from typing import List, Dict, Optional
from PIL import Image, ImageChops
from io import BytesIO

from .security import scan_payload_signatures


def robust_z_score(series: pd.Series) -> pd.Series:
    s = pd.to_numeric(series, errors='coerce')
    med = np.nanmedian(s)
    mad = np.nanmedian(np.abs(s - med))
    if mad == 0 or np.isnan(mad):
        std = np.nanstd(s)
        if std == 0 or np.isnan(std):
            return pd.Series(np.zeros(len(s)), index=series.index)
        return (s - np.nanmean(s)) / std
    return 0.6745 * (s - med) / mad


def iqr_bounds(series: pd.Series):
    s = pd.to_numeric(series, errors='coerce')
    q1 = np.nanpercentile(s, 25)
    q3 = np.nanpercentile(s, 75)
    iqr = q3 - q1
    return q1 - 1.5 * iqr, q3 + 1.5 * iqr


def detect_csv_anomalies(df: pd.DataFrame, max_findings: int = 50) -> List[Dict]:
    anomalies: List[Dict] = []
    if df.empty:
        return anomalies

    # Text-based injection signatures across object columns
    text_cols = df.select_dtypes(include=['object']).columns
    injection_rows = []
    for col in text_cols:
        for idx, val in df[col].items():
            sig = scan_payload_signatures(str(val))
            if sig:
                injection_rows.append(idx)
                anomalies.append({
                    'type': 'Injection Signature',
                    'location': f"Row {int(idx)+1}, Column '{col}'",
                    'severity': 'High',
                    'description': f"Suspicious payload pattern detected: {sig}",
                    'confidence': 0.9,
                })

    # Numeric outlier analysis
    num_df = df.select_dtypes(include=[np.number]).copy()
    if num_df.empty:
        return anomalies

    row_scores = np.zeros(len(num_df))
    details = []

    for col in num_df.columns:
        rz = robust_z_score(num_df[col])
        lower, upper = iqr_bounds(num_df[col])
        z_flags = np.abs(rz) > 3.5
        iqr_flags = (num_df[col] < lower) | (num_df[col] > upper)
        flags = z_flags | iqr_flags
        row_scores += np.where(flags, np.minimum(np.abs(rz.fillna(0)), 10), 0)

        flagged_idx = np.where(flags)[0]
        for idx in flagged_idx:
            value = num_df.iloc[idx][col]
            rz_val = float(rz.iloc[idx]) if not np.isnan(rz.iloc[idx]) else 0.0
            severity = 'High' if abs(rz_val) > 5 else 'Medium' if abs(rz_val) > 4 else 'Low'
            details.append({
                'row': int(idx) + 1,
                'column': col,
                'rz': rz_val,
                'val': None if pd.isna(value) else (float(value) if isinstance(value, (int, float, np.floating, np.integer)) else value),
                'severity': severity,
            })

    top_indices = np.argsort(-row_scores)[:max_findings]
    for idx in top_indices:
        if row_scores[idx] <= 0:
            continue
        cols = [d for d in details if d['row'] == int(idx) + 1]
        if not cols:
            continue
        high = any(c['severity'] == 'High' for c in cols)
        med = any(c['severity'] == 'Medium' for c in cols)
        severity = 'High' if high else 'Medium' if med else 'Low'
        confidence = float(np.clip(0.5 + 0.05 * len(cols) + 0.02 * float(row_scores[idx]), 0, 0.95))
        columns_str = ', '.join(sorted({c['column'] for c in cols}))
        anomalies.append({
            'type': 'Data Outlier',
            'location': f'Row {int(idx) + 1} (Columns: {columns_str})',
            'severity': severity,
            'description': 'Robust statistical detection flagged outlier values (MAD/IQR).',
            'confidence': round(confidence, 2)
        })

    if len(anomalies) < 5 and details:
        details.sort(key=lambda d: abs(d['rz']), reverse=True)
        for d in details[: (5 - len(anomalies))]:
            anomalies.append({
                'type': 'Column Outlier',
                'location': f"Row {d['row']}, Column '{d['column']}'",
                'severity': d['severity'],
                'description': 'Value deviates significantly from distribution (robust z-score).',
                'confidence': 0.7
            })

    return anomalies


def _check_exif_anomalies(img: Image.Image) -> List[Dict]:
    """Check EXIF metadata for tampering indicators."""
    findings = []
    try:
        exif_data = img._getexif() if hasattr(img, '_getexif') else None
        if exif_data:
            # Check for software/editing tool traces
            software_tags = [0x0131, 0x013B]  # Software, Artist tags
            for tag in software_tags:
                if tag in exif_data:
                    software = str(exif_data[tag]).lower()
                    if any(editor in software for editor in ['photoshop', 'gimp', 'paint.net', 'affinity']):
                        findings.append({
                            'type': 'EXIF Metadata',
                            'location': 'Headers',
                            'severity': 'Medium',
                            'description': f'Image editing software detected in metadata: {software}',
                            'confidence': 0.8
                        })
            
            # Check for missing expected metadata
            expected_camera_tags = [0x010F, 0x0110]  # Make, Model
            if not any(tag in exif_data for tag in expected_camera_tags):
                findings.append({
                    'type': 'EXIF Metadata',
                    'location': 'Headers',
                    'severity': 'Low',
                    'description': 'Camera metadata missing or stripped - possible editing',
                    'confidence': 0.6
                })
    except Exception:
        pass
    return findings


def _check_entropy(gray: np.ndarray) -> Optional[Dict]:
    """Check statistical entropy for steganography detection."""
    try:
        hist, _ = np.histogram(gray.flatten(), bins=256, range=(0, 256))
        hist = hist[hist > 0]
        prob = hist / hist.sum()
        entropy = float(-np.sum(prob * np.log2(prob)))
        
        # Normal images have entropy 6.5-7.5; hidden data increases it
        if entropy > 7.8:
            return {
                'type': 'Steganography',
                'location': 'Pixel Data',
                'severity': 'High',
                'description': f'Abnormally high entropy ({entropy:.2f}) suggests hidden data',
                'confidence': 0.75
            }
        elif entropy < 5.5:
            return {
                'type': 'Image Quality',
                'location': 'Pixel Data',
                'severity': 'Low',
                'description': f'Very low entropy ({entropy:.2f}) indicates low complexity or synthetic image',
                'confidence': 0.65
            }
    except Exception:
        pass
    return None


def analyze_image(filepath: str) -> List[Dict]:
    findings: List[Dict] = []
    with Image.open(filepath) as img:
        # EXIF analysis
        findings.extend(_check_exif_anomalies(img))
        
        img = img.convert('RGB')
        
        # ELA (Error Level Analysis)
        buf = BytesIO()
        img.save(buf, format='JPEG', quality=90)
        buf.seek(0)
        comp = Image.open(buf).convert('RGB')
        diff = ImageChops.difference(img, comp)
        ela_score = float(np.asarray(diff, dtype=np.uint8).mean())
        if ela_score > 12.0:
            findings.append({
                'type': 'Visual Manipulation',
                'location': 'Global',
                'severity': 'High' if ela_score > 20 else 'Medium',
                'description': f'Error Level Analysis (ELA={ela_score:.1f}) suggests recompression or edits.',
                'confidence': round(min(0.95, 0.5 + (ela_score / 40.0)), 2)
            })
        
        # Grayscale analysis
        gray = np.asarray(img.convert('L'), dtype=np.float32)
        
        # Entropy check for steganography
        entropy_finding = _check_entropy(gray)
        if entropy_finding:
            findings.append(entropy_finding)
        
        # Blur detection via gradient variance
        gx = gray[:, 1:] - gray[:, :-1]
        gy = gray[1:, :] - gray[:-1, :]
        grad_mag = np.sqrt(gx[:, :-1] ** 2 + gy[:-1, :] ** 2)
        grad_var = float(np.var(grad_mag))
        if grad_var < 25.0:
            findings.append({
                'type': 'Image Quality',
                'location': 'Global',
                'severity': 'Medium' if grad_var < 15 else 'Low',
                'description': f'Low edge/texture energy (variance={grad_var:.1f}) indicates blur.',
                'confidence': round(0.6 if grad_var < 20 else 0.55, 2)
            })
        
        # Dynamic range check
        rng = float(gray.max() - gray.min())
        if rng < 30.0:
            findings.append({
                'type': 'Image Quality',
                'location': 'Global',
                'severity': 'Low',
                'description': f'Very low dynamic range ({rng:.1f}) - over-compressed or washed out.',
                'confidence': 0.55
            })
    
    return findings
