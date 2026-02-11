from __future__ import annotations
import pandas as pd
from typing import List, Dict, Optional, Tuple


def auto_clean(df: pd.DataFrame, anomalies: List[Dict]) -> Tuple[pd.DataFrame, Dict]:
    """Drop rows involved in High severity anomalies; keep Medium/Low for review."""
    drop_rows = set()
    for a in anomalies:
        if a.get('severity') == 'High':
            # Parse row index from location strings like "Row 12 (Columns: ...)" or "Row 12, Column 'X'"
            loc = a.get('location', '')
            tokens = [t for t in loc.replace('(', ' ').replace(')', ' ').replace(',', ' ').split() if t.isdigit()]
            if tokens:
                drop_rows.add(int(tokens[0]) - 1)
    cleaned = df.drop(index=[r for r in drop_rows if r in df.index])
    report = {
        'dropped_rows': sorted(list(drop_rows)),
        'original_rows': int(df.shape[0]),
        'cleaned_rows': int(cleaned.shape[0]),
    }
    return cleaned, report


def manual_clean(df: pd.DataFrame, rows_to_drop: Optional[List[int]]) -> Tuple[pd.DataFrame, Dict]:
    rows_to_drop = rows_to_drop or []
    cleaned = df.drop(index=[r for r in rows_to_drop if r in df.index])
    report = {
        'dropped_rows': sorted([r for r in rows_to_drop if r in df.index]),
        'original_rows': int(df.shape[0]),
        'cleaned_rows': int(cleaned.shape[0]),
    }
    return cleaned, report
