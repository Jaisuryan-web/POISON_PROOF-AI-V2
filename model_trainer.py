from __future__ import annotations
import os
import json
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
import joblib

from utils.security import hash_file

TRAINED_DIR = os.path.join(os.getcwd(), 'trained_models')
HASHES_PATH = os.path.join(TRAINED_DIR, 'model_hashes.json')


def ensure_model_paths():
    os.makedirs(TRAINED_DIR, exist_ok=True)
    if not os.path.exists(HASHES_PATH):
        with open(HASHES_PATH, 'w', encoding='utf-8') as f:
            json.dump([], f)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _choose_model(model_type: str = 'LogisticRegression'):
    """Return a model instance based on model_type string."""
    if model_type == 'RandomForestClassifier':
        return RandomForestClassifier(random_state=42)
    if model_type == 'SVC':
        return SVC(probability=True, random_state=42)
    # Default to Logistic Regression
    return LogisticRegression(max_iter=1000, random_state=42)


def _prepare_xy(df: pd.DataFrame, target: Optional[str]) -> Tuple[pd.DataFrame, pd.Series]:
    if target is None:
        # Heuristic: last column as target
        target = df.columns[-1]
    y = df[target]
    X = df.drop(columns=[target]).select_dtypes(include=[np.number]).copy()
    # Simple fillna for numeric features
    X = X.fillna(X.median(numeric_only=True))
    # If y is not numeric and has few categories, factorize
    if not np.issubdtype(y.dtype, np.number):
        y, _ = pd.factorize(y)
    return X, pd.Series(y)


def train_model(df: pd.DataFrame, target: Optional[str] = None, model_type: str = 'LogisticRegression') -> Dict[str, Any]:
    ensure_model_paths()
    X, y = _prepare_xy(df, target)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

    model = _choose_model(model_type)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, average='macro', zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, average='macro', zero_division=0)),
    }

    ts = int(time.time())
    model_name = f"{model.__class__.__name__}_{ts}.pkl"
    model_path = os.path.join(TRAINED_DIR, model_name)
    joblib.dump(model, model_path)

    model_hash = hash_file(model_path)
    
    try:
        with open(HASHES_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
        
    data.append({
        'model_name': model_name,
        'hash': model_hash,
        'trained_at': _utc_now_iso(),
        'metrics': metrics,
        'model_type': model.__class__.__name__
    })
    with open(HASHES_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    return {
        'model_path': model_path,
        'model_name': model_name,
        'metrics': metrics,
        'hash': model_hash,
    }


def train_model_streaming(df: pd.DataFrame, model_type: str = 'LogisticRegression', target: Optional[str] = None):
    """Generator that yields training progress events for SSE streaming."""
    ensure_model_paths()
    
    yield {'status': 'Loading dataset...', 'progress': 10}
    
    X, y = _prepare_xy(df, target)
    target_col = target or df.columns[-1]
    
    yield {'status': f'Target column: {target_col}', 'progress': 20}
    yield {'status': 'Splitting data (75/25)...', 'progress': 30}
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
    
    model = _choose_model(model_type)
    
    yield {'status': f'Training {model.__class__.__name__}...', 'progress': 40}
    
    model.fit(X_train, y_train)
    
    yield {'status': 'Training complete.', 'progress': 70}
    
    y_pred = model.predict(X_test)
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, average='macro', zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, average='macro', zero_division=0)),
    }
    
    yield {'metrics': metrics, 'progress': 80}
    yield {'status': f'Accuracy: {metrics["accuracy"]:.4f}', 'progress': 85}
    
    ts = int(time.time())
    model_name = f"{model.__class__.__name__}_{ts}.pkl"
    model_path = os.path.join(TRAINED_DIR, model_name)
    joblib.dump(model, model_path)
    
    yield {'status': 'Generating model hash (SHA-256)...', 'progress': 90}
    
    model_hash = hash_file(model_path)
    
    try:
        with open(HASHES_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    
    data.append({
        'model_name': model_name,
        'hash': model_hash,
        'trained_at': _utc_now_iso(),
        'metrics': metrics,
        'model_type': model.__class__.__name__
    })
    
    with open(HASHES_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    yield {'status': f'Model hash generated.', 'progress': 95}
    yield {'hash': model_hash}
    yield {'status': 'Training and verification complete.', 'progress': 100}
