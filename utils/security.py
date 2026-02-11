import os
import re
import json
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Iterable, Optional

LOGS_DIR = os.path.join(os.getcwd(), 'logs')
AUDIT_LOG_PATH = os.path.join(LOGS_DIR, 'audit.json')

# Expanded payload signatures for comprehensive threat detection
INJECTION_PATTERNS = [
    # XSS (Cross-Site Scripting)
    r"<script[\s>]",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"document\.cookie",
    r"javascript:",
    r"<iframe",
    r"eval\s*\(",
    
    # SQL Injection
    r"drop\s+table",
    r"union\s+select",
    r"insert\s+into",
    r"delete\s+from",
    r"update\s+.+set",
    r"exec\s*\(",
    r"execute\s+immediate",
    r"'\s*or\s*'1'\s*=\s*'1",
    r"--\s*$",
    r";--",
    
    # Command Injection
    r";\s*rm\s+-rf",
    r";\s*cat\s+",
    r"\|\s*nc\s+",
    r"&\s*whoami",
    r">\s*/dev/null",
    r"\$\(.*\)",
    r"`.*`",
    
    # Path Traversal
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"c:\\windows",
    
    # LDAP Injection
    r"\*\)\s*\(",
    r"\(\|",
    r"\)\(.*\)=\*",
    
    # NoSQL Injection
    r"\$ne\s*:",
    r"\$gt\s*:",
    r"\$where\s*:",
]


def ensure_paths():
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(AUDIT_LOG_PATH):
        with open(AUDIT_LOG_PATH, 'w', encoding='utf-8') as f:
            json.dump([], f)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8192), b''):
            sha256.update(block)
    return sha256.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def allowed_file(filename: str, allowed: Iterable[str]) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in set(allowed)


def scan_payload_signatures(text: str) -> Optional[str]:
    """Return the first matched injection signature name if found, else None."""
    if not text:
        return None
    lowered = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            return pattern
    return None


def schedule_cleanup(path: str, delay_seconds: int = 15 * 60) -> None:
    """Schedule background deletion of a file to enforce hygiene."""
    def _delete():
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            # Best-effort cleanup; do not crash app
            pass

    t = threading.Timer(delay_seconds, _delete)
    t.daemon = True
    t.start()


def log_audit_event(event: Dict[str, Any]) -> None:
    """Append an audit event to logs/audit.json (array of objects)."""
    ensure_paths()
    try:
        with open(AUDIT_LOG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = []
    except Exception:
        data = []
    event.setdefault('timestamp', _utc_now_iso())
    data.append(event)
    with open(AUDIT_LOG_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
