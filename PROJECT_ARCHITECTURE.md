# 🛡️ PoisonProof AI — Complete Project Documentation

> **Enterprise-grade AI Security Platform for Data Poisoning Detection, Anomaly Analysis, and ML Model Integrity Verification**

---

## 📋 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Directory Structure](#3-directory-structure)
4. [Core Components](#4-core-components)
5. [Data Flow & Request Lifecycle](#5-data-flow--request-lifecycle)
6. [Detection Engine](#6-detection-engine)
7. [Machine Learning Platform](#7-machine-learning-platform)
8. [Security Features](#8-security-features)
9. [Frontend & UI Components](#9-frontend--ui-components)
10. [API Reference](#10-api-reference)
11. [Configuration](#11-configuration)
12. [Database & Storage](#12-database--storage)
13. [Deployment Guide](#13-deployment-guide)
14. [Testing](#14-testing)
15. [Technology Stack](#15-technology-stack)

---

## 1. Project Overview

### What is PoisonProof AI?

PoisonProof AI is a comprehensive security platform designed to detect and mitigate **data poisoning attacks** on machine learning datasets. It provides:

- **Threat Detection**: Scans CSV datasets for 40+ injection patterns (SQL, XSS, Command Injection, etc.)
- **Statistical Anomaly Detection**: Uses robust statistical methods (MAD, IQR) to identify outliers
- **Image Forensics**: Analyzes images for manipulation, steganography, and metadata tampering
- **ML Model Training**: Live training console with real-time progress streaming
- **Model Integrity**: SHA-256 cryptographic verification for trained models
- **Data Cleaning**: Automated and manual cleaning workflows

### Problem Statement

When training AI/ML models, poisoned training data can lead to:
- **Backdoor Attacks**: Models behave normally but fail on specific trigger inputs
- **Model Degradation**: Gradual reduction in model accuracy
- **Security Vulnerabilities**: Injection payloads embedded in data
- **Data Integrity Issues**: Statistical outliers skewing model behavior

### Solution

PoisonProof AI provides a multi-layered defense:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PoisonProof AI                                │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1: Injection Detection (40+ patterns)                        │
│  Layer 2: Statistical Outlier Analysis (MAD/IQR)                    │
│  Layer 3: Image Forensics (ELA, Entropy, EXIF)                      │
│  Layer 4: Data Cleaning (Auto/Manual)                               │
│  Layer 5: Model Training with Integrity Verification                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT (Browser)                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Upload    │  │   Results   │  │   Train     │  │   Models    │        │
│  │   Page      │  │   View      │  │   Console   │  │  Dashboard  │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
└─────────┼────────────────┼────────────────┼────────────────┼────────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FLASK APPLICATION                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         Route Handlers (app.py)                         │ │
│  │   /scan  │  /clean  │  /train  │  /models  │  /api/*                  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│  ┌─────────────────────────────────┴─────────────────────────────────────┐  │
│  │                           UTILS LAYER                                  │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │  │
│  │  │ detection.py│  │ security.py │  │  cleaner.py │                    │  │
│  │  │ - CSV Scan  │  │ - Hash      │  │ - Auto Clean│                    │  │
│  │  │ - Image     │  │ - Patterns  │  │ - Manual    │                    │  │
│  │  │   Analysis  │  │ - Audit Log │  │   Clean     │                    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│  ┌─────────────────────────────────┴─────────────────────────────────────┐  │
│  │                        ML TRAINING (model_trainer.py)                  │  │
│  │   - Streaming Training (SSE)                                          │  │
│  │   - Multiple Algorithms (LogReg, RF, SVM)                             │  │
│  │   - SHA-256 Model Hashing                                             │  │
│  │   - Metrics Calculation                                               │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
          │                                                    │
          ▼                                                    ▼
┌───────────────────────────┐              ┌───────────────────────────────────┐
│      FILE STORAGE         │              │          MODEL STORAGE            │
│  uploads/                 │              │  trained_models/                  │
│   ├── dataset.csv         │              │   ├── LogisticRegression_*.pkl   │
│   └── *_cleaned.csv       │              │   ├── RandomForest_*.pkl         │
│                           │              │   └── model_hashes.json          │
│  logs/                    │              │                                   │
│   └── audit.json          │              │                                   │
└───────────────────────────┘              └───────────────────────────────────┘
```

### Component Interaction Flow

```
User Upload → Route Handler → Detection Engine → Anomaly Report
                                    │
                                    ▼
                            Cleaning Pipeline
                                    │
                                    ▼
                            ML Training (SSE)
                                    │
                                    ▼
                        Model Registry + Hash Verification
```

---

## 3. Directory Structure

```
PoisonProof-AI/
│
├── 📄 app.py                    # Main Flask application (668 lines)
├── 📄 config.py                 # Configuration classes (Dev/Prod/Test)
├── 📄 run.py                    # Application entry point
├── 📄 model_trainer.py          # ML training with SSE streaming
├── 📄 generate_training_dataset.py  # Dataset generator utility
├── 📄 gen.py                    # Additional generation utilities
│
├── 📁 utils/                    # Core utility modules
│   ├── detection.py             # Anomaly detection engine
│   ├── security.py              # Security utilities & patterns
│   └── cleaner.py               # Data cleaning functions
│
├── 📁 templates/                # Jinja2 HTML templates
│   ├── base.html                # Base template with navbar/footer
│   ├── index.html               # Landing page (hero + features)
│   ├── upload.html              # File upload interface
│   ├── results.html             # Scan results display
│   ├── review.html              # Manual anomaly review
│   ├── clean.html               # Cleaning report
│   ├── train.html               # Training configuration
│   ├── train_live.html          # Live training console (SSE)
│   └── models.html              # Model comparison dashboard
│
├── 📁 static/                   # Static assets
│   ├── css/
│   │   └── style.css            # Cyber-themed CSS (200+ custom rules)
│   └── js/
│       ├── main.js              # Core JavaScript utilities
│       ├── cyber_effects.js     # Matrix rain animation
│       └── train_console.js     # Training console logic
│
├── 📁 uploads/                  # Uploaded files (auto-cleaned after 15min)
│   └── *.csv
│
├── 📁 trained_models/           # Trained model storage
│   ├── *.pkl                    # Serialized scikit-learn models
│   └── model_hashes.json        # Model registry with hashes
│
├── 📁 logs/                     # Audit logs
│   └── audit.json               # JSON audit trail
│
├── 📄 requirements.txt          # Python dependencies
├── 📄 pyproject.toml            # Project metadata
├── 📄 training_dataset.csv      # Pre-built 800-row training dataset
├── 📄 sample_data.csv           # Sample data for testing
├── 📄 test_app.py               # Unit tests
│
├── 📄 README.md                 # Quick start guide
├── 📄 FEATURES.md               # Feature implementation details
├── 📄 DATASET_GUIDE.md          # Dataset documentation
├── 📄 DATASET_SUMMARY.md        # Dataset statistics
├── 📄 TRAINING_QUICKSTART.md    # Training guide
└── 📄 LICENSE                   # License file
```

---

## 4. Core Components

### 4.1 Flask Application (`app.py`)

The main application file implementing the Flask web server using the **Application Factory Pattern**.

```python
def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    config_name = config_name or os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config[config_name])
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    register_routes(app)
    return app
```

**Key Features:**
- Factory pattern for testability
- Environment-based configuration
- Session management with UUID tracking
- Comprehensive route registration

### 4.2 Route Structure

| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/` | GET | `index()` | Landing page |
| `/upload` | GET | `upload_page()` | File upload form |
| `/scan` | POST | `scan_file()` | Process uploaded file |
| `/clean/<filename>` | GET/POST | `clean_file()` | Manual cleaning |
| `/clean/auto/<filename>` | GET | `auto_clean_file()` | Auto cleaning |
| `/train` | GET/POST | `train_model()` | Training page |
| `/train/live/<job_id>` | GET | `train_live()` | Live console |
| `/train/stream/<job_id>` | GET | `train_stream()` | SSE stream |
| `/models` | GET | `models_dashboard()` | Model comparison |
| `/models/download/<file>` | GET | `download_model()` | Download model |
| `/models/delete/<file>` | POST | `delete_model()` | Delete model |

### 4.3 Detection Engine (`utils/detection.py`)

The detection engine provides comprehensive anomaly detection:

```python
def detect_csv_anomalies(df: pd.DataFrame, max_findings: int = 50) -> List[Dict]:
    """
    Multi-layer detection:
    1. Text-based injection signature scanning
    2. Robust Z-score outlier detection (MAD)
    3. IQR-based boundary detection
    """
```

**Detection Methods:**

| Method | Description | Use Case |
|--------|-------------|----------|
| `robust_z_score()` | MAD-based z-scores | Robust to outliers |
| `iqr_bounds()` | Interquartile range fences | Statistical boundaries |
| `_check_exif_anomalies()` | EXIF metadata analysis | Image tampering |
| `_check_entropy()` | Statistical entropy | Steganography detection |
| `analyze_image()` | Full image forensics | ELA, blur, dynamic range |

### 4.4 Security Module (`utils/security.py`)

Handles security-related operations:

```python
# 40+ injection patterns organized by attack type
INJECTION_PATTERNS = [
    # XSS (Cross-Site Scripting)
    r"<script[\s>]",
    r"onerror\s*=",
    r"javascript:",
    
    # SQL Injection
    r"drop\s+table",
    r"union\s+select",
    r"'\s*or\s*'1'\s*=\s*'1",
    
    # Command Injection
    r";\s*rm\s+-rf",
    r"\$\(.*\)",
    r"`.*`",
    
    # Path Traversal
    r"\.\./",
    r"/etc/passwd",
    
    # NoSQL Injection
    r"\$ne\s*:",
    r"\$where\s*:",
    
    # LDAP Injection
    r"\*\)\s*\(",
]
```

**Security Functions:**

| Function | Purpose |
|----------|---------|
| `hash_file(path)` | SHA-256 file hashing |
| `hash_bytes(data)` | SHA-256 bytes hashing |
| `allowed_file(filename)` | Extension validation |
| `scan_payload_signatures(text)` | Injection pattern matching |
| `schedule_cleanup(path, delay)` | Timed file deletion |
| `log_audit_event(event)` | Audit trail logging |

### 4.5 Data Cleaner (`utils/cleaner.py`)

Provides data cleaning capabilities:

```python
def auto_clean(df: pd.DataFrame, anomalies: List[Dict]) -> Tuple[pd.DataFrame, Dict]:
    """Drop rows with High severity anomalies."""
    
def manual_clean(df: pd.DataFrame, rows_to_drop: List[int]) -> Tuple[pd.DataFrame, Dict]:
    """Drop user-selected rows."""
```

### 4.6 Model Trainer (`model_trainer.py`)

ML training with real-time streaming:

```python
def train_model_streaming(df, model_type='LogisticRegression', target=None):
    """Generator yielding training progress for SSE."""
    yield {'status': 'Loading dataset...', 'progress': 10}
    # ... training steps
    yield {'metrics': metrics, 'progress': 80}
    yield {'hash': model_hash}
    yield {'status': 'Training complete.', 'progress': 100}
```

**Supported Models:**

| Model | Class | Use Case |
|-------|-------|----------|
| Logistic Regression | `LogisticRegression` | Binary classification baseline |
| Random Forest | `RandomForestClassifier` | Ensemble with feature importance |
| Support Vector Machine | `SVC` | Non-linear decision boundaries |

---

## 5. Data Flow & Request Lifecycle

### 5.1 File Upload & Scan Flow

```
┌──────────────┐
│   User       │
│ Uploads CSV  │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  1. POST /scan                                                │
│     - Validate file extension                                 │
│     - secure_filename() sanitization                          │
│     - Save to uploads/                                        │
└──────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  2. Detection Engine                                          │
│     ┌─────────────────────────────────────────────────────┐  │
│     │ a) Text Column Scan                                  │  │
│     │    - For each object column                          │  │
│     │    - scan_payload_signatures() on each cell          │  │
│     │    - Flag injection patterns                         │  │
│     └─────────────────────────────────────────────────────┘  │
│     ┌─────────────────────────────────────────────────────┐  │
│     │ b) Numeric Column Analysis                           │  │
│     │    - robust_z_score() per column                     │  │
│     │    - iqr_bounds() per column                         │  │
│     │    - Flag values exceeding thresholds                │  │
│     └─────────────────────────────────────────────────────┘  │
│     ┌─────────────────────────────────────────────────────┐  │
│     │ c) Row Score Aggregation                             │  │
│     │    - Sum flagged column scores per row               │  │
│     │    - Rank rows by total anomaly score                │  │
│     │    - Return top N findings                           │  │
│     └─────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  3. Generate Visualization                                    │
│     - Plotly pie chart (severity distribution)               │
│     - JSON-encoded for frontend                              │
└──────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  4. Store Session Data                                        │
│     - File path, filename, SHA-256 hash                      │
│     - Schedule cleanup (15 min)                              │
└──────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  5. Render results.html                                       │
│     - Anomaly table with severity badges                     │
│     - Interactive chart                                      │
│     - Links to clean/train                                   │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 Training Flow (SSE)

```
┌──────────────┐
│  Start Train │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  POST /train                                             │
│  - Generate job_id (UUID)                               │
│  - Store in session: path, model_type, status           │
│  - Redirect to /train/live/<job_id>                     │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  GET /train/live/<job_id>                               │
│  - Render train_live.html                               │
│  - JavaScript connects to EventSource                   │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  GET /train/stream/<job_id>  (SSE Connection)           │
│                                                          │
│  Generator yields events:                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Event 1: {"status": "Loading dataset...",         │  │
│  │           "progress": 10}                         │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Event 2: {"status": "Target column: is_anomaly",  │  │
│  │           "progress": 20}                         │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Event 3: {"status": "Splitting data (75/25)...",  │  │
│  │           "progress": 30}                         │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Event 4: {"status": "Training RandomForest...",   │  │
│  │           "progress": 40}                         │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Event 5: {"status": "Training complete.",         │  │
│  │           "progress": 70}                         │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Event 6: {"metrics": {"accuracy": 0.85, ...},     │  │
│  │           "progress": 80}                         │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Event 7: {"hash": "abc123...",                    │  │
│  │           "progress": 95}                         │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Event 8: {"message": "complete"}                  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  Model Saved:                                            │
│  - trained_models/RandomForestClassifier_<ts>.pkl       │
│  - model_hashes.json updated with:                      │
│    {                                                    │
│      "model_name": "RandomForestClassifier_1234.pkl",  │
│      "hash": "sha256...",                              │
│      "trained_at": "2026-01-07T10:30:00Z",             │
│      "metrics": {...},                                  │
│      "model_type": "RandomForestClassifier"            │
│    }                                                    │
└─────────────────────────────────────────────────────────┘
```

---

## 6. Detection Engine

### 6.1 Injection Pattern Categories

| Category | Patterns | Severity | Examples |
|----------|----------|----------|----------|
| **XSS** | 8 patterns | High | `<script>`, `onerror=`, `javascript:`, `<iframe>` |
| **SQL Injection** | 10 patterns | High | `DROP TABLE`, `UNION SELECT`, `'OR'1'='1` |
| **Command Injection** | 7 patterns | High | `; rm -rf`, `$(...)`, backticks |
| **Path Traversal** | 4 patterns | Medium | `../`, `..\\`, `/etc/passwd` |
| **NoSQL Injection** | 3 patterns | High | `$ne:`, `$gt:`, `$where:` |
| **LDAP Injection** | 3 patterns | Medium | `*)(`, `(|`, `)(...)=*` |

### 6.2 Statistical Detection Methods

#### Robust Z-Score (MAD-based)

```python
def robust_z_score(series: pd.Series) -> pd.Series:
    """
    Formula: Z = 0.6745 * (x - median) / MAD
    
    - Uses Median Absolute Deviation (MAD) instead of std
    - Robust to outliers (unlike standard z-score)
    - 0.6745 normalizes MAD to be consistent with std for normal distributions
    """
    med = np.nanmedian(s)
    mad = np.nanmedian(np.abs(s - med))
    return 0.6745 * (s - med) / mad
```

**Threshold:** |z| > 3.5 → Flagged as outlier

#### IQR Bounds

```python
def iqr_bounds(series: pd.Series):
    """
    Classic Tukey fences:
    Lower = Q1 - 1.5 * IQR
    Upper = Q3 + 1.5 * IQR
    """
    q1 = np.nanpercentile(s, 25)
    q3 = np.nanpercentile(s, 75)
    iqr = q3 - q1
    return q1 - 1.5 * iqr, q3 + 1.5 * iqr
```

### 6.3 Image Forensics

#### Error Level Analysis (ELA)

```
Original Image → JPEG Compress (90%) → Compare Difference
                                             │
                                             ▼
                                    High difference in region
                                    = Possible manipulation
```

| ELA Score | Interpretation |
|-----------|---------------|
| < 12.0 | Normal |
| 12.0 - 20.0 | Medium suspicion |
| > 20.0 | High suspicion |

#### Entropy Analysis

```python
def _check_entropy(gray: np.ndarray):
    """
    Shannon entropy of pixel histogram
    
    Normal images: 6.5 - 7.5 bits/pixel
    High entropy (>7.8): Hidden data (steganography)
    Low entropy (<5.5): Synthetic/low-complexity
    """
```

#### EXIF Metadata Checks

- **Software Tags**: Detects Photoshop, GIMP, Paint.NET, Affinity
- **Camera Tags**: Flags missing Make/Model (possible stripped metadata)

---

## 7. Machine Learning Platform

### 7.1 Training Pipeline

```python
def _prepare_xy(df, target):
    """
    1. If target not specified, use last column
    2. Extract numeric features only
    3. Fill NaN with median
    4. Factorize categorical targets
    """
    
def train_model_streaming(df, model_type, target):
    """
    1. Prepare X, y
    2. Train/test split (75/25)
    3. Train model with progress events
    4. Calculate metrics
    5. Save model (.pkl)
    6. Generate SHA-256 hash
    7. Update registry
    """
```

### 7.2 Model Registry (`model_hashes.json`)

```json
[
  {
    "model_name": "LogisticRegression_1704614400.pkl",
    "hash": "a3f2b1c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678",
    "trained_at": "2026-01-07T10:00:00+00:00",
    "metrics": {
      "accuracy": 0.8550,
      "precision": 0.8234,
      "recall": 0.7891
    },
    "model_type": "LogisticRegression"
  }
]
```

### 7.3 Model Verification

```python
# On dashboard load:
file_path = os.path.join(TRAINED_DIR, model_name)
if os.path.exists(file_path):
    current_hash = hash_file(file_path)
    verified = (current_hash == stored_hash)  # ✓ or ⚠️
```

### 7.4 Metrics Calculated

| Metric | Formula | Purpose |
|--------|---------|---------|
| **Accuracy** | (TP + TN) / Total | Overall correctness |
| **Precision** | TP / (TP + FP) | Positive prediction accuracy |
| **Recall** | TP / (TP + FN) | True positive capture rate |

---

## 8. Security Features

### 8.1 File Security

| Feature | Implementation |
|---------|---------------|
| **File Extension Validation** | Whitelist: `csv, png, jpg, jpeg, gif, bmp` |
| **Filename Sanitization** | `werkzeug.utils.secure_filename()` |
| **Size Limit** | 16MB max (`MAX_CONTENT_LENGTH`) |
| **Auto-Cleanup** | Files deleted after 15 minutes |

### 8.2 Cryptographic Verification

```python
def hash_file(path: str) -> str:
    """SHA-256 hash with 8KB block reading for large files"""
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8192), b''):
            sha256.update(block)
    return sha256.hexdigest()
```

### 8.3 Session Management

```python
@app.before_request
def _ensure_session():
    session.permanent = True  # 1-hour lifetime
    if 'session_id' not in session:
        session['session_id'] = uuid.uuid4().hex[:8]
```

### 8.4 Audit Logging

```python
def log_audit_event(event: Dict):
    """Append to logs/audit.json with timestamp"""
    event.setdefault('timestamp', datetime.now(timezone.utc).isoformat())
    data.append(event)
```

### 8.5 Production Security Config

```python
class ProductionConfig(Config):
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    SESSION_COOKIE_SECURE = True     # HTTPS only
    SESSION_COOKIE_HTTPONLY = True   # No JavaScript access
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
```

---

## 9. Frontend & UI Components

### 9.1 Template Inheritance

```
base.html
├── index.html      (Hero + Features)
├── upload.html     (File upload form)
├── results.html    (Scan results + chart)
├── review.html     (Manual anomaly review)
├── clean.html      (Cleaning report)
├── train.html      (Training config)
├── train_live.html (SSE console)
└── models.html     (Dashboard)
```

### 9.2 Cyber Theme CSS

```css
:root {
    --accent-green: #00ff7f;
    --accent-cyan: #00ffff;
    --border-color: rgba(0, 255, 127, 0.3);
    --border-glow: rgba(0, 255, 127, 0.5);
    --bg-dark: #0a0f14;
    --text-light: #b0b0b0;
}
```

**Visual Effects:**
- Matrix rain canvas animation
- Neon glow text shadows
- Scan line gradients
- Threat meter color gradients
- Pulsing status badges

### 9.3 JavaScript Components

| File | Purpose |
|------|---------|
| `main.js` | Core utilities, navigation, alerts |
| `cyber_effects.js` | Matrix rain animation |
| `train_console.js` | SSE connection, progress updates |

### 9.4 External Libraries

- **Bootstrap 5.3.2**: Responsive grid, components
- **Bootstrap Icons 1.11.1**: Icon fonts
- **Plotly.js**: Interactive charts
- **Google Fonts**: Orbitron, JetBrains Mono

---

## 10. API Reference

### 10.1 RESTful Endpoints

#### `GET /api/audit-log`

Returns complete audit log.

**Response:**
```json
{
  "success": true,
  "count": 15,
  "logs": [
    {
      "timestamp": "2026-01-07T10:00:00+00:00",
      "event": "file_upload",
      "filename": "dataset.csv",
      "session_id": "abc123"
    }
  ]
}
```

#### `GET /api/audit-log/export`

Downloads audit log as CSV file.

#### `GET /api/models`

Returns all trained models.

**Response:**
```json
{
  "success": true,
  "count": 3,
  "models": [
    {
      "model_name": "LogisticRegression_1234.pkl",
      "hash": "abc123...",
      "metrics": {
        "accuracy": 0.85,
        "precision": 0.82,
        "recall": 0.79
      },
      "trained_at": "2026-01-07T10:00:00Z"
    }
  ]
}
```

#### `POST /api/verify/<file_hash>`

Verify file integrity against expected hash.

**Request:**
```
Content-Type: multipart/form-data
Body: file=@model.pkl
```

**Response:**
```json
{
  "success": true,
  "match": true,
  "expected": "abc123...",
  "actual": "abc123...",
  "status": "verified"
}
```

---

## 11. Configuration

### 11.1 Configuration Classes

```python
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'csv', 'png', 'jpg', 'jpeg', 'gif', 'bmp'}
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
```

### 11.2 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `development` | Environment mode |
| `SECRET_KEY` | random | Session encryption key |
| `PORT` | `5000` | Server port (production) |

---

## 12. Database & Storage

### 12.1 File-Based Storage

PoisonProof AI uses **file-based storage** (no external database required):

| Storage | Path | Format | Purpose |
|---------|------|--------|---------|
| Uploads | `uploads/` | CSV/Images | Temporary file storage |
| Models | `trained_models/*.pkl` | Pickle | Trained sklearn models |
| Registry | `trained_models/model_hashes.json` | JSON | Model metadata |
| Audit | `logs/audit.json` | JSON | Audit trail |

### 12.2 Model Hashes Schema

```json
{
  "model_name": "string",
  "hash": "string (SHA-256)",
  "trained_at": "string (ISO 8601)",
  "metrics": {
    "accuracy": "float",
    "precision": "float",
    "recall": "float"
  },
  "model_type": "string"
}
```

---

## 13. Deployment Guide

### 13.1 Development Setup

```powershell
# 1. Clone repository
git clone https://github.com/joedanields/PoisonProof-AI.git
cd PoisonProof-AI

# 2. Create virtual environment
python -m pip install uv
uv venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
uv pip install -r requirements.txt

# 4. Run development server
python run.py
```

### 13.2 Production Deployment

```bash
# Set environment
export FLASK_ENV=production
export SECRET_KEY=$(openssl rand -hex 32)

# Run with Gunicorn (Linux)
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app('production')"

# Or with Waitress (Windows)
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

### 13.3 Docker Deployment

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_ENV=production
EXPOSE 5000
CMD ["python", "run.py"]
```

---

## 14. Testing

### 14.1 Test Structure (`test_app.py`)

```python
def test_app_creation():
    """Test Flask app factory"""
    app = create_app('testing')
    assert app is not None

def test_file_hash():
    """Test SHA-256 hashing"""
    hash_result = calculate_file_hash(temp_path)
    assert len(hash_result) == 64

def test_csv_anomaly_detection():
    """Test detection engine on sample data"""
```

### 14.2 Running Tests

```bash
python test_app.py

# Or with pytest
pytest test_app.py -v
```

---

## 15. Technology Stack

### 15.1 Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.10+ | Runtime |
| Flask | 2.3.3 | Web framework |
| Werkzeug | 2.3.7 | WSGI utilities |
| pandas | 1.5.x | Data manipulation |
| NumPy | 1.21-1.24 | Numerical computing |
| scikit-learn | - | ML models |
| Pillow | 10.0.1 | Image processing |
| Plotly | 5.17.0 | Charting |
| joblib | - | Model serialization |

### 15.2 Frontend

| Technology | Version | Purpose |
|------------|---------|---------|
| Bootstrap | 5.3.2 | CSS framework |
| Bootstrap Icons | 1.11.1 | Icons |
| Plotly.js | (bundled) | Charts |
| Jinja2 | (Flask) | Templating |
| Custom CSS | - | Cyber theme |

### 15.3 Standards & Protocols

- **HTTP**: RESTful API design
- **SSE**: Server-Sent Events for real-time streaming
- **JSON**: Data interchange format
- **SHA-256**: Cryptographic hashing
- **Pickle**: Model serialization

---

## 📊 Training Dataset

The pre-built `training_dataset.csv` contains:

- **800 rows** total
- **603 normal samples** (75.4%)
- **197 anomalous samples** (24.6%)

**Anomaly Types:**
- SQL Injection payloads
- XSS attack patterns
- Command injection attempts
- Path traversal strings
- Statistical outliers (salary, age extremes)
- Invalid data (negative values, extreme ranges)

---

## 🔗 Quick Links

| Resource | Description |
|----------|-------------|
| [README.md](README.md) | Quick start guide |
| [FEATURES.md](FEATURES.md) | Feature implementation details |
| [TRAINING_QUICKSTART.md](TRAINING_QUICKSTART.md) | ML training guide |
| [DATASET_GUIDE.md](DATASET_GUIDE.md) | Dataset documentation |

---

## 📝 License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

---

**© 2025-2026 PoisonProof AI Secure Lab. All rights reserved.**
