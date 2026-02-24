# PoisonProof AI — Advanced Security Platform

 **Enterprise-grade AI security platform with real-time anomaly detection, ML model training, and cryptographic verification**

> A comprehensive Flask-based security platform that detects data poisoning attacks, injection vulnerabilities, and image manipulation across CSV and image datasets. Features live model training with SSE streaming, automated/manual data cleaning, and a cyber-themed UI with Matrix rain animation.

---

##  Table of Contents

- [Quick Start](#-quick-start)
- [Key Features](#-key-features)
- [Technology Stack](#-technology-stack)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
- [Anomaly Detection](#-anomaly-detection)
- [Machine Learning Platform](#-machine-learning-platform)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#-license)

---

## ⚡ Quick Start

### Prerequisites
- Python 3.10+ (Python 3.12 supported)
- uv package manager (recommended) or pip

### Installation (Windows PowerShell)

```powershell
# 1. Install uv
python -m pip install --upgrade pip
python -m pip install uv

# 2. Clone repository
git clone https://github.com/joedanields/PoisonProof-AI.git
cd PoisonProof-AI

# 3. Create virtual environment
uv venv .venv
.\.venv\Scripts\Activate.ps1

# 4. Install dependencies
uv pip install -r requirements.txt

# 5. Run application
uv run python run.py
```

### Access the Application
Open your browser to: **http://127.0.0.1:5000**

---

## 🎯 Key Features

### 🔍 Advanced Threat Detection

#### CSV Security Scanning
- **40+ Injection Patterns**: Detects SQL injection, XSS, command injection, path traversal, NoSQL, LDAP injection
- **Statistical Outliers**: MAD (Median Absolute Deviation) and IQR (Interquartile Range) analysis
- **Pattern Examples**:
  - SQL: `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
  - XSS: `<script>alert()`, `javascript:`, `onerror=`
  - Command: `; rm -rf`, `| cat /etc`, `&& whoami`
  - Path Traversal: `../../../etc/passwd`, `..\..\windows\system32`
  - NoSQL: `{$ne:null}`, `{$gt:""}`, `$where:`
  - LDAP: `*)(uid=*)`, `admin*`, `(cn=*)`

#### Image Forensics
- **ELA (Error Level Analysis)**: Detects image manipulation by analyzing recompression artifacts
- **EXIF Metadata Analysis**: Extracts camera info, GPS data, timestamps, software used
- **Entropy Detection**: Identifies steganography and hidden data (high entropy = suspicious)
- **Blur Detection**: Gradient variance analysis for quality assessment
- **Dynamic Range Analysis**: Detects washed-out or over-compressed images

### 🧠 Machine Learning Platform

#### Live Training Console
- **Real-time SSE Streaming**: Server-Sent Events display training progress live
- **Progress Indicators**: Watch epoch-by-epoch accuracy improvements
- **Auto-Training**: Trains on pre-built 800-row dataset with one click
- **Model Comparison**: Multiple algorithms (Random Forest, Gradient Boosting, SVM, Logistic Regression)

#### Model Comparison Dashboard
- **Interactive Plotly Charts**:
  - Accuracy comparison bar charts
  - Feature importance rankings
  - ROC curves with AUC scores
  - Confusion matrices
  - Classification reports (precision/recall/f1-score)
- **SHA-256 Verification**: Every model has a cryptographic hash for integrity
- **Model Registry**: JSON-based registry tracks all trained models with timestamps

#### Training Dataset
- **800 Rows**: 603 normal (75.4%), 197 anomalous (24.6%)
- **11 Features**: employee_id, name, email, age, salary, years_experience, department, performance_score, projects_completed, days_absent, overtime_hours
- **Diverse Anomalies**:
  - SQL injection in name/email fields
  - XSS attacks in department names
  - Command injection attempts
  - Path traversal strings
  - Statistical outliers (negative salaries, impossible ages)
- **Generator Script**: `generate_training_dataset.py` creates custom datasets
- **Analysis Tool**: `analyze_dataset.py` validates dataset health

### 🧹 Data Cleaning Modes

#### Auto-Clean Mode
- **One-Click Removal**: Automatically removes all High severity anomalies
- **Animated Progress**: Visual feedback with completion animations
- **Download Clean Data**: Export sanitized CSV immediately
- **Audit Trail**: Logs all auto-cleaning actions

#### Manual Review Mode
- **Interactive Checkboxes**: Select specific rows to remove
- **Live Counter**: Real-time display of selected anomalies
- **Severity Filtering**: Review by High/Medium/Low severity
- **Location Details**: Shows exact row and column for each anomaly
- **Granular Control**: Choose which anomalies to keep or remove

### 🎨 Cyber-Themed UI

#### Visual Design
- **Matrix Rain Animation**: Falling green characters (toggleable via navbar)
- **Neon Green Theme**: `#00FF7F` accents throughout interface
- **Dark Mode**: Cyber-themed dark backgrounds with high contrast
- **Gradient Effects**: Animated gradients on cards and buttons
- **Responsive Design**: Mobile-friendly Bootstrap 5 layout

#### Interactive Elements
- **Loading Spinners**: Modal overlays during file processing
- **Progress Bars**: Visual feedback for long operations
- **Toast Notifications**: Success/error messages with auto-dismiss
- **Hover Effects**: Interactive cards and buttons with transforms
- **Copy-to-Clipboard**: One-click hash copying with feedback

### 🔐 Security & Integrity

#### File Security
- **SHA-256 Hashing**: Cryptographic fingerprinting of all uploaded files
- **Type Validation**: Strict whitelist (CSV, PNG, JPG, JPEG, GIF, BMP)
- **Size Limits**: 16MB maximum upload size
- **Secure Filenames**: Werkzeug's `secure_filename()` sanitization
- **Auto-Cleanup**: Files deleted 15 minutes after upload

#### Session Management
- **UUID Session IDs**: Unique identifier per upload session
- **Isolated Storage**: Each session gets separate directory
- **Audit Logging**: Complete history in `logs/audit.json`
- **Integrity Verification**: API endpoint for hash verification

---

## 🛠️ Technology Stack

### Backend
- **Framework**: Flask 2.3.3
- **Security**: Werkzeug 2.3.7, SHA-256 hashing
- **Data Processing**: Pandas 2.2+, NumPy 1.26+
- **Machine Learning**: scikit-learn 1.4+
- **Image Processing**: Pillow 10.0.1

### Frontend
- **UI Framework**: Bootstrap 5
- **Charts**: Plotly.js 5.17.0
- **JavaScript**: Vanilla JS with EventSource API (SSE)
- **Canvas API**: Matrix rain animation
- **CSS3**: Custom animations and transitions

### Data Science
- **Statistical Methods**: MAD, IQR, Z-scores
- **ML Algorithms**: Random Forest, Gradient Boosting, SVM, Logistic Regression
- **Evaluation Metrics**: Accuracy, Precision, Recall, F1-score, ROC-AUC
- **Feature Engineering**: Numeric feature scaling and selection

### Architecture
- **Modular Design**: Separated utils (security, detection, cleaner)
- **RESTful API**: JSON/CSV endpoints
- **Server-Sent Events**: Real-time streaming updates
- **Session-based Storage**: Isolated file handling

---

## 📦 Installation

### Using uv (Recommended - Fast)

```powershell
# Install uv package manager
python -m pip install uv

# Create virtual environment
uv venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies (Python 3.12 compatible)
uv pip install -r requirements.txt
```

### Using pip (Traditional)

```powershell
# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies (requirements.txt)

```
Flask==2.3.3
Werkzeug==2.3.7
numpy>=1.26,<3.0
pandas>=2.2,<3.0
Pillow==10.0.1
plotly==5.17.0
scikit-learn>=1.4.0
```

**Note**: Python 3.12 requires `numpy>=1.26` and `pandas>=2.2` due to removal of `distutils`.

---

## 📖 Usage Guide

### 1. Generate Training Dataset (Optional)

```powershell
# Create 800-row dataset with labeled anomalies
python generate_training_dataset.py

# Analyze dataset health
python analyze_dataset.py
```

### 2. Start the Application

```powershell
# Using uv
uv run python run.py

# Or directly
python run.py
```

### 3. Upload and Scan Dataset

1. **Navigate to**: http://127.0.0.1:5000
2. **Click**: "Scan Your Dataset" or use navbar
3. **Upload**: Drag-and-drop or browse for CSV/image file
4. **Wait**: Modal spinner shows processing status
5. **Review**: Anomalies displayed with severity badges

### 4. Review Results

#### Results Page Features
- **Anomaly Table**: Color-coded by severity (Red=High, Yellow=Medium, Green=Low)
- **Severity Badges**: Visual indicators for each finding
- **Location Details**: Exact row/column or image region
- **Confidence Scores**: Percentage indicating detection certainty
- **SHA-256 Hash**: Copy-to-clipboard for verification
- **Plotly Chart**: Interactive pie chart of severity distribution
- **Threat Meter**: Visual gauge showing overall risk level

### 5. Clean Your Data

#### Option A: Auto-Clean
1. Click **"Auto Clean"** button on results page
2. System removes all High severity anomalies automatically
3. Download cleaned CSV immediately
4. Review cleaning summary with statistics

#### Option B: Manual Review
1. Click **"Manual Review"** button on results page
2. Review each anomaly individually
3. Check boxes next to anomalies to remove
4. See live counter of selected items
5. Click **"Clean Selected"** to process
6. Download cleaned CSV with custom selections

### 6. Train Machine Learning Models

1. **Navigate to**: "Train Model" in navbar
2. **Upload Dataset**: Use `training_dataset.csv` or your own labeled data
3. **Watch Console**: Live streaming output shows progress
4. **View Metrics**: Accuracy, precision, recall displayed in real-time
5. **Model Saved**: Automatically saved with SHA-256 hash

### 7. Compare Models

1. **Navigate to**: "Models Dashboard"
2. **View Charts**: 
   - Accuracy comparison across all models
   - Feature importance rankings
   - ROC curves with AUC scores
3. **Verify Integrity**: Each model shows SHA-256 hash
4. **Export Data**: Download model metrics as CSV

### 8. API Access

#### Get Audit Log
```bash
curl http://127.0.0.1:5000/api/audit-log
```

#### Export Audit Log (JSON)
```bash
curl http://127.0.0.1:5000/api/audit-log/export?format=json -o audit.json
```

#### Export Audit Log (CSV)
```bash
curl http://127.0.0.1:5000/api/audit-log/export?format=csv -o audit.csv
```

#### Get All Models
```bash
curl http://127.0.0.1:5000/api/models
```

#### Verify File Integrity
```bash
curl -X POST http://127.0.0.1:5000/api/verify/your-sha256-hash-here
```

---

## 🔬 Anomaly Detection

### CSV Detection Methods

#### 1. Statistical Analysis

**MAD (Median Absolute Deviation)**
- Formula: `rz = 0.6745 * (x - median) / mad`
- Threshold: `|rz| > 3.5` flags as outlier
- Robust to extreme values (uses median, not mean)
- Scales MAD to approximate standard deviation

**IQR (Interquartile Range)**
- Calculate: `Q1 (25th percentile)`, `Q3 (75th percentile)`
- IQR: `Q3 - Q1`
- Lower fence: `Q1 - 1.5 * IQR`
- Upper fence: `Q3 + 1.5 * IQR`
- Values outside fences are outliers

**Row Aggregation**
- Analyzes all numeric columns per row
- Aggregates anomaly scores across columns
- Severity levels:
  - **High**: `|rz| > 5` or extreme IQR violations
  - **Medium**: `3.5 < |rz| < 5`
  - **Low**: Moderate outliers
- Confidence increases with magnitude and flagged column count

#### 2. Injection Pattern Detection (40+ Patterns)

**SQL Injection**
```
' OR '1'='1
UNION SELECT
DROP TABLE
DELETE FROM
UPDATE SET
INSERT INTO
1=1 --
admin'--
```

**Cross-Site Scripting (XSS)**
```
<script>alert()
<img src=x onerror=
javascript:void(0)
<iframe src=
onload=
onerror=
document.cookie
```

**Command Injection**
```
; rm -rf /
| cat /etc/passwd
&& whoami
`ls -la`
$(commands)
powershell.exe
cmd.exe /c
```

**Path Traversal**
```
../../../etc/passwd
..\..\windows\system32
..%2F..%2F
/etc/shadow
c:\boot.ini
```

**NoSQL Injection**
```
{$ne:null}
{$gt:""}
$where:
$regex:
{$nin:[]}
```

**LDAP Injection**
```
*)(uid=*)
admin*)(|(uid=*
(cn=*)
(|(objectClass=*))
```

### Image Detection Methods

#### 1. Error Level Analysis (ELA)
- **Method**: Recompress image at 90% quality, compute pixel differences
- **Detection**: Edited regions recompress differently (higher ELA values)
- **Thresholds**:
  - Mean ELA > 20: High severity (likely manipulated)
  - Mean ELA > 12: Medium severity (possible edits)
  - Mean ELA < 12: Low risk

#### 2. EXIF Metadata Analysis
- **Extracts**:
  - Camera make/model
  - GPS coordinates (latitude/longitude)
  - Timestamps (DateTimeOriginal)
  - Software used for editing
  - Image dimensions and format
- **Flags**: Missing EXIF = potential manipulation

#### 3. Entropy Detection
- **Method**: Calculate Shannon entropy of pixel values
- **Detection**: High entropy indicates hidden data (steganography)
- **Thresholds**:
  - Entropy > 7.5: High suspicion
  - Entropy > 7.0: Medium suspicion
  - Entropy < 7.0: Normal

#### 4. Blur Detection
- **Method**: Gradient variance (Laplacian of Gaussian)
- **Calculation**: Variance of gradient magnitude
- **Thresholds**:
  - Variance < 25: High blur (poor quality)
  - Variance < 50: Medium blur
  - Variance > 50: Sharp image

#### 5. Dynamic Range Analysis
- **Method**: Calculate `max(pixel) - min(pixel)` in grayscale
- **Detection**: Low range indicates compression artifacts
- **Thresholds**:
  - Range < 30: High compression (washed out)
  - Range < 50: Medium compression
  - Range > 50: Good dynamic range

---

## 🤖 Machine Learning Platform

### Training Dataset

#### Dataset Structure
- **File**: `training_dataset.csv`
- **Rows**: 800 (603 normal + 197 anomalous)
- **Columns**: 11 features + 1 target

#### Features
1. `employee_id`: Unique identifier
2. `name`: Employee name (injection testing field)
3. `email`: Email address (injection testing field)
4. `age`: Numeric (18-70)
5. `salary`: Numeric (30,000-150,000)
6. `years_experience`: Numeric (0-40)
7. `department`: Categorical (injection testing field)
8. `performance_score`: Numeric (1.0-10.0)
9. `projects_completed`: Numeric (0-50)
10. `days_absent`: Numeric (0-30)
11. `overtime_hours`: Numeric (0-100)

#### Target
- `is_anomaly`: Binary (0=normal, 1=anomalous)

#### Anomaly Distribution
- **Normal Records**: 603 (75.4%)
- **Anomalous Records**: 197 (24.6%)
- **Anomaly Types**:
  - SQL injection: ~25%
  - XSS attacks: ~20%
  - Command injection: ~15%
  - Path traversal: ~10%
  - Statistical outliers: ~30%

### Model Training

#### Supported Algorithms
1. **Random Forest**
   - Ensemble of decision trees
   - Good for non-linear relationships
   - Feature importance built-in

2. **Gradient Boosting**
   - Sequential tree building
   - High accuracy on complex patterns
   - Resistant to overfitting

3. **Support Vector Machine (SVM)**
   - Finds optimal hyperplane
   - Works well with high-dimensional data
   - Kernel tricks for non-linearity

4. **Logistic Regression**
   - Linear classification baseline
   - Fast training and inference
   - Interpretable coefficients

#### Training Process
1. **Data Loading**: Reads CSV with pandas
2. **Preprocessing**: 
   - Numeric feature extraction
   - Scaling with StandardScaler
   - Train/test split (80/20)
3. **Training**: Fits model on training set
4. **Evaluation**:
   - Accuracy, precision, recall, F1-score
   - ROC curve and AUC
   - Confusion matrix
5. **Saving**: Pickled model + SHA-256 hash + metadata

#### Live Training Console
- **Real-time Updates**: SSE streams progress to browser
- **Progress Display**: Shows current epoch/step
- **Metrics**: Live accuracy, loss, and evaluation metrics
- **Auto-Scroll**: Console follows output automatically
- **Completion Alert**: Success message when training finishes

### Model Comparison Dashboard

#### Comparison Metrics
1. **Accuracy Bar Chart**: Compare overall accuracy across models
2. **Feature Importance**: Top 10 features ranked by importance
3. **ROC Curves**: True Positive Rate vs False Positive Rate
4. **Confusion Matrices**: Visual heatmaps of predictions
5. **Classification Reports**: Detailed precision/recall/f1 tables

#### Model Registry
- **Location**: `trained_models/model_hashes.json`
- **Structure**:
```json
{
  "models": [
    {
      "model_name": "RandomForest_20241105_143022",
      "hash": "sha256_hash_here",
      "timestamp": "2024-11-05T14:30:22",
      "accuracy": 0.9375,
      "algorithm": "RandomForestClassifier"
    }
  ]
}
```

---

## 🌐 API Documentation

### Endpoints

#### 1. Get Audit Log
```http
GET /api/audit-log
```

**Response** (JSON):
```json
{
  "total": 15,
  "logs": [
    {
      "session_id": "uuid-here",
      "filename": "dataset.csv",
      "sha256": "hash-here",
      "timestamp": "2024-11-05T14:30:22",
      "anomalies_found": 12,
      "severity_breakdown": {
        "High": 4,
        "Medium": 5,
        "Low": 3
      }
    }
  ]
}
```

#### 2. Export Audit Log
```http
GET /api/audit-log/export?format=json
GET /api/audit-log/export?format=csv
```

**Query Parameters**:
- `format`: `json` or `csv` (required)

**Response**: File download (audit.json or audit.csv)

#### 3. Get All Models
```http
GET /api/models
```

**Response** (JSON):
```json
{
  "total": 3,
  "models": [
    {
      "model_name": "RandomForest_20241105_143022",
      "hash": "sha256_hash_here",
      "timestamp": "2024-11-05T14:30:22",
      "accuracy": 0.9375
    }
  ]
}
```

#### 4. Verify Hash
```http
POST /api/verify/<sha256_hash>
```

**Response** (JSON):
```json
{
  "verified": true,
  "session_id": "uuid-here",
  "filename": "dataset.csv",
  "timestamp": "2024-11-05T14:30:22"
}
```

---

## 📁 Project Structure

```
PoisonProof-AI/
├── app.py                          # Main Flask application
├── config.py                       # Configuration settings
├── run.py                          # Application entry point
├── requirements.txt                # Python dependencies
├── pyproject.toml                  # uv project config
├── README.md                       # This file
├── FEATURES.md                     # Detailed feature documentation
├── DATASET_GUIDE.md                # Dataset creation guide
├── TRAINING_QUICKSTART.md          # ML training quick start
├── LICENSE                         # MIT License
│
├── templates/                      # Jinja2 templates
│   ├── base.html                  # Base template with navbar
│   ├── index.html                 # Landing page (comprehensive features)
│   ├── upload.html                # File upload page
│   ├── results.html               # Scan results with cleaning options
│   ├── review.html                # Manual review with checkboxes
│   ├── clean.html                 # Cleaning results page
│   ├── train.html                 # Live training console
│   └── models.html                # Model comparison dashboard
│
├── static/                        # Static assets
│   ├── css/
│   │   └── style.css             # Custom styles (cyber theme)
│   └── js/
│       └── main.js               # JavaScript utilities
│
├── utils/                         # Utility modules
│   ├── __init__.py
│   ├── security.py               # SHA-256 hashing, file cleanup
│   ├── detection.py              # Anomaly detection (CSV + image)
│   └── cleaner.py                # Auto-clean and manual clean functions
│
├── model_trainer.py               # ML training with SSE streaming
├── generate_training_dataset.py   # Dataset generator script
├── analyze_dataset.py             # Dataset health checker
│
├── uploads/                       # Temporary file storage (auto-created)
│   └── session_<uuid>/           # Session-isolated directories
│
├── trained_models/                # Trained ML models (auto-created)
│   ├── *.pkl                     # Pickled scikit-learn models
│   └── model_hashes.json         # Model registry with SHA-256 hashes
│
├── logs/                          # Application logs (auto-created)
│   └── audit.json                # Audit trail of all scans
│
├── training_dataset.csv           # Pre-built 800-row training dataset
├── large_employee_dataset.csv     # Optional large dataset (1000 rows)
└── sample_data.csv                # Small sample for testing
```

---

## ⚙️ Configuration

### Environment Variables

```powershell
# Development mode
$env:FLASK_ENV = "development"

# Production mode
$env:FLASK_ENV = "production"
$env:SECRET_KEY = "your-super-secure-secret-key-here"

# Custom port
$env:FLASK_PORT = "8080"
```

### Configuration File (config.py)

```python
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'csv', 'png', 'jpg', 'jpeg', 'gif', 'bmp'}
    CLEANUP_INTERVAL = 900  # 15 minutes
```

### Tunable Detection Parameters

**CSV Detection (app.py)**:
```python
MAD_THRESHOLD = 3.5        # Robust z-score threshold
IQR_FACTOR = 1.5           # IQR fence multiplier
MAX_RESULTS = 50           # Maximum anomalies to report
HIGH_SEVERITY_THRESHOLD = 5.0  # |rz| threshold for High severity
```

**Image Detection (app.py)**:
```python
ELA_THRESHOLD_MEDIUM = 12.0    # ELA mean for Medium severity
ELA_THRESHOLD_HIGH = 20.0      # ELA mean for High severity
BLUR_THRESHOLD = 25.0          # Gradient variance threshold
DYNAMIC_RANGE_THRESHOLD = 30.0  # Min dynamic range
ENTROPY_THRESHOLD = 7.0        # Shannon entropy threshold
```

---

## 🧪 Testing

### Manual Testing

```powershell
# Test with sample CSV
python -c "import pandas as pd; pd.read_csv('sample_data.csv').head()"

# Test with training dataset
python -c "import pandas as pd; print(pd.read_csv('training_dataset.csv').info())"

# Generate large dataset for stress testing
python generate_large_dataset.py
```

### Dataset Health Check

```powershell
# Analyze training dataset
python analyze_dataset.py
```

**Expected Output**:
```
Dataset Health Check
====================
Total rows: 800
Total columns: 12
Missing values: 0
Anomaly distribution:
  - Normal: 603 (75.4%)
  - Anomalous: 197 (24.6%)
Anomaly types:
  - SQL Injection: 49 (6.1%)
  - XSS: 39 (4.9%)
  - Command Injection: 30 (3.8%)
  - Statistical Outliers: 79 (9.9%)
```

---

## 🚀 Deployment

### Local Production

```powershell
# Set production environment
$env:FLASK_ENV = "production"
$env:SECRET_KEY = "generate-strong-random-key"

# Run with production settings
python run.py
```

### Docker Deployment (Future)

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "run.py"]
```

### Security Checklist
- [ ] Set strong `SECRET_KEY` environment variable
- [ ] Enable HTTPS (use reverse proxy like nginx)
- [ ] Configure firewall rules (limit to port 5000)
- [ ] Set up rate limiting (e.g., Flask-Limiter)
- [ ] Enable CSRF protection (Flask-WTF)
- [ ] Configure secure session cookies
- [ ] Set up logging and monitoring
- [ ] Regular security updates for dependencies

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Development Workflow

1. **Fork the repository**
   ```bash
   git clone https://github.com/joedanields/PoisonProof-AI.git
   cd PoisonProof-AI
   ```

2. **Create feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes**
   - Write clear, commented code
   - Follow PEP 8 style guide
   - Add tests if applicable

4. **Test your changes**
   ```powershell
   # Run the app
   python run.py
   
   # Test manually with sample data
   # Upload files, train models, check API endpoints
   ```

5. **Commit with conventional commits**
   ```bash
   git commit -m "feat: add new anomaly detection pattern"
   git commit -m "fix: resolve checkbox selection issue"
   git commit -m "docs: update README with new features"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   # Open Pull Request on GitHub
   ```

### Contribution Ideas
- Add new injection pattern detection
- Implement additional ML algorithms
- Create unit tests and integration tests
- Improve UI/UX with new animations
- Add database persistence (PostgreSQL/MongoDB)
- Implement user authentication
- Add batch processing for multiple files
- Create CLI interface
- Add internationalization (i18n)

---

## 📄 License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2024 PoisonProof AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

See [LICENSE](LICENSE) file for full text.

---

## 🙏 Acknowledgments

- **Bootstrap Team**: Excellent CSS framework
- **Plotly**: Interactive data visualization library
- **Flask Community**: Robust web framework and extensions
- **scikit-learn**: Comprehensive ML library
- **Pillow**: Python imaging library
- **Open Source Community**: Inspiration and tools

---

## 📞 Support

### Get Help
- **Email**: joedanielajd@gmail.com
- **GitHub Issues**: [Create an issue](https://github.com/joedanields/PoisonProof-AI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/joedanields/PoisonProof-AI/discussions)

### Documentation
- [FEATURES.md](FEATURES.md) - Detailed feature documentation
- [DATASET_GUIDE.md](DATASET_GUIDE.md) - Dataset creation guide
- [TRAINING_QUICKSTART.md](TRAINING_QUICKSTART.md) - ML training quick start

---

## 🔮 Roadmap

### Version 2.0 (Planned)
- [ ] Database persistence (PostgreSQL)
- [ ] User authentication and authorization
- [ ] Multi-user support with teams
- [ ] Real-time collaboration features
- [ ] Advanced ML models (Deep Learning)
- [ ] Natural language processing for text anomalies
- [ ] API rate limiting and authentication
- [ ] Docker containerization
- [ ] Kubernetes deployment config
- [ ] Comprehensive unit and integration tests

### Version 3.0 (Future)
- [ ] Cloud deployment (AWS/Azure/GCP)
- [ ] Microservices architecture
- [ ] GraphQL API
- [ ] Real-time dashboards with WebSocket
- [ ] Mobile app (React Native)
- [ ] Plugin system for custom detectors
- [ ] Integration with CI/CD pipelines
- [ ] Blockchain-based audit trail
- [ ] Federated learning support

---

## 📊 Statistics

- **Lines of Code**: ~5,000+
- **Python Files**: 12
- **Templates**: 8
- **Detection Patterns**: 40+
- **Supported Algorithms**: 4
- **API Endpoints**: 4
- **Documentation Pages**: 4

---

## 🎓 Educational Use

This project is designed for:
- **Cybersecurity Education**: Understanding data poisoning attacks
- **ML Security**: Learning about adversarial machine learning
- **Web Development**: Flask application architecture
- **Data Science**: Anomaly detection techniques
- **DevSecOps**: Secure development practices

---

## ⚠️ Disclaimer

This is a **proof-of-concept** and **educational tool**. For production use:
- Implement additional security hardening
- Add comprehensive error handling
- Set up proper logging and monitoring
- Use database instead of JSON files
- Add user authentication
- Implement rate limiting
- Conduct security audit
- Add automated testing

---

## 📝 Changelog

### Version 1.0.0 (November 5, 2024)

**Features**
- ✅ Initial release with core functionality
- ✅ CSV and image upload support
- ✅ 40+ injection pattern detection
- ✅ Statistical anomaly detection (MAD/IQR)
- ✅ Image forensics (ELA/EXIF/Entropy)
- ✅ Live ML training console with SSE
- ✅ Model comparison dashboard
- ✅ Auto-clean and manual review modes
- ✅ Cyber-themed UI with Matrix rain
- ✅ RESTful API (4 endpoints)
- ✅ SHA-256 integrity verification
- ✅ Training dataset (800 rows)
- ✅ Comprehensive documentation

**Bug Fixes**
- Fixed template variable access in clean.html
- Fixed models dashboard JSON format compatibility
- Fixed checkbox selection row extraction
- Fixed excessive whitespace on landing pages
- Enhanced dropdown visibility with custom styling

---

**Made with ❤️ and ☕ by the PoisonProof AI Team**

*Securing AI, One Dataset at a Time* 🛡️
#   P O I S O N _ P R O O F - A I - V 2 
 
 
