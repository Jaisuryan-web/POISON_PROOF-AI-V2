# PoisonProof AI v2 - User Guide

## 🎯 Welcome to PoisonProof AI

PoisonProof AI v2 is an enterprise-grade security platform that combines advanced threat detection, machine learning security, and AI-powered cybersecurity assistance through **Sentra**, your intelligent security assistant.

---

## 🚀 Quick Start

### System Requirements
- **Python 3.10+** (Python 3.12 supported)
- **Memory**: 8GB RAM minimum (16GB recommended)
- **Storage**: 10GB free space
- **Network**: Stable internet connection for threat intelligence updates

### Installation (Windows)

1. **Install UV Package Manager**
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install uv
   ```

2. **Clone Repository**
   ```powershell
   git clone https://github.com/Jaisuryan-web/POISON_PROOF-AI-V2.git
   cd POISON_PROOF-AI-V2
   ```

3. **Create Virtual Environment**
   ```powershell
   uv venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. **Install Dependencies**
   ```powershell
   uv pip install -r requirements.txt
   ```

5. **Launch Application**
   ```powershell
   uv run python run.py
   ```

### Access the Platform
- **URL**: http://127.0.0.1:5000
- **Default Port**: 5000
- **First Load**: May take 30-60 seconds for initialization

---

## 🏠 Navigation Overview

### Main Menu
1. **Home** - Dashboard overview and system status
2. **Scan Dataset** - Upload and analyze CSV/image files
3. **Models** - View trained ML models and performance
4. **Train** - Train new ML models with custom data
5. **Sentra** - AI Security Assistant for cybersecurity guidance

### Quick Actions
- **Upload Files**: Drag & drop or click to upload
- **Real-time Analysis**: Watch detection progress live
- **Model Training**: One-click training with progress tracking
- **Chat with Sentra**: Ask cybersecurity questions naturally

---

## 📊 Dataset Scanning

### Supported File Types

#### CSV Files
- **Format**: .csv, .xlsx, .xls
- **Max Size**: 100MB
- **Columns**: Auto-detects 11 security-relevant features

#### Image Files
- **Formats**: .jpg, .jpeg, .png, .bmp, .tiff
- **Max Size**: 50MB per image
- **Analysis**: ELA, EXIF, entropy, blur detection

### Security Analysis

#### CSV Security Checks
1. **Injection Attack Detection**
   - SQL Injection: `' OR '1'='1`, `UNION SELECT`
   - XSS Attacks: `<script>`, `javascript:`, `onerror=`
   - Command Injection: `; rm -rf`, `| cat /etc`
   - Path Traversal: `../../../etc/passwd`
   - NoSQL Injection: `{$ne:null}`, `{$gt:""}`
   - LDAP Injection: `*)(uid=*)`, `admin*`

2. **Statistical Anomaly Detection**
   - MAD (Median Absolute Deviation) analysis
   - IQR (Interquartile Range) outliers
   - Z-score anomaly detection
   - Pattern-based anomaly recognition

#### Image Forensics
1. **Error Level Analysis (ELA)**
   - Detects image manipulation and resaving
   - Identifies inconsistent compression artifacts
   - Highlights potential tampering evidence

2. **EXIF Metadata Analysis**
   - Camera information and GPS data
   - Timestamps and software used
   - Potential evidence of manipulation

3. **Entropy Detection**
   - Identifies steganography and hidden data
   - High entropy indicates suspicious content
   - Statistical analysis of pixel distribution

4. **Quality Assessment**
   - Blur detection using gradient variance
   - Dynamic range analysis
   - Compression artifact detection

### Results Interpretation

#### Security Report
- **Risk Level**: Low/Medium/High/Critical
- **Threat Type**: Specific attack category
- **Affected Rows**: Number of suspicious entries
- **Recommendations**: Actionable security advice

#### Visual Indicators
- **🟢 Green**: Safe, no threats detected
- **🟡 Yellow**: Suspicious, manual review needed
- **🔴 Red**: Critical threats found
- **⚠️ Orange**: High-risk anomalies detected

---

## 🤖 Sentra AI Security Assistant

### Getting Started with Sentra

#### Access Sentra
1. Click **"Sentra"** in the main navigation
2. Wait for the chat interface to load
3. Start typing your cybersecurity questions

#### What Sentra Can Help With

##### 🔒 Data Poisoning & ML Security
- "What is data poisoning in machine learning?"
- "How can I prevent adversarial attacks?"
- "What are model robustness techniques?"
- "How to detect poisoned training data?"

##### 💉 Injection Attacks
- "How can I prevent SQL injection attacks?"
- "What are common XSS vulnerabilities?"
- "How to stop command injection?"
- "Best practices for input validation?"

##### 🦠 Malware Protection
- "What are the common types of malware?"
- "How does ransomware work?"
- "How to detect spyware?"
- "What's the difference between virus and worm?"

##### 🛡️ Network Security
- "How does a firewall protect my network?"
- "What are VPN best practices?"
- "How to configure network segmentation?"
- "What is zero-trust architecture?"

##### 🔐 Password Security
- "How do I create strong passwords?"
- "What are password manager best practices?"
- "How to implement multi-factor authentication?"
- "What are common password attacks?"

#### Using Sentra Effectively

##### Question Tips
- **Be Specific**: "How to prevent SQL injection in Python Flask apps?"
- **Provide Context**: "I'm securing a healthcare application, what are the compliance requirements?"
- **Ask for Examples**: "Show me SQL injection prevention code examples"
- **Follow-up Questions**: "That helped, but what about ORM frameworks?"

##### Conversation Features
- **History**: Sentra remembers previous questions in the session
- **Context**: Builds on previous answers for deeper understanding
- **Clear Chat**: Start fresh conversations for privacy
- **Suggestions**: Quick access to common topics

#### Advanced Features

##### Code Examples
Sentra provides practical code snippets:
```python
# Example: Parameterized query to prevent SQL injection
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

##### Prevention Checklists
Step-by-step security guidance:
1. Input validation patterns
2. Output encoding techniques
3. Authentication best practices
4. Monitoring and logging

##### Real-world Scenarios
Industry-specific security advice:
- Healthcare applications
- Financial services
- E-commerce platforms
- Government systems

---

## 🎓 Machine Learning Platform

### Model Training

#### Quick Training
1. Navigate to **"Train"** section
2. Click **"Start Training"** for auto-training
3. Watch real-time progress with SSE streaming
4. Review accuracy metrics and confusion matrix

#### Custom Training
1. **Upload Dataset**: Use your own CSV file
2. **Configure Parameters**:
   - Algorithm: Random Forest, Gradient Boosting, SVM, Logistic Regression
   - Test Size: 20-30% recommended
   - Cross-validation: 5-fold standard
3. **Monitor Training**: Real-time accuracy tracking
4. **Evaluate Performance**: ROC curves, feature importance

### Model Management

#### Model Registry
- **SHA-256 Verification**: Cryptographic integrity checks
- **Performance Metrics**: Accuracy, precision, recall, F1-score
- **Training History**: Timestamps and datasets used
- **Model Comparison**: Side-by-side performance analysis

#### Advanced Features
- **Feature Importance**: Understand what drives predictions
- **ROC Curves**: True positive vs false positive rates
- **Confusion Matrix**: Detailed classification analysis
- **Classification Reports**: Comprehensive performance metrics

---

## 🔧 Configuration & Customization

### Environment Setup

#### Development Mode
```python
# Set Flask environment
set FLASK_ENV=development
uv run python run.py
```

#### Production Mode
```python
# Production configuration
set FLASK_ENV=production
uv run python run.py
```

### Custom Configuration

#### Detection Sensitivity
- **Low Sensitivity**: Fewer false positives, might miss some threats
- **Medium Sensitivity**: Balanced approach (recommended)
- **High Sensitivity**: Maximum detection, more false positives

#### Model Parameters
- **Algorithms**: Choose from 4 ML algorithms
- **Training Epochs**: 100-500 depending on dataset size
- **Learning Rate**: 0.001-0.1 for optimal convergence

---

## 🚨 Troubleshooting

### Common Issues

#### Installation Problems
**Issue**: "ModuleNotFoundError: No module named 'pandas'"
- **Solution**: Ensure virtual environment is activated
- **Command**: `.\.venv\Scripts\Activate.ps1`

**Issue**: "Port 5000 already in use"
- **Solution**: Kill existing process or change port
- **Command**: `uv run python run.py --port 5001`

#### Performance Issues
**Issue**: Slow analysis on large files
- **Solution**: Upload smaller chunks or increase system resources
- **Recommendation**: 16GB RAM for files >50MB

**Issue**: Model training stuck at 0% accuracy
- **Solution**: Check dataset for proper labeling
- **Debug**: Verify target column exists and has correct values

#### UI Problems
**Issue**: Matrix animation not working
- **Solution**: Enable JavaScript and check browser console
- **Browser**: Chrome, Firefox, Safari recommended

**Issue**: Sentra not responding
- **Solution**: Check internet connection for knowledge base
- **Refresh**: Clear browser cache and reload

### Error Messages

#### Security Analysis Errors
- **"Invalid file format"**: Use supported CSV/image formats
- **"File too large"**: Compress files or use smaller datasets
- **"Analysis failed"**: Check file corruption and permissions

#### Model Training Errors
- **"Insufficient memory"**: Reduce dataset size or increase RAM
- **"Convergence failed"**: Adjust learning rate or algorithm parameters
- **"Dataset imbalance"**: Use balanced training data

---

## 📞 Support & Resources

### Getting Help

#### Documentation
- **README.md**: Project overview and installation
- **ROADMAP.md**: Future development plans
- **API Documentation**: REST endpoints and integration

#### Community Support
- **GitHub Issues**: Report bugs and feature requests
- **Discussions**: Ask questions and share knowledge
- **Wiki**: Community-contributed guides

#### Professional Support
- **Email**: support@poisonproof-ai.com
- **Response Time**: 24-48 hours for technical issues
- **Priority**: Enterprise customers receive expedited support

### Security Updates

#### Automatic Updates
- **Threat Intelligence**: Daily updates for new attack patterns
- **Model Improvements**: Monthly algorithm enhancements
- **Security Patches**: Immediate deployment for critical fixes

#### Manual Updates
```bash
# Update to latest version
git pull origin main
uv pip install -r requirements.txt --upgrade
```

---

## 🎯 Best Practices

### Security Workflow

#### Daily Operations
1. **Monitor**: Check dashboard for new alerts
2. **Analyze**: Review detected threats and anomalies
3. **Respond**: Apply recommended security measures
4. **Document**: Record incidents and resolutions

#### Weekly Operations
1. **Update**: Apply security patches and updates
2. **Train**: Retrain models with new data
3. **Review**: Analyze trends and patterns
4. **Plan**: Prepare for emerging threats

#### Monthly Operations
1. **Audit**: Conduct comprehensive security assessment
2. **Backup**: Secure critical data and models
3. **Test**: Validate detection accuracy
4. **Report**: Generate security summaries

### Data Protection

#### Privacy Guidelines
- **Data Minimization**: Only collect necessary information
- **Encryption**: All sensitive data encrypted at rest
- **Access Control**: Role-based permissions
- **Audit Trails**: Complete logging of all actions

#### Compliance Standards
- **ISO 27001**: Information security management
- **SOC 2**: Security controls and processes
- **GDPR**: Data protection and privacy rights
- **HIPAA**: Healthcare data security (if applicable)

---

## 🚀 Advanced Usage

### API Integration

#### REST Endpoints
```python
# Example: Scan file via API
import requests

response = requests.post(
    'http://127.0.0.1:5000/api/scan',
    files={'file': open('data.csv', 'rb')}
)
results = response.json()
```

#### Webhook Configuration
- **Alerts**: Real-time security notifications
- **Integration**: Slack, Teams, Email notifications
- **Customization**: Define alert thresholds and conditions

### Custom Development

#### Extending Sentra
```python
# Add custom knowledge to Sentra
from utils.chatbot import CyberSecurityChatbot

chatbot = CyberSecurityChatbot()
chatbot.add_custom_knowledge("custom_topic", {
    "definition": "Your custom definition",
    "prevention": ["Custom prevention steps"]
})
```

#### Plugin Development
- **Custom Detectors**: Add new threat detection algorithms
- **ML Models**: Integrate custom machine learning models
- **UI Components**: Develop specialized security dashboards

---

*Last Updated: March 2025*
*Version: 2.0.0*
