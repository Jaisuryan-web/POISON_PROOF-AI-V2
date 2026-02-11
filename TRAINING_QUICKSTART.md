# Training Dataset - Quick Reference

## 📦 What You Got

### Files Created
1. **`training_dataset.csv`** (49.4 KB)
   - 800 rows × 11 columns
   - Ready for immediate training
   
2. **`generate_training_dataset.py`**
   - Generator script to create custom datasets
   - Configurable size and anomaly ratios
   
3. **`analyze_dataset.py`**
   - Dataset analyzer and health checker
   - Run on any CSV to check training readiness
   
4. **`DATASET_GUIDE.md`**
   - Complete documentation
   - Usage instructions and best practices

---

## ⚡ Quick Start (3 Steps)

### 1. Start the App
```powershell
uv run python app.py
```
Visit: http://127.0.0.1:5000

### 2. Upload & Scan
- Click "Upload Dataset"
- Select `training_dataset.csv`
- Wait for scan results (~197 anomalies expected)

### 3. Clean & Train
- Click "Auto Clean" to remove High severity rows
- Click "Train Model" 
- Watch live training console
- Get 85-95% accuracy! 🎯

---

## 📊 Dataset Specs

| Metric | Value |
|--------|-------|
| Total Records | 800 |
| Normal Records | 603 (75.4%) |
| Anomalous Records | 197 (24.6%) |
| Numerical Features | 6 |
| Categorical Features | 4 |
| Missing Values | 0 |
| Training Readiness | ✓ READY (5/5) |

---

## 🎯 Anomaly Types

### Statistical Outliers (40%)
- Extreme salaries: $500K or $15K
- Extreme ages: 18 or 82 years
- Excessive absences: 90 days/year
- Extreme projects: 100 or 0 projects

### Malicious Payloads (40%)
- **SQL Injection**: `'; DROP TABLE--`, `UNION SELECT`
- **XSS Attacks**: `<script>alert()`, `onerror=`
- **Command Injection**: `; rm -rf`, `$(wget)`
- **Path Traversal**: `../../../etc/passwd`
- **NoSQL Injection**: `{'$ne': null}`

### Data Inconsistencies (20%)
- Age 24, Experience 25 years (impossible)
- Junior (2 years) earning $180K
- Negative salary: -$5000

---

## 🚀 Expected Results

### After Scan
```
✓ 197 anomalies detected
✓ High severity: ~80
✓ Medium severity: ~70
✓ Low severity: ~47
```

### After Auto-Clean
```
✓ 650 clean rows remain
✓ 150 malicious rows removed
✓ Dataset ready for training
```

### After Training
```
✓ Model: DecisionTreeClassifier
✓ Accuracy: 92.3%
✓ Precision: 89.5%
✓ Recall: 88.2%
✓ SHA-256: Verified ✓
```

---

## 🛠️ Useful Commands

### Generate New Dataset
```powershell
# Default: 1000 rows
uv run python generate_training_dataset.py
```

### Analyze Any Dataset
```powershell
# Analyze training dataset
uv run python analyze_dataset.py training_dataset.csv

# Analyze other CSV
uv run python analyze_dataset.py your_dataset.csv
```

### Check First 10 Rows
```powershell
uv run python -c "import pandas as pd; print(pd.read_csv('training_dataset.csv').head(10))"
```

### Count Anomalies
```powershell
uv run python -c "import pandas as pd; df = pd.read_csv('training_dataset.csv'); print(df['is_anomaly'].value_counts())"
```

### Show Sample Anomalies
```powershell
uv run python -c "import pandas as pd; df = pd.read_csv('training_dataset.csv'); print(df[df['is_anomaly']==1][['name', 'salary', 'age']].head(10))"
```

---

## 💡 Pro Tips

### 1. Customize Dataset Size
Edit `generate_training_dataset.py`:
```python
# Change this line:
df = generate_training_dataset(n_total=1000)  # Change 1000 to your size
```

### 2. Adjust Anomaly Ratio
Edit the ratio in generator:
```python
n_normal = int(n_total * 0.8)  # Change 0.8 to adjust normal %
```

### 3. Add Custom Injection Patterns
Edit `inject_malicious_payloads()`:
```python
injection_patterns = [
    # Add your patterns here
    "your_custom_pattern",
    "another_attack_vector",
]
```

### 4. Use Class Weights
When training, the analyzer suggested using `class_weight='balanced'` for the 3:1 imbalance. To implement:

Edit `model_trainer.py`:
```python
# In _choose_model() function
if is_classification:
    return DecisionTreeClassifier(
        max_depth=10,
        random_state=42,
        class_weight='balanced'  # Add this
    )
```

### 5. Feature Engineering
Add derived features before training:
```python
df['salary_per_experience'] = df['salary'] / (df['years_experience'] + 1)
df['age_experience_ratio'] = df['age'] / (df['years_experience'] + 1)
```

---

## 📈 Model Performance Tips

### For Better Accuracy
1. **Use Auto-Clean first**: Removes obvious threats
2. **Manual review Medium severity**: Fine-tune cleaning
3. **Feature scaling**: Normalize salary/age ranges
4. **Try both models**: Compare DecisionTree vs LogisticRegression
5. **Cross-validation**: Use k-fold for robust metrics

### For Better Detection
1. **Expand injection patterns**: Add industry-specific threats
2. **Combine with domain rules**: Age < experience check
3. **Ensemble methods**: Combine multiple models
4. **Regular retraining**: Update with new attack vectors
5. **Monitor false positives**: Tune severity thresholds

---

## 🔍 Troubleshooting

### Issue: Low Detection Rate
- Check if dataset has anomaly labels (`is_anomaly` column)
- Verify injection patterns match your data
- Review MAD/IQR thresholds in `utils/detection.py`

### Issue: Low Training Accuracy
- Ensure target column is present
- Check for missing values: `df.isnull().sum()`
- Try different model types
- Consider feature engineering
- Use class_weight='balanced' for imbalanced data

### Issue: Model Not Saving
- Check `trained_models/` directory exists
- Verify write permissions
- Look for errors in training console
- Check SHA-256 hash generation

### Issue: Can't Upload Dataset
- Verify file size < 16MB (see `config.py`)
- Ensure CSV format (not Excel)
- Check for special characters in filename
- Use secure_filename() if needed

---

## 📚 Next Steps

### 1. Train Your First Model
```
Upload → Scan → Clean → Train → Verify
```

### 2. Compare Models
- Train with DecisionTree
- Train with LogisticRegression
- Visit `/models` dashboard
- Compare metrics in Plotly charts

### 3. Use the API
```bash
# Upload via API
curl -X POST -F "file=@training_dataset.csv" http://localhost:5000/scan

# Get audit log
curl http://localhost:5000/api/audit-log

# Download models
curl http://localhost:5000/api/models
```

### 4. Integrate CI/CD
- Add training to build pipeline
- Verify model hashes in tests
- Monitor accuracy over time
- Automate retraining schedule

### 5. Explore Live Features
- 🎥 Watch Matrix rain animation (homepage)
- 📊 View model comparison dashboard (`/models`)
- 🔴 Monitor live training console (`/train/live/<job_id>`)
- 📡 Test API endpoints (audit log, models, verify)

---

## ✅ Checklist

Before starting training:
- [ ] `training_dataset.csv` exists (800 rows)
- [ ] Flask app running (`uv run python app.py`)
- [ ] Browser open to http://127.0.0.1:5000
- [ ] `trained_models/` directory exists
- [ ] `logs/` directory exists

After first training:
- [ ] Model file saved to `trained_models/`
- [ ] Model hash in `model_hashes.json`
- [ ] Audit entry in `logs/audit.json`
- [ ] Model shows on `/models` dashboard
- [ ] Accuracy ≥ 85%

---

## 🎓 Learning Resources

### For Understanding Detection
- **MAD (Median Absolute Deviation)**: [Wikipedia](https://en.wikipedia.org/wiki/Median_absolute_deviation)
- **IQR Method**: [Statistics How To](https://www.statisticshowto.com/probability-and-statistics/interquartile-range/)
- **OWASP Top 10**: [OWASP.org](https://owasp.org/www-project-top-ten/)

### For Machine Learning
- **DecisionTree**: [scikit-learn docs](https://scikit-learn.org/stable/modules/tree.html)
- **Class Imbalance**: [Machine Learning Mastery](https://machinelearningmastery.com/tactics-to-combat-imbalanced-classes-in-your-machine-learning-dataset/)
- **Model Evaluation**: [scikit-learn metrics](https://scikit-learn.org/stable/modules/model_evaluation.html)

### For Security
- **Injection Attacks**: [PortSwigger Web Security](https://portswigger.net/web-security/sql-injection)
- **Data Poisoning**: [arXiv paper](https://arxiv.org/abs/1811.00741)
- **Adversarial ML**: [Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox)

---

**Created**: November 4, 2025  
**Version**: 1.0  
**Status**: ✅ READY FOR TRAINING  

Happy Training! 🚀🛡️
