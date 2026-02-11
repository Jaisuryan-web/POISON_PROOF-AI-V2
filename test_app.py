#!/usr/bin/env python3
"""
Simple test script to verify the Flask application works correctly
"""

import os
import sys
import tempfile
import pandas as pd
from PIL import Image
import numpy as np

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, calculate_file_hash, simulate_anomaly_detection

def test_app_creation():
    """Test that the app can be created successfully"""
    app = create_app('testing')
    assert app is not None
    print("✓ App creation test passed")

def test_file_hash():
    """Test the SHA-256 hash calculation"""
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("This is a test file for hashing")
        temp_path = f.name
    
    try:
        hash_result = calculate_file_hash(temp_path)
        assert len(hash_result) == 64  # SHA-256 produces 64 character hex string
        assert all(c in '0123456789abcdef' for c in hash_result)
        print("✓ File hash test passed")
    finally:
        os.unlink(temp_path)

def test_csv_anomaly_detection():
    """Test anomaly detection on a sample CSV file"""
    # Create a sample CSV file
    data = {
        'feature1': np.random.normal(0, 1, 100),
        'feature2': np.random.normal(5, 2, 100),
        'feature3': np.random.uniform(0, 10, 100)
    }
    df = pd.DataFrame(data)
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
        df.to_csv(f.name, index=False)
        temp_path = f.name
    
    try:
        anomalies = simulate_anomaly_detection(temp_path, 'csv')
        assert isinstance(anomalies, list)
        assert len(anomalies) > 0
        
        # Check anomaly structure
        for anomaly in anomalies:
            assert 'type' in anomaly
            assert 'location' in anomaly
            assert 'severity' in anomaly
            assert 'description' in anomaly
            assert 'confidence' in anomaly
        
        print("✓ CSV anomaly detection test passed")
    finally:
        os.unlink(temp_path)

def test_image_anomaly_detection():
    """Test anomaly detection on a sample image file"""
    # Create a sample image
    img_array = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(img_array)
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as f:
        img.save(f.name, 'PNG')
        temp_path = f.name
    
    try:
        anomalies = simulate_anomaly_detection(temp_path, 'png')
        assert isinstance(anomalies, list)
        assert len(anomalies) > 0
        
        # Check anomaly structure
        for anomaly in anomalies:
            assert 'type' in anomaly
            assert 'location' in anomaly
            assert 'severity' in anomaly
            assert 'description' in anomaly
            assert 'confidence' in anomaly
        
        print("✓ Image anomaly detection test passed")
    finally:
        os.unlink(temp_path)

def test_flask_routes():
    """Test that all Flask routes are accessible"""
    app = create_app('testing')
    
    with app.test_client() as client:
        # Test home page
        response = client.get('/')
        assert response.status_code == 200
        assert b'PoisonProof AI' in response.data
        
        # Test upload page
        response = client.get('/upload')
        assert response.status_code == 200
        assert b'Upload Your Dataset' in response.data
        
        print("✓ Flask routes test passed")

def run_all_tests():
    """Run all tests"""
    print("Running PoisonProof AI Tests...")
    print("=" * 40)
    
    try:
        test_app_creation()
        test_file_hash()
        test_csv_anomaly_detection()
        test_image_anomaly_detection()
        test_flask_routes()
        
        print("=" * 40)
        print("✅ All tests passed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)