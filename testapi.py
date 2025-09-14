"""
Test script for ML Prediction API integration
"""

import requests
import json
import time

# API Configuration
API_BASE_URL = "http://localhost:5000"
HEALTH_URL = f"{API_BASE_URL}/health"
PREDICT_URL = f"{API_BASE_URL}/predict"
SINGLE_PREDICT_URL = f"{API_BASE_URL}/predict/single"

def test_health_check():
    """Test the health check endpoint"""
    print("🔍 Testing health check endpoint...")
    try:
        response = requests.get(HEALTH_URL, timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed")
            print(f"   Status: {data.get('status')}")
            print(f"   Model loaded: {data.get('model_loaded')}")
            print(f"   Timestamp: {data.get('timestamp')}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_single_prediction():
    """Test single prediction endpoint"""
    print("\n🔍 Testing single prediction endpoint...")
    
    # Sample ML string (suspicious process from Downloads folder)
    sample_ml_string = "12345,1,0,1,1,1,0,1,0,1,1,0,65,5,15,0.25,2,0,1,4.2"
    
    payload = {
        "ml_string": sample_ml_string
    }
    
    try:
        response = requests.post(
            SINGLE_PREDICT_URL, 
            json=payload, 
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Single prediction successful")
            print(f"   Processing time: {data.get('processing_time', 0):.4f}s")
            
            predictions = data.get('predictions', [])
            if predictions:
                pred = predictions[0]
                print(f"   Process ID: {pred['process_id']}")
                print(f"   Prediction: {pred['prediction']}")
                print(f"   Confidence: {pred['confidence']}")
                print(f"   Top reasons:")
                for reason in pred['reasoning'][:2]:
                    print(f"     - {reason['description']}")
            return True
        else:
            print(f"❌ Single prediction failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Single prediction error: {e}")
        return False

def test_batch_prediction():
    """Test batch prediction endpoint"""
    print("\n🔍 Testing batch prediction endpoint...")
    
    # Sample ML strings (mix of suspicious and benign)
    sample_ml_strings = [
        "12345,1,0,1,1,1,0,1,0,1,1,0,65,5,15,0.25,2,0,1,4.2",  # Suspicious
        "67890,0,0,0,1,0,0,0,0,0,0,1,31,3,11,1.0,0,1,1,2.5",   # Benign system process
        "11111,1,1,0,1,1,1,1,1,1,1,0,95,7,22,0.1,3,0,0,5.8",   # Very suspicious
        "22222,0,0,0,0,1,0,0,0,1,0,1,45,4,12,2.0,-1,1,1,1.2"   # Normal
    ]
    
    payload = {
        "ml_strings": sample_ml_strings
    }
    
    try:
        response = requests.post(
            PREDICT_URL, 
            json=payload, 
            headers={'Content-Type': 'application/json'},
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Batch prediction successful")
            print(f"   Processing time: {data.get('processing_time', 0):.4f}s")
            print(f"   Total processes: {data.get('total_processes', 0)}")
            
            summary = data.get('summary', {})
            print(f"   Summary: {summary.get('malware_count', 0)} malware, "
                  f"{summary.get('benign_count', 0)} benign "
                  f"({summary.get('malware_percentage', 0)}% malware)")
            
            # Show individual predictions (fixed formatting)
            predictions = data.get('predictions', [])
            print("   Individual results:")
            for pred in predictions:
                status_icon = "🚨" if pred['prediction'] == 'malware' else "✅"
                print(f"     {status_icon} Process {pred['process_id']}: {pred['prediction']} "
                      f"(confidence: {pred['confidence']:.3f})")
            
            return True
        else:
            print(f"❌ Batch prediction failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Batch prediction error: {e}")
        return False

def test_error_handling():
    """Test error handling"""
    print("\n🔍 Testing error handling...")
    
    # Test with invalid ML string
    invalid_payload = {
        "ml_strings": ["invalid,data,string"]
    }
    
    try:
        response = requests.post(
            PREDICT_URL, 
            json=invalid_payload, 
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 400:
            print("✅ Error handling working correctly (returned 400 for invalid data)")
            return True
        else:
            print(f"⚠️ Unexpected response for invalid data: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Testing ML Prediction API Integration")
    print("="*50)
    
    tests_passed = 0
    total_tests = 4
    
    # Run tests
    if test_health_check():
        tests_passed += 1
    
    if test_single_prediction():
        tests_passed += 1
    
    if test_batch_prediction():
        tests_passed += 1
        
    if test_error_handling():
        tests_passed += 1
    
    # Summary
    print(f"\n📊 Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All tests passed! The API integration is working correctly.")
        print("\n📋 Next steps:")
        print("1. Start the prediction API server: python prediction_api_server.py")
        print("2. Run your Sysmon analyzer: python sysmon_analyzer.py --continuous")
        print("3. The analyzer will automatically send ML features to the API every 30 seconds")
    else:
        print("⚠️ Some tests failed. Please check:")
        print("1. Is the prediction API server running on http://localhost:5000?")
        print("2. Is the XGBoost model file available at 'models/xgb_detector.joblib'?")
        print("3. Are all required Python packages installed (flask, joblib, shap, etc.)?")

if __name__ == "__main__":
    main()