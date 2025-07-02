#!/usr/bin/env python3
"""
Test script for CyberSentinel AI - ATITA
Tests all major components and API endpoints
"""

import asyncio
import json
import requests
import time
from datetime import datetime
from core.models import ThreatType, ThreatSeverity, SourceType

def test_health_endpoint():
    """Test the health endpoint"""
    print("🔍 Testing health endpoint...")
    try:
        response = requests.get("http://localhost:8000/health")
        if response.status_code == 200:
            print("✅ Health endpoint working")
            return True
        else:
            print(f"❌ Health endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health endpoint error: {e}")
        return False

def test_threat_submission():
    """Test threat submission with proper data"""
    print("🔍 Testing threat submission...")
    
    threat_data = {
        "title": "Suspicious Email Detected",
        "description": "Phishing email attempting to steal credentials from employees",
        "source": "email",
        "source_details": {
            "sender": "suspicious@example.com",
            "recipient": "employee@company.com",
            "subject": "Urgent: Account Verification Required"
        },
        "threat_metadata": {
            "detection_method": "email_filter",
            "confidence": 0.85
        }
    }
    
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/threats",
            headers={"Content-Type": "application/json"},
            data=json.dumps(threat_data)
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Threat submitted successfully: {result['threat_id']}")
            return result['threat_id']
        else:
            print(f"❌ Threat submission failed: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Threat submission error: {e}")
        return None

def test_threat_retrieval(threat_id):
    """Test retrieving a threat by ID"""
    if not threat_id:
        return False
        
    print(f"🔍 Testing threat retrieval for {threat_id}...")
    try:
        response = requests.get(f"http://localhost:8000/api/v1/threats/{threat_id}")
        if response.status_code == 200:
            threat = response.json()
            print(f"✅ Threat retrieved successfully")
            print(f"   Title: {threat['title']}")
            print(f"   Status: {threat['status']}")
            print(f"   Type: {threat['threat_type']}")
            print(f"   Severity: {threat['severity']}")
            return True
        else:
            print(f"❌ Threat retrieval failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Threat retrieval error: {e}")
        return False

def test_analytics():
    """Test analytics endpoint"""
    print("🔍 Testing analytics endpoint...")
    try:
        response = requests.get("http://localhost:8000/api/v1/analytics")
        if response.status_code == 200:
            analytics = response.json()
            print("✅ Analytics endpoint working")
            print(f"   Total threats: {analytics['total_threats_processed']}")
            print(f"   Auto resolution rate: {analytics['auto_resolution_rate']:.2%}")
            return True
        else:
            print(f"❌ Analytics failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Analytics error: {e}")
        return False

def test_agent_status():
    """Test agent status endpoint"""
    print("🔍 Testing agent status endpoint...")
    try:
        response = requests.get("http://localhost:8000/api/v1/agents/status")
        if response.status_code == 200:
            agents = response.json()
            print("✅ Agent status endpoint working")
            for agent in agents:
                print(f"   {agent['agent_name']}: {agent['status']}")
            return True
        else:
            print(f"❌ Agent status failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Agent status error: {e}")
        return False

def test_ml_models():
    """Test ML model functionality"""
    print("🔍 Testing ML models...")
    try:
        from core.ml_models import threat_classifier, severity_assessor, anomaly_detector, nlp_model
        
        # Test NLP model
        text = "This is a suspicious phishing email"
        sentiment = nlp_model.analyze_sentiment(text)
        entities = nlp_model.extract_entities(text)
        embeddings = nlp_model.get_embeddings(text)
        
        print("✅ NLP models working")
        print(f"   Sentiment: {sentiment}")
        print(f"   Entities found: {len(entities)}")
        print(f"   Embedding dimensions: {len(embeddings)}")
        
        # Test classification (will use fallback if no trained model)
        threat_type, confidence = threat_classifier.predict(text)
        print(f"   Threat classification: {threat_type} (confidence: {confidence:.2f})")
        
        return True
    except Exception as e:
        print(f"❌ ML models error: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting CyberSentinel AI - ATITA System Tests")
    print("=" * 50)
    
    # Wait for server to be ready
    print("⏳ Waiting for server to be ready...")
    time.sleep(2)
    
    tests = [
        ("Health Endpoint", test_health_endpoint),
        ("ML Models", test_ml_models),
        ("Threat Submission", test_threat_submission),
        ("Analytics", test_analytics),
        ("Agent Status", test_agent_status),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_name == "Threat Submission":
                threat_id = test_func()
                results[test_name] = threat_id is not None
                if threat_id:
                    # Test threat retrieval
                    results["Threat Retrieval"] = test_threat_retrieval(threat_id)
            else:
                results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results[test_name] = False
    
    # Summary
    print(f"\n{'='*50}")
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the logs above for details.")

if __name__ == "__main__":
    main() 