#!/usr/bin/env python3
"""
Model Training Script for CyberSentinel AI - ATITA
Trains ML models for threat classification, severity assessment, and anomaly detection
"""

import asyncio
import sys
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.ml_models import threat_classifier, severity_assessor, anomaly_detector, nlp_model
from core.logging import setup_logging

setup_logging()
logger = setup_logging()


def generate_sample_data():
    """Generate sample training data"""
    
    # Sample threat texts for classification
    threat_texts = [
        "Ransomware attack detected on network server",
        "Phishing email with malicious attachment",
        "Malware infection in user workstation",
        "DDoS attack targeting web servers",
        "Suspicious login attempt from unknown IP",
        "Virus detected in downloaded file",
        "Credential theft attempt via fake login page",
        "Network intrusion detected",
        "Data breach notification",
        "Social engineering attack via phone call",
        "SQL injection attempt on database",
        "Cross-site scripting vulnerability exploited",
        "Man-in-the-middle attack detected",
        "Brute force attack on admin account",
        "Zero-day exploit in web application"
    ]
    
    threat_labels = [
        "ransomware", "phishing", "malware", "ddos", "unknown",
        "malware", "phishing", "unknown", "unknown", "unknown",
        "unknown", "unknown", "unknown", "unknown", "unknown"
    ]
    
    # Sample features for severity assessment
    severity_features = []
    severities = []
    
    for i, text in enumerate(threat_texts):
        feature = {
            "description": text,
            "confidence": np.random.uniform(0.3, 0.95),
            "source_reputation": np.random.uniform(0.1, 1.0),
            "ioc_count": np.random.randint(1, 10),
            "processing_time": np.random.uniform(1, 30)
        }
        severity_features.append(feature)
        
        # Assign severity based on confidence and content
        if "critical" in text.lower() or feature["confidence"] > 0.9:
            severities.append("critical")
        elif "high" in text.lower() or feature["confidence"] > 0.7:
            severities.append("high")
        elif "medium" in text.lower() or feature["confidence"] > 0.5:
            severities.append("medium")
        else:
            severities.append("low")
    
    # Sample threat data for anomaly detection
    threat_data = []
    for i, feature in enumerate(severity_features):
        threat = {
            "confidence": feature["confidence"],
            "description": feature["description"],
            "source_details": {"sender_reputation": feature["source_reputation"]},
            "iocs": ["ioc_" + str(j) for j in range(feature["ioc_count"])],
            "processing_time": feature["processing_time"]
        }
        threat_data.append(threat)
    
    return threat_texts, threat_labels, severity_features, severities, threat_data


async def train_models():
    """Train all ML models"""
    logger.info("Starting model training...")
    
    # Generate sample data
    threat_texts, threat_labels, severity_features, severities, threat_data = generate_sample_data()
    
    try:
        # Train threat classification model
        logger.info("Training threat classification model...")
        classification_accuracy = threat_classifier.train(threat_texts, threat_labels)
        logger.info(f"Classification model accuracy: {classification_accuracy:.3f}")
        
        # Train severity assessment model
        logger.info("Training severity assessment model...")
        severity_accuracy = severity_assessor.train(severity_features, severities)
        logger.info(f"Severity model accuracy: {severity_accuracy:.3f}")
        
        # Train anomaly detection model
        logger.info("Training anomaly detection model...")
        anomaly_detector.train(threat_data)
        logger.info("Anomaly detection model trained successfully")
        
        # Initialize NLP models
        logger.info("Initializing NLP models...")
        nlp_model.initialize()
        
        logger.info("All models trained successfully!")
        
        # Test the models
        await test_models()
        
    except Exception as e:
        logger.error(f"Model training failed: {e}")
        raise


async def test_models():
    """Test the trained models"""
    logger.info("Testing trained models...")
    
    # Test threat classification
    test_text = "Ransomware attack with encryption of critical files"
    threat_type, confidence = threat_classifier.predict(test_text)
    logger.info(f"Classification test: {test_text} -> {threat_type} (confidence: {confidence:.3f})")
    
    # Test severity assessment
    test_features = {
        "description": "Critical ransomware attack with high confidence",
        "confidence": 0.95
    }
    severity, confidence = severity_assessor.predict(test_features)
    logger.info(f"Severity test: {test_features} -> {severity} (confidence: {confidence:.3f})")
    
    # Test anomaly detection
    test_threat = {
        "confidence": 0.3,
        "description": "Unusual pattern detected",
        "source_details": {"sender_reputation": 0.1},
        "iocs": ["suspicious_ioc"],
        "processing_time": 50
    }
    is_anomaly, score = anomaly_detector.detect_anomaly(test_threat)
    logger.info(f"Anomaly test: {test_threat} -> Anomaly: {is_anomaly} (score: {score:.3f})")
    
    # Test NLP analysis
    nlp_result = nlp_model.analyze_sentiment(test_text)
    logger.info(f"NLP sentiment test: {nlp_result}")
    
    entities = nlp_model.extract_entities(test_text)
    logger.info(f"NLP entities test: {entities}")


def main():
    """Main training function"""
    try:
        asyncio.run(train_models())
        logger.info("Model training completed successfully!")
    except Exception as e:
        logger.error(f"Training failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 