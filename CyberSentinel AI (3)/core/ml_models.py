"""
Machine Learning Models for CyberSentinel AI - ATITA
"""

import joblib
import re
from typing import Dict, Any, List, Tuple
from datetime import datetime
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from core.config import settings
from core.logging import get_logger

logger = get_logger("ml_models")

# Optional imports for advanced ML features
try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("TensorFlow not available")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available")

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers not available")

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("Sentence Transformers not available")

try:
    import mlflow
    import mlflow.sklearn
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    logger.warning("MLflow not available")


class ModelManager:
    """Manages ML model lifecycle, versioning, and deployment"""
    
    def __init__(self):
        self.models_dir = Path(settings.model_path)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.models = {}
        self.model_versions = {}
        
    def save_model(self, model, model_name: str, version: str | None = None):
        """Save a model with versioning"""
        if version is None:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        model_path = self.models_dir / f"{model_name}_v{version}.pkl"
        
        # Save with MLflow for experiment tracking if available
        if MLFLOW_AVAILABLE:
            try:
                with mlflow.start_run():
                    mlflow.log_param("model_name", model_name)
                    mlflow.log_param("version", version)
                    
                    if hasattr(model, 'predict_proba'):
                        mlflow.sklearn.log_model(model, f"{model_name}_v{version}")
                    else:
                        mlflow.pytorch.log_model(model, f"{model_name}_v{version}")
            except Exception as e:
                logger.warning(f"MLflow logging failed: {e}")
        
        # Save locally
        joblib.dump(model, model_path)
        self.models[model_name] = model
        self.model_versions[model_name] = version
        
        logger.info(f"Model {model_name} v{version} saved successfully")
        return model_path
    
    def load_model(self, model_name: str, version: str | None = None):
        """Load a specific model version"""
        if version is None:
            # Load latest version
            model_files = list(self.models_dir.glob(f"{model_name}_v*.pkl"))
            if not model_files:
                raise FileNotFoundError(f"No models found for {model_name}")
            model_path = max(model_files, key=lambda x: x.stat().st_mtime)
        else:
            model_path = self.models_dir / f"{model_name}_v{version}.pkl"
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model {model_name} v{version} not found")
        
        model = joblib.load(model_path)
        self.models[model_name] = model
        logger.info(f"Model {model_name} v{version} loaded successfully")
        return model


class ThreatClassificationModel:
    """ML model for threat classification"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.classes = ['malware', 'phishing', 'ransomware', 'ddos', 'unknown']
        self.model_manager = ModelManager()
        
    def train(self, texts: List[str], labels: List[str]):
        """Train the classification model"""
        # Create TF-IDF features
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english'
        )
        
        X = self.vectorizer.fit_transform(texts)
        y = [self.classes.index(label) if label in self.classes else 4 for label in labels]
        
        # Train Random Forest classifier
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"Classification model accuracy: {accuracy:.3f}")
        
        # Save model
        pipeline = Pipeline([
            ('vectorizer', self.vectorizer),
            ('classifier', self.model)
        ])
        
        self.model_manager.save_model(pipeline, "threat_classifier")
        return accuracy
    
    def predict(self, text: str) -> Tuple[str, float]:
        """Predict threat type and confidence"""
        if self.model is None or self.vectorizer is None:
            try:
                pipeline = self.model_manager.load_model("threat_classifier")
                self.vectorizer = pipeline.named_steps['vectorizer']
                self.model = pipeline.named_steps['classifier']
            except FileNotFoundError:
                logger.warning("No trained classification model found")
                return 'unknown', 0.5
        
        X = self.vectorizer.transform([text])  # type: ignore
        prediction = self.model.predict(X)[0]
        confidence = float(np.max(self.model.predict_proba(X)))
        
        threat_type = self.classes[prediction]
        return threat_type, confidence


class SeverityAssessmentModel:
    """ML model for threat severity assessment"""
    
    def __init__(self):
        self.model = None
        self.model_manager = ModelManager()
        
    def train(self, features: List[Dict[str, Any]], severities: List[str]):
        """Train severity assessment model"""
        # Convert features to DataFrame
        df = pd.DataFrame(features)
        
        # Feature engineering
        df['text_length'] = df['description'].str.len()
        df['has_urls'] = df['description'].str.contains('http', case=False).astype(int)
        df['has_attachments'] = df['description'].str.contains('attachment', case=False).astype(int)
        df['urgency_words'] = df['description'].str.count(r'\b(urgent|critical|immediate|emergency)\b', case=False)
        
        # Convert severities to numeric
        severity_map = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        y = [severity_map.get(s, 1) for s in severities]
        
        # Select features
        feature_cols = ['confidence', 'text_length', 'has_urls', 'has_attachments', 'urgency_words']
        X = df[feature_cols].fillna(0)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"Severity model accuracy: {accuracy:.3f}")
        
        # Save model
        self.model_manager.save_model(self.model, "severity_assessor")
        return accuracy
    
    def predict(self, features: Dict[str, Any]) -> Tuple[str, float]:
        """Predict severity and confidence"""
        if self.model is None:
            try:
                self.model = self.model_manager.load_model("severity_assessor")
            except FileNotFoundError:
                logger.warning("No trained severity model found")
                return 'medium', 0.5
        
        # Prepare features
        feature_vector = np.array([
            features.get('confidence', 0.5),
            len(features.get('description', '')),
            int('http' in features.get('description', '').lower()),
            int('attachment' in features.get('description', '').lower()),
            len(re.findall(r'\b(urgent|critical|immediate|emergency)\b', features.get('description', ''), re.IGNORECASE))
        ]).reshape(1, -1)
        
        prediction = self.model.predict(feature_vector)[0]
        confidence = float(np.max(self.model.predict_proba(feature_vector)))
        
        severity_map = {0: 'low', 1: 'medium', 2: 'high', 3: 'critical'}
        severity = severity_map.get(prediction, 'medium')
        
        return severity, confidence


class AnomalyDetectionModel:
    """ML model for anomaly detection in threat patterns"""
    
    def __init__(self):
        self.model = None
        self.model_manager = ModelManager()
        
    def train(self, threat_data: List[Dict[str, Any]]):
        """Train anomaly detection model"""
        # Extract features for anomaly detection
        features = []
        for threat in threat_data:
            feature_vector = [
                threat.get('confidence', 0.5),
                len(threat.get('description', '')),
                threat.get('source_details', {}).get('sender_reputation', 0.5),
                len(threat.get('iocs', [])),
                threat.get('processing_time', 0)
            ]
            features.append(feature_vector)
        
        X = np.array(features)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination="auto",  # Use auto instead of float
            random_state=42
        )
        self.model.fit(X)
        
        # Save model
        self.model_manager.save_model(self.model, "anomaly_detector")
        logger.info("Anomaly detection model trained successfully")
    
    def detect_anomaly(self, threat_data: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if threat is anomalous"""
        if self.model is None:
            try:
                self.model = self.model_manager.load_model("anomaly_detector")
            except FileNotFoundError:
                logger.warning("No trained anomaly detection model found")
                return False, 0.0
        
        feature_vector = np.array([
            threat_data.get('confidence', 0.5),
            len(threat_data.get('description', '')),
            threat_data.get('source_details', {}).get('sender_reputation', 0.5),
            len(threat_data.get('iocs', [])),
            threat_data.get('processing_time', 0)
        ]).reshape(1, -1)
        
        # Isolation Forest returns -1 for anomalies, 1 for normal
        prediction = self.model.predict(feature_vector)[0]
        anomaly_score = self.model.decision_function(feature_vector)[0]
        
        is_anomaly = prediction == -1
        return is_anomaly, abs(anomaly_score)


class NLPModel:
    """NLP model for text analysis and sentiment"""
    
    def __init__(self):
        self.sentiment_analyzer = None
        self.text_classifier = None
        self.embedding_model = None
        self.model_manager = ModelManager()
        
    def initialize(self):
        """Initialize NLP models"""
        if not TRANSFORMERS_AVAILABLE:
            logger.warning("Transformers not available, skipping NLP model initialization")
            return
            
        try:
            # Sentiment analysis
            self.sentiment_analyzer = pipeline(
                "sentiment-analysis",
                model="cardiffnlp/twitter-roberta-base-sentiment-latest"
            )
            
            # Text classification for threat indicators
            self.text_classifier = pipeline(
                "text-classification",
                model="microsoft/DialoGPT-medium"
            )
            
            # Sentence embeddings
            if SENTENCE_TRANSFORMERS_AVAILABLE:
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            logger.info("NLP models initialized successfully")
        except Exception as e:
            logger.warning(f"Could not load pre-trained NLP models: {e}")
    
    def analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """Analyze sentiment of threat description"""
        if self.sentiment_analyzer is None:
            return {"sentiment": "neutral", "confidence": 0.5}
        
        try:
            result = self.sentiment_analyzer(text[:512])  # Limit text length
            # Convert generator to list if needed
            if hasattr(result, '__iter__') and not hasattr(result, 'get'):
                result = list(result)  # type: ignore
            
            if result and len(result) > 0:  # type: ignore
                first_result = result[0]  # type: ignore
                return {
                    "sentiment": first_result.get('label', 'neutral'),  # type: ignore
                    "confidence": float(first_result.get('score', 0.5))  # type: ignore
                }
            else:
                return {"sentiment": "neutral", "confidence": 0.5}
        except Exception as e:
            logger.error(f"Sentiment analysis failed: {e}")
            return {"sentiment": "neutral", "confidence": 0.5}
    
    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extract named entities from text"""
        entities = []
        
        # Simple entity extraction (in production, use spaCy or similar)
        # Extract URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        for url in urls:
            entities.append({"type": "URL", "value": url, "confidence": 0.9})
        
        # Extract IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        for ip in ips:
            entities.append({"type": "IP_ADDRESS", "value": ip, "confidence": 0.8})
        
        # Extract email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        for email in emails:
            entities.append({"type": "EMAIL", "value": email, "confidence": 0.9})
        
        return entities
    
    def get_embeddings(self, text: str) -> List[float]:
        """Get text embeddings for similarity analysis"""
        if self.embedding_model is None:
            return [0.0] * 384  # Default embedding size
        
        try:
            embeddings = self.embedding_model.encode(text)
            # Handle different tensor types
            if hasattr(embeddings, 'tolist'):
                return embeddings.tolist()  # type: ignore
            elif hasattr(embeddings, 'detach'):
                # PyTorch tensor
                return embeddings.detach().numpy().tolist()  # type: ignore
            else:
                # Convert any iterable to list of floats
                return [float(x) for x in embeddings]
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            return [0.0] * 384


# Global model instances
model_manager = ModelManager()
threat_classifier = ThreatClassificationModel()
severity_assessor = SeverityAssessmentModel()
anomaly_detector = AnomalyDetectionModel()
nlp_model = NLPModel() 