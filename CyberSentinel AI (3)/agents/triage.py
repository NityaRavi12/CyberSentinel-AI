"""
Triage Agent for CyberSentinel AI - ATITA
Classifies and prioritizes threats using AI/ML models and LLM reasoning
"""

from agents.base_agent import BaseAgent
from core.database import db_manager
from core.models import ThreatType, ThreatSeverity, ThreatStatus
from core.ml_models import threat_classifier, severity_assessor, anomaly_detector, nlp_model
from core.llm_agent import llm_agent
import random

class TriageAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="triage", timeout=60)  # Increased timeout for LLM calls
        self.ml_models_initialized = False
        self.llm_enabled = False

    async def _initialize(self):
        """Initialize ML models and LLM for triage"""
        try:
            # Initialize NLP models (this will handle missing dependencies gracefully)
            nlp_model.initialize()
            
            # Try to load pre-trained models if available
            try:
                # Test if models can be loaded
                threat_classifier.model_manager.load_model("threat_classifier")
                severity_assessor.model_manager.load_model("severity_assessor")
                anomaly_detector.model_manager.load_model("anomaly_detector")
                self.ml_models_initialized = True
                self.logger.info("ML models loaded successfully")
            except FileNotFoundError:
                self.logger.info("No pre-trained models found, using fallback logic")
                self.ml_models_initialized = False
            
            # Check if LLM is available
            if hasattr(llm_agent, 'openai_client') and llm_agent.openai_client:
                self.llm_enabled = True
                self.logger.info("LLM agent enabled for enhanced reasoning")
            elif hasattr(llm_agent, 'anthropic_client') and llm_agent.anthropic_client:
                self.llm_enabled = True
                self.logger.info("LLM agent enabled for enhanced reasoning")
            else:
                self.llm_enabled = False
                self.logger.info("LLM agent not available, using traditional ML only")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize triage agent: {e}")
            self.ml_models_initialized = False
            self.llm_enabled = False

    async def _shutdown(self):
        """Clean up resources"""
        pass

    async def _process_task(self, task_data):
        """Process threat triage using ML models and LLM reasoning"""
        self.logger.info("Triage agent received task", task=task_data)
        threat_data = task_data.get("threat_data")
        threat_id = threat_data.get("id") if threat_data else None
        
        if threat_data and threat_id:
            # Combine title and description for analysis
            text_content = f"{threat_data.get('title', '')} {threat_data.get('description', '')}"
            
            # Traditional ML-based analysis
            ml_results = await self._perform_ml_analysis(threat_data, text_content)
            
            # LLM-enhanced analysis (if available)
            llm_results = {}
            if self.llm_enabled:
                llm_results = await self._perform_llm_analysis(threat_data, ml_results)
            
            # Combine ML and LLM results
            final_results = self._combine_analysis_results(ml_results, llm_results)
            
            # Update threat in database
            await db_manager.update_threat(str(threat_id), {
                "threat_type": final_results["threat_type"].value,
                "severity": final_results["severity"].value,
                "confidence": final_results["confidence"],
                "status": ThreatStatus.TRIAGED.value,
                "threat_metadata": {
                    **threat_data.get("threat_metadata", {}),
                    "ml_analysis": ml_results,
                    "llm_analysis": llm_results,
                    "final_analysis": final_results,
                    "ml_models_used": self.ml_models_initialized,
                    "llm_enabled": self.llm_enabled
                }
            })
            
            return {
                "status": "triaged",
                "threat_id": threat_id,
                "threat_type": final_results["threat_type"].value,
                "severity": final_results["severity"].value,
                "confidence": final_results["confidence"],
                "is_anomaly": final_results["is_anomaly"],
                "anomaly_score": final_results["anomaly_score"],
                "ml_analysis": ml_results,
                "llm_analysis": llm_results,
                "reasoning": final_results.get("reasoning", "Analysis completed")
            }
        
        return {"status": "triaged", "note": "No threat data provided"}

    async def _perform_ml_analysis(self, threat_data: dict, text_content: str) -> dict:
        """Perform traditional ML-based analysis"""
        # ML-based threat classification
        threat_type, type_confidence = await self._classify_threat(text_content)
        
        # ML-based severity assessment
        severity, severity_confidence = await self._assess_severity(threat_data)
        
        # Anomaly detection
        is_anomaly, anomaly_score = await self._detect_anomaly(threat_data)
        
        # NLP analysis
        nlp_analysis = await self._analyze_text(text_content)
        
        return {
            "threat_type": threat_type,
            "type_confidence": type_confidence,
            "severity": severity,
            "severity_confidence": severity_confidence,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "nlp_analysis": nlp_analysis,
            "overall_confidence": (type_confidence + severity_confidence) / 2
        }

    async def _perform_llm_analysis(self, threat_data: dict, ml_results: dict) -> dict:
        """Perform LLM-enhanced analysis"""
        try:
            # Create enhanced threat data with ML results
            enhanced_threat_data = {
                **threat_data,
                "ml_analysis": ml_results
            }
            
            # Get LLM analysis
            llm_analysis = await llm_agent.analyze_threat(enhanced_threat_data)
            
            if "error" in llm_analysis:
                self.logger.warning(f"LLM analysis failed: {llm_analysis['error']}")
                return {"error": llm_analysis["error"]}
            
            return llm_analysis
            
        except Exception as e:
            self.logger.error(f"LLM analysis failed: {e}")
            return {"error": str(e)}

    def _combine_analysis_results(self, ml_results: dict, llm_results: dict) -> dict:
        """Combine ML and LLM results for final decision"""
        # Start with ML results
        final_results = {
            "threat_type": ml_results["threat_type"],
            "severity": ml_results["severity"],
            "confidence": ml_results["overall_confidence"],
            "is_anomaly": ml_results["is_anomaly"],
            "anomaly_score": ml_results["anomaly_score"]
        }
        
        # Enhance with LLM results if available
        if llm_results and "error" not in llm_results:
            # Use LLM confidence if higher than ML
            if llm_results.get("confidence", 0) > ml_results["overall_confidence"]:
                final_results["confidence"] = llm_results["confidence"]
            
            # Use LLM reasoning
            if "reasoning" in llm_results:
                final_results["reasoning"] = llm_results["reasoning"]
            
            # Use LLM impact assessment
            if "impact" in llm_results:
                final_results["impact_assessment"] = llm_results["impact"]
            
            # Use LLM immediate actions
            if "immediate_actions" in llm_results:
                final_results["recommended_actions"] = llm_results["immediate_actions"]
            
            # Use LLM IOCs
            if "iocs" in llm_results:
                final_results["iocs"] = llm_results["iocs"]
        
        return final_results

    async def _classify_threat(self, text_content: str) -> tuple[ThreatType, float]:
        """Classify threat using ML model"""
        if self.ml_models_initialized:
            try:
                threat_type_str, confidence = threat_classifier.predict(text_content)
                threat_type_map = {
                    'malware': ThreatType.MALWARE,
                    'phishing': ThreatType.PHISHING,
                    'ransomware': ThreatType.RANSOMWARE,
                    'ddos': ThreatType.DDOS,
                    'unknown': ThreatType.UNKNOWN
                }
                return threat_type_map.get(threat_type_str, ThreatType.UNKNOWN), confidence
            except Exception as e:
                self.logger.error(f"ML classification failed: {e}")
        
        # Fallback to rule-based classification
        return self._rule_based_classification(text_content)

    async def _assess_severity(self, threat_data: dict) -> tuple[ThreatSeverity, float]:
        """Assess severity using ML model"""
        if self.ml_models_initialized:
            try:
                severity_str, confidence = severity_assessor.predict(threat_data)
                severity_map = {
                    'low': ThreatSeverity.LOW,
                    'medium': ThreatSeverity.MEDIUM,
                    'high': ThreatSeverity.HIGH,
                    'critical': ThreatSeverity.CRITICAL
                }
                return severity_map.get(severity_str, ThreatSeverity.MEDIUM), confidence
            except Exception as e:
                self.logger.error(f"ML severity assessment failed: {e}")
        
        # Fallback to rule-based severity assessment
        return self._rule_based_severity_assessment(threat_data)

    async def _detect_anomaly(self, threat_data: dict) -> tuple[bool, float]:
        """Detect anomalies using ML model"""
        if self.ml_models_initialized:
            try:
                is_anomaly, anomaly_score = anomaly_detector.detect_anomaly(threat_data)
                return is_anomaly, anomaly_score
            except Exception as e:
                self.logger.error(f"Anomaly detection failed: {e}")
        
        # Fallback: no anomaly detection
        return False, 0.0

    async def _analyze_text(self, text_content: str) -> dict:
        """Perform NLP analysis on text"""
        try:
            # Sentiment analysis
            sentiment = nlp_model.analyze_sentiment(text_content)
            
            # Entity extraction
            entities = nlp_model.extract_entities(text_content)
            
            # Text embeddings
            embeddings = nlp_model.get_embeddings(text_content)
            
            return {
                "sentiment": sentiment,
                "entities": entities,
                "embedding_dimensions": len(embeddings),
                "text_length": len(text_content)
            }
        except Exception as e:
            self.logger.error(f"NLP analysis failed: {e}")
            return {"error": str(e)}

    def _rule_based_classification(self, text_content: str) -> tuple[ThreatType, float]:
        """Fallback rule-based classification"""
        text_lower = text_content.lower()
        
        if "ransom" in text_lower:
            return ThreatType.RANSOMWARE, 0.95
        elif "phish" in text_lower:
            return ThreatType.PHISHING, 0.9
        elif "malware" in text_lower or "virus" in text_lower:
            return ThreatType.MALWARE, 0.85
        elif "ddos" in text_lower or "denial" in text_lower:
            return ThreatType.DDOS, 0.8
        else:
            return ThreatType.UNKNOWN, 0.6 + random.uniform(0, 0.2)

    def _rule_based_severity_assessment(self, threat_data: dict) -> tuple[ThreatSeverity, float]:
        """Fallback rule-based severity assessment"""
        confidence = threat_data.get("confidence", 0.5)
        description = threat_data.get("description", "")
        
        # Simple severity rules
        if confidence > 0.9 or "critical" in description.lower():
            return ThreatSeverity.CRITICAL, 0.9
        elif confidence > 0.7 or "high" in description.lower():
            return ThreatSeverity.HIGH, 0.8
        elif confidence > 0.5 or "medium" in description.lower():
            return ThreatSeverity.MEDIUM, 0.7
        else:
            return ThreatSeverity.LOW, 0.6 