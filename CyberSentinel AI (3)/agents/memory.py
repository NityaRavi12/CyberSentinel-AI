"""
Memory & Feedback Agent for CyberSentinel AI - ATITA
Stores case history and incorporates feedback for continuous learning
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from agents.base_agent import BaseAgent
from core.database import db_manager
from core.models import ThreatStatus, AnalystFeedback, ThreatCase
from core.config import settings
from core.logging import get_logger
from pathlib import Path

logger = get_logger("memory_agent")


class MemoryAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="memory", timeout=30)
        self.feedback_store = []
        self.learning_data = {
            "false_positives": [],
            "false_negatives": [],
            "classification_errors": [],
            "severity_errors": [],
            "model_performance": {}
        }

    async def _initialize(self):
        """Initialize memory agent"""
        logger.info("Memory agent initialized")
        # Load existing feedback and learning data
        await self._load_historical_data()

    async def _shutdown(self):
        """Save learning data before shutdown"""
        await self._save_learning_data()

    async def _process_task(self, task_data):
        """Process memory and feedback tasks"""
        self.logger.info("Memory agent processing task", task=task_data)
        
        task_type = task_data.get("type", "case_memory")
        threat_data = task_data.get("threat_data", {})
        threat_id = threat_data.get("id")
        
        if not threat_id:
            return {"status": "error", "message": "No threat ID provided"}

        try:
            if task_type == "case_memory":
                return await self._process_case_memory(threat_id, task_data)
            elif task_type == "feedback_processing":
                return await self._process_feedback(threat_id, task_data)
            elif task_type == "learning_analysis":
                return await self._process_learning_analysis()
            else:
                return {"status": "error", "message": f"Unknown task type: {task_type}"}
                
        except Exception as e:
            self.logger.error(f"Error processing memory task for threat {threat_id}: {e}")
            return {"status": "error", "message": str(e)}

    async def _process_case_memory(self, threat_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and store case memory"""
        all_results = task_data.get("all_results", {})
        
        # Create threat case record
        threat = await db_manager.get_threat(threat_id)
        if not threat:
            return {"status": "error", "message": "Threat not found"}
        
        # Extract data from workflow results
        enrichment_data = all_results.get("enrichment", {}).get("enrichment_data", {})
        policy_decision = all_results.get("policy", {}).get("policy_decision", {})
        escalation_decision = all_results.get("escalation", {}).get("escalation_decision", {})
        
        # Create case record
        case = ThreatCase(
            threat=threat,
            enrichment=enrichment_data,
            policy_decisions=[policy_decision] if policy_decision else [],
            escalation=escalation_decision,
            feedback=[],
            auto_actions_taken=policy_decision.get("actions", []),
            processing_time=self._calculate_processing_time(threat.created_at)
        )
        
        # Store case in database
        await db_manager.create_case(case)
        
        # Update threat status
        await db_manager.update_threat(threat_id, {
            "status": ThreatStatus.CLOSED.value,
            "threat_metadata": {
                **threat.threat_metadata,
                "case_closed_at": datetime.utcnow().isoformat(),
                "processing_time": case.processing_time
            }
        })
        
        # Store learning data
        await self._store_learning_data(threat_id, case, all_results)
        
        return {
            "status": "memory_updated",
            "threat_id": threat_id,
            "case_stored": True,
            "learning_data_updated": True
        }

    async def _process_feedback(self, threat_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process analyst feedback"""
        feedback_data = task_data.get("feedback_data", {})
        
        # Create feedback record
        feedback = AnalystFeedback(
            threat_id=threat_id,
            analyst_id=feedback_data.get("analyst_id", "unknown"),
            feedback_type=feedback_data.get("feedback_type", "general"),
            feedback_data=feedback_data.get("feedback_data", {}),
            confidence_rating=feedback_data.get("confidence_rating")
        )
        
        # Store feedback
        self.feedback_store.append(feedback.dict())
        
        # Analyze feedback for learning
        await self._analyze_feedback_for_learning(threat_id, feedback)
        
        # Update threat with feedback
        await db_manager.update_threat(threat_id, {
            "threat_metadata": {
                "feedback_received": True,
                "feedback_type": feedback.feedback_type,
                "feedback_analyst": feedback.analyst_id,
                "feedback_timestamp": datetime.utcnow().isoformat()
            }
        })
        
        return {
            "status": "feedback_processed",
            "threat_id": threat_id,
            "feedback_stored": True,
            "learning_triggered": True
        }

    async def _process_learning_analysis(self) -> Dict[str, Any]:
        """Process learning analysis and model improvement"""
        try:
            # Analyze feedback patterns
            analysis_results = await self._analyze_feedback_patterns()
            
            # Generate model improvement recommendations
            recommendations = await self._generate_model_recommendations(analysis_results)
            
            # Trigger model retraining if needed
            retraining_needed = await self._check_retraining_needed(analysis_results)
            
            if retraining_needed:
                await self._trigger_model_retraining(analysis_results)
            
            return {
                "status": "learning_analysis_complete",
                "analysis_results": analysis_results,
                "recommendations": recommendations,
                "retraining_triggered": retraining_needed
            }
            
        except Exception as e:
            self.logger.error(f"Error in learning analysis: {e}")
            return {"status": "error", "message": str(e)}

    async def _store_learning_data(self, threat_id: str, case: ThreatCase, all_results: Dict[str, Any]):
        """Store learning data for model improvement"""
        learning_entry = {
            "threat_id": threat_id,
            "timestamp": datetime.utcnow().isoformat(),
            "threat_type": case.threat.threat_type.value,
            "severity": case.threat.severity.value,
            "confidence": case.threat.confidence,
            "escalated": bool(case.escalation),
            "auto_resolved": not bool(case.escalation),
            "processing_time": case.processing_time,
            "ioc_count": len(case.enrichment.ioc_data) if case.enrichment else 0,
            "policy_actions": len(case.auto_actions_taken)
        }
        
        # Store in learning data
        self.learning_data["model_performance"][threat_id] = learning_entry

    async def _analyze_feedback_for_learning(self, threat_id: str, feedback: AnalystFeedback):
        """Analyze feedback for learning opportunities"""
        feedback_type = feedback.feedback_type
        feedback_data = feedback.feedback_data
        
        if feedback_type == "classification":
            # Check for classification errors
            original_type = feedback_data.get("original_classification")
            corrected_type = feedback_data.get("corrected_classification")
            
            if original_type != corrected_type:
                self.learning_data["classification_errors"].append({
                    "threat_id": threat_id,
                    "original": original_type,
                    "corrected": corrected_type,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        elif feedback_type == "severity":
            # Check for severity errors
            original_severity = feedback_data.get("original_severity")
            corrected_severity = feedback_data.get("corrected_severity")
            
            if original_severity != corrected_severity:
                self.learning_data["severity_errors"].append({
                    "threat_id": threat_id,
                    "original": original_severity,
                    "corrected": corrected_severity,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        elif feedback_type == "false_positive":
            # Record false positive
            self.learning_data["false_positives"].append({
                "threat_id": threat_id,
                "reason": feedback_data.get("reason", ""),
                "timestamp": datetime.utcnow().isoformat()
            })
        
        elif feedback_type == "false_negative":
            # Record false negative
            self.learning_data["false_negatives"].append({
                "threat_id": threat_id,
                "reason": feedback_data.get("reason", ""),
                "timestamp": datetime.utcnow().isoformat()
            })

    async def _analyze_feedback_patterns(self) -> Dict[str, Any]:
        """Analyze feedback patterns for model improvement"""
        analysis = {
            "total_feedback": len(self.feedback_store),
            "feedback_by_type": {},
            "classification_accuracy": 0.0,
            "severity_accuracy": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "recent_trends": {}
        }
        
        # Analyze feedback by type
        for feedback in self.feedback_store:
            feedback_type = feedback.get("feedback_type", "unknown")
            analysis["feedback_by_type"][feedback_type] = analysis["feedback_by_type"].get(feedback_type, 0) + 1
        
        # Calculate accuracy metrics
        classification_errors = len(self.learning_data["classification_errors"])
        severity_errors = len(self.learning_data["severity_errors"])
        false_positives = len(self.learning_data["false_positives"])
        false_negatives = len(self.learning_data["false_negatives"])
        
        total_cases = len(self.learning_data["model_performance"])
        
        if total_cases > 0:
            analysis["classification_accuracy"] = 1.0 - (classification_errors / total_cases)
            analysis["severity_accuracy"] = 1.0 - (severity_errors / total_cases)
            analysis["false_positive_rate"] = false_positives / total_cases
            analysis["false_negative_rate"] = false_negatives / total_cases
        
        # Analyze recent trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_feedback = [
            f for f in self.feedback_store 
            if datetime.fromisoformat(f.get("created_at", "2020-01-01T00:00:00")) > thirty_days_ago
        ]
        
        analysis["recent_trends"] = {
            "recent_feedback_count": len(recent_feedback),
            "recent_accuracy_trend": "improving" if len(recent_feedback) > 0 else "stable"
        }
        
        return analysis

    async def _generate_model_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate model improvement recommendations"""
        recommendations = []
        
        # Classification accuracy recommendations
        if analysis_results["classification_accuracy"] < 0.8:
            recommendations.append("Consider retraining classification model with recent feedback data")
        
        # Severity accuracy recommendations
        if analysis_results["severity_accuracy"] < 0.8:
            recommendations.append("Review severity assessment logic and update thresholds")
        
        # False positive recommendations
        if analysis_results["false_positive_rate"] > 0.2:
            recommendations.append("Increase confidence threshold to reduce false positives")
        
        # False negative recommendations
        if analysis_results["false_negative_rate"] > 0.1:
            recommendations.append("Lower confidence threshold to catch more threats")
        
        # General recommendations
        if analysis_results["total_feedback"] < 10:
            recommendations.append("Collect more feedback to improve model accuracy")
        
        return recommendations

    async def _check_retraining_needed(self, analysis_results: Dict[str, Any]) -> bool:
        """Check if model retraining is needed"""
        # Retrain if accuracy is below threshold
        if (analysis_results["classification_accuracy"] < 0.75 or 
            analysis_results["severity_accuracy"] < 0.75):
            return True
        
        # Retrain if there are many recent feedback items
        if analysis_results["recent_trends"]["recent_feedback_count"] > 20:
            return True
        
        # Retrain if false positive/negative rates are high
        if (analysis_results["false_positive_rate"] > 0.25 or 
            analysis_results["false_negative_rate"] > 0.15):
            return True
        
        return False

    async def _trigger_model_retraining(self, analysis_results: Dict[str, Any]):
        """Trigger model retraining (placeholder for actual implementation)"""
        self.logger.info("Triggering model retraining based on analysis results")
        
        # In production, this would:
        # 1. Export training data from feedback
        # 2. Retrain ML models
        # 3. Validate new models
        # 4. Deploy updated models
        
        retraining_data = {
            "triggered_at": datetime.utcnow().isoformat(),
            "reason": "Accuracy below threshold or high feedback volume",
            "analysis_results": analysis_results,
            "training_data_size": len(self.feedback_store)
        }
        
        self.logger.info(f"Model retraining triggered: {retraining_data}")
        
        # Simulate retraining process
        await asyncio.sleep(1)  # Simulate training time

    def _calculate_processing_time(self, created_at: datetime) -> float:
        """Calculate processing time for a threat"""
        return (datetime.utcnow() - created_at).total_seconds()

    async def _load_historical_data(self):
        """Load historical feedback and learning data"""
        # In production, this would load from persistent storage
        self.logger.info("Loading historical learning data")

    async def _save_learning_data(self):
        """Save learning data to persistent storage"""
        # In production, this would save to database or file
        self.logger.info("Saving learning data")
        
        # Save to file for demonstration
        try:
            # Create data directory if it doesn't exist
            data_dir = Path("data")
            data_dir.mkdir(exist_ok=True)
            
            with open(data_dir / "learning_data.json", "w") as f:
                json.dump(self.learning_data, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Error saving learning data: {e}")

    async def get_learning_statistics(self) -> Dict[str, Any]:
        """Get learning statistics for analytics"""
        return {
            "total_cases_processed": len(self.learning_data["model_performance"]),
            "total_feedback_received": len(self.feedback_store),
            "classification_errors": len(self.learning_data["classification_errors"]),
            "severity_errors": len(self.learning_data["severity_errors"]),
            "false_positives": len(self.learning_data["false_positives"]),
            "false_negatives": len(self.learning_data["false_negatives"]),
            "last_analysis": datetime.utcnow().isoformat()
        } 