"""
Enhanced Agents for CyberSentinel AI - ATITA
Using Atomic Agents framework with strict schemas and modular design
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from core.enhanced_llm import enhanced_llm_client
from core.rag_pipeline import rag_pipeline
from core.logging import get_logger

logger = get_logger("enhanced_agents")

# Strict schemas for agent communication
class ThreatAnalysisInput(BaseModel):
    """Input schema for threat analysis"""
    threat_id: str
    title: str
    description: str
    source: str
    source_details: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)

class ThreatAnalysisOutput(BaseModel):
    """Output schema for threat analysis"""
    threat_id: str
    threat_type: str
    severity: str
    confidence: float
    is_anomaly: bool
    anomaly_score: float
    reasoning: str
    immediate_actions: List[str]
    iocs: List[str]
    context_sources: List[str]

class DecisionInput(BaseModel):
    """Input schema for decision making"""
    threat_analysis: ThreatAnalysisOutput
    available_actions: List[str]
    policy_constraints: Dict[str, Any]
    resource_availability: Dict[str, Any]

class DecisionOutput(BaseModel):
    """Output schema for decision making"""
    decision: str
    confidence: float
    reasoning: str
    risks: List[str]
    benefits: List[str]
    timeline: str
    resources_needed: List[str]

class ResponsePlanInput(BaseModel):
    """Input schema for response plan generation"""
    threat_analysis: ThreatAnalysisOutput
    decision: DecisionOutput
    available_resources: Dict[str, Any]
    escalation_level: str

class ResponsePlanOutput(BaseModel):
    """Output schema for response plan generation"""
    plan_id: str
    steps: List[Dict[str, Any]]
    timeline: str
    success_criteria: List[str]
    fallback_plan: Dict[str, Any]
    escalation_triggers: List[str]

class EvaluatorInput(BaseModel):
    """Input schema for evaluator agent"""
    threat_analysis: ThreatAnalysisOutput
    decision: DecisionOutput
    response_plan: ResponsePlanOutput
    context: Dict[str, Any]

class EvaluatorOutput(BaseModel):
    """Output schema for evaluator agent"""
    is_safe: bool
    confidence: float
    issues: List[str]
    recommendations: List[str]
    policy_violations: List[str]
    hallucination_detected: bool

class BaseEnhancedAgent:
    """Base class for enhanced agents"""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = get_logger(f"agent.{name}")
    
    async def process(self, *args, **kwargs):
        """Process method to be implemented by subclasses"""
        raise NotImplementedError

class EnhancedCoordinatorAgent(BaseEnhancedAgent):
    """Enhanced coordinator agent using modular design"""
    
    def __init__(self):
        super().__init__("enhanced_coordinator")
        self.agents = {}
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize all enhanced agents"""
        self.agents = {
            "router": EnhancedRouterAgent(),
            "retrieval": EnhancedRetrievalAgent(),
            "reasoning": EnhancedReasoningAgent(),
            "evaluator": EnhancedEvaluatorAgent(),
            "policy": EnhancedPolicyAgent(),
            "escalation": EnhancedEscalationAgent(),
            "memory": EnhancedMemoryAgent()
        }
    
    async def process_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat through enhanced agent pipeline"""
        try:
            # Step 1: Router Agent - decide processing path
            router_result = await self.agents["router"].process(
                ThreatAnalysisInput(**threat_data)
            )
            
            # Step 2: Retrieval Agent - get context from RAG
            retrieval_result = await self.agents["retrieval"].process(
                threat_data, router_result
            )
            
            # Step 3: Reasoning Agent - analyze with context
            reasoning_result = await self.agents["reasoning"].process(
                threat_data, retrieval_result
            )
            
            # Step 4: Evaluator Agent - check safety and compliance
            evaluator_result = await self.agents["evaluator"].process(
                reasoning_result, retrieval_result
            )
            
            # Step 5: Policy Agent - apply policies
            policy_result = await self.agents["policy"].process(
                reasoning_result, evaluator_result
            )
            
            # Step 6: Escalation Agent - decide escalation
            escalation_result = await self.agents["escalation"].process(
                reasoning_result, policy_result
            )
            
            # Step 7: Memory Agent - store results
            memory_result = await self.agents["memory"].process(
                threat_data, reasoning_result, escalation_result
            )
            
            return {
                "status": "completed",
                "threat_analysis": reasoning_result.dict(),
                "decision": policy_result.dict(),
                "escalation": escalation_result.dict(),
                "evaluation": evaluator_result.dict(),
                "memory": memory_result.dict()
            }
            
        except Exception as e:
            self.logger.error(f"Enhanced coordinator processing failed: {e}")
            return {"status": "error", "error": str(e)}

class EnhancedRouterAgent(BaseEnhancedAgent):
    """Router agent that decides processing path"""
    
    def __init__(self):
        super().__init__("enhanced_router")
    
    async def process(self, input_data: ThreatAnalysisInput) -> Dict[str, Any]:
        """Route threat to appropriate processing path"""
        try:
            # Analyze threat characteristics to determine processing path
            text_content = f"{input_data.title} {input_data.description}"
            
            # Simple routing logic based on keywords
            if any(word in text_content.lower() for word in ["ransomware", "encrypt", "bitcoin"]):
                path = "high_priority_ransomware"
            elif any(word in text_content.lower() for word in ["phishing", "login", "password"]):
                path = "medium_priority_phishing"
            elif any(word in text_content.lower() for word in ["malware", "virus", "trojan"]):
                path = "high_priority_malware"
            else:
                path = "standard_processing"
            
            return {
                "processing_path": path,
                "priority": "high" if "high_priority" in path else "medium",
                "requires_immediate_attention": "high_priority" in path,
                "estimated_processing_time": "5min" if "high_priority" in path else "15min"
            }
            
        except Exception as e:
            self.logger.error(f"Router agent processing failed: {e}")
            return {"processing_path": "standard_processing", "error": str(e)}

class EnhancedRetrievalAgent(BaseEnhancedAgent):
    """Retrieval agent that gets context from RAG pipeline"""
    
    def __init__(self):
        super().__init__("enhanced_retrieval")
    
    async def process(self, threat_data: Dict[str, Any], router_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Retrieve relevant context from RAG pipeline"""
        try:
            # Get context from RAG pipeline
            context = await rag_pipeline.get_context_for_threat(threat_data)
            
            # Filter based on router decision
            if router_result.get("priority") == "high":
                # Get more context for high priority threats
                context = await rag_pipeline.search(
                    f"{threat_data.get('title', '')} {threat_data.get('description', '')}",
                    top_k=15
                )
            else:
                # Standard context retrieval
                context = await rag_pipeline.search(
                    f"{threat_data.get('title', '')} {threat_data.get('description', '')}",
                    top_k=5
                )
            
            return context
            
        except Exception as e:
            self.logger.error(f"Retrieval agent processing failed: {e}")
            return []

class EnhancedReasoningAgent(BaseEnhancedAgent):
    """Reasoning agent using TinyLlama for analysis"""
    
    def __init__(self):
        super().__init__("enhanced_reasoning")
    
    async def process(self, threat_data: Dict[str, Any], context: List[Dict[str, Any]]) -> ThreatAnalysisOutput:
        """Analyze threat using TinyLlama with context"""
        try:
            # Prepare enhanced threat data with context
            enhanced_data = {
                **threat_data,
                "context": context[:5]  # Use top 5 context items
            }
            
            # Get structured analysis from TinyLlama
            analysis = await enhanced_llm_client.analyze_threat_structured(enhanced_data)
            
            if "error" in analysis:
                # Fallback to rule-based analysis
                return self._fallback_analysis(threat_data)
            
            # Convert to structured output
            return ThreatAnalysisOutput(
                threat_id=threat_data.get("id", "unknown"),
                threat_type=analysis.get("assessment", "unknown"),
                severity=analysis.get("impact", "medium"),
                confidence=analysis.get("confidence", 0.5),
                is_anomaly=False,  # Would be determined by anomaly detection
                anomaly_score=0.0,
                reasoning=analysis.get("reasoning", "Analysis completed"),
                immediate_actions=analysis.get("immediate_actions", []),
                iocs=analysis.get("iocs", []),
                context_sources=[ctx.get("source", "unknown") for ctx in context]
            )
            
        except Exception as e:
            self.logger.error(f"Reasoning agent processing failed: {e}")
            return self._fallback_analysis(threat_data)
    
    def _fallback_analysis(self, threat_data: Dict[str, Any]) -> ThreatAnalysisOutput:
        """Fallback rule-based analysis"""
        text_content = f"{threat_data.get('title', '')} {threat_data.get('description', '')}"
        
        # Simple rule-based classification
        if any(word in text_content.lower() for word in ["ransomware", "encrypt"]):
            threat_type = "ransomware"
            severity = "critical"
        elif any(word in text_content.lower() for word in ["phishing", "login"]):
            threat_type = "phishing"
            severity = "high"
        elif any(word in text_content.lower() for word in ["malware", "virus"]):
            threat_type = "malware"
            severity = "high"
        else:
            threat_type = "unknown"
            severity = "medium"
        
        return ThreatAnalysisOutput(
            threat_id=threat_data.get("id", "unknown"),
            threat_type=threat_type,
            severity=severity,
            confidence=0.6,
            is_anomaly=False,
            anomaly_score=0.0,
            reasoning="Rule-based fallback analysis",
            immediate_actions=["escalate_to_analyst"],
            iocs=[],
            context_sources=[]
        )

class EnhancedEvaluatorAgent(BaseEnhancedAgent):
    """Evaluator agent for safety and compliance checks"""
    
    def __init__(self):
        super().__init__("enhanced_evaluator")
    
    async def process(self, analysis: ThreatAnalysisOutput, context: List[Dict[str, Any]]) -> EvaluatorOutput:
        """Evaluate analysis for safety and compliance"""
        try:
            issues = []
            recommendations = []
            policy_violations = []
            
            # Check for potential issues
            if analysis.confidence < 0.7:
                issues.append("Low confidence analysis")
                recommendations.append("Require human review")
            
            if analysis.severity == "critical" and analysis.confidence < 0.8:
                issues.append("Critical severity with low confidence")
                recommendations.append("Immediate escalation required")
            
            # Check for policy violations
            if analysis.threat_type == "unknown" and analysis.severity == "critical":
                policy_violations.append("Cannot assign critical severity to unknown threat type")
            
            # Check for hallucination (simple heuristic)
            hallucination_detected = False
            if len(analysis.reasoning) < 50 and analysis.confidence > 0.9:
                hallucination_detected = True
                issues.append("Potential hallucination detected")
            
            return EvaluatorOutput(
                is_safe=len(issues) == 0,
                confidence=analysis.confidence,
                issues=issues,
                recommendations=recommendations,
                policy_violations=policy_violations,
                hallucination_detected=hallucination_detected
            )
            
        except Exception as e:
            self.logger.error(f"Evaluator agent processing failed: {e}")
            return EvaluatorOutput(
                is_safe=False,
                confidence=0.0,
                issues=[f"Evaluation error: {str(e)}"],
                recommendations=["Escalate to human analyst"],
                policy_violations=[],
                hallucination_detected=False
            )

class EnhancedPolicyAgent(BaseEnhancedAgent):
    """Policy agent for applying organizational policies"""
    
    def __init__(self):
        super().__init__("enhanced_policy")
    
    async def process(self, analysis: ThreatAnalysisOutput, evaluation: EvaluatorOutput) -> DecisionOutput:
        """Apply policies and make decisions"""
        try:
            # Policy-based decision making
            if not evaluation.is_safe:
                decision = "escalate_to_human"
                reasoning = "Policy violation or safety issue detected"
            elif analysis.severity == "critical":
                decision = "immediate_response"
                reasoning = "Critical severity requires immediate action"
            elif analysis.confidence < 0.7:
                decision = "escalate_to_analyst"
                reasoning = "Low confidence requires human review"
            else:
                decision = "automated_response"
                reasoning = "High confidence allows automated response"
            
            return DecisionOutput(
                decision=decision,
                confidence=analysis.confidence,
                reasoning=reasoning,
                risks=["Standard operational risks"],
                benefits=["Automated threat response"],
                timeline="immediate" if decision == "immediate_response" else "within_1_hour",
                resources_needed=["security_team", "incident_response_tools"]
            )
            
        except Exception as e:
            self.logger.error(f"Policy agent processing failed: {e}")
            return DecisionOutput(
                decision="escalate_to_human",
                confidence=0.0,
                reasoning=f"Policy processing error: {str(e)}",
                risks=["System error"],
                benefits=[],
                timeline="immediate",
                resources_needed=["human_analyst"]
            )

class EnhancedEscalationAgent(BaseEnhancedAgent):
    """Escalation agent for managing human intervention"""
    
    def __init__(self):
        super().__init__("enhanced_escalation")
    
    async def process(self, analysis: ThreatAnalysisOutput, decision: DecisionOutput) -> Dict[str, Any]:
        """Determine escalation requirements"""
        try:
            escalation_required = decision.decision in ["escalate_to_human", "escalate_to_analyst"]
            
            if escalation_required:
                if analysis.severity == "critical":
                    escalation_level = "immediate"
                    assigned_to = "senior_analyst"
                else:
                    escalation_level = "normal"
                    assigned_to = "analyst"
            else:
                escalation_level = "none"
                assigned_to = "automated_system"
            
            return {
                "escalation_required": escalation_required,
                "escalation_level": escalation_level,
                "assigned_to": assigned_to,
                "estimated_response_time": "5min" if escalation_level == "immediate" else "1hour",
                "notification_channels": ["email", "slack"] if escalation_required else []
            }
            
        except Exception as e:
            self.logger.error(f"Escalation agent processing failed: {e}")
            return {
                "escalation_required": True,
                "escalation_level": "immediate",
                "assigned_to": "human_analyst",
                "estimated_response_time": "immediate",
                "notification_channels": ["email", "slack"]
            }

class EnhancedMemoryAgent(BaseEnhancedAgent):
    """Memory agent for storing and retrieving case history"""
    
    def __init__(self):
        super().__init__("enhanced_memory")
    
    async def process(self, threat_data: Dict[str, Any], analysis: ThreatAnalysisOutput, escalation: Dict[str, Any]) -> Dict[str, Any]:
        """Store case information and retrieve relevant history"""
        try:
            # Store current case
            case_data = {
                "threat_id": threat_data.get("id"),
                "timestamp": datetime.utcnow().isoformat(),
                "analysis": analysis.dict(),
                "escalation": escalation,
                "outcome": "processing"
            }
            
            # Add to RAG pipeline for future reference
            await rag_pipeline.add_threat_intelligence(threat_data)
            
            # Retrieve similar cases
            similar_cases = await rag_pipeline.search(
                f"{analysis.threat_type} {analysis.severity}",
                top_k=3
            )
            
            return {
                "case_stored": True,
                "case_id": threat_data.get("id"),
                "similar_cases": len(similar_cases),
                "learning_applied": True,
                "next_actions": ["monitor_outcome", "update_models"]
            }
            
        except Exception as e:
            self.logger.error(f"Memory agent processing failed: {e}")
            return {
                "case_stored": False,
                "error": str(e),
                "next_actions": ["manual_review"]
            }

# Global enhanced coordinator instance
enhanced_coordinator = EnhancedCoordinatorAgent() 