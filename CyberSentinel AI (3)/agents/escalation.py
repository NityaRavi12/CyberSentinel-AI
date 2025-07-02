"""
Escalation Agent for CyberSentinel AI - ATITA
Decides if human intervention is needed
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from agents.base_agent import BaseAgent
from core.database import db_manager
from core.models import ThreatStatus, EscalationData
from core.config import settings
from core.logging import get_logger

logger = get_logger("escalation_agent")


class EscalationAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="escalation", timeout=15)
        self.escalation_threshold = settings.auto_escalation_threshold
        self.analyst_assignments = self._load_analyst_assignments()

    async def _initialize(self):
        """Initialize escalation agent"""
        logger.info("Escalation agent initialized")

    async def _shutdown(self):
        """Cleanup resources"""
        pass

    def _load_analyst_assignments(self) -> Dict[str, List[str]]:
        """Load analyst assignments by threat type"""
        return {
            "malware": ["analyst1@company.com", "analyst2@company.com"],
            "phishing": ["analyst3@company.com", "analyst4@company.com"],
            "ransomware": ["senior_analyst1@company.com", "senior_analyst2@company.com"],
            "apt": ["senior_analyst1@company.com", "senior_analyst2@company.com"],
            "data_breach": ["senior_analyst1@company.com", "senior_analyst2@company.com"],
            "ddos": ["analyst5@company.com", "analyst6@company.com"],
            "insider_threat": ["senior_analyst1@company.com", "senior_analyst2@company.com"],
            "unknown": ["analyst1@company.com", "analyst2@company.com"]
        }

    async def _process_task(self, task_data):
        """Process escalation decision for a threat"""
        self.logger.info("Escalation agent processing task", task=task_data)
        
        threat_data = task_data.get("threat_data", {})
        threat_id = threat_data.get("id")
        policy_result = task_data.get("policy_result", {})
        
        if not threat_id:
            return {"status": "error", "message": "No threat ID provided"}

        try:
            # Analyze threat and determine escalation decision
            escalation_decision = await self._analyze_escalation_need(threat_data, policy_result)
            
            # Create escalation data
            escalation_data = EscalationData(
                threat_id=threat_id,
                escalated_at=datetime.utcnow(),
                reason=escalation_decision["reason"],
                assigned_to=escalation_decision.get("assigned_to"),
                priority=escalation_decision["priority"],
                notes=escalation_decision.get("notes")
            )
            
            # Update threat in database
            await db_manager.update_threat(threat_id, {
                "status": ThreatStatus.ESCALATED.value if escalation_decision["escalate"] else "auto_resolved",
                "threat_metadata": {
                    **threat_data.get("threat_metadata", {}),
                    "escalation_decision": escalation_decision
                }
            })
            
            # Execute escalation actions
            if escalation_decision["escalate"]:
                await self._execute_escalation_actions(threat_id, escalation_decision)
            else:
                await self._execute_auto_resolution(threat_id, escalation_decision)
            
            return {
                "status": "escalation_decided",
                "threat_id": threat_id,
                "escalation_decision": escalation_decision
            }
            
        except Exception as e:
            self.logger.error(f"Error processing escalation for threat {threat_id}: {e}")
            return {"status": "error", "message": str(e)}

    async def _analyze_escalation_need(self, threat_data: Dict[str, Any], policy_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze whether human escalation is needed"""
        threat_type = threat_data.get("threat_type", "unknown")
        severity = threat_data.get("severity", "medium")
        confidence = threat_data.get("confidence", 0.5)
        policy_decision = policy_result.get("policy_decision", {})
        
        # Determine escalation factors
        escalation_factors = self._calculate_escalation_factors(threat_data, policy_result)
        
        # Check if escalation is required based on policy
        policy_requires_escalation = policy_decision.get("requires_approval", False)
        
        # Check if confidence is too low
        low_confidence = confidence < self.escalation_threshold
        
        # Check if threat is novel or unknown
        novel_threat = threat_type == "unknown" or confidence < 0.3
        
        # Check if threat is critical
        critical_threat = severity in ["critical", "high"] and threat_type in ["ransomware", "apt", "data_breach"]
        
        # Determine if escalation is needed
        escalate = (policy_requires_escalation or 
                   low_confidence or 
                   novel_threat or 
                   critical_threat or
                   escalation_factors["total_score"] > 0.7)
        
        # Determine priority
        priority = self._determine_priority(severity, threat_type, escalation_factors)
        
        # Assign analyst
        assigned_to = None
        if escalate:
            assigned_to = self._assign_analyst(threat_type, priority)
        
        # Generate reason
        reason = self._generate_escalation_reason(
            escalate, policy_requires_escalation, low_confidence, 
            novel_threat, critical_threat, escalation_factors
        )
        
        # Generate notes
        notes = self._generate_escalation_notes(threat_data, policy_result, escalation_factors)
        
        return {
            "escalate": escalate,
            "priority": priority,
            "assigned_to": assigned_to,
            "reason": reason,
            "notes": notes,
            "escalation_factors": escalation_factors,
            "confidence": confidence,
            "policy_requires_approval": policy_requires_escalation
        }

    def _calculate_escalation_factors(self, threat_data: Dict[str, Any], policy_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate escalation factors and scores"""
        factors = {
            "low_confidence": 0.0,
            "novel_threat": 0.0,
            "critical_severity": 0.0,
            "policy_approval_required": 0.0,
            "high_impact": 0.0,
            "uncertainty": 0.0,
            "total_score": 0.0
        }
        
        confidence = threat_data.get("confidence", 0.5)
        severity = threat_data.get("severity", "medium")
        threat_type = threat_data.get("threat_type", "unknown")
        policy_decision = policy_result.get("policy_decision", {})
        
        # Low confidence factor
        if confidence < 0.5:
            factors["low_confidence"] = (0.5 - confidence) * 2  # 0.0 to 1.0
        
        # Novel threat factor
        if threat_type == "unknown":
            factors["novel_threat"] = 0.8
        elif confidence < 0.3:
            factors["novel_threat"] = 0.6
        
        # Critical severity factor
        if severity == "critical":
            factors["critical_severity"] = 0.9
        elif severity == "high":
            factors["critical_severity"] = 0.6
        
        # Policy approval required factor
        if policy_decision.get("requires_approval", False):
            factors["policy_approval_required"] = 0.7
        
        # High impact factor
        if threat_type in ["ransomware", "apt", "data_breach"]:
            factors["high_impact"] = 0.8
        
        # Uncertainty factor
        threat_metadata = threat_data.get("threat_metadata", {})
        enrichment_data = threat_metadata.get("enrichment", {})
        if not enrichment_data.get("ioc_data"):
            factors["uncertainty"] = 0.5
        
        # Calculate total score
        factors["total_score"] = sum([
            factors["low_confidence"],
            factors["novel_threat"],
            factors["critical_severity"],
            factors["policy_approval_required"],
            factors["high_impact"],
            factors["uncertainty"]
        ]) / 6.0  # Average of all factors
        
        return factors

    def _determine_priority(self, severity: str, threat_type: str, escalation_factors: Dict[str, Any]) -> str:
        """Determine escalation priority"""
        if severity == "critical" or threat_type in ["ransomware", "apt"]:
            return "critical"
        elif severity == "high" or escalation_factors["total_score"] > 0.7:
            return "high"
        elif severity == "medium" or escalation_factors["total_score"] > 0.4:
            return "medium"
        else:
            return "low"

    def _assign_analyst(self, threat_type: str, priority: str) -> str:
        """Assign analyst based on threat type and priority"""
        analysts = self.analyst_assignments.get(threat_type, self.analyst_assignments["unknown"])
        
        # For critical priority, prefer senior analysts
        if priority == "critical":
            senior_analysts = [a for a in analysts if "senior" in a.lower()]
            if senior_analysts:
                return senior_analysts[0]
        
        # Return first available analyst
        return analysts[0] if analysts else "analyst1@company.com"

    def _generate_escalation_reason(self, escalate: bool, policy_requires: bool, 
                                  low_confidence: bool, novel_threat: bool, 
                                  critical_threat: bool, factors: Dict[str, Any]) -> str:
        """Generate escalation reason"""
        if not escalate:
            return "Auto-resolved: High confidence and no policy requirements"
        
        reasons = []
        if policy_requires:
            reasons.append("Policy requires approval")
        if low_confidence:
            reasons.append("Low confidence score")
        if novel_threat:
            reasons.append("Novel or unknown threat type")
        if critical_threat:
            reasons.append("Critical threat severity")
        if factors["total_score"] > 0.7:
            reasons.append("High escalation factor score")
        
        return "; ".join(reasons) if reasons else "Manual review recommended"

    def _generate_escalation_notes(self, threat_data: Dict[str, Any], 
                                 policy_result: Dict[str, Any], 
                                 factors: Dict[str, Any]) -> str:
        """Generate detailed escalation notes"""
        notes = []
        
        # Threat details
        notes.append(f"Threat Type: {threat_data.get('threat_type', 'unknown')}")
        notes.append(f"Severity: {threat_data.get('severity', 'medium')}")
        notes.append(f"Confidence: {threat_data.get('confidence', 0.5):.2f}")
        
        # Policy decision
        policy_decision = policy_result.get("policy_decision", {})
        if policy_decision:
            notes.append(f"Policy Decision: {policy_decision.get('decision', 'unknown')}")
            notes.append(f"Actions: {', '.join(policy_decision.get('actions', []))}")
        
        # Escalation factors
        notes.append(f"Escalation Score: {factors['total_score']:.2f}")
        
        # Enrichment data
        threat_metadata = threat_data.get("threat_metadata", {})
        enrichment = threat_metadata.get("enrichment", {})
        if enrichment.get("ioc_data"):
            notes.append(f"IOCs Found: {len(enrichment['ioc_data'])}")
        
        return "\n".join(notes)

    async def _execute_escalation_actions(self, threat_id: str, escalation_decision: Dict[str, Any]):
        """Execute escalation actions"""
        self.logger.info(f"Executing escalation actions for threat {threat_id}")
        
        try:
            # Create escalation report
            report = await self._create_escalation_report(threat_id, escalation_decision)
            
            # Notify assigned analyst
            if escalation_decision.get("assigned_to"):
                await self._notify_analyst(escalation_decision["assigned_to"], report)
            
            # Create escalation ticket
            await self._create_escalation_ticket(threat_id, escalation_decision)
            
            # Log escalation
            await self._log_escalation(threat_id, escalation_decision)
            
            self.logger.info(f"Successfully escalated threat {threat_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to execute escalation actions for threat {threat_id}: {e}")

    async def _execute_auto_resolution(self, threat_id: str, escalation_decision: Dict[str, Any]):
        """Execute auto-resolution actions"""
        self.logger.info(f"Executing auto-resolution for threat {threat_id}")
        
        try:
            # Log auto-resolution
            await self._log_auto_resolution(threat_id, escalation_decision)
            
            # Update threat status
            await db_manager.update_threat(threat_id, {
                "status": "resolved",
                "threat_metadata": {
                    "resolution": "auto_resolved",
                    "resolution_reason": escalation_decision["reason"]
                }
            })
            
            self.logger.info(f"Successfully auto-resolved threat {threat_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to execute auto-resolution for threat {threat_id}: {e}")

    async def _create_escalation_report(self, threat_id: str, escalation_decision: Dict[str, Any]) -> Dict[str, Any]:
        """Create escalation report (placeholder)"""
        # In production, this would generate a detailed report
        return {
            "threat_id": threat_id,
            "escalation_reason": escalation_decision["reason"],
            "priority": escalation_decision["priority"],
            "assigned_to": escalation_decision.get("assigned_to"),
            "created_at": datetime.utcnow().isoformat()
        }

    async def _notify_analyst(self, analyst_email: str, report: Dict[str, Any]):
        """Notify analyst (placeholder)"""
        # In production, this would send email/SMS notification
        self.logger.info(f"Notifying analyst {analyst_email} with report")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _create_escalation_ticket(self, threat_id: str, escalation_decision: Dict[str, Any]):
        """Create escalation ticket (placeholder)"""
        # In production, this would create a ticket in Jira, ServiceNow, etc.
        self.logger.info(f"Creating escalation ticket for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _log_escalation(self, threat_id: str, escalation_decision: Dict[str, Any]):
        """Log escalation (placeholder)"""
        # In production, this would log to SIEM or audit system
        self.logger.info(f"Logging escalation for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _log_auto_resolution(self, threat_id: str, escalation_decision: Dict[str, Any]):
        """Log auto-resolution (placeholder)"""
        # In production, this would log to SIEM or audit system
        self.logger.info(f"Logging auto-resolution for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call 