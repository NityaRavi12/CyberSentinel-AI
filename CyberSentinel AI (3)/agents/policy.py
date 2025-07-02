"""
Policy Agent for CyberSentinel AI - ATITA
Applies organizational policies and determines actions
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from agents.base_agent import BaseAgent
from core.database import db_manager
from core.models import ThreatStatus, ThreatType, ThreatSeverity, PolicyDecision
from core.config import settings
from core.logging import get_logger

logger = get_logger("policy_agent")


class PolicyAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="policy", timeout=30)
        # Load organizational policies
        self.policies = self._load_policies()

    async def _initialize(self):
        """Initialize policy agent"""
        logger.info("Policy agent initialized with organizational policies")

    async def _shutdown(self):
        """Cleanup resources"""
        pass

    def _load_policies(self) -> Dict[str, Any]:
        """Load organizational security policies"""
        return {
            "auto_block_threshold": 0.8,  # Confidence threshold for auto-blocking
            "critical_threats": {
                "ransomware": {
                    "auto_block": True,
                    "isolate_device": True,
                    "notify_admin": True,
                    "escalate": True
                },
                "apt": {
                    "auto_block": True,
                    "isolate_device": True,
                    "notify_admin": True,
                    "escalate": True
                },
                "data_breach": {
                    "auto_block": True,
                    "isolate_device": False,
                    "notify_admin": True,
                    "escalate": True
                }
            },
            "high_severity": {
                "malware": {
                    "auto_block": True,
                    "isolate_device": False,
                    "notify_admin": True,
                    "escalate": False
                },
                "phishing": {
                    "auto_block": True,
                    "isolate_device": False,
                    "notify_admin": True,
                    "escalate": False
                }
            },
            "medium_severity": {
                "malware": {
                    "auto_block": False,
                    "isolate_device": False,
                    "notify_admin": False,
                    "escalate": False
                },
                "phishing": {
                    "auto_block": False,
                    "isolate_device": False,
                    "notify_admin": False,
                    "escalate": False
                }
            },
            "low_severity": {
                "auto_block": False,
                "isolate_device": False,
                "notify_admin": False,
                "escalate": False
            },
            "vip_exemptions": [
                "ceo@company.com",
                "cto@company.com",
                "ciso@company.com"
            ],
            "protected_systems": [
                "192.168.1.100",  # Example protected system
                "10.0.0.50"       # Example protected system
            ]
        }

    async def _process_task(self, task_data):
        """Process policy decisions for a threat"""
        self.logger.info("Policy agent processing task", task=task_data)
        
        threat_data = task_data.get("threat_data", {})
        threat_id = threat_data.get("id")
        enrichment_result = task_data.get("enrichment_result", {})
        
        if not threat_id:
            return {"status": "error", "message": "No threat ID provided"}

        try:
            # Analyze threat and determine policy actions
            policy_decision = await self._analyze_threat_policy(threat_data, enrichment_result)
            
            # Create policy decision record
            policy_record = PolicyDecision(
                threat_id=threat_id,
                policy_name=policy_decision["policy_name"],
                decision=policy_decision["decision"],
                actions=policy_decision["actions"],
                requires_approval=policy_decision["requires_approval"]
            )
            
            # Update threat in database
            await db_manager.update_threat(threat_id, {
                "status": "policy_applied",
                "threat_metadata": {
                    **threat_data.get("threat_metadata", {}),
                    "policy_decision": policy_decision
                }
            })
            
            # Execute auto-actions if confidence is high enough
            if policy_decision["auto_execute"]:
                await self._execute_auto_actions(threat_id, policy_decision["actions"])
            
            return {
                "status": "policy_applied",
                "threat_id": threat_id,
                "policy_decision": policy_decision
            }
            
        except Exception as e:
            self.logger.error(f"Error applying policy to threat {threat_id}: {e}")
            return {"status": "error", "message": str(e)}

    async def _analyze_threat_policy(self, threat_data: Dict[str, Any], enrichment_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat and determine policy actions"""
        threat_type = threat_data.get("threat_type", "unknown")
        severity = threat_data.get("severity", "medium")
        confidence = threat_data.get("confidence", 0.5)
        source_details = threat_data.get("source_details", {})
        
        # Check for VIP exemptions
        if self._is_vip_exempted(source_details):
            return {
                "policy_name": "vip_exemption",
                "decision": "exempted",
                "actions": [],
                "requires_approval": False,
                "auto_execute": False,
                "reason": "VIP user exempted from automatic actions"
            }
        
        # Check for protected systems
        if self._is_protected_system(source_details):
            return {
                "policy_name": "protected_system",
                "decision": "manual_review_required",
                "actions": ["notify_admin"],
                "requires_approval": True,
                "auto_execute": False,
                "reason": "Protected system requires manual review"
            }
        
        # Determine policy based on threat type and severity
        if threat_type in ["ransomware", "apt", "data_breach"]:
            policy = self.policies["critical_threats"].get(threat_type, {})
            decision = "critical_action_required"
        elif severity == "high":
            policy = self.policies["high_severity"].get(threat_type, {})
            decision = "high_priority_action"
        elif severity == "medium":
            policy = self.policies["medium_severity"].get(threat_type, {})
            decision = "medium_priority_action"
        else:
            policy = self.policies["low_severity"]
            decision = "low_priority_action"
        
        # Determine actions based on policy and confidence
        actions = self._determine_actions(policy, confidence, enrichment_result)
        
        # Check if auto-execution is allowed
        auto_execute = confidence >= self.policies["auto_block_threshold"] and not settings.require_human_approval
        
        return {
            "policy_name": f"{threat_type}_{severity}_policy",
            "decision": decision,
            "actions": actions,
            "requires_approval": not auto_execute,
            "auto_execute": auto_execute,
            "confidence": confidence,
            "reason": f"Policy applied based on {threat_type} threat with {severity} severity"
        }

    def _is_vip_exempted(self, source_details: Dict[str, Any]) -> bool:
        """Check if the source is a VIP exemption"""
        email = source_details.get("sender", "").lower()
        return email in [vip.lower() for vip in self.policies["vip_exemptions"]]

    def _is_protected_system(self, source_details: Dict[str, Any]) -> bool:
        """Check if the source is a protected system"""
        ip = source_details.get("ip", "")
        return ip in self.policies["protected_systems"]

    def _determine_actions(self, policy: Dict[str, Any], confidence: float, enrichment_result: Dict[str, Any]) -> List[str]:
        """Determine actions based on policy and enrichment data"""
        actions = []
        
        # Add actions based on policy
        if policy.get("auto_block", False):
            actions.append("block_ioc")
        
        if policy.get("isolate_device", False):
            actions.append("isolate_device")
        
        if policy.get("notify_admin", False):
            actions.append("notify_admin")
        
        if policy.get("escalate", False):
            actions.append("escalate_to_analyst")
        
        # Add actions based on enrichment data
        if enrichment_result.get("ioc_data"):
            malicious_iocs = [ioc for ioc in enrichment_result["ioc_data"] 
                            if ioc.get("malicious_score", 0) > 0.7]
            if malicious_iocs:
                actions.append("block_malicious_iocs")
                actions.append("update_firewall_rules")
        
        # Add logging action
        actions.append("log_action")
        
        return actions

    async def _execute_auto_actions(self, threat_id: str, actions: List[str]):
        """Execute automatic actions"""
        self.logger.info(f"Executing auto-actions for threat {threat_id}: {actions}")
        
        for action in actions:
            try:
                if action == "block_ioc":
                    await self._block_ioc(threat_id)
                elif action == "isolate_device":
                    await self._isolate_device(threat_id)
                elif action == "notify_admin":
                    await self._notify_admin(threat_id)
                elif action == "block_malicious_iocs":
                    await self._block_malicious_iocs(threat_id)
                elif action == "update_firewall_rules":
                    await self._update_firewall_rules(threat_id)
                elif action == "log_action":
                    await self._log_action(threat_id, action)
                
                self.logger.info(f"Successfully executed action: {action}")
                
            except Exception as e:
                self.logger.error(f"Failed to execute action {action}: {e}")

    async def _block_ioc(self, threat_id: str):
        """Block IOC (placeholder for actual implementation)"""
        # In production, this would integrate with firewall/IDS
        self.logger.info(f"Blocking IOC for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _isolate_device(self, threat_id: str):
        """Isolate device (placeholder for actual implementation)"""
        # In production, this would integrate with network management
        self.logger.info(f"Isolating device for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _notify_admin(self, threat_id: str):
        """Notify admin (placeholder for actual implementation)"""
        # In production, this would send email/SMS notification
        self.logger.info(f"Notifying admin for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _block_malicious_iocs(self, threat_id: str):
        """Block malicious IOCs (placeholder for actual implementation)"""
        # In production, this would update threat intelligence feeds
        self.logger.info(f"Blocking malicious IOCs for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _update_firewall_rules(self, threat_id: str):
        """Update firewall rules (placeholder for actual implementation)"""
        # In production, this would update firewall configurations
        self.logger.info(f"Updating firewall rules for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call

    async def _log_action(self, threat_id: str, action: str):
        """Log action (placeholder for actual implementation)"""
        # In production, this would log to SIEM or audit system
        self.logger.info(f"Logging action {action} for threat {threat_id}")
        await asyncio.sleep(0.1)  # Simulate API call 