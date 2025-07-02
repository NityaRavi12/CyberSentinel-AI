"""
Coordinator Agent for CyberSentinel AI - ATITA
Manages workflow and delegates tasks across the ATITA system
"""

import asyncio
from typing import Dict, Any, List
from datetime import datetime
from agents.base_agent import BaseAgent
from agents.intake import IntakeAgent
from agents.triage import TriageAgent
from agents.enrichment import EnrichmentAgent
from agents.policy import PolicyAgent
from agents.escalation import EscalationAgent
from agents.memory import MemoryAgent
from core.models import ThreatData, ThreatStatus


class CoordinatorAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="coordinator", timeout=60)
        self.agents: Dict[str, BaseAgent] = {}
        self.workflow_queue: List[Dict[str, Any]] = []
        self.active_cases: Dict[str, Dict[str, Any]] = {}

    async def _initialize(self):
        """Initialize all agents and start the workflow processor"""
        self.logger.info("Initializing coordinator agent and all sub-agents")
        
        # Initialize all agents
        self.agents = {
            "intake": IntakeAgent(),
            "triage": TriageAgent(),
            "enrichment": EnrichmentAgent(),
            "policy": PolicyAgent(),
            "escalation": EscalationAgent(),
            "memory": MemoryAgent()
        }
        
        # Initialize each agent
        for name, agent in self.agents.items():
            try:
                await agent.initialize()
                self.logger.info(f"Agent {name} initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize agent {name}: {e}")
                raise
        
        # Start the workflow processor
        asyncio.create_task(self._workflow_processor())
        self.logger.info("Coordinator agent initialization complete")

    async def _shutdown(self):
        """Shutdown all agents"""
        self.logger.info("Shutting down coordinator agent and all sub-agents")
        
        for name, agent in self.agents.items():
            try:
                await agent.shutdown()
                self.logger.info(f"Agent {name} shut down successfully")
            except Exception as e:
                self.logger.error(f"Error shutting down agent {name}: {e}")

    async def _process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a task through the coordinator workflow"""
        task_id = task_data.get("id", f"task_{datetime.utcnow().timestamp()}")
        
        self.logger.info(f"Coordinator processing task {task_id}", task_type=task_data.get("type"))
        
        # Add task to workflow queue
        workflow_task = {
            "id": task_id,
            "type": task_data.get("type"),
            "data": task_data,
            "status": "queued",
            "created_at": datetime.utcnow(),
            "current_step": "coordinator",
            "steps_completed": [],
            "results": {}
        }
        
        self.workflow_queue.append(workflow_task)
        self.active_cases[task_id] = workflow_task
        
        # For immediate tasks, process them right away
        if task_data.get("type") == "threat_processing":
            await self._process_threat_workflow(workflow_task)
        
        return {
            "task_id": task_id,
            "status": "queued",
            "message": "Task queued for processing"
        }

    async def _workflow_processor(self):
        """Background processor for workflow queue"""
        while self._running:
            try:
                if self.workflow_queue:
                    task = self.workflow_queue.pop(0)
                    await self._process_workflow_task(task)
                else:
                    await asyncio.sleep(1)  # Wait for new tasks
            except Exception as e:
                self.logger.error(f"Error in workflow processor: {e}")
                await asyncio.sleep(5)  # Wait before retrying

    async def _process_workflow_task(self, task: Dict[str, Any]):
        """Process a workflow task"""
        task_id = task["id"]
        task_type = task["type"]
        
        self.logger.info(f"Processing workflow task {task_id}", task_type=task_type)
        
        try:
            if task_type == "threat_processing":
                await self._process_threat_workflow(task)
            elif task_type == "feedback_processing":
                await self._process_feedback_workflow(task)
            else:
                self.logger.warning(f"Unknown task type: {task_type}")
                
        except Exception as e:
            self.logger.error(f"Error processing workflow task {task_id}: {e}")
            task["status"] = "error"
            task["error"] = str(e)

    async def _process_threat_workflow(self, task: Dict[str, Any]):
        """Process a threat through the complete workflow"""
        task_id = task["id"]
        threat_data = task["data"].get("threat_data", {})
        
        self.logger.info(f"Starting threat workflow for task {task_id}")
        
        try:
            # Step 1: Intake Processing
            task["current_step"] = "intake"
            intake_result = await self.agents["intake"].process_task({
                "id": task_id,
                "type": "threat_intake",
                "threat_data": threat_data
            })
            task["results"]["intake"] = intake_result
            task["steps_completed"].append("intake")
            
            # Step 2: Triage Processing
            task["current_step"] = "triage"
            triage_result = await self.agents["triage"].process_task({
                "id": task_id,
                "type": "threat_triage",
                "threat_data": threat_data,
                "intake_result": intake_result
            })
            task["results"]["triage"] = triage_result
            task["steps_completed"].append("triage")
            
            # Step 3: Enrichment Processing
            task["current_step"] = "enrichment"
            enrichment_result = await self.agents["enrichment"].process_task({
                "id": task_id,
                "type": "threat_enrichment",
                "threat_data": threat_data,
                "triage_result": triage_result
            })
            task["results"]["enrichment"] = enrichment_result
            task["steps_completed"].append("enrichment")
            
            # Step 4: Policy Processing
            task["current_step"] = "policy"
            policy_result = await self.agents["policy"].process_task({
                "id": task_id,
                "type": "policy_decision",
                "threat_data": threat_data,
                "enrichment_result": enrichment_result
            })
            task["results"]["policy"] = policy_result
            task["steps_completed"].append("policy")
            
            # Step 5: Escalation Decision
            task["current_step"] = "escalation"
            escalation_result = await self.agents["escalation"].process_task({
                "id": task_id,
                "type": "escalation_decision",
                "threat_data": threat_data,
                "policy_result": policy_result
            })
            task["results"]["escalation"] = escalation_result
            task["steps_completed"].append("escalation")
            
            # Step 6: Memory Update
            task["current_step"] = "memory"
            memory_result = await self.agents["memory"].process_task({
                "id": task_id,
                "type": "case_memory",
                "threat_data": threat_data,
                "all_results": task["results"]
            })
            task["results"]["memory"] = memory_result
            task["steps_completed"].append("memory")
            
            # Mark task as completed
            task["status"] = "completed"
            task["completed_at"] = datetime.utcnow()
            
            self.logger.info(f"Threat workflow completed for task {task_id}")
            
        except Exception as e:
            self.logger.error(f"Error in threat workflow for task {task_id}: {e}")
            task["status"] = "error"
            task["error"] = str(e)
            task["error_at"] = datetime.utcnow()

    async def _process_feedback_workflow(self, task: Dict[str, Any]):
        """Process analyst feedback"""
        task_id = task["id"]
        
        self.logger.info(f"Processing feedback workflow for task {task_id}")
        
        try:
            # Update memory with feedback
            feedback_result = await self.agents["memory"].process_task({
                "id": task_id,
                "type": "feedback_processing",
                "feedback_data": task["data"]
            })
            
            task["results"]["feedback"] = feedback_result
            task["status"] = "completed"
            task["completed_at"] = datetime.utcnow()
            
        except Exception as e:
            self.logger.error(f"Error in feedback workflow for task {task_id}: {e}")
            task["status"] = "error"
            task["error"] = str(e)

    def get_workflow_status(self, task_id: str) -> Dict[str, Any]:
        """Get the status of a workflow task"""
        if task_id in self.active_cases:
            return self.active_cases[task_id]
        return {"error": "Task not found"}

    def get_all_agent_status(self) -> Dict[str, Any]:
        """Get status of all agents"""
        return {
            name: agent.get_status().dict() 
            for name, agent in self.agents.items()
        } 