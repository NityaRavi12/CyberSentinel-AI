"""
Base agent class for CyberSentinel AI - ATITA
"""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
import structlog
from core.config import settings
from core.models import AgentStatus


class BaseAgent(ABC):
    """Base class for all AI agents in the ATITA system"""
    
    def __init__(self, name: str, timeout: int = 30):
        self.name = name
        self.timeout = timeout
        self.logger = structlog.get_logger(f"agent.{name}")
        self.status = "stopped"
        self.tasks_processed = 0
        self.errors_count = 0
        self.performance_metrics: Dict[str, Any] = {}
        self.last_heartbeat = datetime.utcnow()
        self._running = False
    
    async def initialize(self) -> None:
        """Initialize the agent"""
        try:
            self.logger.info(f"Initializing {self.name} agent")
            await self._initialize()
            self.status = "running"
            self._running = True
            self.logger.info(f"{self.name} agent initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.name} agent: {e}")
            self.status = "error"
            raise
    
    async def shutdown(self) -> None:
        """Shutdown the agent"""
        try:
            self.logger.info(f"Shutting down {self.name} agent")
            self._running = False
            await self._shutdown()
            self.status = "stopped"
            self.logger.info(f"{self.name} agent shut down successfully")
        except Exception as e:
            self.logger.error(f"Error shutting down {self.name} agent: {e}")
            raise
    
    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a task with timeout and error handling"""
        start_time = datetime.utcnow()
        
        try:
            self.logger.info(f"Processing task in {self.name} agent", task_id=task_data.get("id"))
            
            # Update heartbeat
            self.last_heartbeat = datetime.utcnow()
            
            # Process the task with timeout
            result = await asyncio.wait_for(
                self._process_task(task_data),
                timeout=self.timeout
            )
            
            # Update metrics
            self.tasks_processed += 1
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            self.performance_metrics["last_processing_time"] = processing_time
            self.performance_metrics["average_processing_time"] = (
                (self.performance_metrics.get("average_processing_time", 0) * (self.tasks_processed - 1) + processing_time) 
                / self.tasks_processed
            )
            
            self.logger.info(f"Task processed successfully in {self.name} agent", 
                           task_id=task_data.get("id"), processing_time=processing_time)
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.error(f"Task timeout in {self.name} agent", task_id=task_data.get("id"))
            self.errors_count += 1
            raise
        except Exception as e:
            self.logger.error(f"Error processing task in {self.name} agent: {e}", 
                            task_id=task_data.get("id"))
            self.errors_count += 1
            raise
    
    def get_status(self) -> AgentStatus:
        """Get current agent status"""
        return AgentStatus(
            agent_name=self.name,
            status=self.status,
            last_heartbeat=self.last_heartbeat,
            tasks_processed=self.tasks_processed,
            errors_count=self.errors_count,
            performance_metrics=self.performance_metrics
        )
    
    def is_running(self) -> bool:
        """Check if agent is running"""
        return self._running and self.status == "running"
    
    @abstractmethod
    async def _initialize(self) -> None:
        """Agent-specific initialization"""
        pass
    
    @abstractmethod
    async def _shutdown(self) -> None:
        """Agent-specific shutdown"""
        pass
    
    @abstractmethod
    async def _process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Agent-specific task processing"""
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the agent"""
        return {
            "name": self.name,
            "status": self.status,
            "running": self._running,
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "tasks_processed": self.tasks_processed,
            "errors_count": self.errors_count,
            "performance_metrics": self.performance_metrics
        } 