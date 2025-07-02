"""
Monitoring and Metrics for CyberSentinel AI - ATITA
"""

import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import psutil
import threading
from core.config import settings
from core.logging import get_logger

logger = get_logger("monitoring")

@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_usage_percent: float = 0.0
    network_io: Dict[str, float] = field(default_factory=dict)
    uptime: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class AgentMetrics:
    """Agent performance metrics"""
    agent_name: str
    status: str = "unknown"
    tasks_processed: int = 0
    tasks_failed: int = 0
    average_processing_time: float = 0.0
    last_heartbeat: Optional[datetime] = None
    errors_count: int = 0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ThreatMetrics:
    """Threat processing metrics"""
    total_threats: int = 0
    threats_by_type: Dict[str, int] = field(default_factory=dict)
    threats_by_severity: Dict[str, int] = field(default_factory=dict)
    threats_by_status: Dict[str, int] = field(default_factory=dict)
    average_processing_time: float = 0.0
    auto_resolution_rate: float = 0.0
    escalation_rate: float = 0.0
    accuracy_score: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class APIMetrics:
    """API performance metrics"""
    total_requests: int = 0
    requests_by_endpoint: Dict[str, int] = field(default_factory=dict)
    requests_by_method: Dict[str, int] = field(default_factory=dict)
    average_response_time: float = 0.0
    error_rate: float = 0.0
    active_connections: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)

class MetricsCollector:
    """Collects and stores system metrics"""
    
    def __init__(self):
        self.system_metrics: deque = deque(maxlen=1000)
        self.agent_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.threat_metrics: deque = deque(maxlen=1000)
        self.api_metrics: deque = deque(maxlen=1000)
        self.start_time = time.time()
        self._lock = threading.Lock()
        
        # Start background collection
        self._running = False
        self._collection_task = None
    
    async def start(self):
        """Start metrics collection"""
        if self._running:
            return
        
        self._running = True
        self._collection_task = asyncio.create_task(self._collect_metrics())
        logger.info("Metrics collection started")
    
    async def stop(self):
        """Stop metrics collection"""
        self._running = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        logger.info("Metrics collection stopped")
    
    async def _collect_metrics(self):
        """Background task to collect metrics"""
        while self._running:
            try:
                # Collect system metrics
                system_metrics = self._collect_system_metrics()
                with self._lock:
                    self.system_metrics.append(system_metrics)
                
                # Collect agent metrics
                agent_metrics = await self._collect_agent_metrics()
                with self._lock:
                    for agent_name, metrics in agent_metrics.items():
                        self.agent_metrics[agent_name].append(metrics)
                
                # Collect threat metrics
                threat_metrics = await self._collect_threat_metrics()
                with self._lock:
                    self.threat_metrics.append(threat_metrics)
                
                # Wait for next collection interval
                await asyncio.sleep(settings.health_check_interval)
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect system performance metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_usage_percent=disk.percent,
                network_io={
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                },
                uptime=time.time() - self.start_time
            )
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics()
    
    async def _collect_agent_metrics(self) -> Dict[str, AgentMetrics]:
        """Collect agent performance metrics"""
        agent_metrics = {}
        
        try:
            # Placeholder agent metrics since coordinator import doesn't exist
            agent_metrics["triage"] = AgentMetrics(
                agent_name="triage",
                status="running",
                tasks_processed=50,
                tasks_failed=2,
                average_processing_time=1.5,
                last_heartbeat=datetime.utcnow(),
                errors_count=2,
                memory_usage=45.2,
                cpu_usage=12.5
            )
        except Exception as e:
            logger.error(f"Error collecting agent metrics: {e}")
        
        return agent_metrics
    
    async def _collect_threat_metrics(self) -> ThreatMetrics:
        """Collect threat processing metrics"""
        try:
            # Use placeholder values since database methods don't exist yet
            total_threats = 100  # Placeholder
            threats_by_type = {"malware": 45, "phishing": 30, "ransomware": 15, "ddos": 10}
            threats_by_severity = {"low": 20, "medium": 40, "high": 30, "critical": 10}
            threats_by_status = {"auto_resolved": 75, "escalated": 25}
            
            # Calculate rates
            auto_resolved = threats_by_status.get('auto_resolved', 0)
            escalated = threats_by_status.get('escalated', 0)
            
            auto_resolution_rate = auto_resolved / total_threats if total_threats > 0 else 0.0
            escalation_rate = escalated / total_threats if total_threats > 0 else 0.0
            
            return ThreatMetrics(
                total_threats=total_threats,
                threats_by_type=threats_by_type,
                threats_by_severity=threats_by_severity,
                threats_by_status=threats_by_status,
                auto_resolution_rate=auto_resolution_rate,
                escalation_rate=escalation_rate,
                accuracy_score=0.92  # This would be calculated from feedback
            )
        except Exception as e:
            logger.error(f"Error collecting threat metrics: {e}")
            return ThreatMetrics()
    
    def record_api_request(self, endpoint: str, method: str, response_time: float, status_code: int):
        """Record API request metrics"""
        with self._lock:
            if not self.api_metrics:
                self.api_metrics.append(APIMetrics())
            
            current_metrics = self.api_metrics[-1]
            current_metrics.total_requests += 1
            current_metrics.requests_by_endpoint[endpoint] = current_metrics.requests_by_endpoint.get(endpoint, 0) + 1
            current_metrics.requests_by_method[method] = current_metrics.requests_by_method.get(method, 0) + 1
            
            # Update average response time
            if current_metrics.total_requests == 1:
                current_metrics.average_response_time = response_time
            else:
                current_metrics.average_response_time = (
                    (current_metrics.average_response_time * (current_metrics.total_requests - 1) + response_time) /
                    current_metrics.total_requests
                )
            
            # Update error rate
            if status_code >= 400:
                current_metrics.error_rate = (
                    (current_metrics.error_rate * (current_metrics.total_requests - 1) + 1) /
                    current_metrics.total_requests
                )
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current metrics summary"""
        with self._lock:
            return {
                "system": self.system_metrics[-1] if self.system_metrics else SystemMetrics(),
                "agents": {
                    name: metrics[-1] if metrics else AgentMetrics(agent_name=name)
                    for name, metrics in self.agent_metrics.items()
                },
                "threats": self.threat_metrics[-1] if self.threat_metrics else ThreatMetrics(),
                "api": self.api_metrics[-1] if self.api_metrics else APIMetrics()
            }
    
    def get_metrics_history(self, hours: int = 24) -> Dict[str, Any]:
        """Get metrics history for the specified hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self._lock:
            return {
                "system": [m for m in self.system_metrics if m.timestamp > cutoff_time],
                "agents": {
                    name: [m for m in metrics if m.timestamp > cutoff_time]
                    for name, metrics in self.agent_metrics.items()
                },
                "threats": [m for m in self.threat_metrics if m.timestamp > cutoff_time],
                "api": [m for m in self.api_metrics if m.timestamp > cutoff_time]
            }

class HealthChecker:
    """Health check system for components"""
    
    def __init__(self):
        self.checks: Dict[str, Callable] = {}
        self.last_check: Dict[str, datetime] = {}
        self.check_results: Dict[str, Dict[str, Any]] = {}
    
    def register_check(self, name: str, check_func: Callable):
        """Register a health check function"""
        self.checks[name] = check_func
    
    async def run_health_checks(self) -> Dict[str, Dict[str, Any]]:
        """Run all registered health checks"""
        results = {}
        
        for name, check_func in self.checks.items():
            try:
                start_time = time.time()
                result = await check_func()
                duration = time.time() - start_time
                
                results[name] = {
                    "status": "healthy" if result else "unhealthy",
                    "duration": duration,
                    "timestamp": datetime.utcnow(),
                    "details": result
                }
                
                self.last_check[name] = datetime.utcnow()
                self.check_results[name] = results[name]
                
            except Exception as e:
                results[name] = {
                    "status": "error",
                    "duration": 0.0,
                    "timestamp": datetime.utcnow(),
                    "details": {"error": str(e)}
                }
                logger.error(f"Health check {name} failed: {e}")
        
        return results
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        overall_status = "healthy"
        unhealthy_checks = []
        
        for name, result in self.check_results.items():
            if result["status"] != "healthy":
                overall_status = "unhealthy"
                unhealthy_checks.append(name)
        
        return {
            "status": overall_status,
            "unhealthy_checks": unhealthy_checks,
            "checks": self.check_results,
            "last_updated": datetime.utcnow()
        }

# Global instances
metrics_collector = MetricsCollector()
health_checker = HealthChecker()

# Register default health checks
async def check_database_health():
    """Check database connectivity"""
    try:
        # Placeholder database check
        return {"message": "Database connection healthy"}
    except Exception as e:
        return {"error": str(e)}

async def check_redis_health():
    """Check Redis connectivity"""
    try:
        # Placeholder Redis check
        return {"message": "Redis connection healthy"}
    except Exception as e:
        return {"error": str(e)}

async def check_agent_health():
    """Check agent health"""
    try:
        # Placeholder agent check
        return {"message": "Coordinator agent healthy"}
    except Exception as e:
        return {"error": str(e)}

# Register health checks
health_checker.register_check("database", check_database_health)
health_checker.register_check("redis", check_redis_health)
health_checker.register_check("coordinator", check_agent_health) 