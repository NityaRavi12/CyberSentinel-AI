"""
Core data models for CyberSentinel AI - ATITA
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4
from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(str, Enum):
    """Threat processing status"""
    RECEIVED = "received"
    TRIAGED = "triaged"
    ENRICHED = "enriched"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ThreatType(str, Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    DDoS = "ddos"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Threat source types"""
    EMAIL = "email"
    API = "api"
    FILE_UPLOAD = "file_upload"
    SIEM = "siem"
    IDS_IPS = "ids_ips"
    USER_REPORT = "user_report"


class ThreatData(BaseModel):
    """Base threat data model"""
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    source: SourceType
    source_details: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: ThreatStatus = ThreatStatus.RECEIVED
    threat_metadata: Dict[str, Any] = Field(default_factory=dict)


class EnrichmentData(BaseModel):
    """Threat enrichment data"""
    threat_id: str
    virustotal_data: Optional[Dict[str, Any]] = None
    alienvault_data: Optional[Dict[str, Any]] = None
    threatfox_data: Optional[Dict[str, Any]] = None
    ioc_data: List[Dict[str, Any]] = Field(default_factory=list)
    related_threats: List[str] = Field(default_factory=list)
    enriched_at: datetime = Field(default_factory=datetime.utcnow)


class PolicyDecision(BaseModel):
    """Policy-based decision"""
    threat_id: str
    policy_name: str
    decision: str
    actions: List[str] = Field(default_factory=list)
    requires_approval: bool = True
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EscalationData(BaseModel):
    """Escalation information"""
    threat_id: str
    escalated_at: datetime = Field(default_factory=datetime.utcnow)
    reason: str
    assigned_to: Optional[str] = None
    priority: str = "normal"
    notes: Optional[str] = None


class AnalystFeedback(BaseModel):
    """Analyst feedback on threat processing"""
    threat_id: str
    analyst_id: str
    feedback_type: str  # "classification", "severity", "action", "general"
    feedback_data: Dict[str, Any]
    confidence_rating: Optional[float] = Field(None, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ThreatCase(BaseModel):
    """Complete threat case with all related data"""
    threat: ThreatData
    enrichment: Optional[EnrichmentData] = None
    policy_decisions: List[PolicyDecision] = Field(default_factory=list)
    escalation: Optional[EscalationData] = None
    feedback: List[AnalystFeedback] = Field(default_factory=list)
    auto_actions_taken: List[str] = Field(default_factory=list)
    processing_time: Optional[float] = None  # in seconds
    threat_metadata: Dict[str, Any] = Field(default_factory=dict)


class SystemMetrics(BaseModel):
    """System performance metrics"""
    total_threats_processed: int = 0
    threats_by_type: Dict[str, int] = Field(default_factory=dict)
    threats_by_severity: Dict[str, int] = Field(default_factory=dict)
    average_processing_time: float = 0.0
    auto_resolution_rate: float = 0.0
    escalation_rate: float = 0.0
    accuracy_score: float = 0.0
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class AgentStatus(BaseModel):
    """Agent status information"""
    agent_name: str
    status: str  # "running", "stopped", "error"
    last_heartbeat: datetime
    tasks_processed: int = 0
    errors_count: int = 0
    performance_metrics: Dict[str, Any] = Field(default_factory=dict) 