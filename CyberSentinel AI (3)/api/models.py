"""
API models for CyberSentinel AI - ATITA
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from core.models import ThreatType, ThreatSeverity, SourceType


class ThreatSubmissionRequest(BaseModel):
    """Request model for threat submission"""
    title: str = Field(..., description="Threat title")
    description: str = Field(..., description="Detailed threat description")
    threat_type: Optional[ThreatType] = Field(None, description="Type of threat")
    severity: Optional[ThreatSeverity] = Field(None, description="Threat severity")
    source: Optional[SourceType] = Field(None, description="Source of the threat")
    source_details: Dict[str, Any] = Field(default_factory=dict, description="Additional source information")
    threat_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ThreatResponse(BaseModel):
    """Response model for threat data"""
    id: str
    title: str
    description: str
    threat_type: ThreatType
    severity: ThreatSeverity
    source: SourceType
    confidence: float
    status: str
    created_at: datetime
    updated_at: datetime
    processing_time: Optional[float] = None


class ThreatSubmissionResponse(BaseModel):
    """Response model for threat submission"""
    threat_id: str
    status: str
    message: str
    processing_started: bool = True
    estimated_completion_time: Optional[datetime] = None


class FeedbackRequest(BaseModel):
    """Request model for analyst feedback"""
    analyst_id: str = Field(..., description="ID of the analyst providing feedback")
    feedback_type: str = Field(..., description="Type of feedback (classification, severity, action, general)")
    feedback_data: Dict[str, Any] = Field(..., description="Feedback data")
    confidence_rating: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence rating")


class AnalyticsResponse(BaseModel):
    """Response model for system analytics"""
    total_threats_processed: int
    threats_by_type: Dict[str, int]
    threats_by_severity: Dict[str, int]
    average_processing_time: float
    auto_resolution_rate: float
    escalation_rate: float
    accuracy_score: float
    last_updated: datetime


class AgentStatusResponse(BaseModel):
    """Response model for agent status"""
    agent_name: str
    status: str
    last_heartbeat: datetime
    tasks_processed: int
    errors_count: int
    performance_metrics: Dict[str, Any]


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None 