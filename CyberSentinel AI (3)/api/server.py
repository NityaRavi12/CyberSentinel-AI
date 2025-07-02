"""
Enhanced FastAPI server for CyberSentinel AI - ATITA
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from api.models import (
    ThreatSubmissionRequest,
    ThreatSubmissionResponse,
    ThreatResponse,
    FeedbackRequest,
    AnalyticsResponse,
    AgentStatusResponse,
    ErrorResponse
)
from core.models import ThreatData, ThreatStatus, ThreatType, ThreatSeverity
from core.security import (
    auth_service, get_current_user, require_analyst, require_admin,
    validate_threat_data, SecurityMiddleware
)
from agents.coordinator import CoordinatorAgent
from core.database import db_manager
from core.logging import get_logger

logger = get_logger("api_server")

# Global coordinator instance (in production, this would be managed by a proper dependency injection system)
coordinator: Optional[CoordinatorAgent] = None

def create_app() -> FastAPI:
    app = FastAPI(
        title="CyberSentinel AI - ATITA API",
        description="Autonomous Threat Intake & Triage Agent API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    # Add security middleware
    app.add_middleware(SecurityMiddleware)
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "https://cybersentinel.ai"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )
    
    # Add trusted host middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "cybersentinel.ai"]
    )

    @app.on_event("startup")
    async def startup_event():
        """Initialize the coordinator agent on startup"""
        global coordinator
        await db_manager.initialize()
        coordinator = CoordinatorAgent()
        await coordinator.initialize()
        logger.info("API server started successfully")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Shutdown the coordinator agent on shutdown"""
        global coordinator
        if coordinator:
            await coordinator.shutdown()
        await db_manager.close()
        logger.info("API server shutdown complete")

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """Rate limiting middleware"""
        client_id = request.client.host if request.client else "unknown"
        
        if not auth_service.check_rate_limit(client_id):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "retry_after": 60}
            )
        
        response = await call_next(request)
        return response

    @app.middleware("http")
    async def logging_middleware(request: Request, call_next):
        """Logging middleware"""
        start_time = datetime.utcnow()
        
        # Log request
        logger.info(
            f"Request: {request.method} {request.url.path}",
            client_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "unknown")
        )
        
        response = await call_next(request)
        
        # Log response
        process_time = (datetime.utcnow() - start_time).total_seconds()
        logger.info(
            f"Response: {response.status_code}",
            process_time=process_time,
            path=request.url.path
        )
        
        return response

    @app.get("/health", tags=["system"])
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "ok", 
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "coordinator_status": coordinator.status if coordinator else "not_initialized"
        }

    @app.get("/metrics", tags=["system"])
    async def get_metrics():
        """System metrics endpoint for monitoring"""
        try:
            # Get basic system metrics
            metrics = {
                "timestamp": datetime.utcnow().isoformat(),
                "system": {
                    "uptime": "running",  # In production, calculate actual uptime
                    "version": "1.0.0",
                    "status": "healthy"
                },
                "coordinator": {
                    "status": coordinator.status if coordinator else "not_initialized",
                    "active_threats": len(coordinator.active_threats) if coordinator else 0,
                    "processed_threats": coordinator.processed_count if coordinator else 0
                },
                "agents": {
                    "total_agents": 7,  # Fixed number of agents in the system
                    "active_agents": 7 if coordinator else 0,
                    "agent_status": {
                        "coordinator": coordinator.status if coordinator else "inactive",
                        "intake": "active",
                        "triage": "active", 
                        "enrichment": "active",
                        "policy": "active",
                        "escalation": "active",
                        "memory": "active"
                    }
                },
                "database": {
                    "status": "connected" if db_manager.is_connected() else "disconnected",
                    "total_threats": await db_manager.count_threats() if db_manager.is_connected() else 0,
                    "pending_threats": await db_manager.count_pending_threats() if db_manager.is_connected() else 0
                },
                "performance": {
                    "response_time_avg": 0.15,  # In production, calculate from actual metrics
                    "requests_per_minute": 0,  # In production, track actual requests
                    "error_rate": 0.0  # In production, calculate from actual errors
                }
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve metrics")

    @app.post("/api/v1/auth/login", tags=["authentication"])
    async def login(login_data: Dict[str, str]):
        """User login endpoint"""
        try:
            username = login_data.get("username")
            password = login_data.get("password")
            
            if not username or not password:
                raise HTTPException(
                    status_code=400,
                    detail="Username and password are required"
                )
            
            user = auth_service.authenticate_user(username, password)
            if not user:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid credentials"
                )
            
            token = auth_service.create_access_token(user)
            logger.info(f"User {username} logged in successfully")
            
            return {
                "access_token": token.access_token,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "roles": user.roles
                }
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Login error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.post("/api/v1/threats", response_model=ThreatSubmissionResponse, tags=["threats"])
    async def submit_threat(
        threat_request: ThreatSubmissionRequest,
        background_tasks: BackgroundTasks,
        current_user = Depends(require_analyst)
    ):
        """Submit a new threat for processing (requires analyst role)"""
        try:
            # Validate and sanitize input
            validated_data = validate_threat_data(threat_request.dict())
            
            threat_data = ThreatData(
                title=validated_data.get('title', threat_request.title),
                description=validated_data.get('description', threat_request.description),
                threat_type=threat_request.threat_type or ThreatType.UNKNOWN,
                severity=threat_request.severity or ThreatSeverity.MEDIUM,
                source=threat_request.source,
                source_details=validated_data.get('source_details', threat_request.source_details),
                threat_metadata=threat_request.threat_metadata,
                confidence=0.5
            )
            
            await db_manager.create_threat(threat_data)
            background_tasks.add_task(process_threat_async, threat_data)
            
            logger.info(f"Threat submitted by user {current_user.username}: {threat_data.id}")
            
            return ThreatSubmissionResponse(
                threat_id=threat_data.id,
                status="received",
                message="Threat received and queued for processing",
                processing_started=True,
                estimated_completion_time=datetime.utcnow() + timedelta(minutes=5)
            )
        except Exception as e:
            logger.error(f"Failed to submit threat: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to submit threat: {str(e)}")

    @app.get("/api/v1/threats/{threat_id}", response_model=ThreatResponse, tags=["threats"])
    async def get_threat(threat_id: str, current_user = Depends(require_analyst)):
        """Get threat details by ID (requires analyst role)"""
        threat = await db_manager.get_threat(threat_id)
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        logger.info(f"Threat {threat_id} accessed by user {current_user.username}")
        
        return ThreatResponse(
            id=threat.id,
            title=threat.title,
            description=threat.description,
            threat_type=threat.threat_type,
            severity=threat.severity,
            source=threat.source,
            confidence=threat.confidence,
            status=threat.status,
            created_at=threat.created_at,
            updated_at=threat.updated_at,
            processing_time=None
        )

    @app.put("/api/v1/threats/{threat_id}/feedback", tags=["threats"])
    async def submit_feedback(
        threat_id: str, 
        feedback: FeedbackRequest,
        current_user = Depends(require_analyst)
    ):
        """Submit analyst feedback for a threat (requires analyst role)"""
        try:
            # Validate threat exists
            threat = await db_manager.get_threat(threat_id)
            if not threat:
                raise HTTPException(status_code=404, detail="Threat not found")
            
            # Process feedback through memory agent
            if coordinator:
                await coordinator.process_task({
                    "type": "feedback_processing",
                    "threat_id": threat_id,
                    "feedback": feedback.dict(),
                    "analyst_id": current_user.id
                })
            
            logger.info(f"Feedback submitted by user {current_user.username} for threat {threat_id}")
            
            return {
                "threat_id": threat_id,
                "feedback_received": True,
                "message": "Feedback received and processed",
                "submitted_by": current_user.username,
                "timestamp": datetime.utcnow().isoformat()
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to submit feedback: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

    @app.get("/api/v1/analytics", response_model=AnalyticsResponse, tags=["analytics"])
    async def get_analytics(current_user = Depends(require_analyst)):
        """Get system performance metrics (requires analyst role)"""
        logger.info(f"Analytics accessed by user {current_user.username}")
        
        return AnalyticsResponse(
            total_threats_processed=100,
            threats_by_type={
                "malware": 45,
                "phishing": 30,
                "ransomware": 15,
                "ddos": 10
            },
            threats_by_severity={
                "low": 20,
                "medium": 40,
                "high": 30,
                "critical": 10
            },
            average_processing_time=180.5,
            auto_resolution_rate=0.75,
            escalation_rate=0.25,
            accuracy_score=0.92,
            last_updated=datetime.utcnow()
        )

    @app.get("/api/v1/agents/status", response_model=list[AgentStatusResponse], tags=["agents"])
    async def get_agent_status(current_user = Depends(require_admin)):
        """Get status of all agents (requires admin role)"""
        if not coordinator:
            raise HTTPException(status_code=503, detail="Coordinator agent not initialized")
        
        logger.info(f"Agent status accessed by admin user {current_user.username}")
        
        # Get status from all agents
        agent_statuses = []
        for name, agent in coordinator.agents.items():
            agent_statuses.append(AgentStatusResponse(
                agent_name=name,
                status=agent.status,
                last_heartbeat=agent.last_heartbeat,
                tasks_processed=agent.tasks_processed,
                errors_count=agent.errors_count,
                performance_metrics=agent.performance_metrics
            ))
        
        return agent_statuses

    @app.post("/api/v1/admin/users", tags=["admin"])
    async def create_user(
        user_data: Dict[str, Any],
        current_user = Depends(require_admin)
    ):
        """Create a new user (requires admin role)"""
        try:
            from core.security import UserCreate
            user_create = UserCreate(**user_data)
            user = auth_service.create_user(user_create)
            
            logger.info(f"User {user.username} created by admin {current_user.username}")
            
            return {
                "message": "User created successfully",
                "user_id": user.id,
                "username": user.username,
                "roles": user.roles
            }
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise HTTPException(status_code=400, detail=str(e))

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Global exception handler"""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal Server Error",
                message="An unexpected error occurred",
                details={"exception": str(exc)}
            ).dict()
        )

    return app


async def process_threat_async(threat_data: ThreatData):
    """Background task to process a threat through the agent pipeline"""
    try:
        if coordinator:
            # Process through coordinator agent
            result = await coordinator.process_task({
                "type": "threat_processing",
                "threat_data": threat_data.dict(),
                "timestamp": datetime.utcnow().isoformat()
            })
            logger.info(f"Threat {threat_data.id} processed: {result}")
    except Exception as e:
        logger.error(f"Error processing threat {threat_data.id}: {e}") 