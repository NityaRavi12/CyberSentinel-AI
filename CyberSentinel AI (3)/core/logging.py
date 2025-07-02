"""
Logging configuration for CyberSentinel AI - ATITA
"""

import logging
import sys
from typing import Any, Dict
import structlog
from core.config import settings


def setup_logging() -> None:
    """Setup structured logging for the application"""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level.upper()),
    )
    
    # Set specific logger levels
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance"""
    return structlog.get_logger(name)


class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self, name: str = "security"):
        self.logger = get_logger(name)
    
    def log_threat_detected(self, threat_data: Dict[str, Any]) -> None:
        """Log a detected threat"""
        self.logger.warning(
            "Threat detected",
            threat_id=threat_data.get("id"),
            threat_type=threat_data.get("type"),
            confidence=threat_data.get("confidence"),
            source=threat_data.get("source"),
            severity=threat_data.get("severity")
        )
    
    def log_escalation(self, threat_id: str, reason: str) -> None:
        """Log threat escalation"""
        self.logger.info(
            "Threat escalated",
            threat_id=threat_id,
            reason=reason
        )
    
    def log_auto_response(self, threat_id: str, action: str) -> None:
        """Log automatic response action"""
        self.logger.info(
            "Automatic response executed",
            threat_id=threat_id,
            action=action
        )
    
    def log_analyst_feedback(self, threat_id: str, feedback: Dict[str, Any]) -> None:
        """Log analyst feedback"""
        self.logger.info(
            "Analyst feedback received",
            threat_id=threat_id,
            feedback=feedback
        ) 