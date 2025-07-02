#!/usr/bin/env python3
"""
CyberSentinel AI - Autonomous Threat Intake & Triage Agent (ATITA)
Main application entry point
"""

import logging
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.config import settings
from core.logging import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


def main():
    """Main application entry point"""
    try:
        logger.info("Starting CyberSentinel AI - ATITA System")
        
        # Start the API server
        import uvicorn
        uvicorn.run(
            "api.server:create_app",
            host=settings.api_host,
            port=settings.api_port,
            reload=settings.debug,
            factory=True
        )
        
    except KeyboardInterrupt:
        logger.info("Shutting down CyberSentinel AI - ATITA System")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 