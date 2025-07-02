"""
Comprehensive test for CyberSentinel AI - ATITA complete workflow
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from api.server import create_app
from core.database import db_manager
from core.models import ThreatType, ThreatSeverity, SourceType
from agents.coordinator import CoordinatorAgent
import json


class TestCompleteWorkflow:
    """Test the complete CyberSentinel AI workflow"""
    
    @pytest.fixture(autouse=True)
    async def setup(self):
        """Setup test environment"""
        # Initialize database
        await db_manager.initialize()
        
        # Create test app
        self.app = create_app()
        self.client = TestClient(self.app)
        
        # Initialize coordinator
        self.coordinator = CoordinatorAgent()
        await self.coordinator.initialize()
        
        yield
        
        # Cleanup
        await self.coordinator.shutdown()
        await db_manager.close()

    @pytest.mark.asyncio
    async def test_complete_threat_workflow(self):
        """Test complete threat processing workflow"""
        
        # 1. Submit a threat via API
        threat_payload = {
            "title": "Suspicious Ransomware Email Detected",
            "description": "User received email with ransomware attachment. Email contains urgent language and suspicious attachment.",
            "source": "email",
            "source_details": {
                "sender": "attacker@malicious.com",
                "subject": "URGENT: Your account has been suspended",
                "attachments": ["invoice.exe"]
            },
            "threat_metadata": {
                "user_id": "user123",
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }
        
        response = self.client.post("/api/v1/threats", json=threat_payload)
        assert response.status_code == 200
        
        threat_response = response.json()
        threat_id = threat_response["threat_id"]
        assert threat_response["status"] == "received"
        assert threat_response["processing_started"] == True
        
        # 2. Wait for background processing
        await asyncio.sleep(3)  # Allow time for async processing
        
        # 3. Check threat status after processing
        response = self.client.get(f"/api/v1/threats/{threat_id}")
        assert response.status_code == 200
        
        threat_data = response.json()
        assert threat_data["id"] == threat_id
        assert threat_data["title"] == "Suspicious Ransomware Email Detected"
        
        # 4. Verify threat classification (should be ransomware due to keywords)
        assert threat_data["threat_type"] == "ransomware"
        assert threat_data["severity"] == "critical"
        assert threat_data["confidence"] > 0.8
        
        # 5. Check that threat was processed through all agents
        # The status should be "closed" after memory agent processing
        assert threat_data["status"] in ["triaged", "enriched", "policy_applied", "escalated", "closed"]

    @pytest.mark.asyncio
    async def test_phishing_email_workflow(self):
        """Test phishing email processing workflow"""
        
        # Submit phishing threat
        threat_payload = {
            "title": "Phishing Attempt Detected",
            "description": "User clicked on suspicious link in email claiming to be from bank.",
            "source": "email",
            "source_details": {
                "sender": "noreply@fakebank.com",
                "subject": "Verify your account immediately",
                "urls": ["https://fake-bank-login.com/verify"]
            }
        }
        
        response = self.client.post("/api/v1/threats", json=threat_payload)
        assert response.status_code == 200
        
        threat_id = response.json()["threat_id"]
        
        # Wait for processing
        await asyncio.sleep(3)
        
        # Check results
        response = self.client.get(f"/api/v1/threats/{threat_id}")
        assert response.status_code == 200
        
        threat_data = response.json()
        assert threat_data["threat_type"] == "phishing"
        assert threat_data["severity"] in ["medium", "high"]

    @pytest.mark.asyncio
    async def test_malware_file_workflow(self):
        """Test malware file processing workflow"""
        
        # Submit malware file threat
        threat_payload = {
            "title": "Malicious File Upload",
            "description": "User uploaded suspicious executable file with invoice name.",
            "source": "file_upload",
            "source_details": {
                "filename": "invoice_scan.exe",
                "file_size": 2048576,
                "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd"
            }
        }
        
        response = self.client.post("/api/v1/threats", json=threat_payload)
        assert response.status_code == 200
        
        threat_id = response.json()["threat_id"]
        
        # Wait for processing
        await asyncio.sleep(3)
        
        # Check results
        response = self.client.get(f"/api/v1/threats/{threat_id}")
        assert response.status_code == 200
        
        threat_data = response.json()
        assert threat_data["threat_type"] == "malware"
        assert threat_data["severity"] in ["high", "critical"]

    @pytest.mark.asyncio
    async def test_agent_status_endpoint(self):
        """Test agent status endpoint"""
        
        response = self.client.get("/api/v1/agents/status")
        assert response.status_code == 200
        
        agents = response.json()
        assert len(agents) > 0
        
        # Check coordinator agent status
        coordinator = next((agent for agent in agents if agent["agent_name"] == "coordinator"), None)
        assert coordinator is not None
        assert coordinator["status"] == "running"
        assert coordinator["tasks_processed"] >= 0

    @pytest.mark.asyncio
    async def test_analytics_endpoint(self):
        """Test analytics endpoint"""
        
        response = self.client.get("/api/v1/analytics")
        assert response.status_code == 200
        
        analytics = response.json()
        assert "total_threats_processed" in analytics
        assert "threats_by_type" in analytics
        assert "threats_by_severity" in analytics
        assert "average_processing_time" in analytics
        assert "auto_resolution_rate" in analytics
        assert "escalation_rate" in analytics
        assert "accuracy_score" in analytics

    @pytest.mark.asyncio
    async def test_feedback_workflow(self):
        """Test analyst feedback workflow"""
        
        # First submit a threat
        threat_payload = {
            "title": "Test Threat for Feedback",
            "description": "This is a test threat for feedback processing.",
            "source": "api"
        }
        
        response = self.client.post("/api/v1/threats", json=threat_payload)
        assert response.status_code == 200
        
        threat_id = response.json()["threat_id"]
        
        # Wait for processing
        await asyncio.sleep(2)
        
        # Submit feedback
        feedback_payload = {
            "analyst_id": "analyst1@company.com",
            "feedback_type": "classification",
            "feedback_data": {
                "original_classification": "malware",
                "corrected_classification": "phishing",
                "reason": "False positive - was actually phishing attempt"
            },
            "confidence_rating": 0.9
        }
        
        response = self.client.put(f"/api/v1/threats/{threat_id}/feedback", json=feedback_payload)
        assert response.status_code == 200
        
        feedback_response = response.json()
        assert feedback_response["feedback_received"] == True

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        """Test health check endpoint"""
        
        response = self.client.get("/health")
        assert response.status_code == 200
        
        health_data = response.json()
        assert health_data["status"] == "ok"
        assert "timestamp" in health_data

    @pytest.mark.asyncio
    async def test_coordinator_workflow_direct(self):
        """Test coordinator workflow directly"""
        
        # Create test threat data
        threat_data = {
            "id": "test-threat-123",
            "title": "Direct Test Threat",
            "description": "Testing coordinator workflow directly",
            "threat_type": "malware",
            "severity": "high",
            "source": "api",
            "confidence": 0.8
        }
        
        # Process through coordinator
        task_data = {
            "type": "threat_processing",
            "threat_data": threat_data,
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        result = await self.coordinator.process_task(task_data)
        assert result["status"] == "queued"
        assert "task_id" in result
        
        # Wait for processing
        await asyncio.sleep(2)
        
        # Check workflow status
        workflow_status = self.coordinator.get_workflow_status(result["task_id"])
        assert workflow_status["status"] in ["completed", "error", "queued"]

    @pytest.mark.asyncio
    async def test_database_persistence(self):
        """Test database persistence of threats"""
        
        # Submit threat
        threat_payload = {
            "title": "Database Test Threat",
            "description": "Testing database persistence",
            "source": "api"
        }
        
        response = self.client.post("/api/v1/threats", json=threat_payload)
        assert response.status_code == 200
        
        threat_id = response.json()["threat_id"]
        
        # Wait for processing
        await asyncio.sleep(2)
        
        # Retrieve from database
        threat = await db_manager.get_threat(threat_id)
        assert threat is not None
        assert threat.id == threat_id
        assert threat.title == "Database Test Threat"
        assert threat.status in ["received", "triaged", "enriched", "policy_applied", "escalated", "closed"]

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in workflow"""
        
        # Submit invalid threat (missing required fields)
        invalid_payload = {
            "description": "Missing title field"
        }
        
        response = self.client.post("/api/v1/threats", json=invalid_payload)
        assert response.status_code == 422  # Validation error
        
        # Test non-existent threat retrieval
        response = self.client.get("/api/v1/threats/non-existent-id")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_concurrent_threat_processing(self):
        """Test concurrent threat processing"""
        
        # Submit multiple threats concurrently
        threats = []
        for i in range(3):
            threat_payload = {
                "title": f"Concurrent Test Threat {i+1}",
                "description": f"Testing concurrent processing - threat {i+1}",
                "source": "api"
            }
            
            response = self.client.post("/api/v1/threats", json=threat_payload)
            assert response.status_code == 200
            threats.append(response.json()["threat_id"])
        
        # Wait for processing
        await asyncio.sleep(4)
        
        # Check all threats were processed
        for threat_id in threats:
            response = self.client.get(f"/api/v1/threats/{threat_id}")
            assert response.status_code == 200
            
            threat_data = response.json()
            assert threat_data["status"] in ["triaged", "enriched", "policy_applied", "escalated", "closed"] 