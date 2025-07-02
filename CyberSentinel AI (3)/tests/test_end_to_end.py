import pytest
from fastapi.testclient import TestClient
from api.server import create_app
from core.database import db_manager
import asyncio

app = create_app()
client = TestClient(app)

@pytest.mark.asyncio
async def test_end_to_end_flow():
    # Submit a new threat
    threat_payload = {
        "title": "Phishing Email Detected",
        "description": "User reported a suspicious email with phishing content.",
        "source": "email",
        "source_details": {"sender": "attacker@example.com"},
        "threat_metadata": {}
    }
    response = client.post("/api/v1/threats", json=threat_payload)
    assert response.status_code == 200
    threat_id = response.json()["threat_id"]

    # Wait for background processing (simulate async workflow)
    await asyncio.sleep(2)  # Increase if workflow is slow

    # Retrieve the threat and check status
    response = client.get(f"/api/v1/threats/{threat_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == threat_id
    assert data["status"] in ["triaged", "enriched", "policy_applied", "escalated", "closed"] 