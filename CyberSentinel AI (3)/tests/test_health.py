import pytest
from fastapi.testclient import TestClient
from api.server import create_app

app = create_app()
client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"} 