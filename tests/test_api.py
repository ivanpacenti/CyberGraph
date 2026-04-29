from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["message"] == "CyberGraph API is running"


def test_unknown_cve_returns_404():
    response = client.get("/api/v1/vulnerabilities/CVE-0000-0000")

    assert response.status_code == 404