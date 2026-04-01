from http import client


def test_get_cve():
    response = client.get("/api/v1/vulnerabilities/CVE-2005-0012")
    assert response.status_code == 200