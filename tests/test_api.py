import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "apis_configured" in data


def test_translations_en(client):
    resp = client.get("/api/v1/translations/en")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["app_title"] == "Phishing Email Detector"


def test_translations_es(client):
    resp = client.get("/api/v1/translations/es")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["app_title"] == "Detector de Phishing"


def test_translations_invalid(client):
    resp = client.get("/api/v1/translations/xx")
    assert resp.status_code == 404


def test_analyze_text(client):
    resp = client.post("/api/v1/analyze/text", json={
        "text": "Click here: http://192.168.1.1/steal your password",
        "language": "en",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert len(data["alarms"]) > 0
    assert "analysis_time_ms" in data["metadata"]


def test_analyze_text_empty(client):
    resp = client.post("/api/v1/analyze/text", json={"text": ""})
    assert resp.status_code == 400


def test_analyze_text_clean(client):
    resp = client.post("/api/v1/analyze/text", json={
        "text": "Hi, here is the agenda for tomorrow's meeting.",
        "language": "en",
    })
    data = resp.get_json()
    assert data["success"] is True
    assert data["risk_level"] == "low"


def test_analyze_eml(client):
    eml_data = b"""From: attacker@gmail.com
To: victim@example.com
Subject: Urgent
Content-Type: text/plain

Your PayPal account is suspended. Enter your password at http://192.168.1.1/login
"""
    import io
    resp = client.post("/api/v1/analyze/eml", data={
        "file": (io.BytesIO(eml_data), "phishing.eml"),
        "language": "en",
    }, content_type="multipart/form-data")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert len(data["alarms"]) > 0


def test_analyze_eml_no_file(client):
    resp = client.post("/api/v1/analyze/eml")
    assert resp.status_code == 400


def test_analyze_eml_wrong_extension(client):
    import io
    resp = client.post("/api/v1/analyze/eml", data={
        "file": (io.BytesIO(b"test"), "file.txt"),
    }, content_type="multipart/form-data")
    assert resp.status_code == 400
