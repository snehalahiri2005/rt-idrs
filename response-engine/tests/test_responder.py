"""
Unit tests for the Response Engine. Run with `pytest`.
Uses ENABLE_IPTABLES=false so no real firewall rules are touched
and a temporary SQLite DB so tests don't need root or persistent storage.
"""

import importlib
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test_incidents.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    monkeypatch.setenv("ENABLE_IPTABLES", "false")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")

    # Reload modules so they pick up the patched env vars
    import responder
    importlib.reload(responder)
    import app
    importlib.reload(app)

    app.app.config["TESTING"] = True
    with app.app.test_client() as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_incident_missing_fields(client):
    resp = client.post("/incident", json={"src_ip": "1.2.3.4"})
    assert resp.status_code == 400


def test_incident_high_severity_triggers_block(client):
    payload = {
        "src_ip": "203.0.113.10",
        "dest_ip": "10.0.0.1",
        "signature": "Possible SSH Brute Force Attempt",
        "category": "Attempted Administrator Privilege Gain",
        "severity": "high",
    }
    resp = client.post("/incident", json=payload)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["action"] == "blocked"


def test_incident_low_severity_only_logged(client):
    payload = {
        "src_ip": "203.0.113.20",
        "dest_ip": "10.0.0.1",
        "signature": "Generic low severity test",
        "category": "Not Suspicious Traffic",
        "severity": "low",
    }
    resp = client.post("/incident", json=payload)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["action"] == "logged"


def test_repeated_high_severity_already_blocked(client):
    payload = {
        "src_ip": "203.0.113.30",
        "dest_ip": "10.0.0.1",
        "signature": "Possible TCP Port Scan Detected",
        "category": "Attempted Information Leak",
        "severity": "high",
    }
    first = client.post("/incident", json=payload)
    second = client.post("/incident", json=payload)
    assert first.get_json()["action"] == "blocked"
    assert second.get_json()["action"] == "already_blocked"
