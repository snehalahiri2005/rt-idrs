"""
Unit tests for analyzer.py — run with `pytest` inside the Jenkins
'test' stage. These don't require a live Suricata or network.
"""

import importlib
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

analyzer = importlib.import_module("analyzer")


def test_classify_severity_known_category():
    alert = {"alert": {"category": "Attempted Administrator Privilege Gain"}}
    assert analyzer.classify_severity(alert) == "high"


def test_classify_severity_unknown_category_defaults_low():
    alert = {"alert": {"category": "Some Unknown Category"}}
    assert analyzer.classify_severity(alert) == "low"


def test_build_incident_basic_fields():
    alert = {
        "timestamp": "2026-06-13T10:00:00.000000+0000",
        "src_ip": "10.0.0.5",
        "dest_ip": "10.0.0.1",
        "proto": "TCP",
        "alert": {
            "signature": "Possible TCP Port Scan Detected",
            "category": "Attempted Information Leak",
            "signature_id": 1000002,
        },
    }
    incident = analyzer.build_incident(alert)
    assert incident["src_ip"] == "10.0.0.5"
    assert incident["signature"] == "Possible TCP Port Scan Detected"
    assert incident["raw_sid"] == 1000002


def test_correlation_escalates_after_threshold():
    analyzer._recent_events.clear()
    src_ip = "10.0.0.99"
    sig = "Test Signature"

    # Below threshold -> not escalated
    for _ in range(analyzer.CORRELATION_THRESHOLD - 1):
        result = analyzer.correlate(src_ip, sig)
    assert result is False

    # One more event reaches the threshold -> escalated
    result = analyzer.correlate(src_ip, sig)
    assert result is True
