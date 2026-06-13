"""
analyzer.py
-----------
Tails Suricata's eve.json log in real time, normalizes "alert" events,
applies simple correlation/severity rules, and forwards confirmed
incidents to the Response Engine REST API.
"""

import json
import os
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [analyzer] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

EVE_LOG_PATH = os.environ.get("EVE_LOG_PATH", "/var/log/suricata/eve.json")
RESPONSE_ENGINE_URL = os.environ.get(
    "RESPONSE_ENGINE_URL", "http://response-engine:5001/incident"
)
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "1.0"))

# Track recent alert counts per source IP for simple correlation
# (sliding window of timestamps per (src_ip, signature_category))
_recent_events = defaultdict(lambda: deque(maxlen=200))

# Map Suricata alert "category" text (eve.json's human-readable
# classtype description) to our own severity levels used by the
# Response Engine. Matching is done as a case-insensitive substring
# check, so keep these keys lowercase.
SEVERITY_MAP = {
    "attempted administrator privilege gain": "high",
    "attempted denial of service": "high",
    "attempted user privilege gain": "high",
    "web application attack": "high",
    "attempted information leak": "medium",
    "potentially bad traffic": "medium",
}

CORRELATION_WINDOW = timedelta(seconds=60)
CORRELATION_THRESHOLD = 5  # events from same src in window -> escalate


def classify_severity(alert: dict) -> str:
    """Decide a severity level for the alert."""
    classtype = alert.get("alert", {}).get("category", "").lower()
    for key, sev in SEVERITY_MAP.items():
        if key in classtype:
            return sev
    return "low"


def correlate(src_ip: str, signature: str) -> bool:
    """
    Returns True if this src_ip has triggered enough alerts recently
    to be escalated, regardless of base severity.
    """
    now = datetime.utcnow()
    key = (src_ip, signature)
    window = _recent_events[key]
    window.append(now)

    # drop old entries
    while window and (now - window[0]) > CORRELATION_WINDOW:
        window.popleft()

    return len(window) >= CORRELATION_THRESHOLD


def build_incident(alert: dict) -> dict:
    src_ip = alert.get("src_ip", "unknown")
    dest_ip = alert.get("dest_ip", "unknown")
    signature = alert.get("alert", {}).get("signature", "unknown")
    severity = classify_severity(alert)

    if correlate(src_ip, signature):
        severity = "high"

    return {
        "timestamp": alert.get("timestamp"),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "proto": alert.get("proto"),
        "signature": signature,
        "category": alert.get("alert", {}).get("category"),
        "severity": severity,
        "raw_sid": alert.get("alert", {}).get("signature_id"),
    }


def forward_incident(incident: dict):
    try:
        resp = requests.post(RESPONSE_ENGINE_URL, json=incident, timeout=5)
        if resp.status_code >= 300:
            log.warning(
                "Response engine returned %s for incident %s",
                resp.status_code,
                incident,
            )
        else:
            log.info(
                "Forwarded incident (severity=%s, src=%s, sig=%s)",
                incident["severity"],
                incident["src_ip"],
                incident["signature"],
            )
    except requests.RequestException as exc:
        log.error("Failed to reach response engine: %s", exc)


def tail_file(path: str):
    """Generator that yields new lines appended to `path`, like `tail -f`."""
    while not os.path.exists(path):
        log.info("Waiting for log file %s to appear...", path)
        time.sleep(POLL_INTERVAL)

    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue
            yield line


def main():
    log.info("Starting analyzer, tailing %s", EVE_LOG_PATH)
    for line in tail_file(EVE_LOG_PATH):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        incident = build_incident(event)
        forward_incident(incident)


if __name__ == "__main__":
    main()
