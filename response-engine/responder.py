"""
responder.py — helper functions used by the Response Engine:
- blocking IPs with iptables/ipset
- sending notifications (Slack webhook + email)
- persisting incidents/actions to SQLite
"""

import json
import logging
import os
import smtplib
import sqlite3
import subprocess
from datetime import datetime
from email.mime.text import MIMEText

import requests

log = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/incidents.db")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
# Set to "false" to disable real iptables calls (useful for local/dev/testing)
ENABLE_IPTABLES = os.environ.get("ENABLE_IPTABLES", "true").lower() == "true"

# --- Email alert configuration ---
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", SMTP_USERNAME)
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO", "")  # comma-separated list
# Only send an email for incidents at or above this severity
ALERT_EMAIL_MIN_SEVERITY = os.environ.get("ALERT_EMAIL_MIN_SEVERITY", "medium")

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

_blocked_ips_cache = set()


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            signature TEXT,
            category TEXT,
            severity TEXT,
            action TEXT,
            raw_json TEXT
        )
        """
    )
    return conn


def save_incident(incident: dict, action: str):
    conn = _get_db()
    try:
        conn.execute(
            """
            INSERT INTO incidents
              (received_at, src_ip, dest_ip, signature, category, severity, action, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                incident.get("src_ip"),
                incident.get("dest_ip"),
                incident.get("signature"),
                incident.get("category"),
                incident.get("severity"),
                action,
                json.dumps(incident),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def is_ip_blocked(ip: str) -> bool:
    return ip in _blocked_ips_cache


def block_ip(ip: str) -> bool:
    """
    Block an IP address using iptables. Returns True on success.
    When ENABLE_IPTABLES is false (e.g. in CI/test environments where
    the container lacks NET_ADMIN), this only updates the in-memory
    cache so the rest of the flow can still be tested.
    """
    if not ENABLE_IPTABLES:
        log.info("ENABLE_IPTABLES=false, skipping real block for %s", ip)
        _blocked_ips_cache.add(ip)
        return True

    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        _blocked_ips_cache.add(ip)
        log.info("Blocked IP %s via iptables", ip)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        log.error("Failed to block IP %s: %s", ip, exc)
        return False


def unblock_ip(ip: str) -> bool:
    if not ENABLE_IPTABLES:
        _blocked_ips_cache.discard(ip)
        return True

    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        _blocked_ips_cache.discard(ip)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        log.error("Failed to unblock IP %s: %s", ip, exc)
        return False


def send_notification(incident: dict, action: str):
    if not SLACK_WEBHOOK_URL:
        log.debug("SLACK_WEBHOOK_URL not set, skipping Slack notification")
        return

    text = (
        f":rotating_light: *IDS Alert* (`{incident.get('severity')}`)\n"
        f"Signature: {incident.get('signature')}\n"
        f"Source IP: {incident.get('src_ip')}\n"
        f"Destination IP: {incident.get('dest_ip')}\n"
        f"Action taken: *{action}*"
    )

    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=5)
    except requests.RequestException as exc:
        log.error("Failed to send Slack notification: %s", exc)


def send_email_alert(incident: dict, action: str):
    """
    Sends an email alert to the configured recipient(s) — typically the
    owner/administrator of the system being targeted — when an incident
    meets or exceeds ALERT_EMAIL_MIN_SEVERITY.

    Requires SMTP_HOST and ALERT_EMAIL_TO to be set; otherwise this is a
    no-op (useful for local/dev/testing where no mail server is configured).
    """
    log.info(
    "Email config loaded. SMTP_HOST=%s ALERT_EMAIL_TO=%s",
    SMTP_HOST,
    ALERT_EMAIL_TO,
    )
    if not SMTP_HOST or not ALERT_EMAIL_TO:
        log.debug("Email alerting not configured, skipping email")
        return

    severity = (incident.get("severity") or "low").lower()
    if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(ALERT_EMAIL_MIN_SEVERITY, 1):
        log.debug(
            "Incident severity '%s' below ALERT_EMAIL_MIN_SEVERITY '%s', skipping email",
            severity,
            ALERT_EMAIL_MIN_SEVERITY,
        )
        return

    recipients = [addr.strip() for addr in ALERT_EMAIL_TO.split(",") if addr.strip()]
    if not recipients:
        return

    subject = f"[RT-IDRS] {severity.upper()} severity alert — {incident.get('signature', 'Unknown signature')}"

    body = (
        f"A security incident was detected on your system by RT-IDRS.\n\n"
        f"Time (UTC):     {incident.get('timestamp') or datetime.utcnow().isoformat()}\n"
        f"Severity:       {severity.upper()}\n"
        f"Signature:      {incident.get('signature')}\n"
        f"Category:       {incident.get('category')}\n"
        f"Source IP:      {incident.get('src_ip')}\n"
        f"Destination IP: {incident.get('dest_ip')}\n"
        f"Protocol:       {incident.get('proto')}\n"
        f"Response taken: {action}\n\n"
        f"If the action above is 'blocked', the source IP has already been\n"
        f"dropped at the firewall on the affected host. If it is 'logged',\n"
        f"please review this incident and decide whether manual action is needed.\n\n"
        f"-- RT-IDRS automated alert\n"
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = ALERT_EMAIL_FROM
    msg["To"] = ", ".join(recipients)

    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            if SMTP_USE_TLS:
                server.starttls()

        if SMTP_USERNAME and SMTP_PASSWORD:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)

        server.sendmail(ALERT_EMAIL_FROM, recipients, msg.as_string())
        log.info("EMAIL SENT SUCCESSFULLY")
        server.quit()
        log.info("Sent email alert to %s for incident from %s", recipients, incident.get("src_ip"))
    except Exception as exc:  # noqa: BLE001 - log and continue, never block the response flow
        log.error("Failed to send email alert: %s", exc)
