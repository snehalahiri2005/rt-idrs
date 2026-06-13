"""
app.py — Response Engine REST API

Receives incident reports from the Analyzer, decides on a response
based on severity, executes that response (e.g., block an IP), records
the incident + action to the database, and sends notifications.
"""

import logging
import os

from flask import Flask, request, jsonify

from responder import (
    block_ip,
    is_ip_blocked,
    send_notification,
    send_email_alert,
    save_incident,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [response-engine] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# Severity levels that trigger an automatic block
AUTO_BLOCK_SEVERITIES = {"high"}


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/incident", methods=["POST"])
def incident():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "invalid or missing JSON body"}), 400

    required_fields = ["src_ip", "signature", "severity"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"missing field: {field}"}), 400

    src_ip = data["src_ip"]
    severity = data["severity"]
    signature = data["signature"]

    action_taken = "logged"

    if severity in AUTO_BLOCK_SEVERITIES and src_ip != "unknown":
        if is_ip_blocked(src_ip):
            action_taken = "already_blocked"
        else:
            blocked = block_ip(src_ip)
            action_taken = "blocked" if blocked else "block_failed"

    # Persist incident + action
    save_incident(data, action_taken)

    # Notify (Slack + email), regardless of action, for visibility
    send_notification(data, action_taken)
    send_email_alert(data, action_taken)

    log.info(
        "Incident processed: src=%s severity=%s sig=%s action=%s",
        src_ip,
        severity,
        signature,
        action_taken,
    )

    return jsonify({"status": "received", "action": action_taken}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port)
