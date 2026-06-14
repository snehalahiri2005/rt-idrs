import os
import sqlite3
from collections import Counter

from flask import Flask, render_template, jsonify
from flask import send_file
import requests
import subprocess
import random
DB_PATH = os.environ.get("DB_PATH", "/data/incidents.db")

app = Flask(__name__)


def get_incidents(limit=500):
    if not os.path.exists(DB_PATH):
        return []

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()

        return [dict(r) for r in rows]

    finally:
        conn.close()


MITRE_MAP = {
    "SSH Brute Force": "T1110",
    "Port Scan": "T1046",
    "SQL Injection": "T1190",
    "Command Injection": "T1059",
}


@app.route("/")
def index():

    incidents = get_incidents()
    latest_incident = incidents[0] if incidents else None

    high_count = sum(
    1 for i in incidents
    if i["severity"] == "high"
)
    medium_count = sum(
        1 for i in incidents
        if i["severity"] == "medium"
    )

    low_count = sum(
        1 for i in incidents
        if i["severity"] == "low"
    )
    risk_low = low_count * 30
    risk_medium = medium_count * 60
    risk_high = high_count * 90
    overall_risk = (
    risk_low +
    risk_medium +
    risk_high
    )
    conn = sqlite3.connect(DB_PATH)

    total_alerts = conn.execute(
        "SELECT COUNT(*) FROM incidents"
    ).fetchone()[0]

    conn.close()
    blocked_count = sum(
    1 for i in incidents
    if i["action"] in ["blocked","already_blocked"]
)
   

    top_ips = Counter(
        i["src_ip"]
        for i in incidents
        if i["src_ip"]
    ).most_common(5)

    for incident in incidents:

        severity = incident["severity"]

        if severity == "high":
            incident["risk_score"] = 90
        elif severity == "medium":
            incident["risk_score"] = 60
        else:
            incident["risk_score"] = 30

        signature = incident["signature"]

        incident["mitre"] = MITRE_MAP.get(
            signature,
            "Unknown"
        )
    email_sent = sum(
    1 for i in incidents
    if i["severity"] in ["high","medium"]
)

    critical_threats = [
    i for i in incidents
    if i["severity"] == "high"
    ][:5]

    active_threats = len(critical_threats)

    campaigns = len(
    set(
    i["src_ip"]
    for i in incidents
    if i["severity"] == "high"
    )
    )

    docker_services = [
    ("Suricata","ONLINE"),
    ("Analyzer","ONLINE"),
    ("Response Engine","ONLINE"),
    ("Dashboard","ONLINE")
    ]

    blocked_ips = []

    seen = set()

    for incident in incidents:

        if incident["action"] in ["blocked","already_blocked"]:

            ip = incident["src_ip"]

            if ip not in seen:

                blocked_ips.append({
                    "src_ip": ip,
                    "received_at": incident["received_at"]
                })

                seen.add(ip)
    from collections import defaultdict

    incident_trend = defaultdict(int)

    for incident in incidents:
        if incident.get("received_at"):
            hour = incident["received_at"][11:13] + ":00"
            incident_trend[hour] += 1

    trend_labels = list(sorted(incident_trend.keys()))
    trend_values = [incident_trend[h] for h in trend_labels]
    top_ips = Counter(
    i["src_ip"]
    for i in incidents
    if i["src_ip"]
    ).most_common(5)
    top_ip_labels = [ip for ip, count in top_ips]

    top_ip_values = [count for ip, count in top_ips]
    ssh_count = sum(
    1 for i in incidents
    if "SSH" in str(i["signature"])
    )

    portscan_count = sum(
        1 for i in incidents
        if "Port" in str(i["signature"])
    )

    sqli_count = sum(
        1 for i in incidents
        if "SQL" in str(i["signature"])
    )
    return render_template(
    "index.html",
    incidents=incidents,
    blocked_count=blocked_count,
    high_count=high_count,
    medium_count=medium_count,
    low_count=low_count,
    total_alerts=total_alerts,
    top_ips=top_ips,
    email_sent=email_sent,
    active_threats=active_threats,
    campaigns=campaigns,
    critical_threats=critical_threats,
    docker_services=docker_services,
    blocked_ips=blocked_ips,
    risk_low=risk_low,
    risk_medium=risk_medium,
    risk_high=risk_high,
    latest_incident=latest_incident,
    overall_risk=overall_risk,
    trend_labels=trend_labels,
    trend_values=trend_values,
    ssh_count=ssh_count,
    portscan_count=portscan_count,
    sqli_count=sqli_count,
    top_ip_labels=top_ip_labels,
    top_ip_values=top_ip_values
)
@app.route("/export")
def export():

    import pandas as pd

    incidents = get_incidents()

    if not incidents:
        return {"error": "No incidents found"}, 404

    df = pd.DataFrame(incidents)

    file_path = "/tmp/incidents.csv"

    df.to_csv(
        file_path,
        index=False
    )

    return send_file(
        file_path,
        as_attachment=True,
        download_name="incidents.csv",
        mimetype="text/csv"
    )
@app.route("/simulate/ssh")
def simulate_ssh():

    try:

        payload = {
            "src_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            "dest_ip": "10.0.0.5",
            "severity": "high",
            "signature": "Possible SSH Brute Force Attempt"
        }

        r = requests.post(
            "http://response-engine:5001/incident",
            json=payload,
            timeout=20
        )

        return jsonify({
            "status": "SSH attack launched",
            "response_code": r.status_code,
            "response_text": r.text
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


@app.route("/simulate/portscan")
def simulate_portscan():

    payload = {
        "src_ip": f"172.16.{random.randint(1,254)}.{random.randint(1,254)}",
        "dest_ip": "10.0.0.5",
        "severity": "medium",
        "signature": "Possible TCP Port Scan Detected"
    }

    requests.post(
        "http://response-engine:5001/incident",
        json=payload,
        timeout=20
    )

    return jsonify({"status": "Port Scan launched"})


@app.route("/simulate/sqli")
def simulate_sqli():

    payload = {
        "src_ip": f"10.10.{random.randint(1,254)}.{random.randint(1,254)}",
        "dest_ip": "10.0.0.5",
        "severity": "high",
        "signature": "SQL Injection"
    }

    requests.post(
        "http://response-engine:5001/incident",
        json=payload,
        timeout=20
    )

    return jsonify({"status": "SQL Injection launched"})
@app.route("/test")
def test():
    return {"status": "dashboard working"}
@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5002
    )