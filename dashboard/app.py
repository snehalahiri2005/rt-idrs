"""
dashboard/app.py — web dashboard showing recent incidents, live charts,
and stats, reading from the shared SQLite database that the Response
Engine writes to. Exposes JSON endpoints (/api/stats, /api/incidents)
used by the front-end for live (polling-based) updates.
"""

import os
import sqlite3
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta

from flask import Flask, render_template, jsonify

DB_PATH = os.environ.get("DB_PATH", "/data/incidents.db")
TIMELINE_MINUTES = int(os.environ.get("TIMELINE_MINUTES", "30"))

app = Flask(__name__)


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_incidents(limit=50):
    if not os.path.exists(DB_PATH):
        return []
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_stats():
    """
    Returns a dict with everything the dashboard charts need:
      - totals: total incidents, blocked count
      - severity_counts: {high, medium, low}
      - action_counts: {blocked, logged, already_blocked, block_failed}
      - top_src_ips: [(ip, count), ...] top 5
      - timeline: {labels: [...], counts: [...]} incidents per minute
    """
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    action_counts = defaultdict(int)
    src_ip_counts = defaultdict(int)

    # Build empty timeline buckets for the last TIMELINE_MINUTES minutes
    now = datetime.utcnow().replace(second=0, microsecond=0)
    timeline = OrderedDict()
    for i in range(TIMELINE_MINUTES - 1, -1, -1):
        bucket_time = now - timedelta(minutes=i)
        timeline[bucket_time.strftime("%H:%M")] = 0

    total = 0
    blocked_total = 0

    if os.path.exists(DB_PATH):
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT severity, action, src_ip, received_at FROM incidents"
            ).fetchall()
        finally:
            conn.close()

        for row in rows:
            total += 1
            sev = (row["severity"] or "low").lower()
            if sev not in severity_counts:
                sev = "low"
            severity_counts[sev] += 1

            action = row["action"] or "logged"
            action_counts[action] += 1
            if action == "blocked":
                blocked_total += 1

            if row["src_ip"]:
                src_ip_counts[row["src_ip"]] += 1

            try:
                ts = datetime.fromisoformat(row["received_at"])
                bucket = ts.replace(second=0, microsecond=0).strftime("%H:%M")
                if bucket in timeline:
                    timeline[bucket] += 1
            except (ValueError, TypeError):
                pass

    top_src_ips = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_incidents": total,
        "blocked_total": blocked_total,
        "severity_counts": severity_counts,
        "action_counts": dict(action_counts),
        "top_src_ips": top_src_ips,
        "timeline": {
            "labels": list(timeline.keys()),
            "counts": list(timeline.values()),
        },
    }


@app.route("/")
def index():
    incidents = get_incidents()
    stats = get_stats()
    return render_template("index.html", incidents=incidents, stats=stats)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/incidents")
def api_incidents():
    return jsonify(get_incidents())


@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5002"))
    app.run(host="0.0.0.0", port=port)
