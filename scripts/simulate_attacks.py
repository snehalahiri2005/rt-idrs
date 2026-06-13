#!/usr/bin/env python3
"""
scripts/simulate_attacks.py
----------------------------
Demo / presentation tool for RT-IDRS.

This script sends a sequence of realistic, pre-crafted "incident" events
directly to the Response Engine's /incident API — the same API the
Analyzer uses. It lets you demonstrate the full detect -> classify ->
respond -> log -> notify -> email -> dashboard pipeline WITHOUT needing
to run a real attack (nmap, hydra, etc.) against the lab network.

Usage:
    python3 scripts/simulate_attacks.py
    python3 scripts/simulate_attacks.py --url http://localhost:5001/incident
    python3 scripts/simulate_attacks.py --delay 2 --scenario brute_force

While this runs, keep the dashboard open at http://localhost:5002 — you
will see the stat cards, charts, and live incident log update within a
few seconds of each simulated event, and (if SMTP is configured) an
email alert will be sent for medium/high severity incidents.
"""

import argparse
import time
from datetime import datetime, timezone

import requests

DEFAULT_URL = "http://localhost:5001/incident"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def scenario_port_scan(attacker_ip="203.0.113.10", target_ip="10.0.0.5"):
    """Simulate a low/medium severity reconnaissance scan."""
    return [
        {
            "timestamp": now_iso(),
            "src_ip": attacker_ip,
            "dest_ip": target_ip,
            "proto": "TCP",
            "signature": "Possible TCP Port Scan Detected",
            "category": "Attempted Information Leak",
            "severity": "medium",
            "raw_sid": 1000002,
        }
        for _ in range(1)
    ]


def scenario_brute_force(attacker_ip="198.51.100.23", target_ip="10.0.0.5"):
    """Simulate repeated SSH brute-force attempts -> high severity -> auto-block + email."""
    return [
        {
            "timestamp": now_iso(),
            "src_ip": attacker_ip,
            "dest_ip": target_ip,
            "proto": "TCP",
            "signature": "Possible SSH Brute Force Attempt",
            "category": "Attempted Administrator Privilege Gain",
            "severity": "high",
            "raw_sid": 1000003,
        }
    ]


def scenario_web_attack(attacker_ip="192.0.2.77", target_ip="10.0.0.10"):
    """Simulate a SQLMap-style web application attack -> high severity."""
    return [
        {
            "timestamp": now_iso(),
            "src_ip": attacker_ip,
            "dest_ip": target_ip,
            "proto": "TCP",
            "signature": "Suspicious User-Agent (Scanner Tool)",
            "category": "Web Application Attack",
            "severity": "high",
            "raw_sid": 1000005,
        }
    ]


def scenario_benign(target_ip="10.0.0.5"):
    """Simulate a harmless/low severity event for contrast on the dashboard."""
    return [
        {
            "timestamp": now_iso(),
            "src_ip": "10.0.0.42",
            "dest_ip": target_ip,
            "proto": "ICMP",
            "signature": "ICMP Flood / Ping Sweep Detected",
            "category": "Potentially Bad Traffic",
            "severity": "low",
            "raw_sid": 1000001,
        }
    ]


SCENARIOS = {
    "port_scan": scenario_port_scan,
    "brute_force": scenario_brute_force,
    "web_attack": scenario_web_attack,
    "benign": scenario_benign,
}


def send_incident(url, incident):
    try:
        resp = requests.post(url, json=incident, timeout=5)
        return resp.status_code, resp.json()
    except requests.RequestException as exc:
        return None, {"error": str(exc)}


def run_full_demo(url, delay):
    print("=" * 60)
    print("RT-IDRS LIVE DEMO — simulated attack sequence")
    print("Open the dashboard at http://localhost:5002 to follow along")
    print("=" * 60)

    steps = [
        ("Benign background traffic", scenario_benign()),
        ("Reconnaissance: port scan from 203.0.113.10", scenario_port_scan()),
        ("Web application attack from 192.0.2.77 (sqlmap)", scenario_web_attack()),
        ("SSH brute-force from 198.51.100.23 (auto-block + email expected)", scenario_brute_force()),
        ("Repeat SSH brute-force (should show 'already_blocked')", scenario_brute_force()),
    ]

    for label, incidents in steps:
        print(f"\n--- {label} ---")
        for incident in incidents:
            status, body = send_incident(url, incident)
            print(f"  POST {url} -> {status}: {body}")
        time.sleep(delay)

    print("\nDemo complete. Check the dashboard for updated charts, the")
    print("incident log table, and (if SMTP is configured) your inbox for")
    print("email alerts on the high-severity events.")


def main():
    parser = argparse.ArgumentParser(description="RT-IDRS attack simulator")
    parser.add_argument(
        "--url", default=DEFAULT_URL, help=f"Response Engine /incident URL (default: {DEFAULT_URL})"
    )
    parser.add_argument(
        "--delay", type=float, default=3.0, help="Seconds to wait between steps (default: 3)"
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        help="Run a single scenario instead of the full demo sequence",
    )
    args = parser.parse_args()

    if args.scenario:
        incidents = SCENARIOS[args.scenario]()
        for incident in incidents:
            status, body = send_incident(args.url, incident)
            print(f"POST {args.url} -> {status}: {body}")
    else:
        run_full_demo(args.url, args.delay)


if __name__ == "__main__":
    main()
