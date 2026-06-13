# RT-IDRS — Real-Time Intrusion Detection and Response System

A real-time network intrusion detection and automated response system, built and
deployed using a GitHub → Jenkins → Docker CI/CD pipeline.

## Components

- **suricata/** — Network IDS (Suricata) with custom detection rules
- **analyzer/** — Tails Suricata alerts, correlates events, classifies severity
- **response-engine/** — Receives incidents, auto-blocks high-severity source IPs via iptables, stores history, sends Slack + **email alerts**
- **dashboard/** — Aesthetic, auto-refreshing web dashboard with live charts (timeline, severity breakdown, top attackers, response actions) and an incident log
- **Jenkinsfile** — CI/CD pipeline: test → build → scan → push → deploy
- **docker-compose.yml** — Orchestrates all services
- **scripts/simulate_attacks.py** — Demo tool that injects realistic incidents so you can showcase the whole pipeline live

## 1. Local Setup (without Jenkins)

Requirements: Docker, Docker Compose v2, Linux host (for `iptables` and `af-packet`).

```bash
git clone https://github.com/<your-username>/rt-idrs.git
cd rt-idrs
cp .env.example .env
# edit .env: set DOCKERHUB_USER, optionally SLACK_WEBHOOK_URL

docker compose build
docker compose up -d
```

- Dashboard: http://localhost:5002
- Response Engine API: http://localhost:5001/health

The dashboard ("RT-IDRS Ops Console") auto-refreshes every 5 seconds and shows:
- Stat cards: total incidents, IPs blocked, and counts by severity (high/medium/low)
- A timeline chart of incidents per minute
- A severity breakdown donut chart
- A bar chart of response actions taken (blocked / logged / already_blocked / block_failed)
- A "Top Source IPs" list of the most frequent attackers
- A live, color-coded incident log table

Suricata runs with `network_mode: host`, so adjust `suricata/suricata.yaml`'s
`af-packet.interface` to match your host's network interface (e.g. `eth0`, `ens33`).

### Email alerts (notify the person/system being attacked)

The response engine can email the system owner/administrator whenever a
medium or high severity incident occurs. Configure these in your `.env`
(see `.env.example` for full details and a Gmail example):

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=youraccount@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_FROM=youraccount@gmail.com
ALERT_EMAIL_TO=victim@example.com
ALERT_EMAIL_MIN_SEVERITY=medium
```

If `SMTP_HOST` or `ALERT_EMAIL_TO` is left blank, email alerting is simply
skipped (no errors). Each email includes the timestamp, severity, signature,
source/destination IPs, and the action RT-IDRS took (e.g. "blocked").

### Demonstrating the project (no real attack needed)

For a presentation/viva, you don't need to run a real attack — use the
included simulator, which posts realistic incident events directly to the
Response Engine, exactly as the Analyzer would:

```bash
# from the project root, with the stack running
pip install requests
python3 scripts/simulate_attacks.py
```

This runs a five-step scenario: benign traffic, a port scan, a web attack,
an SSH brute-force (which gets **auto-blocked** and triggers an **email
alert** if configured), and a repeat brute-force (shown as
`already_blocked`). Keep the dashboard open at http://localhost:5002 while
it runs — the stat cards, charts, and incident log update within ~5 seconds
of each event.

You can also run a single scenario on demand:

```bash
python3 scripts/simulate_attacks.py --scenario brute_force
```

For a more "real" demo with actual network traffic against the Suricata
sensor, run from another host on the same network:

```bash
# Port scan (triggers sid 1000002)
nmap -sS <target-ip>

# SSH brute-force pattern (triggers sid 1000003)
for i in {1..12}; do (echo) | nc -w1 <target-ip> 22; done
```

## 2. GitHub Setup

1. Create a new repository, e.g. `rt-idrs`.
2. Push this project:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: RT-IDRS project"
   git branch -M main
   git remote add origin https://github.com/<your-username>/rt-idrs.git
   git push -u origin main
   ```
3. In the repo settings, add a webhook pointing to your Jenkins server:
   `http://<jenkins-host>:8080/github-webhook/`, content type
   `application/json`, event: "Just the push event".

## 3. Jenkins Setup

1. Install plugins: **Git**, **Docker Pipeline**, **SSH Agent**, **GitHub Integration**, **JUnit**.
2. Add credentials:
   - `dockerhub-creds` — Docker Hub username/password (or access token)
   - `deploy-server-ssh` — SSH private key for the deployment host
3. Create a new **Pipeline** job:
   - "Pipeline script from SCM" → Git → your repo URL → branch `main` → script path `Jenkinsfile`
   - Enable "GitHub hook trigger for GITScm polling"
4. Set the `DEPLOY_HOST` environment variable (Manage Jenkins → System → Global properties)
   to the IP/hostname of your deployment server, and `DOCKERHUB_USER` in the Jenkinsfile
   to your Docker Hub username.
5. On the deployment server, create `/opt/rt-idrs` containing `docker-compose.yml`
   (and a `.env` with `DOCKERHUB_USER`/`SLACK_WEBHOOK_URL`), so the pipeline's
   "Deploy" stage can run `docker compose pull && docker compose up -d` there.

## 4. Pipeline Flow

```
Push to GitHub
   │
   ▼
Jenkins webhook trigger
   │
   ├─ Checkout
   ├─ Unit Tests (pytest, analyzer + response-engine)
   ├─ Build Docker images (suricata, analyzer, response-engine, dashboard)
   ├─ Trivy security scan (fails build on HIGH/CRITICAL CVEs)
   ├─ Push images to Docker Hub (tag = build number + latest)
   └─ Deploy: SSH to target host → docker compose pull && up -d
```

## 5. Extending the Project

- Add more Suricata rules in `suricata/rules/local.rules` for additional
  attack signatures (DDoS patterns, malware C2 domains, etc.).
- Add a machine-learning based anomaly detector as a new microservice that
  also posts to `/incident`.
- Add Slack/Email/SMS notification channels in `responder.py`.
- Replace SQLite with PostgreSQL for production use, and add Grafana for
  visualization on top of the incidents table.
- Add a "whitelist" mechanism so trusted IPs are never auto-blocked.
- Add an `/unblock/<ip>` endpoint and dashboard button for analysts to
  reverse automatic blocks.

## 6. Project Report Sections (suggested)

For your DevOps project report/presentation, structure it as:

1. Introduction & Problem Statement
2. Literature Review (IDS types: signature-based vs anomaly-based; CI/CD basics)
3. System Architecture (diagram from this README)
4. Tools Used: GitHub, Jenkins, Docker, Docker Compose, Suricata, Flask, Trivy
5. Implementation Details (per component, as in this repo)
6. CI/CD Pipeline Design (Jenkinsfile stages, screenshots of Jenkins runs)
7. Testing & Results (unit tests, simulated attacks, dashboard screenshots)
8. Challenges & Limitations
9. Future Enhancements
10. Conclusion
