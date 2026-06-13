FROM python:3.11-slim

# iptables is needed for the response engine to block IPs on the host
# network namespace (container must run with --cap-add=NET_ADMIN,
# --network host or similar, set in docker-compose.yml)
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py responder.py ./

ENV PORT=5001
EXPOSE 5001

CMD ["python", "app.py"]
