#!/usr/bin/env bash
# scripts/trivy-scan.sh
# Run Trivy vulnerability scans locally against all RT-IDRS images.
# Usage: ./scripts/trivy-scan.sh [tag]

set -euo pipefail

TAG="${1:-latest}"
DOCKERHUB_USER="${DOCKERHUB_USER:-yourdockerhub}"

SERVICES=("suricata" "analyzer" "response-engine" "dashboard")

for SERVICE in "${SERVICES[@]}"; do
    IMAGE="${DOCKERHUB_USER}/rt-idrs-${SERVICE}:${TAG}"
    echo "=================================================="
    echo "Scanning ${IMAGE}"
    echo "=================================================="
    trivy image --severity HIGH,CRITICAL "${IMAGE}"
done
