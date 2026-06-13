#!/usr/bin/env bash
# scripts/deploy.sh
# Convenience script to (re)deploy RT-IDRS on a target host.
# Intended to be run on the deploy server, or via Jenkins' "Deploy" stage.

set -euo pipefail

PROJECT_DIR="/opt/rt-idrs"
DOCKERHUB_USER="${DOCKERHUB_USER:-yourdockerhub}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

cd "$PROJECT_DIR"

export DOCKERHUB_USER
export IMAGE_TAG

echo "Pulling images (tag=${IMAGE_TAG})..."
docker compose pull

echo "Restarting services..."
docker compose up -d --remove-orphans

echo "Current container status:"
docker compose ps
