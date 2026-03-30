#!/usr/bin/env bash
# ============================================================
# Start the Modbuster ICS lab in one command:
#   1. Bring up all containers (or a specific service if given)
#   2. Set up TC traffic mirroring so Kali can see ICS traffic
#
# Usage:
#   sudo ./start-lab.sh              # start/restart all containers
#   sudo ./start-lab.sh kali         # rebuild & restart only kali
#   sudo ./start-lab.sh --mirror     # re-apply mirroring only (no restart)
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Shared with Kali at ./workspace -> /workspace (container often runs as root).
# Mode 1777: any user may create files; sticky bit limits deleting others' files.
ensure_workspace_permissions() {
  mkdir -p "$SCRIPT_DIR/workspace"
  if chmod 1777 "$SCRIPT_DIR/workspace" 2>/dev/null; then
    return 0
  fi
  if [[ "$(id -u)" -eq 0 ]]; then
    chmod 1777 "$SCRIPT_DIR/workspace"
    return 0
  fi
  echo "[lab] workspace/ not world-writable; fixing with sudo..."
  sudo chmod 1777 "$SCRIPT_DIR/workspace"
}
ensure_workspace_permissions

SERVICE="${1:-}"

if [[ "$SERVICE" == "--mirror" ]]; then
    echo "[lab] Re-applying traffic mirroring..."
    bash setup_mirror.sh
    exit 0
fi

if [[ -n "$SERVICE" ]]; then
    echo "[lab] Rebuilding and restarting service: $SERVICE ..."
    docker compose build --no-cache "$SERVICE"
    docker compose up -d "$SERVICE"
else
    echo "[lab] Starting all containers..."
    docker compose up -d
fi

echo "[lab] Waiting for containers to be ready..."
sleep 3

echo "[lab] Setting up traffic mirroring..."
bash setup_mirror.sh

echo ""
echo "================================================================"
echo "  Lab ready."
echo "  Kali desktop:     http://localhost:6080/vnc.html"
echo "  Controller panel: http://localhost:8080"
echo "  Field device 1:   http://localhost:8082  (Units 1-4)"
echo "  Field device 2:   http://localhost:8083  (Units 5-8)"
echo "================================================================"
