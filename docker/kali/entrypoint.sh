#!/usr/bin/env bash
# ============================================================
# Kali pentest container entrypoint
# Waits for field device, then prints a usage banner.
# ============================================================
set -e

FIELD_DEVICE_HOST="${FIELD_DEVICE_HOST:-172.20.0.20}"
CONTROLLER_HOST="${CONTROLLER_HOST:-172.20.0.10}"

# --------------------------------------------------------------------------
# Wait for field device port 502
# --------------------------------------------------------------------------
echo "[entrypoint] Waiting for field device at ${FIELD_DEVICE_HOST}:502..."
timeout=30
elapsed=0
while ! nc -z "${FIELD_DEVICE_HOST}" 502 2>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge "$timeout" ]; then
        echo "[entrypoint] WARNING: field device not reachable after ${timeout}s, continuing anyway"
        break
    fi
done
echo "[entrypoint] Field device reachable."

# --------------------------------------------------------------------------
# Verify Modbuster import
# --------------------------------------------------------------------------
if python3 -c "import modbuster" 2>/dev/null; then
    MODBUSTER_VER=$(python3 -c "import modbuster; print(modbuster.__version__)" 2>/dev/null || echo "unknown")
    echo "[entrypoint] Modbuster v${MODBUSTER_VER} ready."
else
    echo "[entrypoint] WARNING: modbuster import failed. Check /opt/modbuster volume mount."
fi

# --------------------------------------------------------------------------
# Detect sniff interface
# --------------------------------------------------------------------------
if ip link show eth0 > /dev/null 2>&1; then
    SNIFF_IFACE="eth0"
else
    SNIFF_IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
fi
export SNIFF_IFACE
echo "[entrypoint] Sniff interface: ${SNIFF_IFACE}"

# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------
cat <<BANNER

================================================================
  Modbuster ICS/SCADA Pentest Lab  |  Kali Pentest Container
  Authorized laboratory use ONLY.
================================================================

  Network:
    Field Device  (Modbus slave / field-device):  ${FIELD_DEVICE_HOST}:502
    Controller    (Modbus master / controller):   ${CONTROLLER_HOST}
    This box      (kali_pentest):                 172.20.0.30
    Sniff iface:  ${SNIFF_IFACE}

  ┌─ ANALYZE ─────────────────────────────────────────────────
  │ Live sniff (Ctrl+C to stop):
  │   python3 -m modbuster analyze --live --iface ${SNIFF_IFACE}
  │
  │ Live sniff with TUI:
  │   python3 -m modbuster analyze --live --iface ${SNIFF_IFACE} --tui
  │
  │ Capture to PCAP then analyze:
  │   tcpdump -i ${SNIFF_IFACE} -w /workspace/capture.pcap tcp port 502 &
  │   # ... wait, then Ctrl+C the background job:  kill %1
  │   python3 -m modbuster analyze --pcap /workspace/capture.pcap

  ┌─ INJECT: READ ────────────────────────────────────────────
  │ Unit 1 — Engine Room (all 10 regs):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding \
  │     --unit 1 --addr 0 --count 10
  │
  │ Unit 2 — Navigation:
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding \
  │     --unit 2 --addr 0 --count 10
  │
  │ Unit 3 — Ballast/Safety:
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding \
  │     --unit 3 --addr 0 --count 10

  ┌─ INJECT: WRITE (requires --write) ────────────────────────
  │ Set rudder to 15° starboard (unit 2, addr 0, value=195):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 2 --addr 0 --value 195
  │
  │ Set bow thruster to 10% (unit 1, addr 6, value=100):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 1 --addr 6 --value 100
  │
  │ Set fore ballast to 60% (unit 3, addr 0, value=600):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 3 --addr 0 --value 600

  ┌─ REPLAY ──────────────────────────────────────────────────
  │ Replay first packet from capture:
  │   python3 -m modbuster replay \
  │     --pcap /workspace/capture.pcap \
  │     --target ${FIELD_DEVICE_HOST} --index 0
  │
  │ Replay a write (requires --write):
  │   python3 -m modbuster replay \
  │     --pcap /workspace/capture.pcap \
  │     --target ${FIELD_DEVICE_HOST} --index 0 --write

  ┌─ WEB DASHBOARDS (open in your Windows browser) ───────────
  │ Controller panel:   http://localhost:8080
  │ Field device view:  http://localhost:8081

================================================================

BANNER

# Drop to bash (or run any command passed to docker exec)
if [ "$#" -gt 0 ]; then
    exec "$@"
else
    exec /bin/bash
fi
