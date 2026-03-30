# Modbuster

SCADA traffic analysis, inference, and injection tool for OT/ICS pentesting. Analyzes Modbus TCP (and future protocols) from live capture or PCAP files with human-readable interpretation and offline register auto-classification. Can craft and inject Modbus requests onto the network.

**Authorized use only.** Use only on systems you are explicitly permitted to test. Writing registers/coils can affect physical processes. No warranty.

## Install

Requires **Python 3.9+**.

```bash
pip install -r requirements.txt
```

On Windows, live capture requires [Npcap](https://npcap.com/) (or WinPcap). Run with root/admin if prompted.

## Usage

### GUI

```bash
python -m modbuster gui
```

The GUI has five tabs (left to right):

- **Analyze** *(default)* — load PCAP or start live capture; collapsible Auto Analysis panel shows inferred register types; Network Map shows discovered hosts with clickable IPs that auto-populate target fields.
- **Infer** — full register classification table with confidence levels, value ranges, and hints. Includes a Classification Guide popup explaining all 19 inference rules.
- **Recon** — active network reconnaissance: Host Discovery (TCP/UDP probe across a subnet for OT devices), Unit ID Scan (sweeps all 247 Modbus unit IDs on a target), Register Scan (FC3 bulk read across an address range). Each scanner has a `?` help button. Results feed directly into the Inject tab.
- **Inject** — craft and send Modbus read/write commands (FC3, FC6, FC16) to a target; supports single-shot and looped injection with timestamps. Write commands require explicit opt-in.
- **Replay** — retransmit captured Modbus packets from a PCAP to a live target.

### CLI: Analyze

```bash
# PCAP file
python -m modbuster analyze --pcap path/to/capture.pcap

# Live capture
python -m modbuster analyze --live [--iface eth0] [--count N]

# Terminal UI (Rich)
python -m modbuster analyze --pcap path/to/capture.pcap --tui
python -m modbuster analyze --live --tui
```

### CLI: Inject

```bash
# Read holding registers (safe, no --write needed)
python -m modbuster inject --protocol modbus --target 192.168.1.10 read-holding --unit 1 --addr 0 --count 10

# Write single register (requires explicit --write flag)
python -m modbuster inject --protocol modbus --target 192.168.1.10 write-register --unit 1 --addr 0 --value 123 --write
```

### CLI: Replay

```bash
python -m modbuster replay --pcap path/to/capture.pcap --index 0 --target 192.168.1.10 [--write]
```

## Auto Register Classification

Modbuster's inference engine classifies Modbus registers entirely offline — no internet, no firmware, no documentation needed. Feed it live or PCAP traffic and it will characterize each register:

- **Binary Status** — single bit, detects watchdog cycling vs. slow-changing state
- **Alarm / Event** — discrete set where 0=normal, maps 0–4 to Normal/Warning/Alarm/Suppressed/Fault
- **State / Mode** — small discrete set (up to 7 states)
- **Electrical** — grid frequency (50 Hz vs. 60 Hz), high-voltage (6.6 kV), medium-voltage (3.3/4.16 kV), low-voltage (400/440 V), generator kW output
- **RPM / Speed** — multi-scale detection (×1, ×0.1, ×10)
- **Temperature** — four conventions: direct °C, Kelvin, ×10 scale, +50 bias
- **Percentage, Flow, Pressure, Position/Angle, Counter, Setpoint, Analog Sensor**
- **Cross-register**: setpoint/actual pairs, channel groups (≥3 consecutive same-type), mirrored/redundant registers

Results appear in the Infer tab and the collapsible Auto Analysis panel in the Analyze tab.

## Testing

```bash
pytest tests/
pytest tests/test_modbus.py::ClassName::test_method_name
```

---

## Docker Lab — Royal Caribbean ICS Simulation

A self-contained 8-unit cruise ship ICS/SCADA lab is included under `docker/`. No physical hardware required.

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin on Linux)
- Linux host recommended for the SPAN port mirroring feature (requires `tc`)

### Network layout

```
Host machine
  └─ Docker bridge (172.20.0.0/24)
       ├─ controller     172.20.0.10   Modbus master + bridge control web UI
       ├─ field_device   172.20.0.20   Modbus slave (8 unit IDs)
       └─ kali_pentest   172.20.0.30   Attacker box (Modbuster + Kali tools)
```

By default Kali cannot see controller↔field-device traffic (Docker bridge = L2 switch). `setup_mirror.sh` mirrors both veth interfaces to Kali using `tc`, simulating a SPAN/monitor port.

### Start the lab

```bash
# 1. Build and start containers
docker compose build --no-cache
docker compose up -d

# 2. Set up traffic mirroring (Linux only, requires sudo)
#    Re-run this after every 'docker compose up'
sudo bash setup_mirror.sh

# 3. Open dashboards in your browser
#    Controller:    http://localhost:8080
#    Field Device:  http://localhost:8082
#    Kali Desktop:  http://localhost:6080/vnc.html  (no password)
```

### Kali access options

**Browser desktop (recommended):**
Open `http://localhost:6080/vnc.html` — no password. Click the Modbuster desktop icon to launch the GUI.

**Shell:**
```bash
docker exec -it kali_pentest /bin/bash
```
A banner prints with ready-to-paste Modbuster commands for all 8 units.

### Installing the desktop launcher on a new machine

A `Modbuster.desktop` file is included in the project root. After deploying the project to `/opt/modbuster`, install the launcher with:

```bash
cp Modbuster.desktop ~/Desktop/
chmod +x ~/Desktop/Modbuster.desktop
```

The launcher assumes the project is mounted/installed at `/opt/modbuster` (the default Docker volume path). The orange CT Cubed icon is at `modbuster/icon.svg` and is referenced automatically.

### Controller Bridge Control Console

`http://localhost:8080` includes a full Bridge Control Console:
- **Engine telegraph levers** (port + stbd) — drag to set throttle 0–100%, syncs both engines, writes to Unit 1 registers 0/1 via Modbus
- **Rudder arc gauge** — live SVG dial showing current rudder angle (±35°)
- **Nav readouts** — Speed (kn), Heading (°T), Rate of Turn (°/min)
- **Write lock toggle** — prevents accidental writes; must be unlocked to send commands

### Field Device — 8 Unit IDs

Each unit exposes 10 holding registers (addresses 0–9) with realistic sensor drift simulation.

**Unit 1 — Main Propulsion**

| Addr | Register | Scale |
|------|----------|-------|
| 0 | Port Engine RPM | raw ÷ 10 = RPM |
| 1 | Stbd Engine RPM | raw ÷ 10 = RPM |
| 2 | Port Fuel Flow | raw ÷ 10 = L/hr |
| 3 | Stbd Fuel Flow | raw ÷ 10 = L/hr |
| 4 | Port Coolant Temp | raw − 50 = °C |
| 5 | Stbd Coolant Temp | raw − 50 = °C |
| 6 | Bow Thruster | raw ÷ 10 = % |
| 7 | Stern Thruster | raw ÷ 10 = % |
| 8 | Port Shaft RPM | raw ÷ 10 = RPM |
| 9 | Stbd Shaft RPM | raw ÷ 10 = RPM |

**Unit 2 — Navigation/Bridge**

| Addr | Register | Scale |
|------|----------|-------|
| 0 | Rudder Angle | raw − 180 = degrees (negative = port) |
| 1 | Speed OG | raw ÷ 10 = knots |
| 2 | Heading (True) | raw ÷ 10 = degrees |
| 3 | Rate of Turn | raw − 1800 = °/min |
| 4 | Wind Speed | raw ÷ 10 = knots |
| 5 | Wind Direction | raw = degrees |
| 6–9 | GPS lat/lon | degrees + min×100 |

**Unit 3 — Ballast/Safety**

| Addr | Register | Scale |
|------|----------|-------|
| 0–3 | Fore/Aft/Port/Stbd ballast tanks | raw ÷ 10 = % full |
| 4 | Flood Alarm | 0=normal, 1=alarm |
| 5–6 | Fire Suppress Z1/Z2 | 0=off, 1=active |
| 7–8 | Bilge Pump Port/Stbd | 0=off, 1=on, 2=fault |
| 9 | General Alarm | bitmask (bit0=fire, bit1=flood, bit2=engine) |

**Unit 4 — Power Management**

| Addr | Register | Scale |
|------|----------|-------|
| 0–3 | Generator 1–4 (kW) | raw = kW |
| 4–5 | Bus A/B Voltage | raw ÷ 10 = V |
| 6 | Grid Frequency | raw ÷ 10 = Hz |
| 7 | Total Load (kW) | raw = kW |
| 8 | Shore Power | 0=off, 1=on |
| 9 | Emergency Gen | 0=off, 1=standby, 2=running |

**Unit 5 — HVAC/Environmental**

| Addr | Register | Scale |
|------|----------|-------|
| 0–2 | Deck 3/7/12 Zone Temp | raw ÷ 10 = °C |
| 3 | Engine Room Temp | raw ÷ 10 = °C |
| 4 | Chilled Water Supply | raw ÷ 10 = °C |
| 5 | Chilled Water Return | raw ÷ 10 = °C |
| 6–7 | AHU 1/2 Status | 0=off, 1=on, 2=fault |
| 8 | Chiller 1 Status | 0=off, 1=on, 2=fault |
| 9 | Outside Air Temp | raw ÷ 10 = °C |

**Unit 6 — Fire Safety & Alarms**

| Addr | Register | Scale |
|------|----------|-------|
| 0–3 | Fire Zone 1–4 | 0=normal, 1=warning, 2=alarm |
| 4–5 | CO2 Bank 1/2 | 0=charged, 1=partial, 2=discharged |
| 6 | General Alarm | 0=clear, 1=active |
| 7–8 | Bilge Pump Port/Stbd | 0=off, 1=on |
| 9 | Smoke Detector Count | raw = active detectors |

**Unit 7 — Fuel Management**

| Addr | Register | Scale |
|------|----------|-------|
| 0–1 | HFO Port/Stbd Wing Tank | raw ÷ 10 = % |
| 2–3 | MGO Port/Stbd Tank | raw ÷ 10 = % |
| 4 | HFO Day Tank | raw ÷ 10 = % |
| 5 | MGO Day Tank | raw ÷ 10 = % |
| 6 | HFO Flow Rate | raw ÷ 10 = L/hr |
| 7 | MGO Flow Rate | raw ÷ 10 = L/hr |
| 8 | Fuel Mode | 0=HFO, 1=MGO, 2=dual |
| 9 | Total Fuel Remaining | raw ÷ 10 = % |

**Unit 8 — Stabilizer/Motion**

| Addr | Register | Scale |
|------|----------|-------|
| 0–1 | Port/Stbd Fin Angle | raw − 500 = tenths of degree |
| 2–3 | Port/Stbd Fin Status | 0=retracted, 1=deploying, 2=deployed |
| 4 | Roll Angle | raw − 1800 = tenths of degree |
| 5 | Pitch Angle | raw − 1800 = tenths of degree |
| 6 | Vertical Accel | raw − 1000 = mg |
| 7 | Stabilizer Mode | 0=off, 1=auto, 2=manual |
| 8–9 | Port/Stbd Fin Hydraulic Pressure | raw ÷ 10 = bar |

### Example Modbuster commands (inside Kali container)

```bash
# Live analysis — packets stream in real-time
python3 -m modbuster analyze --live --iface eth0

# Read all generators (Unit 4, Power Management)
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 read-holding --unit 4 --addr 0 --count 10

# Read fire safety (Unit 6)
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 read-holding --unit 6 --addr 0 --count 10

# Spike port engine to 950 RPM (raw value 9500 = 950 × 10)
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 --write write-register --unit 1 --addr 0 --value 9500

# Set cabin temp setpoint to 18°C (raw value 180 = 18 × 10)
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 --write write-register --unit 5 --addr 0 --value 180

# Switch to MGO fuel mode (Unit 7, addr 8, value 1)
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 --write write-register --unit 7 --addr 8 --value 1

# Capture to PCAP then analyze
tcpdump -i eth0 -w /workspace/capture.pcap tcp port 502 &
sleep 30 && kill %1
python3 -m modbuster analyze --pcap /workspace/capture.pcap

# Replay a captured packet
python3 -m modbuster replay --pcap /workspace/capture.pcap --target 172.20.0.20 --index 0
```

### Stop the lab

```bash
docker compose down
```

> **Note:** Traffic mirroring (`tc` rules) is automatically removed when the containers stop. Re-run `sudo bash setup_mirror.sh` after the next `docker compose up`.
