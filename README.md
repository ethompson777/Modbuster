# Modbuster

SCADA traffic analysis and injection tool for OT/ICS pentesting. Analyzes Modbus TCP (and future protocols) from live capture or PCAP files with human-readable interpretation, and can craft/inject Modbus requests onto the network.

**Authorized use only.** Use only on systems you are explicitly permitted to test. Writing registers/coils can affect physical processes. No warranty.

## Install

```bash
pip install -r requirements.txt
```

On Windows, live capture requires [Npcap](https://npcap.com/) (or WinPcap). Run the tool with appropriate permissions if prompted.

## Usage

### GUI

Launch the graphical interface (Analyze, Inject, Replay tabs):

```bash
python -m modbuster gui
```

### Analyze (PCAP)

```bash
python -m modbuster analyze --pcap path/to/capture.pcap
```

Optional: `--protocol modbus`, `--filter "tcp port 502"`, `--export summary.json`.

### Analyze (live)

```bash
python -m modbuster analyze --live [--iface <name>] [--count N]
```

### Analyze with TUI

```bash
python -m modbuster analyze --pcap path/to/capture.pcap --tui
python -m modbuster analyze --live --tui
```

### Inject (Modbus)

Read holding registers:

```bash
python -m modbuster inject --protocol modbus --target 192.168.1.10 read-holding --unit 1 --addr 0 --count 10
```

Write single register (requires `--write`):

```bash
python -m modbuster inject --protocol modbus --target 192.168.1.10 write-register --unit 1 --addr 0 --value 123 --write
```

### Replay

Re-send selected messages from a PCAP toward a target:

```bash
python -m modbuster replay --pcap path/to/capture.pcap --index 0 --target 192.168.1.10 [--port 502] [--write]
```

### Global options

`--verbose`, `--quiet`. For any write operation (inject or replay), `--write` is required.

## Target systems

Designed for ABB (800xA, Symphony, protection relays) and Valmet DNA environments; Modbus TCP is commonly used on connected devices.

## Testing

Unit tests:

```bash
pytest tests/
```

## Docker Lab Environment

A self-contained cruise ship ICS/SCADA simulation lab is included under `docker/`. It spins up three containers on an isolated network so you can practice analyzing, injecting, and replaying Modbus traffic without any physical hardware.

### Containers

| Container | IP | Role |
|---|---|---|
| `field_device` | 172.20.0.20 | Modbus TCP slave — simulates engines, navigation, and ballast systems |
| `controller` | 172.20.0.10 | Modbus TCP master — continuously polls and writes the field device |
| `kali_pentest` | 172.20.0.30 | Kali Linux box with Modbuster mounted from source |

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

### Start the lab

```bash
docker compose build --no-cache
docker compose up -d
```

### Web dashboards

Open these in your browser while the lab is running:

| Dashboard | URL | What it shows |
|---|---|---|
| Controller | http://localhost:8080 | Manual read/write command panel + live poll log |
| Field Device | http://localhost:8081 | Live register table (all 3 units) + incoming request log |

### Shell into the Kali pentest box

```bash
docker exec -it kali_pentest /bin/bash
```

A banner prints on entry with ready-to-paste Modbuster commands. The Modbuster source directory is mounted read-only at `/opt/modbuster` — any edits you make on the host are immediately visible inside the container without rebuilding. PCAP captures are saved to `/workspace/` inside the container.

### Example Modbuster commands (run inside Kali container)

**Sniff live Modbus traffic:**
```bash
python3 -m modbuster analyze --live --iface eth0
python3 -m modbuster analyze --live --iface eth0 --tui
```

**Capture to PCAP then analyze:**
```bash
tcpdump -i eth0 -w /workspace/capture.pcap tcp port 502 &
# let it run for a while, then:
kill %1
python3 -m modbuster analyze --pcap /workspace/capture.pcap
```

**Read registers from the field device:**
```bash
# Unit 1 — Engine Room
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 read-holding --unit 1 --addr 0 --count 10

# Unit 2 — Navigation
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 read-holding --unit 2 --addr 0 --count 10

# Unit 3 — Ballast/Safety
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 read-holding --unit 3 --addr 0 --count 10
```

**Write registers (requires `--write`):**
```bash
# Rudder to 15° starboard (unit 2, addr 0 — raw value = 180 + 15 = 195)
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 --write write-register --unit 2 --addr 0 --value 195

# Bow thruster to 10% (unit 1, addr 6 — raw value = 10 × 10 = 100)
python3 -m modbuster inject --protocol modbus --target 172.20.0.20 --write write-register --unit 1 --addr 6 --value 100
```

**Replay a captured packet:**
```bash
python3 -m modbuster replay --pcap /workspace/capture.pcap --target 172.20.0.20 --index 0
```

### Register map

The field device exposes 10 holding registers per unit (addresses 0–9):

**Unit 1 — Engine Room**

| Addr | Register | Scale |
|------|----------|-------|
| 0 | Port main engine RPM | raw ÷ 10 = RPM |
| 1 | Stbd main engine RPM | raw ÷ 10 = RPM |
| 2 | Port fuel flow | raw ÷ 10 = L/hr |
| 3 | Stbd fuel flow | raw ÷ 10 = L/hr |
| 4 | Port coolant temp | raw − 50 = °C |
| 5 | Stbd coolant temp | raw − 50 = °C |
| 6 | Bow thruster speed | raw ÷ 10 = % |
| 7 | Stern thruster speed | raw ÷ 10 = % |
| 8 | Port shaft RPM | raw ÷ 10 = RPM |
| 9 | Stbd shaft RPM | raw ÷ 10 = RPM |

**Unit 2 — Navigation/Bridge**

| Addr | Register | Scale |
|------|----------|-------|
| 0 | Rudder angle | raw − 180 = degrees (negative = port, positive = stbd) |
| 1 | Speed over ground | raw ÷ 10 = knots |
| 2 | Heading (true) | raw ÷ 10 = degrees |
| 3 | Rate of turn | raw − 1800 = °/min |
| 4 | Wind speed | raw ÷ 10 = knots |
| 5 | Wind direction | raw = degrees |
| 6–9 | GPS lat/lon | integer degrees + fractional minutes ×100 |

**Unit 3 — Ballast/Safety**

| Addr | Register | Scale |
|------|----------|-------|
| 0–3 | Fore / Aft / Port / Stbd ballast tanks | raw ÷ 10 = % full |
| 4 | Void space flood alarm | 0 = normal, 1 = alarm |
| 5–6 | Fire suppression zones 1–2 | 0 = off, 1 = active |
| 7–8 | Bilge pumps port / stbd | 0 = off, 1 = on, 2 = fault |
| 9 | General alarm bitmask | bit 0 = fire, bit 1 = flood, bit 2 = engine |

### Stop the lab

```bash
docker compose down
```
