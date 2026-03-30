# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run GUI (primary interface)
python -m modbuster gui
# Windows alternative: python Modbuster.py

# CLI: analyze a PCAP file
python -m modbuster analyze --pcap test_modbus.pcap

# CLI: live capture (requires root/admin)
python -m modbuster analyze --live --iface eth0

# CLI: TUI mode
python -m modbuster analyze --pcap test_modbus.pcap --tui

# CLI: inject read (safe — no --write flag needed)
python -m modbuster inject --protocol modbus --target 192.168.1.10 read-holding --unit 1 --addr 0 --count 10

# CLI: inject write (requires explicit --write flag)
python -m modbuster inject --protocol modbus --target 192.168.1.10 write-register --unit 1 --addr 0 --value 123 --write

# CLI: replay from PCAP
python -m modbuster replay --pcap test_modbus.pcap --target 192.168.1.10 --index 0

# Run tests
pytest tests/

# Run a single test
pytest tests/test_modbus.py::ClassName::test_method_name

# Docker lab (isolated ICS simulation)
docker compose build --no-cache
docker compose up -d
# After every 'docker compose up' run this to restore traffic mirroring:
sudo bash setup_mirror.sh
# Lab dashboards: Controller http://localhost:8080, Field Device http://localhost:8082
# Kali noVNC desktop: http://localhost:6080/vnc.html  (no password)
docker exec -it kali_pentest /bin/bash
```

## Architecture

Modbuster is an OT/ICS pentesting tool for Modbus TCP, extensible to DNP3, BACnet, EtherNet/IP. It exposes a shared core through three interfaces: CLI, GUI (customtkinter), and TUI (Rich). Requires **Python 3.9+** (uses `dict[K, V]` union syntax). Use `--verbose` on analyze/inject commands to see exception traces instead of silent failures.

### Data Flow

```
PCAP/Live traffic
    → capture.py       iter_pcap() / iter_live() — yields Scapy packets lazily;
                       handles PCAP, PCAPNG, and raw-IP link-layer type 0xE4;
                       iter_live() uses Queue+prn callback for real-time streaming
    → protocols/       detect(pkt) → parse(pkt) → dict of fields
    → inference.py     InferenceEngine.feed(parsed) — classifies registers offline
    → interpreter.py   format_line() / summary() — human-readable output & stats
    → export.py        JSON/CSV for pentest reports
       OR display layer (cli.py prints, tui.py Rich table, gui.py tkinter widgets)

Target system
    ← inject.py        build_* payload via protocol handler → send over TCP socket
    ← replay.py        extract Modbus ADU from PCAP → retransmit to target
```

### Key Modules

| Module | Role |
|---|---|
| `cli.py` | argparse entry point; subcommands `analyze`, `inject`, `replay`, `gui` |
| `gui.py` | customtkinter GUI; four tabs (Analyze, Inject, Replay, Infer); capture in background threads; collapsible Auto Analysis panel; Network Map with clickable IPs |
| `tui.py` | Rich terminal UI; invoked by `--tui` flag on `analyze` |
| `capture.py` | Scapy PCAP/live wrapper |
| `interpreter.py` | Packet → human string; per-protocol summary stats |
| `inference.py` | Offline register classification engine — no internet required |
| `inject.py` | Protocol-agnostic TCP socket sender; delegates payload construction to protocol handlers |
| `replay.py` | Reads Modbus payloads from a PCAP and retransmits them |
| `export.py` | Flattens parsed records to JSON or CSV |

### Protocol Plugin System (`modbuster/protocols/`)

- `base.py` — abstract `BaseProtocolHandler` with required methods: `detect(pkt)`, `parse(pkt)`, `build_read_holding()`, `build_write_single()`, `build_write_multiple()`
- `modbus.py` — the only fully-implemented handler; Modbus TCP on port 502; uses Scapy's `contrib.modbus` (lazy-loaded)
- `__init__.py` — `PROTOCOLS` dict; register new handlers here to extend protocol support
- DNP3, IEC 60870-5-104, BACnet, EtherNet/IP are listed in the GUI but **not yet implemented**

**`parse()` output contract** — all handlers must return a dict with these keys (missing keys default to `None`):

| Key | Type | Description |
|---|---|---|
| `protocol` | str | handler name (e.g. `"modbus"`) |
| `direction` | str | `"request"` or `"response"` |
| `unit_id` | int | Modbus unit / device address |
| `func_code` | int | raw function code |
| `op_name` | str | human label (e.g. `"Read Holding Registers"`) |
| `start_addr` | int | first register address |
| `quantity` | int | number of registers (read ops) |
| `address` | int | single register address (write ops) |
| `value` | int | single value (write single) |
| `values` | list[int] | multiple values (write multiple / read response) |
| `exception_code` | int | set when func_code ≥ 0x80 |
| `raw_hex` | str | hex dump of raw payload |

`InferenceEngine.feed()` and `interpreter.format_line()` both consume this dict, so adding a new protocol only requires implementing `parse()` to this schema.

### Safety Mechanism

All write operations (inject and replay with writes) require an explicit `--write` flag. This is intentional — writing to OT registers affects physical processes.

### Inference Engine (`modbuster/inference.py`)

`InferenceEngine` accumulates observations per (unit_id, address) from `feed(parsed_dict)` calls and runs 19 ordered classification rules entirely offline:

1. Write-only (never polled) → Command
2. Heavy write ratio → Setpoint
3. Binary {0,1} → Status bit (with rate: watchdog/cycling/static)
4. Small discrete set with 0=normal → Alarm (maps 0=Normal, 1=Warning, 2=Alarm, 3=Suppressed, 4=Fault)
5. Discrete steps ≤7 states → State/Mode
6. Mean 480–620, low σ → Grid frequency (detects 50 Hz vs 60 Hz)
7. Mean 5500–7500 → 6.6 kV ship HV bus
8. Mean 3200–4500 → 3.3/4.16 kV MV bus
9. Mean 360–480 → 400/440 V LV bus
10. Mean 500–20 000, high σ → Generator kW
11. RPM (multi-scale: ×1, ×0.1, ×10)
12. Temperature (direct °C, Kelvin, ×10 scale, +50 bias)
13. Percentage (×10 scale, 0–1100 raw)
14. Flow rate
15. Pressure / Level
16. Position / Angle (center-offset detection: 180/1800/500)
17. Monotonic counter
18. Very stable → Setpoint candidate
19. Generic analog fallback

Cross-register analysis: setpoint/actual pairs, channel groups (≥3 consecutive same-type), mirrored/redundant registers.

### GUI Panels (Analyze tab)

- **Traffic log** — scrolling textbox of decoded packets
- **Auto Analysis** — collapsible strip (▶/▼ toggle); flicker-free CTkTextbox showing `Unit / Addr / Conf / Type / LastVal / Range / Hint` for all classified registers; updates every 3 s during live capture
- **Network Map** — hidden until hosts are discovered; clickable IP buttons auto-populate Inject/Replay target fields and switch to Inject tab
- **Infer tab** — full table of `InferenceEngine.classify_all()` results with confidence and hints

### Docker Lab

`docker/` contains an isolated Royal Caribbean-style cruise ship ICS simulation (8 Modbus unit IDs):

| Unit | System |
|---|---|
| 1 | Main Propulsion (RPM, fuel flow, coolant, thrusters) |
| 2 | Navigation/Bridge (rudder, speed, heading, ROT, wind, GPS) |
| 3 | Ballast/Safety (tanks, flood alarm, fire suppress, bilge, general alarm) |
| 4 | Power Management (4× generators, bus voltage, grid frequency, total load) |
| 5 | HVAC/Environmental (deck zone temps, chilled water, AHU/chiller status) |
| 6 | Fire Safety & Alarms (fire zones, CO2 banks, smoke detectors) |
| 7 | Fuel Management (HFO/MGO wing tanks, day tanks, flow rates, fuel mode) |
| 8 | Stabilizer/Motion (fin angles, roll/pitch, vertical accel, hydraulics) |

**SPAN port simulation:** The Kali container is on the same Docker bridge but cannot see controller↔field-device traffic by default (bridge = L2 switch). `setup_mirror.sh` uses `tc` (traffic control) to mirror all frames from the controller and field-device veth interfaces to Kali's veth on the host. Must be re-run after every `docker compose up`.

**Kali GUI access:** noVNC browser desktop at `http://localhost:6080/vnc.html` (no password). A desktop icon launches the Modbuster GUI. VNC is served by running `Xtigervnc` directly (not the `tigervncserver` wrapper) with `-SecurityTypes None` so no password is required.

**Controller dashboard** at `http://localhost:8080` includes a Bridge Control Console: engine telegraph levers (port + stbd), rudder arc gauge, sync mode, write lock toggle, and live nav readouts (speed, heading, ROT).

Use `test_modbus.pcap` in the repo root as a sample capture for offline testing.
