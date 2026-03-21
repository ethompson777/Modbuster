# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run GUI (primary interface)
python -m modbuster gui
# Windows alternative:
python Modbuster.py

# CLI: analyze a PCAP file
python -m modbuster analyze --pcap test_modbus.pcap

# CLI: live capture
python -m modbuster analyze --live --iface eth0

# CLI: inject (read)
python -m modbuster inject --protocol modbus --target 192.168.1.10 read-holding --unit 1 --addr 0 --count 10

# CLI: inject (write — requires --write flag)
python -m modbuster inject --protocol modbus --target 192.168.1.10 write-register --unit 1 --addr 0 --value 123 --write

# CLI: replay from PCAP
python -m modbuster replay --pcap test_modbus.pcap --target 192.168.1.10 --index 0

# TUI mode
python -m modbuster analyze --pcap test_modbus.pcap --tui

# Run tests
pytest tests/

# Run a single test
pytest tests/test_modbus.py::TestClassName::test_method_name
```

## Architecture

Modbuster is an OT/ICS pentesting tool for Modbus TCP (and extensible to DNP3, BACnet, etc.). It provides three interfaces — CLI, GUI (customtkinter), and TUI (Rich) — over a shared core.

### Data Flow

```
PCAP/Live → capture.py (iter_pcap / iter_live)
          → protocols/ (detect → parse)
          → interpreter.py (format_line / summary)
          → export.py (JSON/CSV) or display (CLI/TUI/GUI)

Target ← inject.py (build_* payload → send_tcp socket)
```

### Key Modules

- **`cli.py`** — argparse subcommands: `analyze`, `inject`, `replay`, `gui`
- **`gui.py`** — customtkinter GUI with tabs (Analyze, Inject, Replay); runs capture in background threads
- **`tui.py`** — Rich-based terminal UI invoked via `--tui` flag
- **`capture.py`** — Scapy wrapper; `iter_pcap()` and `iter_live()` yield packets lazily; handles PCAP/PCAPNG and link-layer type `0xE4` (raw IP)
- **`interpreter.py`** — Formats packets as human-readable strings; computes summary stats
- **`inject.py`** — Protocol-agnostic TCP socket sender; delegates payload construction to protocol handlers
- **`replay.py`** — Extracts Modbus payloads from a PCAP and retransmits them
- **`export.py`** — Flattens parsed records to JSON or CSV

### Protocol Plugin System (`protocols/`)

- `base.py` defines `BaseProtocolHandler` with abstract methods: `detect(pkt)`, `parse(pkt)`, `build_read_holding()`, `build_write_single()`, `build_write_multiple()`
- `modbus.py` is the only fully-implemented handler (Modbus TCP port 502)
- `__init__.py` exposes a `PROTOCOLS` dict — add new handlers here to extend support
- The GUI references DNP3, IEC 60870-5-104, BACnet, EtherNet/IP but these are not yet implemented

### Safety Mechanism

All write operations (inject, replay with writes) require an explicit `--write` flag. This is intentional — writing registers/coils affects physical processes in OT environments.
