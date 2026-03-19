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

Manual injection testing: use a Modbus TCP simulator (e.g. modbuspal, or a Docker Modbus slave) on a lab network.
