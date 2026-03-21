#!/usr/bin/env python3
"""
controller.py — Cruise Ship Automation Controller Simulator

Modbus TCP master that:
  - Continuously polls the field device (all 3 unit IDs)
  - Periodically writes control register values
  - Exposes a Flask web dashboard (port 8080) for:
      * Viewing live poll results
      * Sending manual read/write commands

Authorized laboratory use only.
"""

import asyncio
import logging
import os
import random
import signal
import sys
import threading
from datetime import datetime

from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusException

import web_gui as _wg

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [controller] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
FIELD_DEVICE_HOST = os.environ.get("FIELD_DEVICE_HOST", "172.20.0.20")
FIELD_DEVICE_PORT = int(os.environ.get("FIELD_DEVICE_PORT", 502))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", 5))
WRITE_INTERVAL = float(os.environ.get("WRITE_INTERVAL", 30))
WEB_PORT = int(os.environ.get("WEB_PORT", 8080))

# Share connection info with web_gui for manual commands
_wg.FIELD_DEVICE_HOST = FIELD_DEVICE_HOST
_wg.FIELD_DEVICE_PORT = FIELD_DEVICE_PORT

# Register name map (matches field_device.py)
REGISTER_NAMES = {
    1: {0:"Port Engine RPM",1:"Stbd Engine RPM",2:"Port Fuel Flow",3:"Stbd Fuel Flow",
        4:"Port Coolant Temp",5:"Stbd Coolant Temp",6:"Bow Thruster",7:"Stern Thruster",
        8:"Port Shaft RPM",9:"Stbd Shaft RPM"},
    2: {0:"Rudder Angle",1:"Speed OG",2:"Heading (True)",3:"Rate of Turn",
        4:"Wind Speed",5:"Wind Direction",6:"GPS Lat (deg)",7:"GPS Lat (min×100)",
        8:"GPS Lon (deg)",9:"GPS Lon (min×100)"},
    3: {0:"Fore Ballast",1:"Aft Ballast",2:"Port Ballast",3:"Stbd Ballast",
        4:"Flood Alarm",5:"Fire Suppress Z1",6:"Fire Suppress Z2",
        7:"Bilge Port",8:"Bilge Stbd",9:"General Alarm"},
}

# ---------------------------------------------------------------------------
# Poll helpers
# ---------------------------------------------------------------------------

def _log_poll(unit: int, addr: int, count: int, values: list, label: str) -> None:
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "unit": unit,
        "label": label,
        "addr": addr,
        "count": count,
        "values": values,
    }
    with _wg.state_lock:
        _wg.shared_state["poll_log"].insert(0, entry)
        if len(_wg.shared_state["poll_log"]) > 100:
            _wg.shared_state["poll_log"].pop()
        # Update latest register snapshot
        for i, v in enumerate(values):
            _wg.shared_state["registers"][unit][addr + i] = v

    _wg.socketio.emit("poll_result", {"entry": entry})
    _wg.socketio.emit("registers", {
        "registers": {str(k): list(v.values()) for k, v in _wg.shared_state["registers"].items()},
        "names": {str(k): v for k, v in REGISTER_NAMES.items()},
    })


async def poll_unit(client: AsyncModbusTcpClient, unit: int, addr: int, count: int, label: str) -> None:
    try:
        rr = await client.read_holding_registers(addr, count=count, device_id=unit)
        if rr.isError():
            log.warning("[Unit %d/%s] read error: %s", unit, label, rr)
            return
        vals = list(rr.registers)
        log.info("[Unit %d/%s] regs %d-%d: %s", unit, label, addr, addr+count-1, vals)
        _log_poll(unit, addr, count, vals, label)
    except ModbusException as exc:
        log.error("[Unit %d/%s] Modbus error: %s", unit, label, exc)
    except Exception as exc:
        log.error("[Unit %d/%s] Error: %s", unit, label, exc)


async def poll_cycle(client: AsyncModbusTcpClient) -> None:
    await poll_unit(client, 1, 0, 10, "engines")
    await asyncio.sleep(0.2)
    await poll_unit(client, 2, 0, 10, "navigation")
    await asyncio.sleep(0.2)
    await poll_unit(client, 3, 0, 10, "ballast")
    await asyncio.sleep(0.2)
    # Targeted critical reads
    await poll_unit(client, 1, 0, 1, "port-engine-RPM")
    await asyncio.sleep(0.1)
    await poll_unit(client, 2, 0, 1, "rudder-angle")
    await asyncio.sleep(0.1)
    await poll_unit(client, 3, 0, 4, "ballast-tanks")


# ---------------------------------------------------------------------------
# Write cycle (simulates control commands)
# ---------------------------------------------------------------------------
_write_counter = 0


async def write_cycle(client: AsyncModbusTcpClient) -> None:
    global _write_counter
    _write_counter += 1
    scenario = _write_counter % 4

    try:
        if scenario == 0:
            val = random.randint(0, 200)
            log.info("[WRITE] Bow thruster → %d (%.1f%%)", val, val/10)
            await client.write_register(6, val, slave=1)
            _log_write(1, 6, [val], "Bow Thruster setpoint")

        elif scenario == 1:
            val = random.randint(175, 185)
            log.info("[WRITE] Rudder → %d (%+d°)", val, val-180)
            await client.write_register(0, val, slave=2)
            _log_write(2, 0, [val], "Rudder setpoint")

        elif scenario == 2:
            fore = random.randint(480, 520)
            aft = random.randint(480, 520)
            log.info("[WRITE] Ballast fore=%d aft=%d", fore, aft)
            await client.write_registers(0, [fore, aft], slave=3)
            _log_write(3, 0, [fore, aft], "Fore/Aft ballast setpoint")

        elif scenario == 3:
            rpm = random.randint(780, 820)
            log.info("[WRITE] Engine RPM setpoint → %d (%.1f RPM)", rpm, rpm/10)
            await client.write_registers(0, [rpm, rpm], slave=1)
            _log_write(1, 0, [rpm, rpm], "Engine RPM setpoints")

    except ModbusException as exc:
        log.error("[WRITE] Modbus error: %s", exc)
    except Exception as exc:
        log.error("[WRITE] Error: %s", exc)


def _log_write(unit: int, addr: int, values: list, label: str) -> None:
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "unit": unit,
        "label": label,
        "addr": addr,
        "count": len(values),
        "values": values,
        "type": "write",
    }
    with _wg.state_lock:
        _wg.shared_state["poll_log"].insert(0, entry)
        if len(_wg.shared_state["poll_log"]) > 100:
            _wg.shared_state["poll_log"].pop()
    _wg.socketio.emit("poll_result", {"entry": entry})


# ---------------------------------------------------------------------------
# Main control loop
# ---------------------------------------------------------------------------

async def main() -> None:
    # Seed shared state structure
    with _wg.state_lock:
        for unit in (1, 2, 3):
            _wg.shared_state["registers"][unit] = {i: 0 for i in range(10)}
        _wg.shared_state["register_names"] = {str(k): v for k, v in REGISTER_NAMES.items()}

    log.info("Controller starting → %s:%d", FIELD_DEVICE_HOST, FIELD_DEVICE_PORT)
    log.info("Poll: %.1fs | Write: %.1fs | Web dashboard: port %d",
             POLL_INTERVAL, WRITE_INTERVAL, WEB_PORT)

    # Start Flask web GUI in daemon thread
    web_thread = threading.Thread(
        target=_wg.run_web,
        args=(WEB_PORT,),
        daemon=True,
    )
    web_thread.start()

    client = AsyncModbusTcpClient(
        host=FIELD_DEVICE_HOST,
        port=FIELD_DEVICE_PORT,
        timeout=5,
        retries=3,
    )
    await client.connect()
    if not client.connected:
        log.error("Could not connect to field device at %s:%d", FIELD_DEVICE_HOST, FIELD_DEVICE_PORT)
        sys.exit(1)

    log.info("Connected to field device")
    last_write = 0.0
    poll_count = 0

    try:
        while True:
            loop_start = asyncio.get_event_loop().time()

            if not client.connected:
                log.warning("Reconnecting...")
                await client.connect()
                if not client.connected:
                    await asyncio.sleep(POLL_INTERVAL)
                    continue

            poll_count += 1
            log.info("--- Poll #%d ---", poll_count)
            await poll_cycle(client)

            now = asyncio.get_event_loop().time()
            if now - last_write >= WRITE_INTERVAL:
                log.info("--- Write cycle ---")
                await write_cycle(client)
                last_write = now

            elapsed = asyncio.get_event_loop().time() - loop_start
            await asyncio.sleep(max(0.1, POLL_INTERVAL - elapsed))

    except asyncio.CancelledError:
        pass
    finally:
        await client.close()
        log.info("Controller stopped")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()

    def _handle_signal():
        log.info("Shutting down controller...")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    loop.add_signal_handler(signal.SIGTERM, _handle_signal)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        log.info("Interrupted")
    finally:
        loop.close()
