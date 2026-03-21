#!/usr/bin/env python3
"""
field_device.py — Cruise Ship ICS Field Device Simulator

Modbus TCP slave exposing three unit IDs:
  Unit 1 = Engine Room   (RPM, fuel, thrusters, coolant)
  Unit 2 = Navigation    (rudder, speed, heading, GPS)
  Unit 3 = Ballast/Safety (tank levels, alarms)

Also starts a Flask web dashboard on WEB_PORT (default 8081) that shows
live register values and a log of every incoming Modbus request.

Authorized laboratory use only.
"""

import asyncio
import logging
import os
import random
import signal
import threading
from datetime import datetime

from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartAsyncTcpServer

import web_gui

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [field-device] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = os.environ.get("MODBUS_HOST", "0.0.0.0")
PORT = int(os.environ.get("MODBUS_PORT", 502))
WEB_PORT = int(os.environ.get("WEB_PORT", 8081))

# ---------------------------------------------------------------------------
# Shared state — read by web_gui, written by this module
# ---------------------------------------------------------------------------
# web_gui imports and uses these directly
import web_gui as _wg

NUM_REGS = 100

REGISTER_NAMES = {
    1: {
        0: "Port Engine RPM",
        1: "Stbd Engine RPM",
        2: "Port Fuel Flow",
        3: "Stbd Fuel Flow",
        4: "Port Coolant Temp",
        5: "Stbd Coolant Temp",
        6: "Bow Thruster",
        7: "Stern Thruster",
        8: "Port Shaft RPM",
        9: "Stbd Shaft RPM",
    },
    2: {
        0: "Rudder Angle",
        1: "Speed OG",
        2: "Heading (True)",
        3: "Rate of Turn",
        4: "Wind Speed",
        5: "Wind Direction",
        6: "GPS Lat (deg)",
        7: "GPS Lat (min×100)",
        8: "GPS Lon (deg)",
        9: "GPS Lon (min×100)",
    },
    3: {
        0: "Fore Ballast Tank",
        1: "Aft Ballast Tank",
        2: "Port Ballast Tank",
        3: "Stbd Ballast Tank",
        4: "Flood Alarm",
        5: "Fire Suppress Z1",
        6: "Fire Suppress Z2",
        7: "Bilge Pump Port",
        8: "Bilge Pump Stbd",
        9: "General Alarm",
    },
}

REGISTER_SCALE = {
    1: {
        0: lambda v: f"{v/10:.1f} RPM",
        1: lambda v: f"{v/10:.1f} RPM",
        2: lambda v: f"{v/10:.1f} L/hr",
        3: lambda v: f"{v/10:.1f} L/hr",
        4: lambda v: f"{v-50}°C",
        5: lambda v: f"{v-50}°C",
        6: lambda v: f"{v/10:.1f}%",
        7: lambda v: f"{v/10:.1f}%",
        8: lambda v: f"{v/10:.1f} RPM",
        9: lambda v: f"{v/10:.1f} RPM",
    },
    2: {
        0: lambda v: f"{v-180:+d}° ({'Port' if v<180 else 'Stbd' if v>180 else 'Amidships'})",
        1: lambda v: f"{v/10:.1f} kn",
        2: lambda v: f"{v/10:.1f}°T",
        3: lambda v: f"{v-1800:+d} °/min",
        4: lambda v: f"{v/10:.1f} kn",
        5: lambda v: f"{v}°",
        6: lambda v: f"{v}°",
        7: lambda v: f"{v/100:.2f}'",
        8: lambda v: f"{v}°",
        9: lambda v: f"{v/100:.2f}'",
    },
    3: {
        0: lambda v: f"{v/10:.1f}%",
        1: lambda v: f"{v/10:.1f}%",
        2: lambda v: f"{v/10:.1f}%",
        3: lambda v: f"{v/10:.1f}%",
        4: lambda v: "ALARM" if v else "Normal",
        5: lambda v: "ACTIVE" if v else "Off",
        6: lambda v: "ACTIVE" if v else "Off",
        7: lambda v: ["Off", "Running", "FAULT"][min(v, 2)],
        8: lambda v: ["Off", "Running", "FAULT"][min(v, 2)],
        9: lambda v: f"{'Fire ' if v&1 else ''}{'Flood ' if v&2 else ''}{'Engine' if v&4 else ''}".strip() or "None",
    },
}


def _unit1_initial() -> list:
    vals = [0] * NUM_REGS
    vals[0] = 800;  vals[1] = 800    # engine RPM × 0.1
    vals[2] = 2400; vals[3] = 2400   # fuel flow L/hr × 10
    vals[4] = 117;  vals[5] = 117    # coolant °C + 50
    vals[6] = 0;    vals[7] = 0      # thrusters off
    vals[8] = 650;  vals[9] = 650    # shaft RPM × 0.1
    return vals


def _unit2_initial() -> list:
    vals = [0] * NUM_REGS
    vals[0] = 180   # rudder amidships
    vals[1] = 185   # 18.5 knots
    vals[2] = 900   # heading 090.0°
    vals[3] = 1800  # zero rate of turn
    vals[4] = 120   # 12.0 kn wind
    vals[5] = 45    # wind from 045°
    vals[6] = 51    # 51°N latitude
    vals[7] = 3000  # 30.00' lat
    vals[8] = 0
    vals[9] = 0
    return vals


def _unit3_initial() -> list:
    vals = [0] * NUM_REGS
    vals[0] = 500; vals[1] = 500    # fore/aft tanks 50%
    vals[2] = 450; vals[3] = 450    # port/stbd tanks 45%
    # all others 0 (no alarms)
    return vals


def build_server_context() -> ModbusServerContext:
    def _device(init):
        return ModbusDeviceContext(
            hr=ModbusSequentialDataBlock(0, init),
            co=ModbusSequentialDataBlock(0, [0] * 100),
            di=ModbusSequentialDataBlock(0, [0] * 100),
            ir=ModbusSequentialDataBlock(0, [0] * NUM_REGS),
        )
    return ModbusServerContext(
        devices={
            1: _device(_unit1_initial()),
            2: _device(_unit2_initial()),
            3: _device(_unit3_initial()),
        },
        single=False,
    )


def _push_registers(context: ModbusServerContext) -> None:
    """Sync current register values into shared_state and push via Socket.IO."""
    regs = {}
    for unit in (1, 2, 3):
        vals = context[unit].getValues(3, 0, count=10)
        regs[unit] = vals
        # Build human-readable scaled values for the GUI
        scaled = {}
        for addr, raw in enumerate(vals):
            fn = REGISTER_SCALE.get(unit, {}).get(addr)
            scaled[addr] = fn(raw) if fn else str(raw)
        _wg.shared_state["scaled"][unit] = scaled

    with _wg.state_lock:
        _wg.shared_state["registers"] = regs

    _wg.socketio.emit("registers", {
        "registers": regs,
        "scaled": {str(k): v for k, v in _wg.shared_state["scaled"].items()},
        "names": {str(k): v for k, v in REGISTER_NAMES.items()},
    })


# ---------------------------------------------------------------------------
# Background sensor drift simulation
# ---------------------------------------------------------------------------
async def simulate_sensor_drift(context: ModbusServerContext) -> None:
    log.info("Sensor simulation started")
    while True:
        await asyncio.sleep(3)
        try:
            # Unit 1 — engines
            s1 = context[1]
            hr = s1.getValues(3, 0, count=10)
            hr[0] = max(700, min(1000, hr[0] + random.randint(-5, 5)))
            hr[1] = max(700, min(1000, hr[1] + random.randint(-5, 5)))
            hr[2] = max(1800, min(3200, hr[0] * 3 + random.randint(-10, 10)))
            hr[3] = max(1800, min(3200, hr[1] * 3 + random.randint(-10, 10)))
            hr[4] = max(100, min(125, hr[4] + random.randint(-1, 1)))
            hr[5] = max(100, min(125, hr[5] + random.randint(-1, 1)))
            hr[8] = max(600, min(900, hr[0] - random.randint(0, 30)))
            hr[9] = max(600, min(900, hr[1] - random.randint(0, 30)))
            s1.setValues(3, 0, hr)

            # Unit 2 — navigation
            s2 = context[2]
            hr2 = s2.getValues(3, 0, count=10)
            hr2[0] = max(145, min(215, hr2[0] + random.randint(-1, 1)))
            hr2[1] = max(100, min(230, hr2[1] + random.randint(-1, 1)))
            hr2[2] = (hr2[2] + random.randint(-3, 3)) % 3600
            hr2[4] = max(0, min(600, hr2[4] + random.randint(-5, 5)))
            s2.setValues(3, 0, hr2)

            # Unit 3 — ballast
            s3 = context[3]
            hr3 = s3.getValues(3, 0, count=10)
            for i in range(4):
                hr3[i] = max(0, min(1000, hr3[i] + random.randint(-2, 2)))
            s3.setValues(3, 0, hr3)

            _push_registers(context)

        except Exception as exc:
            log.warning("Sensor drift error: %s", exc)


# ---------------------------------------------------------------------------
# Custom request logger — intercepts every incoming Modbus request
# ---------------------------------------------------------------------------
class LoggingRequestHandler:
    """Wraps pymodbus request processing to log each request to shared_state."""

    def __init__(self, context):
        self.context = context

    def __call__(self, request, *args, **kwargs):
        # Log the request
        fc = request.function_code
        unit = getattr(request, 'unit_id', getattr(request, 'slave_id', '?'))
        addr = getattr(request, 'address', '?')
        count = getattr(request, 'count', None)
        value = getattr(request, 'value', None)
        values = getattr(request, 'values', None)

        fc_names = {
            1: "Read Coils", 2: "Read Discrete Inputs",
            3: "Read Holding Regs", 4: "Read Input Regs",
            5: "Write Single Coil", 6: "Write Single Reg",
            15: "Write Multiple Coils", 16: "Write Multiple Regs",
        }
        fc_name = fc_names.get(fc, f"FC {fc}")

        write_val = value if value is not None else (str(values) if values is not None else "")

        entry = {
            "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "unit": unit,
            "fc": fc_name,
            "addr": addr,
            "count": count or "",
            "value": write_val,
        }

        with _wg.state_lock:
            _wg.shared_state["request_log"].insert(0, entry)
            if len(_wg.shared_state["request_log"]) > 50:
                _wg.shared_state["request_log"].pop()

        _wg.socketio.emit("request_log", {"entry": entry})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main() -> None:
    context = build_server_context()

    # Seed shared state initial values
    _push_registers(context)
    with _wg.state_lock:
        _wg.shared_state["register_names"] = {
            str(k): v for k, v in REGISTER_NAMES.items()
        }

    log.info("Starting Modbus TCP server on %s:%d", HOST, PORT)
    log.info("Starting web dashboard on port %d", WEB_PORT)

    # Start sensor drift simulation
    asyncio.create_task(simulate_sensor_drift(context))

    # Start Flask web GUI in background thread
    web_thread = threading.Thread(
        target=_wg.run_web,
        args=(WEB_PORT,),
        daemon=True,
    )
    web_thread.start()

    await StartAsyncTcpServer(
        context=context,
        address=(HOST, PORT),
    )


if __name__ == "__main__":
    loop = asyncio.new_event_loop()

    def _handle_signal():
        log.info("Shutting down field device...")
        loop.stop()

    loop.add_signal_handler(signal.SIGTERM, _handle_signal)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        log.info("Interrupted")
    finally:
        loop.close()
