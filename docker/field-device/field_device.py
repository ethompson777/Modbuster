#!/usr/bin/env python3
"""
field_device.py — Cruise Ship ICS Field Device Simulator (Royal Caribbean Scale)

Modbus TCP slave exposing eight unit IDs:
  Unit 1 = Main Propulsion   (engines, thrusters, shaft RPM, fuel flow, coolant)
  Unit 2 = Navigation/Bridge (rudder, speed, heading, GPS, wind, rate of turn)
  Unit 3 = Ballast/Safety    (tank levels, flood/fire alarms, bilge pumps)
  Unit 4 = Power Management  (generators, bus voltage, frequency, total load)
  Unit 5 = HVAC/Environmental (deck zone temps, chilled water, AHUs, chillers)
  Unit 6 = Fire Safety & Alarms (fire zones, CO2 systems, smoke detectors)
  Unit 7 = Fuel Management   (HFO/MGO wing+day tanks, flow rates, fuel mode)
  Unit 8 = Stabilizer/Motion (fin angles, roll/pitch, hydraulic pressure)

Also starts a Flask web dashboard on WEB_PORT (default 8081) that shows
live register values and a log of every incoming Modbus request.

Authorized laboratory use only.
"""

import asyncio
import logging
import os
import signal
import threading
import time
from datetime import datetime

from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartAsyncTcpServer

import web_gui
import web_gui as _wg

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
UNIT_IDS = sorted(int(x.strip()) for x in os.environ.get("UNIT_IDS", "1,2,3,4,5,6,7,8").split(","))

NUM_REGS = 100

# ---------------------------------------------------------------------------
# Register metadata
# ---------------------------------------------------------------------------
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
    4: {
        0: "Generator 1 (kW)",
        1: "Generator 2 (kW)",
        2: "Generator 3 (kW)",
        3: "Generator 4 (kW)",
        4: "Bus A Voltage",
        5: "Bus B Voltage",
        6: "Grid Frequency",
        7: "Total Load (kW)",
        8: "Shore Power",
        9: "Emergency Gen",
    },
    5: {
        0: "Deck 3 Zone Temp",
        1: "Deck 7 Zone Temp",
        2: "Deck 12 Zone Temp",
        3: "Engine Room Temp",
        4: "Chilled Water Supply",
        5: "Chilled Water Return",
        6: "AHU 1 Status",
        7: "AHU 2 Status",
        8: "Chiller 1 Status",
        9: "Outside Air Temp",
    },
    6: {
        0: "Fire Zone 1 (Cargo)",
        1: "Fire Zone 2 (Engine)",
        2: "Fire Zone 3 (Crew)",
        3: "Fire Zone 4 (Pax Decks)",
        4: "CO2 Bank 1",
        5: "CO2 Bank 2",
        6: "General Alarm",
        7: "Bilge Pump Port",
        8: "Bilge Pump Stbd",
        9: "Smoke Detector Count",
    },
    7: {
        0: "HFO Port Wing Tank",
        1: "HFO Stbd Wing Tank",
        2: "MGO Port Tank",
        3: "MGO Stbd Tank",
        4: "HFO Day Tank",
        5: "MGO Day Tank",
        6: "HFO Flow Rate",
        7: "MGO Flow Rate",
        8: "Fuel Mode",
        9: "Total Fuel Remaining",
    },
    8: {
        0: "Port Fin Angle",
        1: "Stbd Fin Angle",
        2: "Port Fin Status",
        3: "Stbd Fin Status",
        4: "Roll Angle",
        5: "Pitch Angle",
        6: "Vertical Accel",
        7: "Stabilizer Mode",
        8: "Port Fin Hyd Press",
        9: "Stbd Fin Hyd Press",
    },
}

REGISTER_SCALE = {
    1: {
        0: lambda v: f"{v} RPM",
        1: lambda v: f"{v} RPM",
        2: lambda v: f"{v/10:.1f} L/hr",
        3: lambda v: f"{v/10:.1f} L/hr",
        4: lambda v: f"{v-50}°C",
        5: lambda v: f"{v-50}°C",
        6: lambda v: f"{v/10:.1f}%",
        7: lambda v: f"{v/10:.1f}%",
        8: lambda v: f"{v} RPM",
        9: lambda v: f"{v} RPM",
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
    4: {
        0: lambda v: f"{v} kW",
        1: lambda v: f"{v} kW",
        2: lambda v: f"{v} kW",
        3: lambda v: f"{v} kW",
        4: lambda v: f"{v} V",
        5: lambda v: f"{v} V",
        6: lambda v: f"{v/10:.1f} Hz",
        7: lambda v: f"{v} kW",
        8: lambda v: "Yes" if v else "No",
        9: lambda v: ["Standby", "Running", "FAULT"][min(v, 2)],
    },
    5: {
        0: lambda v: f"{v/10:.1f}°C",
        1: lambda v: f"{v/10:.1f}°C",
        2: lambda v: f"{v/10:.1f}°C",
        3: lambda v: f"{v/10:.1f}°C",
        4: lambda v: f"{v/10:.1f}°C",
        5: lambda v: f"{v/10:.1f}°C",
        6: lambda v: ["Off", "Running", "FAULT"][min(v, 2)],
        7: lambda v: ["Off", "Running", "FAULT"][min(v, 2)],
        8: lambda v: ["Off", "Running", "FAULT"][min(v, 2)],
        9: lambda v: f"{v/10:.1f}°C",
    },
    6: {
        0: lambda v: ["Normal", "Pre-Alarm", "ALARM", "SUPPRESSION"][min(v, 3)],
        1: lambda v: ["Normal", "Pre-Alarm", "ALARM", "SUPPRESSION"][min(v, 3)],
        2: lambda v: ["Normal", "Pre-Alarm", "ALARM", "SUPPRESSION"][min(v, 3)],
        3: lambda v: ["Normal", "Pre-Alarm", "ALARM", "SUPPRESSION"][min(v, 3)],
        4: lambda v: ["Normal", "Armed", "DISCHARGED", "FAULT"][min(v, 3)],
        5: lambda v: ["Normal", "Armed", "DISCHARGED", "FAULT"][min(v, 3)],
        6: lambda v: "ACTIVE" if v else "Normal",
        7: lambda v: ["Off", "Running", "FAULT"][min(v, 2)],
        8: lambda v: ["Off", "Running", "FAULT"][min(v, 2)],
        9: lambda v: f"{v} detector(s)",
    },
    7: {
        0: lambda v: f"{v/10:.1f}%",
        1: lambda v: f"{v/10:.1f}%",
        2: lambda v: f"{v/10:.1f}%",
        3: lambda v: f"{v/10:.1f}%",
        4: lambda v: f"{v/10:.1f}%",
        5: lambda v: f"{v/10:.1f}%",
        6: lambda v: f"{v} L/hr",
        7: lambda v: f"{v} L/hr",
        8: lambda v: ["HFO", "MGO", "Dual"][min(v, 2)],
        9: lambda v: f"{v/10:.1f} t",
    },
    8: {
        0: lambda v: f"{(v-300)/10:+.1f}°",
        1: lambda v: f"{(v-300)/10:+.1f}°",
        2: lambda v: ["Retracted", "Deployed", "Active", "FAULT"][min(v, 3)],
        3: lambda v: ["Retracted", "Deployed", "Active", "FAULT"][min(v, 3)],
        4: lambda v: f"{(v-150)/10:+.1f}°",
        5: lambda v: f"{(v-100)/10:+.1f}°",
        6: lambda v: f"{v/100:.2f} m/s²",
        7: lambda v: ["Off", "Auto", "Manual"][min(v, 2)],
        8: lambda v: f"{v/10:.1f} bar",
        9: lambda v: f"{v/10:.1f} bar",
    },
}


# ---------------------------------------------------------------------------
# Initial register values (realistic cruise ship at sea)
# ---------------------------------------------------------------------------
def _unit1_initial() -> list:
    vals = [0] * NUM_REGS
    vals[0] = 105;  vals[1] = 105    # engine RPM direct → 105 RPM cruise
    vals[2] = 20600; vals[3] = 20600 # fuel flow ÷10 → 2060.0 L/hr/engine (Wärtsilä 46C cruise)
    vals[4] = 142;  vals[5] = 142    # coolant °C+50 → 92°C at cruise load
    vals[6] = 0;    vals[7] = 0      # thrusters off at sea
    vals[8] = 102;  vals[9] = 102    # shaft RPM direct → 102 RPM (engine × 0.975)
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


def _unit4_initial() -> list:
    """Power Management: Wärtsilä 16V46C (14 MW) × 2 + 12V46C (12 MW) × 1 running, gen4 standby."""
    vals = [0] * NUM_REGS
    vals[0] = 14000; vals[1] = 14000  # gen 1-2 kW (16V46C-class at ~83% MCR)
    vals[2] = 12000; vals[3] = 0      # gen 3 kW (12V46C-class), gen 4 hot standby
    vals[4] = 6600; vals[5] = 6600    # bus A/B: 6,600 V (6.6 kV HV bus)
    vals[6] = 600                     # frequency ÷10 = 60.0 Hz
    vals[7] = 40000                   # total load ~40 MW (propulsion + hotel + HVAC)
    vals[8] = 0                       # no shore power
    vals[9] = 0                       # emergency gen standby
    return vals


def _unit5_initial() -> list:
    """HVAC: cabin zones at 22°C, chilled water 7°C supply / 13°C return, all AHUs on."""
    vals = [0] * NUM_REGS
    vals[0] = 220; vals[1] = 220; vals[2] = 220   # deck zones 22.0°C
    vals[3] = 390                                  # engine room 39.0°C
    vals[4] = 70                                   # chilled water supply 7.0°C
    vals[5] = 130                                  # chilled water return 13.0°C
    vals[6] = 1; vals[7] = 1                       # AHU 1+2 running
    vals[8] = 1                                    # chiller 1 running
    vals[9] = 150                                  # outside air 15.0°C
    return vals


def _unit6_initial() -> list:
    """Fire Safety: all zones normal, all CO2 normal, no alarms."""
    vals = [0] * NUM_REGS
    # regs 0-9 all 0 = normal/off
    return vals


def _unit7_initial() -> list:
    """Fuel: HFO wings 75%, MGO 50%, day tanks 90%, HFO flow ~13,000 L/hr, 3000 t remaining."""
    vals = [0] * NUM_REGS
    vals[0] = 750; vals[1] = 750   # HFO wing tanks 75.0%
    vals[2] = 500; vals[3] = 500   # MGO tanks 50.0%
    vals[4] = 900                  # HFO day tank 90.0%
    vals[5] = 800                  # MGO day tank 80.0%
    vals[6] = 13000                # HFO flow ~13,000 L/hr ship-wide (~300 t/day cruise)
    vals[7] = 0                    # MGO flow 0 (running on HFO)
    vals[8] = 0                    # fuel mode: HFO
    vals[9] = 30000                # total remaining ÷10 → 3000.0 t (Oasis-class ~3,500 t cap)
    return vals


def _unit8_initial() -> list:
    """Stabilizers: fins deployed active, neutral angle, auto mode, 130 bar hydraulic."""
    vals = [0] * NUM_REGS
    vals[0] = 300; vals[1] = 300   # fin angles neutral (offset 300 = 0°)
    vals[2] = 2; vals[3] = 2       # both fins active
    vals[4] = 150; vals[5] = 100   # roll/pitch neutral (offset 150/100 = 0°)
    vals[6] = 0                    # vertical accel 0
    vals[7] = 1                    # stabilizer mode: auto
    vals[8] = 1300; vals[9] = 1300 # hydraulic pressure 130.0 bar
    return vals


# ---------------------------------------------------------------------------
# Build server context
# ---------------------------------------------------------------------------
def build_server_context() -> ModbusServerContext:
    def _device(init):
        return ModbusDeviceContext(
            hr=ModbusSequentialDataBlock(0, init),
            co=ModbusSequentialDataBlock(0, [0] * 100),
            di=ModbusSequentialDataBlock(0, [0] * 100),
            ir=ModbusSequentialDataBlock(0, [0] * NUM_REGS),
        )
    init_fns = {
        1: _unit1_initial, 2: _unit2_initial, 3: _unit3_initial, 4: _unit4_initial,
        5: _unit5_initial, 6: _unit6_initial, 7: _unit7_initial, 8: _unit8_initial,
    }
    return ModbusServerContext(
        devices={uid: _device(init_fns[uid]()) for uid in UNIT_IDS},
        single=False,
    )


def _push_registers(context: ModbusServerContext) -> None:
    """Sync current register values into shared_state and push via Socket.IO."""
    regs = {}
    for unit in UNIT_IDS:
        vals = context[unit].getValues(3, 0, count=10)
        regs[unit] = vals
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
        "names": _wg.shared_state["register_names"],
    })


_WRITE_FCS = {5, 6, 15, 16}
_COMMS_TIMEOUT = 15.0   # seconds without a write before COMMS LOST


# ---------------------------------------------------------------------------
# Dashboard refresh loop — pushes current register values to web UI and
# monitors controller comms health (no write in _COMMS_TIMEOUT → LOST).
# ---------------------------------------------------------------------------
async def dashboard_refresh(context: ModbusServerContext) -> None:
    log.info("Dashboard refresh loop started (controller-driven mode)")
    while True:
        await asyncio.sleep(3)
        try:
            _push_registers(context)
            last_write = _wg.shared_state.get("last_write_time", 0.0)
            if last_write == 0.0:
                _wg.socketio.emit("comms_status", {"lost": True, "seconds": None})
            else:
                elapsed = time.time() - last_write
                _wg.socketio.emit("comms_status", {
                    "lost": elapsed > _COMMS_TIMEOUT,
                    "seconds": int(elapsed),
                })
        except Exception as exc:
            log.warning("Dashboard refresh error: %s", exc)


# ---------------------------------------------------------------------------
# Custom request logger
# ---------------------------------------------------------------------------
class LoggingRequestHandler:
    """Wraps pymodbus request processing to log each request to shared_state."""

    def __init__(self, context):
        self.context = context

    def __call__(self, request, *args, **kwargs):
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
            if fc in _WRITE_FCS:
                _wg.shared_state["last_write_time"] = time.time()

        _wg.socketio.emit("request_log", {"entry": entry})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main() -> None:
    context = build_server_context()

    _push_registers(context)
    with _wg.state_lock:
        _wg.shared_state["register_names"] = {
            str(k): v for k, v in REGISTER_NAMES.items() if k in UNIT_IDS
        }

    log.info("Starting Modbus TCP server on %s:%d", HOST, PORT)
    log.info("Starting web dashboard on port %d", WEB_PORT)

    asyncio.create_task(dashboard_refresh(context))

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
