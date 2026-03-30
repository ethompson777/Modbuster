#!/usr/bin/env python3
"""
controller.py — Cruise Ship Automation Controller Simulator (Royal Caribbean Scale)

Modbus TCP master that:
  - Continuously polls the field device (all 8 unit IDs)
  - Periodically writes control register values (8 rotating scenarios)
  - Exposes a Flask web dashboard (port 8080) for:
      * Viewing live poll results across all subsystems
      * Sending manual read/write commands to any unit

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
FIELD_DEVICE_2_HOST = os.environ.get("FIELD_DEVICE_2_HOST", "172.20.0.21")
FIELD_DEVICE_2_PORT = int(os.environ.get("FIELD_DEVICE_2_PORT", 502))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", 5))
WEB_PORT = int(os.environ.get("WEB_PORT", 8080))

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
    4: {0:"Generator 1 (kW)",1:"Generator 2 (kW)",2:"Generator 3 (kW)",3:"Generator 4 (kW)",
        4:"Bus A Voltage",5:"Bus B Voltage",6:"Grid Frequency",7:"Total Load (kW)",
        8:"Shore Power",9:"Emergency Gen"},
    5: {0:"Deck 3 Zone Temp",1:"Deck 7 Zone Temp",2:"Deck 12 Zone Temp",3:"Engine Room Temp",
        4:"Chilled Water Supply",5:"Chilled Water Return",6:"AHU 1 Status",7:"AHU 2 Status",
        8:"Chiller 1 Status",9:"Outside Air Temp"},
    6: {0:"Fire Zone 1 (Cargo)",1:"Fire Zone 2 (Engine)",2:"Fire Zone 3 (Crew)",3:"Fire Zone 4 (Pax)",
        4:"CO2 Bank 1",5:"CO2 Bank 2",6:"General Alarm",7:"Bilge Pump Port",
        8:"Bilge Pump Stbd",9:"Smoke Detector Count"},
    7: {0:"HFO Port Wing",1:"HFO Stbd Wing",2:"MGO Port Tank",3:"MGO Stbd Tank",
        4:"HFO Day Tank",5:"MGO Day Tank",6:"HFO Flow Rate",7:"MGO Flow Rate",
        8:"Fuel Mode",9:"Total Fuel Remaining"},
    8: {0:"Port Fin Angle",1:"Stbd Fin Angle",2:"Port Fin Status",3:"Stbd Fin Status",
        4:"Roll Angle",5:"Pitch Angle",6:"Vertical Accel",7:"Stabilizer Mode",
        8:"Port Fin Hyd Press",9:"Stbd Fin Hyd Press"},
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


async def poll_cycle_fd1(client: AsyncModbusTcpClient) -> None:
    """Poll units 1-4 on Field Device 1."""
    await poll_unit(client, 1, 0, 10, "propulsion")
    await asyncio.sleep(0.1)
    await poll_unit(client, 2, 0, 10, "navigation")
    await asyncio.sleep(0.1)
    await poll_unit(client, 3, 0, 10, "ballast")
    await asyncio.sleep(0.1)
    await poll_unit(client, 4, 0, 10, "power")
    await asyncio.sleep(0.1)
    # Targeted critical reads
    await poll_unit(client, 1, 0, 1, "port-engine-RPM")
    await asyncio.sleep(0.05)
    await poll_unit(client, 2, 0, 1, "rudder-angle")
    await asyncio.sleep(0.05)
    await poll_unit(client, 4, 7, 1, "total-load")


async def poll_cycle_fd2(client: AsyncModbusTcpClient) -> None:
    """Poll units 5-8 on Field Device 2."""
    await poll_unit(client, 5, 0, 10, "hvac")
    await asyncio.sleep(0.1)
    await poll_unit(client, 6, 0, 10, "fire-safety")
    await asyncio.sleep(0.1)
    await poll_unit(client, 7, 0, 10, "fuel")
    await asyncio.sleep(0.1)
    await poll_unit(client, 8, 0, 10, "stabilizers")
    await asyncio.sleep(0.1)
    # Targeted critical read
    await poll_unit(client, 6, 6, 1, "general-alarm")


# ---------------------------------------------------------------------------
# Write cycle — persistent setpoints written every scan cycle (realistic PLC)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Process simulation — realistic sensor values written to field devices
# ---------------------------------------------------------------------------

# Operator setpoints (web GUI can override key ones)
# Scales match REGISTER_SCALE in field_device.py (what the dashboards expect)
_SP_DEFAULTS = {
    (1, 0): 105,   # port engine RPM (direct = 105 RPM cruise, max 144 RPM)
    (1, 1): 105,   # stbd engine RPM
    (1, 6): 0,     # bow thruster %×10
    (2, 0): 180,   # rudder (180 = amidships)
    (3, 0): 500,   (3, 1): 500,   # fore/aft ballast (÷10 = 50.0%)
    (4, 0): 14000, (4, 1): 14000, (4, 2): 12000,  # gen kW (Wärtsilä 16V46C/12V46C)
    (5, 0): 220,   # deck 3 zone temp (÷10 = 22.0°C)
    (7, 8): 0,     # fuel mode (0=HFO)
    (8, 7): 1,     # stabilizer mode (1=Auto)
}

# Full process state — every register on every unit.
# All scales match REGISTER_SCALE formatters in field_device.py.
_PROC: dict = {
    # Unit 1 – Main Propulsion
    # Engine RPM direct (raw = RPM): cruise 105 RPM, max 144 RPM
    (1,0):105,  (1,1):105,    # engine RPM direct → 105 RPM
    # Fuel flow ÷10 L/hr: Wärtsilä 46C ~200 g/kWh × 10,000 kW ÷ 0.97 kg/L ≈ 2,060 L/hr/engine
    (1,2):20600,(1,3):20600,  # fuel flow (÷10 → 2060.0 L/hr per engine)
    (1,4):142,  (1,5):142,    # coolant temp (v-50 → 92°C at cruise load)
    (1,6):0,    (1,7):0,      # bow/stern thruster (÷10 → 0.0%)
    (1,8):102,  (1,9):102,    # shaft RPM direct → 102 RPM (engine × 0.975)
    # Unit 2 – Navigation/Bridge
    (2,0):180,                 # rudder angle (180 = amidships)
    (2,1):192,                 # speed OG (÷10 → 19.2 kn at cruise)
    (2,2):2700,                # heading true (÷10 → 270.0°T)
    (2,3):1800,                # rate of turn (v-1800 → 0 °/min)
    (2,4):142,                 # wind speed (÷10 → 14.2 kn)
    (2,5):45,                  # wind direction (°)
    (2,6):25,                  # GPS lat degrees
    (2,7):2341,                # GPS lat min×100 (÷100 → 23.41')
    (2,8):80,                  # GPS lon degrees
    (2,9):1247,                # GPS lon min×100 (÷100 → 12.47')
    # Unit 3 – Ballast/Safety
    (3,0):500,  (3,1):500,    # fore/aft ballast (÷10 → 50.0%)
    (3,2):500,  (3,3):500,    # port/stbd ballast (÷10 → 50.0%)
    (3,4):0,                   # flood alarm
    (3,5):0,    (3,6):0,      # fire suppress Z1/Z2
    (3,7):0,    (3,8):0,      # bilge port/stbd
    (3,9):0,                   # general alarm
    # Unit 4 – Power Management
    # Generators: Wärtsilä 16V46C = 16,800 kW, 12V46C = 12,600 kW
    # Running 3 of 4 at cruise; gen 4 on hot standby
    (4,0):14000,(4,1):14000,  # gen 1/2 kW (16V46C-class, ~83% load)
    (4,2):12000,(4,3):0,      # gen 3 kW (12V46C-class), gen 4 standby
    (4,4):6600, (4,5):6600,   # bus A/B voltage (6.6 kV HV bus)
    (4,6):600,                 # grid freq (÷10 → 60.0 Hz)
    (4,7):40000,               # total load kW (~40 MW: propulsion + hotel)
    (4,8):0,    (4,9):0,      # shore power / emergency gen
    # Unit 5 – HVAC/Environmental  (all ÷10 °C)
    (5,0):220,  (5,1):230,    # deck 3/7 zone temp (÷10 → 22.0/23.0°C)
    (5,2):210,  (5,3):450,    # deck 12 / engine room (÷10 → 21.0/45.0°C)
    (5,4):80,   (5,5):140,    # chilled water supply/return (÷10 → 8.0/14.0°C)
    (5,6):1,    (5,7):1,      # AHU 1/2 status
    (5,8):1,                   # chiller 1 status
    (5,9):280,                 # outside air temp (÷10 → 28.0°C)
    # Unit 6 – Fire Safety
    (6,0):0,  (6,1):0,  (6,2):0,  (6,3):0,   # fire zones 1-4 (0=Normal)
    (6,4):1,  (6,5):1,           # CO2 bank 1/2 (1=Armed)
    (6,6):0,                   # general alarm
    (6,7):0,   (6,8):0,       # bilge pump port/stbd
    (6,9):0,                   # smoke detector count
    # Unit 7 – Fuel Management
    (7,0):750,  (7,1):750,    # HFO port/stbd wing tank (÷10 → 75.0%)
    (7,2):500,  (7,3):500,    # MGO port/stbd tank (÷10 → 50.0%)
    (7,4):950,  (7,5):900,    # HFO/MGO day tank (÷10 → 95.0/90.0%)
    # HFO flow: ~300 t/day cruise = 12,500 kg/hr ÷ 0.97 kg/L ≈ 12,900 L/hr ship-wide
    (7,6):13000,(7,7):0,      # HFO/MGO flow rate (L/hr direct)
    (7,8):0,                   # fuel mode (0=HFO)
    # Total fuel: Oasis-class ~3,500 t HFO capacity; at sea mid-voyage ~3,000 t
    (7,9):30000,               # total fuel remaining (÷10 → 3000.0 t)
    # Unit 8 – Stabilizer/Motion
    (8,0):300,  (8,1):300,    # port/stbd fin angle ((v-300)÷10 → 0.0°)
    (8,2):2,    (8,3):2,      # port/stbd fin status (2=Active)
    (8,4):150,  (8,5):100,    # roll/pitch angle ((v-150)÷10 / (v-100)÷10 → 0.0°)
    (8,6):980,                 # vertical accel (÷100 → 9.80 m/s²)
    (8,7):1,                   # stabilizer mode (1=Auto)
    (8,8):1300, (8,9):1300,   # port/stbd fin hydraulic pressure (÷10 → 130.0 bar)
}


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


def _u16(v: int) -> int:
    """Convert a signed int16 to unsigned uint16 for Modbus wire encoding."""
    return v & 0xFFFF


def _noise(current: int, target: int, step: int, lo: int, hi: int) -> int:
    """Nudge current toward target with random noise, clamped to [lo, hi]."""
    delta = random.randint(-step, step)
    if current < target - step:
        delta += step
    elif current > target + step:
        delta -= step
    return _clamp(current + delta, lo, hi)


def _simulate_process() -> None:
    """Update all process values with realistic sensor noise and physical relationships.
    All scales match REGISTER_SCALE formatters in field_device.py."""
    p = _PROC
    sp = _wg.shared_state["setpoints"]

    with _wg.state_lock:
        # ── Unit 1: Propulsion ────────────────────────────────────────────────
        # RPM direct (raw = RPM): Stop(0) → Full Ahead (144 RPM)
        rpm_sp = sp.get((1, 0), 105)
        p[(1,0)] = _clamp(rpm_sp + random.randint(-1, 1), 0, 144)
        p[(1,1)] = _clamp(sp.get((1,1), rpm_sp) + random.randint(-1, 1), 0, 144)
        rpm_avg  = (p[(1,0)] + p[(1,1)]) / 2   # raw = RPM (~105 at cruise)

        # Fuel flow ÷10 L/hr — Wärtsilä 46C: ~200 g/kWh × load ÷ 0.97 kg/L
        # At cruise 105 RPM: 105 × 196 = 20580 → 2058 L/hr/engine ✓
        fuel_target = int(rpm_avg * 196)
        p[(1,2)] = _noise(p[(1,2)], fuel_target, 200, 0, 30000)
        p[(1,3)] = _noise(p[(1,3)], fuel_target, 200, 0, 30000)

        # Coolant temp: stored as (actual_°C + 50); ranges 65°C idle → 95°C full load
        # At cruise 105 RPM: 110 + 105×0.31 = 143 → 93°C ✓
        coolant_target = _clamp(110 + int(rpm_avg * 0.31), 110, 148)
        p[(1,4)] = _noise(p[(1,4)], coolant_target, 3, 110, 146)
        p[(1,5)] = _noise(p[(1,5)], coolant_target, 3, 110, 146)

        # Shaft RPM direct (raw = RPM) — each shaft tracks its own engine (~2.5% slip)
        p[(1,8)] = _clamp(int(p[(1,0)] * 0.975) + random.randint(-1, 1), 0, 144)
        p[(1,9)] = _clamp(int(p[(1,1)] * 0.975) + random.randint(-1, 1), 0, 144)

        # Thrusters follow setpoint (÷10 %)
        p[(1,6)] = sp.get((1,6), 0)
        p[(1,7)] = sp.get((1,7), 0)

        # ── Unit 2: Navigation ────────────────────────────────────────────────
        # Rudder: snap directly to operator setpoint with minimal noise
        rudder_sp = sp.get((2,0), 180)
        p[(2,0)] = _clamp(rudder_sp + random.randint(-1, 1), 145, 215)

        # Speed OG ÷10 kn — follows engine RPM (cap at 22.6 kn = 226 raw)
        # 105 RPM × 1.83 = 192 → 19.2 kn cruise; 144 × 1.83 = 264 → cap 226 = 22.6 kn
        speed_target = min(int(rpm_avg * 1.83), 226)
        p[(2,1)] = _noise(p[(2,1)], speed_target, 2, 0, 230)

        # Heading ÷10 degrees — autopilot holds with tiny wander
        p[(2,2)] = (p[(2,2)] + random.randint(-1, 1)) % 3600

        # Rate of turn: 1800 = 0 °/min; proportional to rudder deflection
        rot_target = _clamp(1800 + int((p[(2,0)] - 180) * 0.6), 1750, 1850)
        p[(2,3)] = _noise(p[(2,3)], rot_target, 2, 1740, 1860)

        # Wind: slow random walk
        p[(2,4)] = _noise(p[(2,4)], p[(2,4)], 4, 40, 350)
        p[(2,5)] = (p[(2,5)] + random.randint(-3, 3)) % 360

        # GPS: advance lon minutes very slowly
        if random.random() < 0.08:
            p[(2,9)] = (p[(2,9)] + 1) % 6000

        # ── Unit 3: Ballast/Safety ────────────────────────────────────────────
        # ÷10 % display (500 = 50.0%)
        for addr in range(4):
            p[(3, addr)] = _noise(p[(3, addr)], sp.get((3, addr), 500), 1, 460, 540)
        # Alarm registers stay 0

        # ── Unit 4: Power Management ──────────────────────────────────────────
        # Generators: Wärtsilä 16V46C max 16,800 kW; 12V46C max 12,600 kW
        p[(4,0)] = _noise(p[(4,0)], sp.get((4,0), 14000), 100, 8000, 16800)
        p[(4,1)] = _noise(p[(4,1)], sp.get((4,1), 14000), 100, 8000, 16800)
        p[(4,2)] = _noise(p[(4,2)], sp.get((4,2), 12000), 100, 6000, 12600)
        # Gen 4 stays on standby (0)

        # Bus voltage: very stable ±5 V on 6600 V bus
        p[(4,4)] = _noise(p[(4,4)], 6600, 5, 6570, 6630)
        p[(4,5)] = _noise(p[(4,5)], 6600, 5, 6570, 6630)

        # Grid frequency ÷10 Hz (600 = 60.0 Hz), very tight regulation
        p[(4,6)] = _noise(p[(4,6)], 600, 1, 597, 603)

        # Total load = running generators
        p[(4,7)] = p[(4,0)] + p[(4,1)] + p[(4,2)]

        # ── Unit 5: HVAC (all ÷10 °C) ────────────────────────────────────────
        p[(5,0)] = _noise(p[(5,0)], sp.get((5,0), 220), 2, 190, 260)  # deck 3
        p[(5,1)] = _noise(p[(5,1)], 230, 2, 200, 270)                  # deck 7
        p[(5,2)] = _noise(p[(5,2)], 210, 2, 180, 250)                  # deck 12

        # Engine room temp tracks engine load (÷10 → 43-48°C range)
        # At 105 RPM: 430 + (105-70)×0.6 = 451 → 45.1°C ✓
        er_target = 430 + int((rpm_avg - 70) * 0.6)
        p[(5,3)] = _noise(p[(5,3)], er_target, 3, 400, 520)

        p[(5,4)] = _noise(p[(5,4)],  80, 2,  60, 100)  # chilled water supply
        p[(5,5)] = _noise(p[(5,5)], 140, 2, 110, 170)  # chilled water return
        p[(5,9)] = _noise(p[(5,9)], 280, 2, 220, 340)  # outside air temp

        # ── Unit 6: Fire Safety ───────────────────────────────────────────────
        # CO2 banks stay Armed (1); all other alarms stay 0
        p[(6,4)] = 1
        p[(6,5)] = 1

        # ── Unit 7: Fuel Management ───────────────────────────────────────────
        # HFO flow rate (direct L/hr, no ÷10): total ship fuel consumption
        # ~300 t/day cruise = 12,500 kg/hr ÷ 0.97 kg/L ≈ 12,900 L/hr
        # Scales with total generator load (power ∝ fuel consumption)
        hfo_flow_target = int((p[(4,0)] + p[(4,1)] + p[(4,2)]) * 0.325)
        p[(7,6)] = _noise(p[(7,6)], hfo_flow_target, 100, 5000, 21000)
        p[(7,7)] = _noise(p[(7,7)], 0, 2, 0, 50)        # MGO flow: 0 on HFO mode

        # Wing tanks ÷10 % — drain 1 unit every ~10 cycles (realistic slow depletion)
        if random.random() < 0.1:
            p[(7,0)] = max(100, p[(7,0)] - 1)
            p[(7,1)] = max(100, p[(7,1)] - 1)

        # Day tanks ÷10 % — auto-refill keeps ~90-95%; small drift
        p[(7,4)] = _noise(p[(7,4)], 950, 2, 850, 1000)  # HFO day tank
        p[(7,5)] = _noise(p[(7,5)], 900, 2, 800, 970)   # MGO day tank

        # Total fuel ÷10 tonnes — derived from wing + MGO tanks
        p[(7,9)] = (p[(7,0)] + p[(7,1)]) * 8 + (p[(7,2)] + p[(7,3)]) * 2

        # ── Unit 8: Stabilizer/Motion ─────────────────────────────────────────
        # Roll: stored as (v-150)÷10 °, so 150=0°, 162=+1.2°, 138=-1.2°
        roll_disturb = 150 + random.randint(-12, 12)
        p[(8,4)] = _noise(p[(8,4)], roll_disturb, 3, 120, 180)

        # Pitch: stored as (v-100)÷10 °, 100=0°, slight bow-up = 103
        p[(8,5)] = _noise(p[(8,5)], 103, 2, 95, 110)

        # Vertical accel ÷100 m/s² (980 = 9.80 m/s² ≈ 1g)
        p[(8,6)] = _noise(p[(8,6)], 980, 5, 950, 1010)

        # Active fins counter roll: fin angle = 300 + correction×10
        roll_offset = p[(8,4)] - 150   # signed degrees×10 from neutral
        fin_cmd = _clamp(300 - int(roll_offset * 1.3), 240, 360)
        p[(8,0)] = _noise(p[(8,0)], fin_cmd,          3, 240, 360)
        p[(8,1)] = _noise(p[(8,1)], 600 - fin_cmd,    3, 240, 360)  # opposite side

        # Hydraulic pressure ÷10 bar — slight variation with fin effort
        fin_effort = abs(p[(8,0)] - 300) + abs(p[(8,1)] - 300)
        hyd_target = 1300 + int(fin_effort * 0.5)
        p[(8,8)] = _noise(p[(8,8)], hyd_target, 5, 1200, 1450)
        p[(8,9)] = _noise(p[(8,9)], hyd_target, 5, 1200, 1450)


def _sp() -> dict:
    return _wg.shared_state["setpoints"]


async def write_cycle_fd1(client: AsyncModbusTcpClient) -> None:
    """Write all simulated process values for units 1-4 to Field Device 1."""
    p = _PROC
    try:
        for unit in (1, 2, 3, 4):
            vals = [_u16(p[(unit, a)]) for a in range(10)]
            await client.write_registers(0, vals, device_id=unit)
            _log_write(unit, 0, vals, REGISTER_NAMES[unit][0].split()[0] + " (all regs)")
            await asyncio.sleep(0.05)
    except ModbusException as exc:
        log.error("[WRITE FD1] Modbus error: %s", exc)
    except Exception as exc:
        log.error("[WRITE FD1] Error: %s", exc)


async def write_cycle_fd2(client: AsyncModbusTcpClient) -> None:
    """Write all simulated process values for units 5-8 to Field Device 2."""
    p = _PROC
    try:
        for unit in (5, 6, 7, 8):
            vals = [_u16(p[(unit, a)]) for a in range(10)]
            await client.write_registers(0, vals, device_id=unit)
            _log_write(unit, 0, vals, REGISTER_NAMES[unit][0].split()[0] + " (all regs)")
            await asyncio.sleep(0.05)
    except ModbusException as exc:
        log.error("[WRITE FD2] Modbus error: %s", exc)
    except Exception as exc:
        log.error("[WRITE FD2] Error: %s", exc)


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
    with _wg.state_lock:
        for unit in range(1, 9):
            _wg.shared_state["registers"][unit] = {i: 0 for i in range(10)}
        _wg.shared_state["register_names"] = {str(k): v for k, v in REGISTER_NAMES.items()}
        _wg.shared_state["setpoints"].update(_SP_DEFAULTS)
    # Seed process state from setpoints so operator overrides take immediate effect
    for k, v in _SP_DEFAULTS.items():
        _PROC[k] = v

    log.info("Controller starting → FD1 %s:%d  FD2 %s:%d",
             FIELD_DEVICE_HOST, FIELD_DEVICE_PORT,
             FIELD_DEVICE_2_HOST, FIELD_DEVICE_2_PORT)
    log.info("Poll/Write: %.1fs | Web dashboard: port %d", POLL_INTERVAL, WEB_PORT)

    web_thread = threading.Thread(
        target=_wg.run_web,
        args=(WEB_PORT,),
        daemon=True,
    )
    web_thread.start()

    client1 = AsyncModbusTcpClient(
        host=FIELD_DEVICE_HOST,
        port=FIELD_DEVICE_PORT,
        timeout=2,
        retries=0,
    )
    client2 = AsyncModbusTcpClient(
        host=FIELD_DEVICE_2_HOST,
        port=FIELD_DEVICE_2_PORT,
        timeout=2,
        retries=0,
    )
    await client1.connect()
    await client2.connect()
    if not client1.connected:
        log.error("Could not connect to FD1 at %s:%d", FIELD_DEVICE_HOST, FIELD_DEVICE_PORT)
        sys.exit(1)
    if not client2.connected:
        log.warning("Could not connect to FD2 at %s:%d — will retry each cycle", FIELD_DEVICE_2_HOST, FIELD_DEVICE_2_PORT)

    log.info("Connected to field devices")
    poll_count = 0

    try:
        while True:
            loop_start = asyncio.get_event_loop().time()

            # Attempt reconnection if disconnected (fails fast with timeout=2)
            if not client1.connected:
                log.warning("Reconnecting FD1...")
                await client1.connect()
            if not client2.connected:
                log.warning("Reconnecting FD2...")
                await client2.connect()

            poll_count += 1
            log.info("--- Poll #%d ---", poll_count)
            _simulate_process()

            # Always emit fd_info so dashboard stays live regardless of FD reachability
            kali_mac = _wg._arp_mac("172.20.0.30")
            fd_info = [
                {
                    "label": "FD1", "ip": FIELD_DEVICE_HOST, "port": FIELD_DEVICE_PORT,
                    "units": "1–4", "connected": client1.connected,
                    "mac": _wg._arp_mac(FIELD_DEVICE_HOST),
                },
                {
                    "label": "FD2", "ip": FIELD_DEVICE_2_HOST, "port": FIELD_DEVICE_2_PORT,
                    "units": "5–8", "connected": client2.connected,
                    "mac": _wg._arp_mac(FIELD_DEVICE_2_HOST),
                },
            ]
            with _wg.state_lock:
                _wg.shared_state["fd_info"] = fd_info
            _wg.socketio.emit("fd_info", {"devices": fd_info, "kali_mac": kali_mac})

            # Poll and write — capped at 8s total each so a hung FD can't stall the loop
            if client1.connected:
                try:
                    await asyncio.wait_for(poll_cycle_fd1(client1), timeout=8.0)
                except asyncio.TimeoutError:
                    log.warning("FD1 poll cycle timed out")
                try:
                    await asyncio.wait_for(write_cycle_fd1(client1), timeout=8.0)
                except asyncio.TimeoutError:
                    log.warning("FD1 write cycle timed out")

            if client2.connected:
                try:
                    await asyncio.wait_for(poll_cycle_fd2(client2), timeout=8.0)
                except asyncio.TimeoutError:
                    log.warning("FD2 poll cycle timed out")
                try:
                    await asyncio.wait_for(write_cycle_fd2(client2), timeout=8.0)
                except asyncio.TimeoutError:
                    log.warning("FD2 write cycle timed out")

            elapsed = asyncio.get_event_loop().time() - loop_start
            await asyncio.sleep(max(0.1, POLL_INTERVAL - elapsed))

    except asyncio.CancelledError:
        pass
    finally:
        await client1.close()
        await client2.close()
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
