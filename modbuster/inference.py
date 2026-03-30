"""
Register inference engine — classifies unknown Modbus registers from
observed traffic patterns without a pre-existing register map.

Designed to run fully offline with no external lookups.
"""

import json
import math
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

MAX_HISTORY = 500

# Confidence
HIGH   = "HIGH"
MEDIUM = "MED"
LOW    = "LOW"

# Register types
T_BINARY      = "Binary On/Off"
T_ALARM       = "Alarm / Event"
T_STATE       = "State / Mode"
T_SETPOINT    = "Setpoint / Cmd"
T_WRITEONLY   = "Write-Only Cmd"
T_PERCENTAGE  = "Percentage %"
T_TEMPERATURE = "Temperature"
T_RPM         = "RPM / Speed"
T_FLOW        = "Flow Rate"
T_PRESSURE    = "Pressure / Level"
T_ELECTRICAL  = "Electrical"
T_FREQUENCY   = "Frequency"
T_VOLTAGE     = "Voltage"
T_POWER       = "Power (kW)"
T_COUNTER     = "Counter / Total"
T_POSITION    = "Position / Angle"
T_SENSOR      = "Analog Sensor"
T_UNKNOWN     = "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Observation tracker
# ─────────────────────────────────────────────────────────────────────────────

class RegisterObs:
    def __init__(self, ip: str, unit_id: int, addr: int) -> None:
        self.ip      = ip
        self.unit_id = unit_id
        self.addr    = addr
        self.read_values:  List[int]   = []
        self.read_times:   List[float] = []  # epoch timestamp per read_values entry
        self.write_values: List[int] = []
        self.read_count  = 0
        self.write_count = 0
        self.first_seen  = time.time()
        self.last_seen   = time.time()
        self._prev: Optional[int] = None
        self._change_times: List[float] = []

    def observe_read(self, value: int) -> None:
        self.read_count += 1
        now = time.time()
        self.last_seen = now
        if len(self.read_values) >= MAX_HISTORY:
            self.read_values.pop(0)
            self.read_times.pop(0)
        self.read_values.append(value)
        self.read_times.append(now)
        if self._prev is not None and value != self._prev:
            self._change_times.append(time.time())
            if len(self._change_times) > 100:
                self._change_times.pop(0)
        self._prev = value

    def observe_write(self, value: int) -> None:
        self.write_count += 1
        self.last_seen = time.time()
        if len(self.write_values) >= 100:
            self.write_values.pop(0)
        self.write_values.append(value)

    # ── stats ──────────────────────────────────────────────────────────────

    @property
    def all_values(self) -> List[int]:
        return self.read_values + self.write_values

    @property
    def samples(self) -> int:
        return len(self.all_values)

    @property
    def distinct(self) -> Set[int]:
        return set(self.all_values)

    @property
    def mn(self) -> Optional[int]:
        v = self.all_values; return min(v) if v else None

    @property
    def mx(self) -> Optional[int]:
        v = self.all_values; return max(v) if v else None

    @property
    def mean(self) -> Optional[float]:
        v = self.all_values
        return sum(v) / len(v) if v else None

    @property
    def std(self) -> Optional[float]:
        v = self.all_values
        if len(v) < 2: return None
        m = sum(v) / len(v)
        return math.sqrt(sum((x - m) ** 2 for x in v) / len(v))

    @property
    def changes_per_min(self) -> float:
        t = self._change_times
        if len(t) < 2: return 0.0
        e = t[-1] - t[0]
        return (len(t) - 1) / (e / 60) if e > 0 else 0.0

    @property
    def write_ratio(self) -> float:
        total = self.read_count + self.write_count
        return self.write_count / total if total else 0.0

    @property
    def is_monotonic(self) -> bool:
        v = self.read_values
        if len(v) < 6: return False
        rises = sum(1 for i in range(1, len(v)) if v[i] > v[i - 1])
        return rises > len(v) * 0.85

    @property
    def value_range(self) -> Optional[int]:
        if self.mn is None or self.mx is None: return None
        return self.mx - self.mn

    def recent_delta(self, n: int = 10) -> float:
        """Average absolute change between consecutive recent readings."""
        v = self.read_values[-n:]
        if len(v) < 2: return 0.0
        return sum(abs(v[i] - v[i-1]) for i in range(1, len(v))) / (len(v) - 1)

    def is_stable(self) -> bool:
        std = self.std
        return std is not None and std < 2.0 and self.read_count >= 5

    def oscillates_around(self, center: float, tolerance: float) -> bool:
        """Values bounce around a center with some crosses above and below."""
        v = self.read_values
        if len(v) < 4: return False
        above = sum(1 for x in v if x > center + tolerance)
        below = sum(1 for x in v if x < center - tolerance)
        return above >= 1 and below >= 1

    def steps_to_fixed_values(self) -> bool:
        """Values jump between a small number of discrete levels."""
        v = self.read_values
        if len(v) < 8: return False
        d = self.distinct
        if len(d) < 2 or len(d) > 5: return False
        return all(x in d for x in v)

    def last_n(self, n: int = 5) -> List[int]:
        return self.read_values[-n:] if self.read_values else []


# ─────────────────────────────────────────────────────────────────────────────
# Inference engine
# ─────────────────────────────────────────────────────────────────────────────

class InferenceEngine:
    def __init__(self) -> None:
        self._obs: Dict[Tuple[str, int, int], RegisterObs] = {}
        self._pending: Dict[Tuple[str, int], Tuple[int, int]] = {}  # (ip, unit) → (start_addr, count)

    def reset(self) -> None:
        self._obs.clear()
        self._pending.clear()

    def save_session(self, path: Union[str, Path]) -> int:
        """Serialize all register observations to JSON. Returns number of registers saved."""
        records = []
        for obs in self._obs.values():
            records.append({
                "ip":           obs.ip,
                "unit_id":      obs.unit_id,
                "addr":         obs.addr,
                "read_values":  obs.read_values,
                "read_times":   obs.read_times,
                "write_values": obs.write_values,
                "read_count":   obs.read_count,
                "write_count":  obs.write_count,
                "first_seen":   obs.first_seen,
                "last_seen":    obs.last_seen,
                "change_times": obs._change_times,
                "prev":         obs._prev,
            })
        with open(path, "w") as f:
            json.dump({"version": 1, "saved_at": time.time(), "registers": records}, f)
        return len(records)

    def load_session(self, path: Union[str, Path], merge: bool = False) -> int:
        """Load register observations from JSON. merge=False clears existing data first.
        Returns number of registers loaded."""
        with open(path) as f:
            data = json.load(f)
        if not merge:
            self.reset()
        records = data.get("registers", [])
        for rec in records:
            ip      = rec["ip"]
            unit_id = rec["unit_id"]
            addr    = rec["addr"]
            obs = self._get(ip, unit_id, addr)
            obs.read_values  = rec.get("read_values", [])
            obs.read_times   = rec.get("read_times", [])
            obs.write_values = rec.get("write_values", [])
            obs.read_count   = rec.get("read_count", len(obs.read_values))
            obs.write_count  = rec.get("write_count", len(obs.write_values))
            obs.first_seen   = rec.get("first_seen", time.time())
            obs.last_seen    = rec.get("last_seen", time.time())
            obs._change_times = rec.get("change_times", [])
            obs._prev        = rec.get("prev")
        return len(records)

    def get_history(self, ip: str, unit_id: int, addr: int) -> Tuple[List[float], List[int]]:
        """Return (timestamps, values) for the given register. Both lists are copies."""
        obs = self._obs.get((ip, unit_id, addr))
        if obs is None:
            return [], []
        return list(obs.read_times), list(obs.read_values)

    def feed(self, parsed: Dict[str, Any]) -> bool:
        if not parsed: return False
        direction = parsed.get("direction", "")
        unit_id   = int(parsed.get("unit_id") or 0)
        fc        = parsed.get("func_code")

        # Derive the field-device IP: dst for requests, src for responses
        src_ip = parsed.get("_src_ip", "")
        dst_ip = parsed.get("_dst_ip", "")
        ip = dst_ip if direction == "request" else src_ip

        if direction == "request":
            sa  = parsed.get("start_addr")
            qty = parsed.get("quantity")
            wa  = parsed.get("address")
            val = parsed.get("value")
            vs  = parsed.get("values") or []

            # FC3: Read Holding Registers — store pending to match against response
            if fc == 3 and sa is not None and qty:
                self._pending[(ip, unit_id)] = (int(sa), int(qty))
            # FC4: Read Input Registers — same pattern as FC3
            elif fc == 4 and sa is not None and qty:
                self._pending[(ip, unit_id)] = (int(sa), int(qty))
            # FC1: Read Coils — track pending so response values are recorded
            elif fc == 1 and sa is not None and qty:
                self._pending[(ip, unit_id)] = (int(sa), int(qty))
            # FC2: Read Discrete Inputs
            elif fc == 2 and sa is not None and qty:
                self._pending[(ip, unit_id)] = (int(sa), int(qty))
            # FC5: Write Single Coil
            elif fc == 5 and wa is not None and val is not None:
                self._get(ip, unit_id, int(wa)).observe_write(int(val))
                return True
            # FC6: Write Single Register
            elif fc == 6 and wa is not None and val is not None:
                self._get(ip, unit_id, int(wa)).observe_write(int(val))
                return True
            # FC15: Write Multiple Coils
            elif fc == 15 and sa is not None and vs:
                for i, v in enumerate(vs):
                    self._get(ip, unit_id, int(sa) + i).observe_write(int(v))
                return True
            # FC16: Write Multiple Registers
            elif fc == 16 and sa is not None and vs:
                for i, v in enumerate(vs):
                    self._get(ip, unit_id, int(sa) + i).observe_write(int(v))
                return True
            # FC23: Read/Write Multiple Registers — record writes from request,
            #        reads will be resolved when the response arrives
            elif fc == 23:
                if sa is not None and qty:  # read part
                    self._pending[(ip, unit_id)] = (int(sa), int(qty))
                if wa is not None and vs:   # write part (writeStartingAddr → address)
                    for i, v in enumerate(vs):
                        self._get(ip, unit_id, int(wa) + i).observe_write(int(v))
                return True

        elif direction == "response":
            vs = parsed.get("values") or []
            # FC3/FC4: Read Holding/Input Registers — resolve pending read
            if fc in (3, 4) and vs:
                p = self._pending.get((ip, unit_id))
                if p:
                    sa, qty = p
                    for i, v in enumerate(vs[:qty]):
                        self._get(ip, unit_id, sa + i).observe_read(int(v))
                    return True
            # FC1/FC2: Read Coils/Discrete Inputs — resolve pending read
            elif fc in (1, 2) and vs:
                p = self._pending.get((ip, unit_id))
                if p:
                    sa, qty = p
                    for i, v in enumerate(vs[:qty]):
                        self._get(ip, unit_id, sa + i).observe_read(int(v))
                    return True
            # FC23: Read/Write Multiple — read response contains register values
            elif fc == 23 and vs:
                p = self._pending.get((ip, unit_id))
                if p:
                    sa, qty = p
                    for i, v in enumerate(vs[:qty]):
                        self._get(ip, unit_id, sa + i).observe_read(int(v))
                    return True

        return False

    def _get(self, ip: str, unit_id: int, addr: int) -> RegisterObs:
        key = (ip, unit_id, addr)
        if key not in self._obs:
            self._obs[key] = RegisterObs(ip, unit_id, addr)
        return self._obs[key]

    # ── Public interface ───────────────────────────────────────────────────

    def classify_all(self) -> List[Dict[str, Any]]:
        results = {k: self._classify(obs) for k, obs in self._obs.items()}
        self._cross_analyze(results)
        return sorted(results.values(), key=lambda r: (r["ip"], r["unit_id"], r["addr"]))

    # ── Single-register classification ────────────────────────────────────

    def _classify(self, obs: RegisterObs) -> Dict[str, Any]:
        v = obs.all_values
        if not v:
            return self._result(obs, T_UNKNOWN, LOW, "No data yet")

        d    = obs.distinct
        n    = len(d)
        mn   = obs.mn
        mx   = obs.mx
        mean = obs.mean or 0.0
        std  = obs.std  or 0.0
        rng  = obs.value_range or 0

        # ── Write-access note (appended to every type-specific result) ────────
        # Surfacing write access is critical for pentest — it flags attack vectors
        # regardless of what physical type the register is.
        _wn = ""
        if obs.write_count > 0:
            wv = sorted(set(obs.write_values))[:8]
            if obs.write_ratio > 0.25:
                wr_desc = f"HIGH write traffic ({obs.write_ratio:.0%} W:R)"
            elif obs.write_ratio > 0.05:
                wr_desc = f"moderate write traffic ({obs.write_ratio:.0%} W:R)"
            else:
                wr_desc = f"occasional writes ({obs.write_count} total, {obs.write_ratio:.0%} W:R)"
            _wn = (f" ⚡ WRITABLE — {wr_desc}. "
                   f"Observed write values: {wv}. "
                   f"Attack vector: verify impact before writing in production.")

        # ── Write-only: never polled back ──────────────────────────────────────
        if obs.write_count > 0 and obs.read_count == 0:
            return self._result(obs, T_WRITEONLY, HIGH,
                "Never polled — only written. Blind actuator command, config write, "
                "or digital output coil (mode select, relay trip, enable bit)." + _wn)

        # Write activity is already surfaced via the ⚡ WRITABLE note appended
        # to every classification hint (_wn).  We don't override physical-type
        # detection based on write ratio — the right signal is whether a write
        # packet (FC6/FC16) was observed at all, not how often.

        # ── Binary ────────────────────────────────────────────────────────────
        if d <= {0, 1}:
            if obs.write_count > 0:
                return self._result(obs, T_BINARY, HIGH,
                    "Binary control output (read+write). Relay, valve, pump enable, "
                    "circuit breaker, or digital output." + _wn)
            rate = obs.changes_per_min
            if rate > 5:
                action = f"fast-toggling ({rate:.1f}×/min) — watchdog or heartbeat bit"
            elif rate > 0.5:
                action = f"toggles ~{rate:.1f}×/min — equipment cycling (pump, fan, valve)"
            else:
                action = "stable — static flag, permissive interlock, or run/stop status"
            return self._result(obs, T_BINARY, HIGH,
                f"Binary status ({action}). Current: {'ON/TRUE' if v[-1] else 'OFF/FALSE'}.")

        # ── Alarm / status code (small set, 0 = normal) ───────────────────────
        if n <= 5 and mx is not None and mx <= 6 and 0 in d:
            labels = {0:"Normal", 1:"Warning/PreAlarm", 2:"Alarm", 3:"Suppressed",
                      4:"Fault/Trip", 5:"Maintenance", 6:"Inhibited"}
            seen = {s: labels.get(s, f"State{s}") for s in sorted(d)}
            return self._result(obs, T_ALARM, HIGH,
                f"Alarm/status code. States seen: "
                + ", ".join(f"{k}={v}" for k, v in seen.items())
                + ". Standard IEC 62443/ISA-18.2 alarm level pattern." + _wn)

        # ── State / mode selector ─────────────────────────────────────────────
        if n <= 7 and mx is not None and mx <= 20 and obs.steps_to_fixed_values():
            modes = sorted(d)
            guess = ""
            if set(modes) <= {0, 1, 2}:
                guess = " (0=Auto, 1=Manual, 2=Standby likely)"
            elif set(modes) <= {0, 1, 2, 3}:
                guess = " (0=Off, 1=Slow, 2=Medium, 3=Full likely)"
            return self._result(obs, T_STATE, HIGH,
                f"State/mode selector — {n} discrete levels: {modes}{guess}. "
                "Pattern: value jumps between fixed levels, never drifts." + _wn)

        # ── Frequency ─────────────────────────────────────────────────────────
        if 480 <= mean <= 620 and std < 15 and obs.read_count >= 3:
            hz = mean / 10
            region = ("50 Hz grid (Europe/Asia/Africa)"  if abs(hz - 50) < 3 else
                      "60 Hz grid (Americas/Japan)"       if abs(hz - 60) < 3 else
                      "non-standard frequency")
            return self._result(obs, T_FREQUENCY, HIGH,
                f"Grid/AC frequency. Raw÷10 = {hz:.1f} Hz → {region}. "
                f"σ={std:.2f} — {'very stable (normal)' if std < 3 else 'unstable (fault?)'}" + _wn)

        # ── High-voltage bus (ship / industrial HV) ───────────────────────────
        if 5500 <= mean <= 7500 and std < 300 and obs.read_count >= 3:
            return self._result(obs, T_VOLTAGE, HIGH,
                f"HV bus voltage ≈ {mean:.0f} V raw (6.6 kV class — common on cruise/cargo "
                "vessels, offshore platforms, large industrial plants). σ small → stable." + _wn)

        # ── Medium-voltage / transformer secondary ────────────────────────────
        if 3200 <= mean <= 4500 and std < 200:
            return self._result(obs, T_VOLTAGE, MEDIUM,
                f"MV bus ≈ {mean:.0f} V raw. Could be 3.3 kV or 4.16 kV switchboard, "
                f"or scaled ÷1000 → {mean/1000:.2f} kV." + _wn)

        # ── LV distribution bus ───────────────────────────────────────────────
        # Tightened std < 4: real bus voltage is very stable (±2–3 V on a 440 V
        # bus). Temperature sensors in the 360–490 raw range (36–49°C ×10) and
        # percentage registers naturally drift with std 4–10, so they fall
        # through to the correct type handler below.
        if 360 <= mean <= 490 and std < 4 and obs.read_count >= 5:
            return self._result(obs, T_VOLTAGE, HIGH,
                f"LV bus ≈ {mean:.0f} V (400/440/480 V distribution). "
                "σ small → stable. Monitor for sag events." + _wn)

        # ── Generator / motor active power kW ────────────────────────────────
        # Lowered thresholds: real field devices drift ±50 kW → σ≈30–60 and
        # rng≈80–200 in the first few minutes.  rng>200 was too strict and
        # allowed high-power registers to fall through to the RPM ÷10 rule
        # (e.g. 8000 kW raw ÷ 10 = 800 RPM — a spurious but plausible match).
        if 500 <= mean <= 20000 and std > 30 and rng > 80 and (mx is None or mx <= 30000):
            return self._result(obs, T_POWER, MEDIUM,
                f"Likely generator or motor active power — {mn}–{mx} raw. "
                f"If kW direct: {mn}–{mx} kW. Variable load (σ={std:.0f}) → "
                "real-time generation/consumption tracking. "
                "Cruise ship context: Wärtsilä 12V46C ≈ 12,600 kW, 16V46C ≈ 16,800 kW "
                "(typical raw range 8,000–17,000 at 80–100% MCR). "
                "Note: high-volume flow registers (fuel/coolant) occupy the same raw "
                "range — cross-check unit ID and adjacent registers." + _wn)

        # ── Industrial hot sensor (°C + 50 bias) — checked early for read-only ─
        # Engine coolant, lube oil, jacket water: raw = actual_°C + 50.
        # Placed before RPM to prevent coolant registers (raw ~130–165) from
        # being classified as low-speed shafts.  Guards:
        #   • write_count == 0 — operator-writable registers are setpoints/RPM
        #   • (mn−50) >= 55 — enforces actual temp ≥ 55°C (industrial hot zone)
        #     to exclude shaft-RPM registers (raw ~98–108 → raw−50 = 48–58°C)
        if (mn is not None and mx is not None and 0 <= mn
                and mx <= 225 and 110 <= mean <= 170 and std > 0
                and obs.write_count == 0 and (mn - 50) >= 55):
            c_lo, c_hi = mn - 50, mx - 50
            return self._result(obs, T_TEMPERATURE, MEDIUM,
                f"Likely industrial temperature (bias+50 encoding) → "
                f"{c_lo}–{c_hi}°C. Mean {mean-50:.1f}°C. "
                f"Common on engine coolant, lube oil, jacket water, and "
                f"process heat exchangers (raw = actual°C + 50 unsigned). "
                + _temp_context(mean - 50) + _wn)

        # ── HVAC / ambient temperature early check ────────────────────────────
        # Values in the 150–270 raw range that are read-only, low-noise (σ<5),
        # and map cleanly to 15–27°C (×10 scale) are almost certainly cabin or
        # outdoor temperature sensors.  Raised c_lo floor from 8→15°C so that
        # low-range RPM registers (raw ~100–108 → 10°C ×10) and coolant
        # registers (raw ~130–148 → 13–14°C ×10) are not mis-classified here.
        if (mn is not None and mx is not None and 100 <= mean <= 270
                and std > 0 and std < 5 and rng > 0 and obs.write_count == 0
                and rng < mean * 0.25):
            c_lo, c_hi = mn / 10, mx / 10
            if 15.0 <= c_lo and c_hi <= 28.0:
                return self._result(obs, T_TEMPERATURE, MEDIUM,
                    f"Likely HVAC/ambient temperature (×10 scale) → "
                    f"{c_lo:.1f}–{c_hi:.1f}°C. "
                    f"Mean {mean/10:.1f}°C. " + _temp_context(mean / 10) + _wn)

        # ── Position / angle (offset-centered) ───────────────────────────────
        # Checked BEFORE RPM so rudder (mean≈180), fin angles (mean≈300), and
        # rate-of-turn (mean≈1800) are not mistaken for low-speed RPM readings.
        # rng threshold uses mid*0.02 (not 0.04) so rate-of-turn registers
        # with ±20 raw variation are caught (rng 35–40 > 1800×0.02 = 36).
        if mn is not None and mx is not None and mean > 0:
            mid_candidates = [180, 1800, 500, 150, 300, 100, 360, 3600]
            for mid in mid_candidates:
                # Require mean near center AND meaningful range.
                # For small centers (mid ≤ 300) the register must span at least
                # 15% of the center value to distinguish a real position sensor
                # (rudder ±35° → rng ≥ 27) from a pressure or temp sensor that
                # happens to sit near 180 raw.  For large centers (mid > 300),
                # use an absolute floor of 30 raw to catch rate-of-turn (±20 raw
                # around 1800) while blocking temp sensors near center=500 with
                # smaller natural noise.
                _req_rng = (max(mid * 0.15, 10) if mid <= 300
                            else max(30, mid * 0.02))
                if (abs(mean - mid) < mid * 0.18 and rng > _req_rng):
                    dev = rng / 2
                    side = ("Port/Left" if v[-1] < mid else
                            "Stbd/Right" if v[-1] > mid else "Centered")
                    return self._result(obs, T_POSITION, MEDIUM,
                        f"Position/angle — zero-point encoded as {mid}. "
                        f"Raw range {mn}–{mx} → ±{dev:.0f} raw from center. "
                        f"Rudder, actuator, fin, or valve stroke. "
                        f"Current: {side} (raw={v[-1]}, offset={v[-1]-mid:+d})." + _wn)

        # ── RPM / Speed ───────────────────────────────────────────────────────
        # Lowered thresholds to catch direct-RPM ship propulsion registers:
        # Wärtsilä/Azipod shafts run 0–144 RPM direct (raw = actual RPM).
        # ±1 raw noise → σ≈0.7, rng≈2 (values span e.g. 64–66 RPM), so
        # rng > 1 is the correct floor — catches any register with at least
        # 3 raw counts of spread.  Truly static sensors (rng 0–1, std≈0)
        # fall to the setpoint/unknown rules below.
        # _near_position also checks rng so registers that wouldn't satisfy
        # the position rule's own guard don't block RPM detection.
        _near_position = any(
            abs(mean - mid) < mid * 0.12
            and (obs.value_range or 0) > (max(mid * 0.15, 10) if mid <= 300
                                          else max(30, mid * 0.02))
            for mid in [180, 1800, 500, 150, 300, 100, 360, 3600]
        )
        if mn is not None and mn >= 0 and std > 0.5 and rng > 1 and not _near_position:
            rpm_matches = []
            for scale, unit_str, lo, hi in [
                (0.1, "raw÷10",   30, 1500),  # diesel gen-sets, large industrial (÷10 convention)
                (1,   "raw=RPM",   5, 3600),  # direct RPM — cruise ship props 0–144, motors 0–3600
                (10,  "raw×10",    5,  200),  # fine-resolution slow shafts (rare)
            ]:
                lo_raw = lo / scale
                hi_raw = hi / scale
                if lo_raw <= mean <= hi_raw:
                    actual_lo = mn * scale
                    actual_hi = (mx * scale) if mx else 0
                    rpm_matches.append(f"{unit_str}: {actual_lo:.0f}–{actual_hi:.0f} RPM")
            if rpm_matches:
                conf = HIGH if len(rpm_matches) == 1 else MEDIUM
                return self._result(obs, T_RPM, conf,
                    f"Rotational/shaft speed — {len(rpm_matches)} scale candidate(s): "
                    + "; ".join(rpm_matches) + ". "
                    f"σ={std:.1f}, range {mn}–{mx}, "
                    f"changes {obs.changes_per_min:.1f}×/min. "
                    "Ship propulsion: Wärtsilä/Azipod direct raw=RPM (0–144 RPM), "
                    "or raw÷10 for older PLCs. "
                    "Cross-check adjacent torque/power/fuel registers to confirm."
                    + _wn)

        # ── Temperature (multiple convention detection) ────────────────────────
        # Direct °C
        if mn is not None and -50 <= mn <= 50 and mx is not None and mn < mx <= 200 and std > 0:
            return self._result(obs, T_TEMPERATURE, HIGH,
                f"Temperature (direct °C). Range {mn}–{mx}°C, mean {mean:.1f}°C. "
                + _temp_context(mean) + _wn)

        # °C + 273 offset (Kelvin)
        if mn is not None and 243 <= mn <= 373 and mx is not None and mx <= 600 and std > 0:
            c_lo, c_hi = mn - 273, mx - 273
            return self._result(obs, T_TEMPERATURE, MEDIUM,
                f"Possible Kelvin encoding → {c_lo}–{c_hi}°C (raw−273). "
                f"Mean {mean-273:.1f}°C. " + _temp_context(mean - 273) + _wn)

        # °C × 10 scale — checked BEFORE temp+50 and percentage to catch HVAC
        # zone temps (raw 190–260 = 19–26°C) and coolant readings correctly.
        if (mn is not None and mx is not None and 0 <= mn and mx <= 2500
                and 100 <= mean <= 1500 and std > 0 and rng > 0):
            c_lo, c_hi = mn / 10, mx / 10
            # Sanity check: resulting temperature should be a believable sensor range
            if -20 <= c_lo and c_hi <= 250:
                return self._result(obs, T_TEMPERATURE, MEDIUM,
                    f"Likely temperature ×10 scale → {c_lo:.1f}–{c_hi:.1f}°C. "
                    f"Mean {mean/10:.1f}°C. " + _temp_context(mean / 10) + _wn)

        # °C + 50 bias (fallback for writable or lower-temp sensors not caught earlier)
        # The primary hot-sensor bias check (write_count==0, actual≥55°C) runs
        # before the RPM rule above.  This fallback catches writable setpoints
        # and cooler sensors (actual 10–110°C) that slipped through.
        if (mn is not None and mx is not None and 0 <= mn
                and mx <= 210 and 60 <= mean <= 160 and std > 0):
            c_lo, c_hi = mn - 50, mx - 50
            return self._result(obs, T_TEMPERATURE, MEDIUM,
                f"Possible temperature (bias+50) → {c_lo}–{c_hi}°C. "
                f"Mean {mean-50:.1f}°C. " + _temp_context(mean - 50) + _wn)

        # ── Percentage (×10 scale most common) ────────────────────────────────
        # Lowered std threshold to 0.5 to catch slowly-drifting tank levels.
        if mn is not None and mn >= 0 and mx is not None and 10 <= mx <= 1100 and std > 0.5:
            pct_lo = mn / 10
            pct_hi = min(mx / 10, 110)
            context = _percentage_context(pct_lo, pct_hi, mean / 10)
            return self._result(obs, T_PERCENTAGE, MEDIUM,
                f"Percentage — {pct_lo:.0f}%–{pct_hi:.0f}% (raw÷10). "
                f"{context}" + _wn)

        # ── Flow rate ─────────────────────────────────────────────────────────
        # Try multiple scale interpretations and list all that fall in a
        # realistic flow range (10–30,000 L/hr or equivalent).
        # Cruise ship context: engine fuel flow raw÷10 ≈ 2,000–3,000 L/hr/engine
        # (raw 20,000–30,000); HFO ship-wide ÷10 ≈ 13,000 L/hr (raw ~130,000 —
        # above this rule's cap).  Raw=1 L/hr convention is rare for large flows.
        if (mn is not None and mn >= 0 and mx is not None
                and 100 <= mean <= 50000 and std > 5 and rng > 30 and mx <= 100000):
            scale_candidates = []
            for scale, label in [(0.1, "raw÷10 L/hr"), (1, "raw=L/hr"), (10, "raw×10 L/hr")]:
                lo_val = mn * scale; hi_val = mx * scale
                if 5 <= lo_val and hi_val <= 50000:
                    scale_candidates.append(f"{label}: {lo_val:.0f}–{hi_val:.0f}")
            scales_str = ("; ".join(scale_candidates)
                          if scale_candidates else f"raw {mn}–{mx}")
            return self._result(obs, T_FLOW, LOW,
                f"Possible flow rate — range {mn}–{mx} raw. "
                f"Scale candidates: {scales_str}. "
                "Ship propulsion: fuel/coolant flow typically raw÷10 = L/hr "
                "(e.g. raw 20,600 → 2,060 L/hr/engine at cruise). "
                "Often paired with adjacent tank level or totaliser registers."
                + _wn)

        # ── Pressure / level ──────────────────────────────────────────────────
        if mn is not None and mn >= 0 and mx is not None:
            if 10 <= mean <= 10000 and std > 1 and rng > 5:
                for scale, unit in [(0.1, "bar"), (1, "bar×0.1 = mbar"),
                                     (10, "kPa"), (0.01, "MPa")]:
                    p_lo = mn * scale; p_hi = mx * scale
                    if 0 < p_lo < 1000 and p_hi < 5000:
                        return self._result(obs, T_PRESSURE, LOW,
                            f"Possible pressure or liquid level — {mn}–{mx} raw. "
                            f"If {unit}: {p_lo:.1f}–{p_hi:.1f} {unit.split('=')[0].strip()}. "
                            "Verify with adjacent level/pump registers." + _wn)

        # ── Monotonic counter / totaliser ─────────────────────────────────────
        if obs.is_monotonic and mx is not None and mx > 50:
            unit_guess = ("energy (kWh)" if mx > 10000 else
                          "runtime hours or cycle count" if mx < 100000 else
                          "flow total or odometer")
            return self._result(obs, T_COUNTER, MEDIUM,
                f"Monotonically increasing — {unit_guess}. "
                f"Current value: {v[-1]}. Rate: +{obs.recent_delta():.1f}/poll." + _wn)

        # ── Very stable → fixed config or unchanged setpoint ──────────────────
        # Require n <= 2 distinct values to avoid mis-firing on temperature
        # sensors with tight tolerances (e.g. coolant +50 bias that drifts
        # only ±1 raw — 3 distinct values possible — but isn't a setpoint).
        # write_count check removed: controllers often write fixed values every
        # cycle alongside polling — the register is still effectively constant.
        if std < 1.5 and obs.read_count >= 8 and n <= 2 and rng <= 2:
            sv = sorted(d)
            writable_note = " Writable — controller actively sets this value." if obs.write_count > 0 else ""
            return self._result(obs, T_SETPOINT, MEDIUM,
                f"Nearly constant ({sv}) across {obs.read_count} polls.{writable_note} "
                "Fixed configuration register, device address, firmware version, "
                "or a setpoint that hasn't been changed yet." + _wn)

        # ── Generic analog sensor fallback ────────────────────────────────────
        if std > 0.5 and obs.read_count >= 3:
            cv = std / mean if mean else 0
            stability = ("very stable" if cv < 0.01 else
                         "stable"      if cv < 0.05 else
                         "moderate"    if cv < 0.15 else "high variance")
            scale_hints = _guess_scales(mn or 0, mx or 0, mean, std)
            return self._result(obs, T_SENSOR, LOW,
                f"Analog sensor ({stability} — CV={cv:.2f}). Range {mn}–{mx}, "
                f"mean {mean:.0f}, σ={std:.1f}. "
                + (f"Scale hints: {scale_hints}" if scale_hints else
                   "Capture more samples to narrow down physical quantity.")
                + _wn)

        scale_hints = _guess_scales(mn or 0, mx or 0, mean, std) if mn is not None else ""
        return self._result(obs, T_UNKNOWN, LOW,
            f"{obs.samples} sample(s), range {mn}–{mx}, mean {mean:.0f}. "
            + (f"Possible scales: {scale_hints}. " if scale_hints else "")
            + "Needs more samples or context to classify."
            + _wn)

    # ── Cross-register correlation pass ───────────────────────────────────

    def _cross_analyze(self, results: Dict[Tuple[str, int, int], Dict]) -> None:
        """Refine results using relationships between registers on the same device+unit."""
        by_unit: Dict[Tuple[str, int], List[Tuple[int, Dict]]] = defaultdict(list)
        for (ip, uid, addr), r in results.items():
            by_unit[(ip, uid)].append((addr, r))

        for (ip, uid), regs in by_unit.items():
            regs.sort(key=lambda x: x[0])
            addrs = [a for a, _ in regs]
            obs_map = {a: self._obs.get((ip, uid, a)) for a in addrs}

            # Detect setpoint/actual pairs:
            # One register is very stable, adjacent one drifts around it
            for i in range(len(regs) - 1):
                a0, r0 = regs[i]
                a1, r1 = regs[i + 1]
                o0, o1 = obs_map.get(a0), obs_map.get(a1)
                if not o0 or not o1: continue
                if (o0.is_stable() and o1.std and o1.std > 2 and
                        o0.mean and o1.mean and
                        abs(o0.mean - o1.mean) < max(o0.mean, o1.mean) * 0.3):
                    r0["hint"] += (f" ↔ Likely SETPOINT — register {a1} (actual) "
                                   "tracks closely. Classic setpoint/PV pair.")
                    r0["type"] = T_SETPOINT
                    r0["confidence"] = HIGH
                    r1["hint"] += (f" ↔ Likely PROCESS VALUE — register {a0} appears "
                                   "to be its setpoint (stable, nearby, similar range).")

            # Detect channel groups: consecutive registers with same type/range
            i = 0
            while i < len(regs) - 1:
                a0, r0 = regs[i]
                j = i + 1
                group = [a0]
                o0 = obs_map.get(a0)
                while j < len(regs):
                    aj, rj = regs[j]
                    oj = obs_map.get(aj)
                    if (aj == group[-1] + 1 and
                            r0["type"] == rj["type"] and
                            o0 and oj and o0.mean and oj.mean and
                            abs((o0.mean - oj.mean) / max(o0.mean, oj.mean, 1)) < 0.5):
                        group.append(aj)
                        j += 1
                    else:
                        break
                if len(group) >= 3:
                    for k, ga in enumerate(group):
                        gr = results.get((ip, uid, ga))
                        if gr:
                            gr["hint"] += (f" ⚡ Part of {len(group)}-channel block "
                                           f"(addr {group[0]}–{group[-1]}). "
                                           f"Likely multi-channel sensor array, "
                                           f"phase currents, tank array, or zone readings.")
                i = j if j > i else i + 1

            # Detect mirrored / redundant registers
            for i in range(len(regs)):
                for j in range(i + 1, len(regs)):
                    a0, r0 = regs[i]
                    a1, r1 = regs[j]
                    o0, o1 = obs_map.get(a0), obs_map.get(a1)
                    if not o0 or not o1: continue
                    if (len(o0.read_values) >= 5 and len(o1.read_values) >= 5 and
                            o0.mean and o1.mean and o0.std and o1.std and
                            abs(o0.mean - o1.mean) < 1 and
                            abs(o0.std  - o1.std)  < 1 and
                            o0.read_values[-5:] == o1.read_values[-5:]):
                        r0["hint"] += f" ⚠ Identical to addr {a1} — redundant sensor or mirrored register."
                        r1["hint"] += f" ⚠ Identical to addr {a0} — redundant sensor or mirrored register."

    @staticmethod
    def _result(obs: RegisterObs, reg_type: str, confidence: str, hint: str) -> Dict[str, Any]:
        v = obs.all_values
        # Use the most recently observed value (read or write), not list-order last
        last = obs.read_values[-1] if obs.read_values else (obs.write_values[-1] if obs.write_values else None)
        return {
            "ip":          obs.ip,
            "unit_id":     obs.unit_id,
            "addr":        obs.addr,
            "type":        reg_type,
            "confidence":  confidence,
            "hint":        hint.strip(),
            "samples":     obs.samples,
            "reads":       obs.read_count,
            "writes":      obs.write_count,
            "writable":    obs.write_count > 0,
            "min":         obs.mn,
            "max":         obs.mx,
            "mean":        round(obs.mean, 1) if obs.mean is not None else None,
            "std":         round(obs.std,  1) if obs.std  is not None else None,
            "distinct":    len(obs.distinct),
            "chg_per_min": round(obs.changes_per_min, 1),
            "last_value":  last,
            "write_ratio": round(obs.write_ratio, 2),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Domain helpers (offline knowledge base)
# ─────────────────────────────────────────────────────────────────────────────

def _temp_context(c: float) -> str:
    if c < -10:   return "Cryogenic / refrigeration range."
    if c < 10:    return "Chilled water, cold store, or sub-ambient process."
    if c < 30:    return "Ambient / HVAC cabin or outdoor temperature."
    if c < 60:    return "Warm process — HVAC hot deck, heat exchanger outlet."
    if c < 100:   return "Hot water system, lubricating oil, or engine coolant."
    if c < 200:   return "High-temperature process — exhaust gas, furnace coolant."
    return "Extreme heat — furnace, boiler, or kiln process."


def _percentage_context(lo: float, hi: float, mean: float) -> str:
    if hi <= 5 and lo == 0:
        return "Near-zero percentage — possibly inactive or minimal-load sensor."
    if 40 <= mean <= 60:
        return "Mid-range — could be half-open valve, 50% tank, or partial load."
    if mean >= 85:
        return "High percentage — near-full tank, high load, or full-open valve."
    return "Could be: tank level, valve position, motor load %, throttle, or fan speed."


def _guess_scales(mn: int, mx: int, mean: float, std: float) -> str:
    """Suggest plausible physical interpretations at different scales."""
    hints = []
    for scale, unit in [(0.1, "÷10"), (0.01, "÷100"), (10, "×10"), (1, "×1")]:
        lo = mn * scale; hi = mx * scale; m = mean * scale
        if 0 <= lo and hi <= 500 and 1 < m < 300:
            hints.append(f"{lo:.1f}–{hi:.1f} ({unit})")
    return ", ".join(hints[:3]) if hints else ""
