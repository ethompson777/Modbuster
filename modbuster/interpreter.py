"""Consumes (packet, protocol_name, parsed_dict); outputs human-readable lines and optional summary."""

from typing import Any, Dict, List, Optional

from scapy.packet import Packet


def _ts(pkt: Optional[Packet]) -> str:
    if pkt is None or not hasattr(pkt, "time"):
        return ""
    t = getattr(pkt, "time", None)
    if t is None:
        return ""
    from datetime import datetime
    try:
        return datetime.fromtimestamp(float(t)).strftime("%H:%M:%S.%f")[:-3]
    except Exception:
        return ""


def _src_dst(pkt: Optional[Packet]) -> str:
    if pkt is None:
        return ""
    if pkt.haslayer("IP"):
        ip = pkt["IP"]
        src = f"{ip.src}:{ip.sport}" if hasattr(ip, "sport") else str(ip.src)
        dst = f"{ip.dst}:{ip.dport}" if hasattr(ip, "dport") else str(ip.dst)
        return f"{src} -> {dst}"
    return ""


def format_line(
    pkt: Optional[Packet],
    protocol_name: str,
    parsed: Dict[str, Any],
) -> str:
    """One line (or short block) per message: protocol, time, direction, src/dst, unit, op, addr/values."""
    ts = _ts(pkt)
    sd = _src_dst(pkt)
    direction = parsed.get("direction", "?")
    unit = parsed.get("unit_id")
    unit_s = f" unit={unit}" if unit is not None else ""
    op = parsed.get("op_name", parsed.get("op", "?"))
    parts = [f"[{ts}]", protocol_name, direction, sd, unit_s.strip(), op]

    addr = parsed.get("start_addr") if "start_addr" in parsed else parsed.get("address")
    if addr is not None:
        parts.append(f"addr={addr}")
    qty = parsed.get("quantity")
    if qty is not None:
        parts.append(f"count={qty}")
    val = parsed.get("value")
    if val is not None:
        parts.append(f"value={val}")
    vals = parsed.get("values")
    if vals:
        parts.append(f"values={vals}")
    exc = parsed.get("exception_code")
    if exc is not None:
        parts.append(f"exception=0x{exc:02x}")
    raw = parsed.get("raw_hex")
    if raw:
        parts.append(f"raw={raw[:32]}..." if len(raw) > 32 else f"raw={raw}")

    return " | ".join(str(p) for p in parts)


def summary(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Per-protocol and global: unique unit IDs, op distribution, read vs write counts."""
    by_protocol: Dict[str, Dict[str, Any]] = {}
    all_units: set = set()
    read_count = 0
    write_count = 0
    op_counts: Dict[str, int] = {}

    for r in records:
        prot = r.get("protocol", "unknown")
        if prot not in by_protocol:
            by_protocol[prot] = {"units": set(), "read_count": 0, "write_count": 0, "op_counts": {}}
        u = r.get("unit_id")
        if u is not None:
            all_units.add((prot, u))
            by_protocol[prot]["units"].add(u)
        op = r.get("op_name") or r.get("op", "?")
        op_counts[op] = op_counts.get(op, 0) + 1
        by_protocol[prot]["op_counts"][op] = by_protocol[prot]["op_counts"].get(op, 0) + 1

        # Heuristic: write ops have "Write" in name or func_code in (5,6,15,16)
        fc = r.get("func_code")
        if fc in (5, 6, 15, 16) or (isinstance(op, str) and "write" in op.lower()):
            write_count += 1
            by_protocol[prot]["write_count"] += 1
        else:
            read_count += 1
            by_protocol[prot]["read_count"] += 1

    result: Dict[str, Any] = {
        "total_messages": len(records),
        "unique_units": list(all_units),
        "read_count": read_count,
        "write_count": write_count,
        "op_counts": op_counts,
        "by_protocol": {},
    }
    for k, v in by_protocol.items():
        result["by_protocol"][k] = {
            "units": list(v["units"]),
            "read_count": v["read_count"],
            "write_count": v["write_count"],
            "op_counts": v["op_counts"],
        }
    return result
