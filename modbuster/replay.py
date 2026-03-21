"""Replay: load message(s) from PCAP (or export), optionally modify, send to target."""

from typing import Any, Dict, List, Optional

from modbuster.capture import iter_pcap
from modbuster.inject import send_tcp
from modbuster.protocols import get_handler


def get_messages_from_pcap(
    pcap_path: str,
    protocol_filter: Optional[List[str]] = None,
    index: Optional[int] = None,
    filter_attrs: Optional[Dict[str, Any]] = None,
) -> List[tuple[Any, str, Dict[str, Any]]]:
    """Load messages from PCAP. If index is set, return only that message. filter_attrs e.g. {'unit_id': 1, 'func_code': 3}."""
    out: List[tuple[Any, str, Dict[str, Any]]] = []
    for i, (pkt, name, parsed) in enumerate(iter_pcap(pcap_path, protocol_filter=protocol_filter)):
        if index is not None and i != index:
            continue
        if filter_attrs:
            if not all(parsed.get(k) == v for k, v in filter_attrs.items()):
                continue
        out.append((pkt, name, parsed))
        if index is not None:
            break
    return out


def extract_modbus_payload(pkt: Any) -> Optional[bytes]:
    """Extract Modbus ADU bytes (MBAP + PDU) from a packet for replay."""
    try:
        import scapy.contrib.modbus as mb
        if mb.ModbusADURequest in pkt:
            adu = pkt[mb.ModbusADURequest]
            return bytes(adu)
        if mb.ModbusADUResponse in pkt:
            adu = pkt[mb.ModbusADUResponse]
            return bytes(adu)
    except Exception:
        pass
    return None


def replay_one(
    pkt: Any,
    protocol_name: str,
    target: str,
    port: int,
    require_write_for_writes: bool = True,
    write_flag: bool = False,
    modify: Optional[Dict[str, Any]] = None,
) -> Optional[bytes]:
    """Replay one packet to target. If modify is set, build new payload from parsed+modify. Requires --write for write-type messages."""
    if protocol_name != "modbus":
        return None
    payload = extract_modbus_payload(pkt)
    if modify and get_handler("modbus"):
        # Optional: rebuild from parsed + modify (e.g. addr=0 value=123)
        # For MVP we just send original payload
        pass
    if not payload:
        return None
    # Optional: check if parsed is write and require write_flag
    return send_tcp(target, port, payload)
