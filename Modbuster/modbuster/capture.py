"""Live sniff and PCAP read; BPF multi-port; yield (packet, protocol_name, parsed_dict)."""

import os
import struct
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple

from modbuster.protocols import PROTOCOLS, get_handler

# Link-layer type 0xe4 (228): raw IP (no Ethernet). Scapy doesn't map it, so we handle it explicitly.
LINKTYPE_RAW_IP = 0xE4


def _detect_protocol(pkt: Any, protocol_filter: Optional[List[str]] = None) -> Optional[str]:
    """Return protocol name if packet is recognized by a registered handler."""
    names = list(PROTOCOLS.keys()) if not protocol_filter else protocol_filter
    for name in names:
        handler = get_handler(name)
        if handler and handler.detect(pkt):
            return name
    return None


def _pcap_linktype(pcap_path: str) -> Optional[int]:
    """Read link-layer type from PCAP global header. Returns None if not a pcap file."""
    try:
        with open(pcap_path, "rb") as f:
            buf = f.read(24)
        if len(buf) < 24:
            return None
        magic = struct.unpack("<I", buf[:4])[0]
        # Standard pcap magic numbers (little-endian or big-endian)
        if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
            return None
        # network (linktype) is at offset 20, 4 bytes, same endianness as magic
        linktype = struct.unpack("<I", buf[20:24])[0]
        return linktype
    except Exception:
        return None


def _read_pcap_packets(pcap_path: str) -> Iterator[tuple[Any, float]]:
    """
    Read PCAP and yield (packet, timestamp) for each packet.
    Uses the file's link-layer type so we decode correctly and avoid Scapy's "unknown LL type" path.
    """
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapReader, RawPcapReader

    linktype = _pcap_linktype(pcap_path)
    if linktype == LINKTYPE_RAW_IP:
        # Link type 228: raw IP (no Ethernet). Read raw bytes and decode as IP; no Scapy warning.
        with open(pcap_path, "rb") as f:
            reader = RawPcapReader(f)
            try:
                for item in reader:
                    if isinstance(item, tuple) and len(item) >= 2:
                        pkt_bytes, meta = item[0], item[1]
                        if len(pkt_bytes) < 20:
                            continue
                        try:
                            pkt = IP(pkt_bytes)
                            if hasattr(meta, "sec") and hasattr(meta, "usec"):
                                pkt.time = float(meta.sec) + float(meta.usec) / 1e6
                            elif isinstance(meta, (tuple, list)) and len(meta) >= 2:
                                pkt.time = float(meta[0]) + float(meta[1]) / 1e6
                            yield (pkt, getattr(pkt, "time", 0.0))
                        except Exception:
                            continue
            finally:
                reader.close()
        return

    # Standard path: Scapy's PcapReader (Ethernet or other known link types).
    reader = PcapReader(pcap_path)
    try:
        for pkt in reader:
            if pkt is None:
                continue
            ts = getattr(pkt, "time", 0.0)
            # If Scapy returned Raw (unknown link type other than 228), re-decode as Ether or IP.
            if not pkt.haslayer("TCP") and not pkt.haslayer("Ether"):
                raw_bytes = None
                if pkt.haslayer("Raw"):
                    raw_bytes = bytes(pkt.getlayer("Raw").load)
                elif hasattr(pkt, "load"):
                    raw_bytes = bytes(pkt.load)
                if raw_bytes and len(raw_bytes) >= 14:
                    try:
                        decoded = Ether(raw_bytes)
                        if decoded.haslayer("TCP"):
                            decoded.time = ts
                            pkt = decoded
                    except Exception:
                        pass
                if not pkt.haslayer("TCP") and raw_bytes and len(raw_bytes) >= 20:
                    try:
                        decoded = IP(raw_bytes)
                        if decoded.haslayer("TCP"):
                            decoded.time = ts
                            pkt = decoded
                    except Exception:
                        pass
            yield (pkt, getattr(pkt, "time", ts))
    finally:
        reader.close()


def _packet_matches_ports(pkt: Any, selected_ports: List[Tuple[int, str]]) -> bool:
    """True if packet's sport or dport (TCP or UDP) is in selected_ports ((port, proto), ...)."""
    if not selected_ports:
        return True
    try:
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            for port, proto in selected_ports:
                if proto == "tcp" and (tcp.sport == port or tcp.dport == port):
                    return True
        if pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            for port, proto in selected_ports:
                if proto == "udp" and (udp.sport == port or udp.dport == port):
                    return True
    except Exception:
        pass
    return False


def iter_pcap(
    pcap_path: str,
    bpf_filter: Optional[str] = None,
    protocol_filter: Optional[List[str]] = None,
    selected_ports: Optional[List[Tuple[int, str]]] = None,
) -> Iterator[tuple[Any, str, Dict[str, Any]]]:
    """Read PCAP and yield (packet, protocol_name, parsed_dict) for each recognized packet.
    If selected_ports is provided, only packets whose (sport or dport, proto) is in that list are considered."""
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    for pkt, _ts in _read_pcap_packets(pcap_path):
        if selected_ports and not _packet_matches_ports(pkt, selected_ports):
            continue
        if bpf_filter:
            try:
                if not pkt.haslayer("TCP") and not pkt.haslayer("UDP"):
                    continue
            except Exception:
                pass
        name = _detect_protocol(pkt, protocol_filter)
        if not name:
            continue
        handler = get_handler(name)
        parsed = handler.parse(pkt) if handler else None
        if parsed is not None:
            yield (pkt, name, parsed)


def iter_live(
    iface: Optional[str] = None,
    count: int = 0,
    bpf_filter: Optional[str] = None,
    protocol_filter: Optional[List[str]] = None,
) -> Generator[tuple[Any, str, Dict[str, Any]], None, None]:
    """Sniff live and yield (packet, protocol_name, parsed_dict). count=0 means unbounded."""
    from scapy.sendrecv import sniff

    # Default BPF: common SCADA ports (Modbus 502; future: 20000, 2404, 44818, udp 47808)
    default_bpf = "tcp port 502"
    filt = bpf_filter or default_bpf

    def _cb(pkt: Any) -> None:
        # Used only when store=False and we need to queue; we use store=True and iterate
        pass

    kwargs: Dict[str, Any] = {"filter": filt, "store": True}
    if iface:
        kwargs["iface"] = iface
    if count > 0:
        kwargs["count"] = count

    pkts = sniff(**kwargs)
    for pkt in pkts:
        name = _detect_protocol(pkt, protocol_filter)
        if not name:
            continue
        handler = get_handler(name)
        parsed = handler.parse(pkt) if handler else None
        if parsed is not None:
            yield (pkt, name, parsed)
