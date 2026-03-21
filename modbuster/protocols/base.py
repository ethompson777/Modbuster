"""Abstract protocol handler: detect, parse, build. All protocol handlers implement this contract."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

# Optional: type hint for Scapy packet (avoid hard scapy import here)
# from scapy.packet import Packet


class BaseProtocolHandler(ABC):
    """Abstract handler: detect(pkt), parse(pkt), build_* for inject, default_port, transport."""

    name: str = "base"
    default_port: int = 0
    transport: str = "tcp"  # "tcp" or "udp"

    @abstractmethod
    def detect(self, pkt: Any) -> bool:
        """Return True if this packet belongs to this protocol (e.g. by port or layer)."""
        pass

    @abstractmethod
    def parse(self, pkt: Any) -> Optional[Dict[str, Any]]:
        """Parse packet into normalized dict: protocol, direction, op, addresses/values, etc."""
        pass

    def build_read_holding_registers(
        self,
        unit_id: int,
        start_addr: int,
        count: int,
        **kwargs: Any,
    ) -> Optional[bytes]:
        """Build raw payload for read holding registers (Modbus-style). Override per protocol."""
        return None

    def build_write_single_register(
        self,
        unit_id: int,
        addr: int,
        value: int,
        **kwargs: Any,
    ) -> Optional[bytes]:
        """Build raw payload for write single register. Override per protocol."""
        return None

    def build_write_multiple_registers(
        self,
        unit_id: int,
        start_addr: int,
        values: list,
        **kwargs: Any,
    ) -> Optional[bytes]:
        """Build raw payload for write multiple registers. Override per protocol."""
        return None
