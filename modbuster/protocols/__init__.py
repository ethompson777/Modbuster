"""Protocol registry: PROTOCOLS = { "modbus": ModbusHandler, ... }."""

from modbuster.protocols.base import BaseProtocolHandler
from modbuster.protocols.modbus import ModbusHandler

PROTOCOLS: dict[str, BaseProtocolHandler] = {
    "modbus": ModbusHandler(),
}

def get_handler(name: str) -> BaseProtocolHandler | None:
    return PROTOCOLS.get(name)

def list_protocols() -> list[str]:
    return list(PROTOCOLS.keys())
