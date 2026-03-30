"""
Injection: dispatch to protocol builder; TCP or UDP send.
For use only on authorized systems. Writing registers/coils can affect physical processes.
"""

import socket
from typing import Any, Optional

from modbuster.protocols import get_handler


def send_tcp(host: str, port: int, payload: bytes, timeout: float = 5.0) -> Optional[bytes]:
    """Open TCP connection, send payload (e.g. Modbus MBAP+PDU), read response, return it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(payload)
        buf = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(chunk) < 4096:
                break
        return buf or None
    except Exception:
        return None
    finally:
        sock.close()


def inject_modbus_read_holding(
    target: str,
    port: int,
    unit_id: int,
    start_addr: int,
    count: int,
    **kwargs: Any,
) -> Optional[bytes]:
    """Build and send Modbus read holding registers; return response bytes."""
    handler = get_handler("modbus")
    if not handler:
        return None
    payload = handler.build_read_holding_registers(unit_id, start_addr, count, **kwargs)
    if not payload:
        return None
    return send_tcp(target, port, payload, kwargs.get("timeout", 5.0))


def inject_modbus_read_coils(
    target: str,
    port: int,
    unit_id: int,
    start_addr: int,
    count: int,
    **kwargs: Any,
) -> Optional[bytes]:
    """Build and send Modbus FC1 Read Coils; return response bytes."""
    handler = get_handler("modbus")
    if not handler:
        return None
    payload = handler.build_read_coils(unit_id, start_addr, count, **kwargs)
    if not payload:
        return None
    return send_tcp(target, port, payload, kwargs.get("timeout", 5.0))


def inject_modbus_write_single_coil(
    target: str,
    port: int,
    unit_id: int,
    addr: int,
    on: bool,
    require_write_flag: bool = True,
    write_flag: bool = False,
    **kwargs: Any,
) -> Optional[bytes]:
    """Build and send Modbus FC5 Write Single Coil. Requires write_flag=True for safety."""
    if require_write_flag and not write_flag:
        raise ValueError("Write operations require explicit --write flag")
    handler = get_handler("modbus")
    if not handler:
        return None
    payload = handler.build_write_single_coil(unit_id, addr, on, **kwargs)
    if not payload:
        return None
    return send_tcp(target, port, payload, kwargs.get("timeout", 5.0))


def inject_modbus_write_register(
    target: str,
    port: int,
    unit_id: int,
    addr: int,
    value: int,
    require_write_flag: bool = True,
    write_flag: bool = False,
    **kwargs: Any,
) -> Optional[bytes]:
    """Build and send Modbus write single register. Requires write_flag=True for safety."""
    if require_write_flag and not write_flag:
        raise ValueError("Write operations require explicit --write flag")
    handler = get_handler("modbus")
    if not handler:
        return None
    payload = handler.build_write_single_register(unit_id, addr, value, **kwargs)
    if not payload:
        return None
    return send_tcp(target, port, payload, kwargs.get("timeout", 5.0))


def inject_modbus_write_multiple_registers(
    target: str,
    port: int,
    unit_id: int,
    start_addr: int,
    values: list,
    require_write_flag: bool = True,
    write_flag: bool = False,
    **kwargs: Any,
) -> Optional[bytes]:
    """Build and send Modbus write multiple registers. Requires --write for safety."""
    if require_write_flag and not write_flag:
        raise ValueError("Write operations require explicit --write flag")
    handler = get_handler("modbus")
    if not handler:
        return None
    payload = handler.build_write_multiple_registers(unit_id, start_addr, values, **kwargs)
    if not payload:
        return None
    return send_tcp(target, port, payload, kwargs.get("timeout", 5.0))
