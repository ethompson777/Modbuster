"""Modbus TCP: detect, parse, build using Scapy contrib.modbus."""

import random
from typing import Any, Dict, List, Optional

from modbuster.protocols.base import BaseProtocolHandler

# Lazy load Scapy to avoid import cost when not capturing
def _scapy_modbus():
    import scapy.contrib.modbus as mb
    return mb

# Function code to short name (request/response)
FUNC_CODE_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
}
EXCEPTION_OFFSET = 0x80  # response with exception


class ModbusHandler(BaseProtocolHandler):
    name = "modbus"
    default_port = 502
    transport = "tcp"

    def detect(self, pkt: Any) -> bool:
        try:
            mb = _scapy_modbus()
            if mb.ModbusADURequest in pkt or mb.ModbusADUResponse in pkt:
                return True
            # TCP + Raw on port 502 (e.g. after re-decode from unknown link layer)
            if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
                tcp = pkt["TCP"]
                if tcp.sport == 502 or tcp.dport == 502:
                    return True
            return False
        except Exception:
            return False

    def parse(self, pkt: Any) -> Optional[Dict[str, Any]]:
        try:
            mb = _scapy_modbus()
            adu = None
            direction = None
            if mb.ModbusADURequest in pkt:
                adu = pkt[mb.ModbusADURequest]
                direction = "request"
            elif mb.ModbusADUResponse in pkt:
                adu = pkt[mb.ModbusADUResponse]
                direction = "response"
            elif pkt.haslayer("TCP") and pkt.haslayer("Raw"):
                tcp = pkt["TCP"]
                if tcp.sport == 502 or tcp.dport == 502:
                    raw_bytes = bytes(tcp.payload.load)
                    direction = "response" if tcp.sport == 502 else "request"
                    try:
                        adu = mb.ModbusADURequest(raw_bytes) if direction == "request" else mb.ModbusADUResponse(raw_bytes)
                    except Exception:
                        try:
                            adu = mb.ModbusADUResponse(raw_bytes) if direction == "response" else mb.ModbusADURequest(raw_bytes)
                        except Exception:
                            return None
            if adu is None or direction is None:
                return None

            trans_id = int(adu.transId) if hasattr(adu, "transId") else None
            unit_id = int(adu.unitId) if hasattr(adu, "unitId") else None

            # Find PDU (first layer under ADU that isn't Raw)
            payload = adu.payload
            func_code = None
            op_name = "Unknown"
            start_addr = None
            quantity = None
            address = None
            value = None
            values: List[Any] = []
            exception_code = None
            raw_hex: Optional[str] = None

            if payload and not hasattr(payload, "funcCode"):
                # Might be Raw or unknown PDU
                raw_hex = bytes(payload).hex()
                return {
                    "protocol": self.name,
                    "direction": direction,
                    "trans_id": trans_id,
                    "unit_id": unit_id,
                    "op": "raw",
                    "op_name": "Raw/Unknown",
                    "raw_hex": raw_hex,
                }

            if hasattr(payload, "funcCode"):
                func_code = int(payload.funcCode)
                if func_code >= EXCEPTION_OFFSET:
                    exception_code = func_code - EXCEPTION_OFFSET
                    op_name = f"Exception (0x{exception_code:02x})"
                else:
                    op_name = FUNC_CODE_NAMES.get(func_code, f"Func 0x{func_code:02x}")

                if hasattr(payload, "startAddr"):
                    start_addr = int(payload.startAddr)
                if hasattr(payload, "quantity"):
                    quantity = int(payload.quantity)
                if hasattr(payload, "outputAddr"):
                    address = int(payload.outputAddr)
                elif hasattr(payload, "registerAddr"):
                    address = int(payload.registerAddr)
                if hasattr(payload, "outputValue"):
                    value = int(payload.outputValue)
                elif hasattr(payload, "registerValue"):
                    value = int(payload.registerValue)
                if hasattr(payload, "outputValues"):
                    values = list(payload.outputValues) if payload.outputValues else []

                # Response: register/coil values
                if direction == "response" and hasattr(payload, "registerVal"):
                    vals = payload.registerVal
                    if vals is not None:
                        values = list(vals) if hasattr(vals, "__iter__") else [vals]

            return {
                "protocol": self.name,
                "direction": direction,
                "trans_id": trans_id,
                "unit_id": unit_id,
                "func_code": func_code,
                "op": op_name.replace(" ", "_").lower() if op_name else "unknown",
                "op_name": op_name,
                "start_addr": start_addr,
                "quantity": quantity,
                "address": address,
                "value": value,
                "values": values,
                "exception_code": exception_code,
                "raw_hex": raw_hex,
            }
        except Exception:
            return None

    def build_read_holding_registers(
        self,
        unit_id: int,
        start_addr: int,
        count: int,
        trans_id: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[bytes]:
        mb = _scapy_modbus()
        tid = trans_id if trans_id is not None else random.randint(1, 65535)
        pdu = mb.ModbusPDU03ReadHoldingRegistersRequest(startAddr=start_addr, quantity=count)
        adu = mb.ModbusADURequest(transId=tid, unitId=unit_id) / pdu
        return bytes(adu)

    def build_write_single_register(
        self,
        unit_id: int,
        addr: int,
        value: int,
        trans_id: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[bytes]:
        mb = _scapy_modbus()
        tid = trans_id if trans_id is not None else random.randint(1, 65535)
        pdu = mb.ModbusPDU06WriteSingleRegisterRequest(registerAddr=addr, registerValue=value)
        adu = mb.ModbusADURequest(transId=tid, unitId=unit_id) / pdu
        return bytes(adu)

    def build_write_multiple_registers(
        self,
        unit_id: int,
        start_addr: int,
        values: list,
        trans_id: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[bytes]:
        mb = _scapy_modbus()
        tid = trans_id if trans_id is not None else random.randint(1, 65535)
        pdu = mb.ModbusPDU10WriteMultipleRegistersRequest(
            startAddr=start_addr, quantityRegisters=len(values), outputsValue=values
        )
        adu = mb.ModbusADURequest(transId=tid, unitId=unit_id) / pdu
        return bytes(adu)
