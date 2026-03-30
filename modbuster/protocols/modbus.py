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
            # Port number is more reliable than Scapy's layer heuristic — override if possible
            if pkt.haslayer("TCP") and direction is not None:
                tcp = pkt["TCP"]
                if tcp.sport == 502:
                    direction = "response"
                elif tcp.dport == 502:
                    direction = "request"
            if adu is None and pkt.haslayer("TCP") and pkt.haslayer("Raw"):
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

                # FC3/FC4/FC23 read start address; FC23 read part takes priority
                if hasattr(payload, "readStartingAddr"):      # FC23
                    start_addr = int(payload.readStartingAddr)
                elif hasattr(payload, "startAddr"):
                    start_addr = int(payload.startAddr)

                # Quantity of registers/coils to read
                if hasattr(payload, "readQuantityRegisters"): # FC23
                    quantity = int(payload.readQuantityRegisters)
                elif hasattr(payload, "quantityRegisters"):
                    quantity = int(payload.quantityRegisters)
                elif hasattr(payload, "quantity"):
                    quantity = int(payload.quantity)
                elif hasattr(payload, "quantityOutput"):      # FC15
                    quantity = int(payload.quantityOutput)

                # Single-register/coil write address and value (FC5, FC6)
                if hasattr(payload, "outputAddr"):
                    address = int(payload.outputAddr)
                elif hasattr(payload, "registerAddr"):
                    address = int(payload.registerAddr)
                if hasattr(payload, "outputValue"):
                    value = int(payload.outputValue)
                elif hasattr(payload, "registerValue"):
                    value = int(payload.registerValue)

                # Multi-register/coil write values (FC15, FC16, FC23)
                if hasattr(payload, "writeRegistersValue"):   # FC23 write part
                    values = list(payload.writeRegistersValue) if payload.writeRegistersValue else []
                elif hasattr(payload, "outputsValue"):        # FC15 coils / FC16 registers
                    values = list(payload.outputsValue) if payload.outputsValue else []
                elif hasattr(payload, "outputValues"):        # fallback for older Scapy builds
                    values = list(payload.outputValues) if payload.outputValues else []

                # FC23 write starting address (stored separately so feed() can record writes)
                if hasattr(payload, "writeStartingAddr"):
                    address = int(payload.writeStartingAddr)

                # Response read values: FC3/FC4/FC23 holding/input registers
                if direction == "response" and hasattr(payload, "registerVal"):
                    vals = payload.registerVal
                    if vals is not None:
                        values = list(vals) if hasattr(vals, "__iter__") else [vals]

                # Response read values: FC1 coils / FC2 discrete inputs
                if direction == "response" and hasattr(payload, "coilStatus"):
                    vals = payload.coilStatus
                    if vals is not None:
                        values = list(vals) if hasattr(vals, "__iter__") else [vals]
                if direction == "response" and hasattr(payload, "inputStatus"):
                    vals = payload.inputStatus
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

    def build_read_coils(
        self,
        unit_id: int,
        start_addr: int,
        count: int,
        trans_id: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[bytes]:
        mb = _scapy_modbus()
        tid = trans_id if trans_id is not None else random.randint(1, 65535)
        pdu = mb.ModbusPDU01ReadCoilsRequest(startAddr=start_addr, quantity=count)
        adu = mb.ModbusADURequest(transId=tid, unitId=unit_id) / pdu
        return bytes(adu)

    def build_write_single_coil(
        self,
        unit_id: int,
        addr: int,
        on: bool,
        trans_id: Optional[int] = None,
        **kwargs: Any,
    ) -> Optional[bytes]:
        mb = _scapy_modbus()
        tid = trans_id if trans_id is not None else random.randint(1, 65535)
        coil_value = 0xFF00 if on else 0x0000
        pdu = mb.ModbusPDU05WriteSingleCoilRequest(outputAddr=addr, outputValue=coil_value)
        adu = mb.ModbusADURequest(transId=tid, unitId=unit_id) / pdu
        return bytes(adu)

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
