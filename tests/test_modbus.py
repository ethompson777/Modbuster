"""Unit tests for Modbus protocol handler and interpreter."""

import io
import struct
import pytest

# Build minimal Modbus TCP packet: MBAP (7 bytes) + PDU
def _mbap(trans_id: int, unit_id: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, unit_id) + pdu


def _pdu_read_holding(start: int, count: int) -> bytes:
    return bytes([0x03, (start >> 8) & 0xFF, start & 0xFF, (count >> 8) & 0xFF, count & 0xFF])


def _pdu_write_register(addr: int, value: int) -> bytes:
    return bytes([0x06, (addr >> 8) & 0xFF, addr & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


@pytest.fixture
def modbus_handler():
    from modbuster.protocols.modbus import ModbusHandler
    return ModbusHandler()


@pytest.fixture
def read_holding_packet():
    """One Modbus read holding registers request (raw bytes)."""
    from scapy.all import Ether, IP, TCP, Raw
    pdu = _pdu_read_holding(0, 10)
    payload = _mbap(1, 1, pdu)
    return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=502, flags="PA") / Raw(load=payload)


@pytest.fixture
def write_register_packet():
    """One Modbus write single register request."""
    from scapy.all import Ether, IP, TCP, Raw
    pdu = _pdu_write_register(0, 1234)
    payload = _mbap(2, 1, pdu)
    return Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50001, dport=502, flags="PA") / Raw(load=payload)


def test_modbus_detect(modbus_handler):
    from scapy.contrib.modbus import ModbusADURequest, ModbusPDU03ReadHoldingRegistersRequest
    from scapy.all import Ether, IP, TCP
    pdu = ModbusPDU03ReadHoldingRegistersRequest(startAddr=0, quantity=10)
    adu = ModbusADURequest(transId=1, unitId=1) / pdu
    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=502) / adu
    assert modbus_handler.detect(pkt) is True


def test_modbus_parse_read_holding(modbus_handler):
    from scapy.contrib.modbus import ModbusADURequest, ModbusPDU03ReadHoldingRegistersRequest
    from scapy.all import Ether, IP, TCP
    pdu = ModbusPDU03ReadHoldingRegistersRequest(startAddr=0, quantity=10)
    adu = ModbusADURequest(transId=1, unitId=1) / pdu
    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=502) / adu
    parsed = modbus_handler.parse(pkt)
    assert parsed is not None
    assert parsed["protocol"] == "modbus"
    assert parsed["direction"] == "request"
    assert parsed["unit_id"] == 1
    assert parsed["op_name"] == "Read Holding Registers"
    assert parsed["start_addr"] == 0
    assert parsed["quantity"] == 10


def test_modbus_build_read_holding(modbus_handler):
    payload = modbus_handler.build_read_holding_registers(unit_id=1, start_addr=0, count=5)
    assert payload is not None
    assert len(payload) >= 12  # MBAP + PDU
    assert payload[7] == 0x03  # MBAP is 7 bytes; byte 7 is function code Read Holding Registers


def test_modbus_build_write_single(modbus_handler):
    payload = modbus_handler.build_write_single_register(unit_id=1, addr=0, value=100)
    assert payload is not None
    assert len(payload) >= 12
    assert payload[7] == 0x06  # MBAP 7 bytes; byte 7 is function code Write Single Register


def test_interpreter_format_line():
    from scapy.contrib.modbus import ModbusADURequest, ModbusPDU03ReadHoldingRegistersRequest
    from scapy.all import Ether, IP, TCP
    from modbuster.interpreter import format_line
    pdu = ModbusPDU03ReadHoldingRegistersRequest(startAddr=0, quantity=10)
    adu = ModbusADURequest(transId=1, unitId=1) / pdu
    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=50000, dport=502) / adu
    parsed = {"protocol": "modbus", "direction": "request", "unit_id": 1, "op_name": "Read Holding Registers", "start_addr": 0, "quantity": 10}
    line = format_line(pkt, "modbus", parsed)
    assert "modbus" in line
    assert "request" in line
    assert "Read Holding Registers" in line
    assert "addr=0" in line
    assert "count=10" in line


def test_summary():
    from modbuster.interpreter import summary
    records = [
        {"protocol": "modbus", "unit_id": 1, "op_name": "Read Holding Registers", "func_code": 3},
        {"protocol": "modbus", "unit_id": 1, "op_name": "Write Single Register", "func_code": 6},
    ]
    s = summary(records)
    assert s["total_messages"] == 2
    assert s["read_count"] == 1
    assert s["write_count"] == 1
    assert "modbus" in s["by_protocol"]
