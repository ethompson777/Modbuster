"""
web_gui.py — Controller Web Dashboard (Flask + Socket.IO)

Provides:
  GET  /         → dashboard HTML
  GET  /api/state → current state JSON
  POST /api/command → execute a manual Modbus command
                     body: {fc, unit, addr, count, value, values}
"""

import logging
import threading

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO

log = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = "ics-lab-controller"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
# Shared state — written by controller.py, read/written here
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
shared_state = {
    "registers": {1: {}, 2: {}, 3: {}},
    "register_names": {},
    "poll_log": [],
    "cmd_log": [],
}

# Connection info set by controller.py before starting this module
FIELD_DEVICE_HOST = "172.20.0.20"
FIELD_DEVICE_PORT = 502

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/state")
def api_state():
    with state_lock:
        return jsonify({
            "registers": {str(k): dict(v) for k, v in shared_state["registers"].items()},
            "names": shared_state["register_names"],
            "poll_log": shared_state["poll_log"][:50],
            "cmd_log": shared_state["cmd_log"][:50],
        })


@app.route("/api/command", methods=["POST"])
def api_command():
    """Execute a manual Modbus command and return the result."""
    data = request.get_json(force=True)
    fc = data.get("fc", "read_holding")
    unit = int(data.get("unit", 1))
    addr = int(data.get("addr", 0))
    count = int(data.get("count", 1))
    value = data.get("value")
    values = data.get("values")

    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(host=FIELD_DEVICE_HOST, port=FIELD_DEVICE_PORT, timeout=5)
        client.connect()
        if not client.connected:
            return jsonify({"ok": False, "error": "Could not connect to field device"}), 503

        result_data = {}

        if fc == "read_holding":
            rr = client.read_holding_registers(addr, count=count, device_id=unit)
            if rr.isError():
                result_data = {"ok": False, "error": str(rr)}
            else:
                result_data = {"ok": True, "values": list(rr.registers)}

        elif fc == "read_coils":
            rr = client.read_coils(addr, count=count, device_id=unit)
            if rr.isError():
                result_data = {"ok": False, "error": str(rr)}
            else:
                result_data = {"ok": True, "values": list(rr.bits[:count])}

        elif fc == "write_single":
            val = int(value) if value is not None else 0
            rr = client.write_register(addr, val, device_id=unit)
            result_data = {"ok": not rr.isError(), "error": str(rr) if rr.isError() else None}

        elif fc == "write_multiple":
            if isinstance(values, str):
                vals = [int(x.strip()) for x in values.split(",") if x.strip()]
            elif isinstance(values, list):
                vals = [int(x) for x in values]
            else:
                vals = [int(value)] if value is not None else [0]
            rr = client.write_registers(addr, vals, device_id=unit)
            result_data = {"ok": not rr.isError(), "error": str(rr) if rr.isError() else None}

        else:
            result_data = {"ok": False, "error": f"Unknown function: {fc}"}

        client.close()

    except Exception as exc:
        result_data = {"ok": False, "error": str(exc)}

    # Log the command
    from datetime import datetime
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "fc": fc,
        "unit": unit,
        "addr": addr,
        "count": count,
        "value": value,
        "values": values,
        "result": result_data,
    }
    with state_lock:
        shared_state["cmd_log"].insert(0, entry)
        if len(shared_state["cmd_log"]) > 50:
            shared_state["cmd_log"].pop()

    socketio.emit("cmd_result", {"entry": entry})
    return jsonify(result_data)


# ---------------------------------------------------------------------------
# Socket.IO events
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    with state_lock:
        socketio.emit("registers", {
            "registers": {str(k): dict(v) for k, v in shared_state["registers"].items()},
            "names": shared_state["register_names"],
        })
        socketio.emit("full_log", {
            "poll_log": shared_state["poll_log"][:50],
            "cmd_log": shared_state["cmd_log"][:50],
        })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_web(port: int = 8080) -> None:
    log.info("Controller web dashboard starting on port %d", port)
    socketio.run(app, host="0.0.0.0", port=port, use_reloader=False, log_output=False, allow_unsafe_werkzeug=True)
