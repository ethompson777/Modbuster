"""
web_gui.py — Field Device Web Dashboard (Flask + Socket.IO)

Shared state is populated by field_device.py and served here.
Runs in a daemon thread alongside the async Modbus server.
"""

import logging
import threading

from flask import Flask, render_template, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO

log = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = "ics-lab-field-device"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
# Shared state — written by field_device.py, read here
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
shared_state = {
    "registers": {1: [0] * 10, 2: [0] * 10, 3: [0] * 10},
    "scaled": {1: {}, 2: {}, 3: {}},
    "register_names": {},
    "request_log": [],
}

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
            "registers": {str(k): v for k, v in shared_state["registers"].items()},
            "scaled": {str(k): v for k, v in shared_state["scaled"].items()},
            "names": shared_state["register_names"],
            "request_log": shared_state["request_log"][:50],
        })


@socketio.on("connect")
def on_connect():
    with state_lock:
        socketio.emit("registers", {
            "registers": {str(k): v for k, v in shared_state["registers"].items()},
            "scaled": {str(k): {str(a): v for a, v in sv.items()} for k, sv in shared_state["scaled"].items()},
            "names": shared_state["register_names"],
        })
        socketio.emit("full_log", {"entries": shared_state["request_log"]})


# ---------------------------------------------------------------------------
# Entry point (called from field_device.py in a thread)
# ---------------------------------------------------------------------------

def run_web(port: int = 8081) -> None:
    log.info("Web dashboard starting on port %d", port)
    socketio.run(app, host="0.0.0.0", port=port, use_reloader=False, log_output=False, allow_unsafe_werkzeug=True)
