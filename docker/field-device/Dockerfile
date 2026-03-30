FROM python:3.11-slim

LABEL description="Cruise ship ICS field device (Modbus TCP slave + web dashboard)"

RUN apt-get update && \
    apt-get install -y --no-install-recommends netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir \
    "pymodbus>=3.0,<4.0" \
    "Flask>=3.0" \
    "Flask-SocketIO>=5.3" \
    "Flask-CORS>=4.0" \
    "simple-websocket>=1.0"

COPY field_device.py web_gui.py ./
COPY templates/ templates/

EXPOSE 502 8081

CMD ["python3", "field_device.py"]
