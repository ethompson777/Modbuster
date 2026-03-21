FROM kalilinux/kali-rolling:latest

LABEL description="Kali OT pentest box — Modbuster ICS traffic analysis"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        tcpdump \
        libpcap-dev \
        nmap \
        netcat-traditional \
        iproute2 \
        iputils-ping \
        curl \
        wget \
        less \
        vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# Install Modbuster CLI dependencies (no customtkinter — no display in container)
RUN pip3 install --no-cache-dir --break-system-packages \
        "scapy>=2.5" \
        "rich>=13.0" \
        "pymodbus>=3.0,<4.0"

# Modbuster source is volume-mounted at /opt/modbuster by docker-compose
ENV PYTHONPATH="/opt/modbuster:${PYTHONPATH}"

RUN mkdir -p /workspace
WORKDIR /workspace

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/bin/bash"]
