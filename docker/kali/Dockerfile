FROM kalilinux/kali-rolling:latest

LABEL description="Kali OT pentest box — Modbuster ICS traffic analysis"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        python3-tk \
        tcpdump \
        libpcap-dev \
        nmap \
        netcat-traditional \
        iproute2 \
        iputils-ping \
        iptables \
        dsniff \
        arping \
        curl \
        wget \
        less \
        vim-tiny \
        xfce4 \
        xfce4-terminal \
        tigervnc-standalone-server \
        novnc \
        websockify \
        dbus-x11 \
        x11-utils \
        libglib2.0-bin \
        zathura \
        librsvg2-bin \
        mousepad \
    && rm -rf /var/lib/apt/lists/*

# Install Modbuster dependencies including GUI support
RUN pip3 install --no-cache-dir --break-system-packages \
        "scapy>=2.5" \
        "rich>=13.0" \
        "customtkinter>=5.0" \
        "pymodbus>=3.0,<4.0" \
        "fpdf2>=2.7"

# Modbuster source is volume-mounted at /opt/modbuster by docker-compose
ENV PYTHONPATH="/opt/modbuster:${PYTHONPATH}"

RUN mkdir -p /workspace
WORKDIR /workspace

COPY entrypoint.sh /entrypoint.sh
COPY start_desktop.sh /start_desktop.sh
COPY modbuster_icon.svg /tmp/modbuster_icon.svg
RUN rsvg-convert -w 128 -h 128 /tmp/modbuster_icon.svg -o /usr/share/pixmaps/modbuster.png \
    && rm /tmp/modbuster_icon.svg
RUN chmod +x /entrypoint.sh /start_desktop.sh

# Expose noVNC (browser) and raw VNC ports
EXPOSE 6080 5901

CMD ["/bin/bash"]
