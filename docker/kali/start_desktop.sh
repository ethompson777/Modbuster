#!/usr/bin/env bash
# ============================================================
# Start XFCE desktop + VNC + noVNC for Kali pentest container
# Access via browser: http://localhost:6080/vnc.html  (no password)
# ============================================================

# Kill any existing VNC sessions and clean lock files
tigervncserver -kill :1 2>/dev/null || true
sleep 1
rm -f /tmp/.X1-lock /tmp/.X11-unix/X1 2>/dev/null || true

# Start dbus system daemon
mkdir -p /var/run/dbus
dbus-daemon --system --fork 2>/dev/null || true

mkdir -p ~/.vnc

# Start Xtigervnc DIRECTLY (bypasses the tigervncserver wrapper
# which ignores -SecurityTypes and always forces VncAuth)
Xtigervnc :1 \
    -SecurityTypes None \
    -rfbport 5901 \
    -localhost 0 \
    -desktop "Kali Pentest" \
    -geometry 1920x1080 \
    -depth 24 \
    -auth /root/.Xauthority \
    &

sleep 3

# Start XFCE on display :1
export DISPLAY=:1
export XDG_SESSION_TYPE=x11
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
dbus-launch --exit-with-session startxfce4 &

sleep 2

# Create Modbuster desktop launcher
mkdir -p ~/Desktop
cat > ~/Desktop/Modbuster.desktop <<'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Modbuster
Comment=ICS/SCADA Pentest Tool
Exec=bash -c "cd /opt/modbuster && python3 -m modbuster gui"
Icon=/usr/share/pixmaps/modbuster.png
Terminal=false
Categories=Security;
EOF
chmod +x ~/Desktop/Modbuster.desktop
# Trust the launcher so XFCE doesn't show an "untrusted" warning.
# xfce4-desktop must be running before gio set will stick — wait for it.
(
  for i in $(seq 1 20); do
    if pgrep -x xfce4-desktop >/dev/null 2>&1; then
      gio set ~/Desktop/Modbuster.desktop metadata::trusted true 2>/dev/null || true
      break
    fi
    sleep 1
  done
) &

# Kill any stale websockify and start fresh
pkill -f websockify 2>/dev/null || true
sleep 1
websockify --web /usr/share/novnc/ 6080 localhost:5901 &

echo ""
echo "================================================================"
echo "  Kali Desktop Ready"
echo "  Open in browser: http://localhost:6080/vnc.html"
echo "  Click Connect — NO password required"
echo "  Then run: python3 -m modbuster gui"
echo "================================================================"
echo ""

tail -f /dev/null
