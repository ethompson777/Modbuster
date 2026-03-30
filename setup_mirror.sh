#!/usr/bin/env bash
# ============================================================
# Set up TC port mirroring so Kali container can see all
# Modbus traffic between controller and both field devices.
# Run this after "docker compose up -d"
# ============================================================
set -e

# Find the bridge for ics_network
BR=$(ip link show | grep -oP 'br-[a-f0-9]+' | head -1)
if [ -z "$BR" ]; then
  echo "ERROR: Docker bridge not found. Is 'docker compose up -d' running?"
  exit 1
fi
echo "Bridge: $BR"

# Match veths to containers via bridge FDB MAC table
CTRL_MAC=$(docker exec controller cat /sys/class/net/eth0/address 2>/dev/null)
FD1_MAC=$(docker exec field_device_1 cat /sys/class/net/eth0/address 2>/dev/null)
FD2_MAC=$(docker exec field_device_2 cat /sys/class/net/eth0/address 2>/dev/null)
KALI_MAC=$(docker exec kali_pentest cat /sys/class/net/eth0/address 2>/dev/null)

echo "Controller MAC:    $CTRL_MAC"
echo "Field Device 1 MAC: $FD1_MAC"
echo "Field Device 2 MAC: $FD2_MAC"
echo "Kali MAC:          $KALI_MAC"

find_veth() {
  local target_mac="$1"
  for veth in $(ip link show master $BR | grep -oP '^\d+: \K\S+(?=@)'); do
    if bridge fdb show dev $veth 2>/dev/null | grep -q "$target_mac"; then
      echo "$veth"
      return
    fi
  done
}

CTRL_VETH=$(find_veth "$CTRL_MAC")
FD1_VETH=$(find_veth "$FD1_MAC")
FD2_VETH=$(find_veth "$FD2_MAC")
KALI_VETH=$(find_veth "$KALI_MAC")

echo "Controller veth:    $CTRL_VETH"
echo "Field Device 1 veth: $FD1_VETH"
echo "Field Device 2 veth: $FD2_VETH"
echo "Kali veth:          $KALI_VETH"

if [ -z "$CTRL_VETH" ] || [ -z "$FD1_VETH" ] || [ -z "$FD2_VETH" ] || [ -z "$KALI_VETH" ]; then
  echo "ERROR: Could not identify all veth interfaces."
  exit 1
fi

# Clear existing rules and set up fresh mirroring
for dev in $CTRL_VETH $FD1_VETH $FD2_VETH; do
  tc qdisc del dev $dev ingress 2>/dev/null || true
  tc qdisc del dev $dev root    2>/dev/null || true

  # ingress = packets coming OUT of the container (requests/responses)
  tc qdisc add dev $dev handle ffff: ingress
  tc filter add dev $dev parent ffff: matchall action mirred egress mirror dev $KALI_VETH

  # egress = packets going INTO the container
  tc qdisc add dev $dev root handle 1: prio
  tc filter add dev $dev parent 1: matchall action mirred egress mirror dev $KALI_VETH
done

echo ""
echo "Done — Kali ($KALI_VETH) now mirrors all traffic between"
echo "  controller ($CTRL_VETH) <-> field-device-1 ($FD1_VETH)"
echo "  controller ($CTRL_VETH) <-> field-device-2 ($FD2_VETH)"
echo ""
echo "In Modbuster GUI: select interface 'eth0', click Start Live."
