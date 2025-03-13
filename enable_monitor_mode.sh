#!/bin/bash
# Script to set a wireless interface to monitor mode

if [ -z "$1" ]; then
    echo "Usage: $0 <wireless-interface>"
    echo "Example: $0 wlan1"
    exit 1
fi

INTERFACE=$1

# Check if interface exists
if ! ip link show $INTERFACE &>/dev/null; then
    echo "Error: Interface $INTERFACE does not exist"
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/ //g'
    exit 1
fi

echo "Setting up $INTERFACE for monitor mode..."

# Bring the interface down
echo "Bringing interface down..."
ip link set $INTERFACE down

# Set interface to monitor mode
echo "Setting monitor mode..."
iw dev $INTERFACE set type monitor

# Bring the interface up
echo "Bringing interface up..."
ip link set $INTERFACE up

# Verify monitor mode
if iw dev $INTERFACE info | grep -q "type monitor"; then
    echo "Success! $INTERFACE is now in monitor mode"
else
    echo "Failed to set $INTERFACE to monitor mode"
    echo "Check if your card supports monitor mode"
    exit 1
fi

echo "Monitor mode setup complete."
echo "You can now run: sudo python3 wifi_monitor.py"