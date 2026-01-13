#!/bin/bash
# Starts tcpdump in monitor mode and writes to Named Pipe

set -e

# Configuration
INTERFACE="${1:-wlan0mon}"
FIFO_PATH="${2:-/tmp/tcpdump_fifo}"
SNAPLEN=2048

echo "=================================================="
echo "WLAN Packet Capture - tcpdump Starter"
echo "=================================================="
echo "Interface: $INTERFACE"
echo "Named Pipe: $FIFO_PATH"
echo ""

# Check if script is running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root!"
    echo "Usage: sudo $0 [interface] [fifo_path]"
    exit 1
fi

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo "ERROR: Interface '$INTERFACE' not found!"
    echo ""
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print "  - " $2}' | sed 's/:$//'
    echo ""
    echo "To put an interface into monitor mode:"
    echo "  sudo ip link set wlan0 down"
    echo "  sudo iw wlan0 set monitor none"
    echo "  sudo ip link set wlan0 up"
    echo "  sudo ip link set wlan0 name wlan0mon"
    exit 1
fi

# Check if tcpdump is installed
if ! command -v tcpdump &> /dev/null; then
    echo "ERROR: tcpdump not found!"
    echo "Install with: sudo apt-get install tcpdump"
    exit 1
fi

# Create Named Pipe if it doesn't exist
if [ ! -p "$FIFO_PATH" ]; then
    echo "Creating Named Pipe: $FIFO_PATH"
    mkfifo "$FIFO_PATH"
else
    echo "Named Pipe already exists: $FIFO_PATH"
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping tcpdump..."
    if [ -n "$TCPDUMP_PID" ]; then
        kill $TCPDUMP_PID 2>/dev/null || true
        wait $TCPDUMP_PID 2>/dev/null || true
    fi
    echo "tcpdump stopped."
}

trap cleanup EXIT INT TERM

# Start tcpdump
echo ""
echo "Starting tcpdump..."
echo "Command: tcpdump -i $INTERFACE -s $SNAPLEN -w - -U"
echo ""
echo "tcpdump is running. Packets are being written to Named Pipe."
echo "Press Ctrl+C to stop"
echo "=================================================="

# -i: Interface
# -s: Snaplen (bytes per packet)
# -w -: Write to stdout
# -U: Unbuffered (important for streaming!)
tcpdump -i "$INTERFACE" -s "$SNAPLEN" -w - -U > "$FIFO_PATH" &
TCPDUMP_PID=$!

# Wait for tcpdump process
wait $TCPDUMP_PID
