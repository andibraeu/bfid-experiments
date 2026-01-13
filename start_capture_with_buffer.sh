#!/bin/bash
# Starts tcpdump with buffer solution
# Uses 'tee' to create multiple pipes or a buffer process

set -e

# Configuration
INTERFACE="${1:-wlan0mon}"
FIFO_PATH="${2:-/tmp/tcpdump_fifo}"
BUFFER_FIFO="${3:-/tmp/tcpdump_buffer.fifo}"
SNAPLEN=2048
BUFFER_METHOD="${4:-cat}"  # "cat" or "python"

echo "=================================================="
echo "WLAN Packet Capture - tcpdump with Buffer"
echo "=================================================="
echo "Interface: $INTERFACE"
echo "Input Pipe: $FIFO_PATH"
echo "Buffer Pipe: $BUFFER_FIFO"
echo "Method: $BUFFER_METHOD"
echo ""

# Check if script is running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root!"
    echo "Usage: sudo $0 [interface] [input_fifo] [buffer_fifo] [method]"
    exit 1
fi

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo "ERROR: Interface '$INTERFACE' not found!"
    exit 1
fi

# Create Named Pipes
if [ ! -p "$FIFO_PATH" ]; then
    echo "Creating input pipe: $FIFO_PATH"
    mkfifo "$FIFO_PATH"
fi

if [ ! -p "$BUFFER_FIFO" ]; then
    echo "Creating buffer pipe: $BUFFER_FIFO"
    mkfifo "$BUFFER_FIFO"
fi

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping processes..."
    if [ -n "$TCPDUMP_PID" ]; then
        kill $TCPDUMP_PID 2>/dev/null || true
        wait $TCPDUMP_PID 2>/dev/null || true
    fi
    if [ -n "$BUFFER_PID" ]; then
        kill $BUFFER_PID 2>/dev/null || true
        wait $BUFFER_PID 2>/dev/null || true
    fi
    echo "Stopped."
}

trap cleanup EXIT INT TERM

# Start tcpdump
echo ""
echo "Starting tcpdump..."
tcpdump -i "$INTERFACE" -s "$SNAPLEN" -w - -U > "$FIFO_PATH" &
TCPDUMP_PID=$!

# Wait briefly for tcpdump to start
sleep 1

# Start buffer process
if [ "$BUFFER_METHOD" = "cat" ] || [ "$BUFFER_METHOD" = "tee" ]; then
    echo "Starting cat as buffer..."
    # cat reads from input pipe and writes to buffer pipe
    # The trick: cat keeps the input pipe open so tcpdump doesn't terminate
    # Even if no one reads from the buffer pipe, tcpdump continues running
    cat "$FIFO_PATH" > "$BUFFER_FIFO" &
    BUFFER_PID=$!
    echo "cat is running (PID: $BUFFER_PID)"
elif [ "$BUFFER_METHOD" = "python" ]; then
    echo "Starting Python buffer process..."
    # Find Python script
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PYTHON_SCRIPT="$SCRIPT_DIR/pipe_buffer.py"
    
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo "ERROR: pipe_buffer.py not found in $SCRIPT_DIR"
        exit 1
    fi
    
    python3 "$PYTHON_SCRIPT" "$FIFO_PATH" "$BUFFER_FIFO" &
    BUFFER_PID=$!
    echo "Python buffer is running (PID: $BUFFER_PID)"
else
    echo "ERROR: Unknown method: $BUFFER_METHOD"
    echo "Usage: cat or python"
    exit 1
fi

echo ""
echo "tcpdump is running (PID: $TCPDUMP_PID)"
echo "Buffer process is running (PID: $BUFFER_PID)"
echo ""
echo "Use the buffer pipe for your consumer:"
echo "  python3 capture_stream.py --input $BUFFER_FIFO"
echo ""
echo "Press Ctrl+C to stop"
echo "=================================================="

# Wait for processes
wait $TCPDUMP_PID
