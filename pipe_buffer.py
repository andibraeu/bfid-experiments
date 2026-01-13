#!/usr/bin/env python3
"""
Buffer process for Named Pipe.
Continuously reads from the Named Pipe and buffers the data,
so tcpdump doesn't terminate when no consumer is reading.

Usage:
    # Terminal 1: Start tcpdump
    sudo tcpdump -i wlan0mon -w - -U > /tmp/tcpdump_fifo &
    
    # Terminal 2: Start buffer process
    python3 pipe_buffer.py /tmp/tcpdump_fifo /tmp/tcpdump_buffer.fifo
    
    # Terminal 3: Start HTTP Server
    python3 capture_stream.py --input /tmp/tcpdump_buffer.fifo
"""

import sys
import os
import time
import signal
from threading import Thread, Event

BUFFER_SIZE = 1024 * 1024  # 1 MB Ringbuffer
CHUNK_SIZE = 8192


class RingBuffer:
    """Simple ring buffer for PCAP data."""
    
    def __init__(self, size):
        self.size = size
        self.buffer = bytearray(size)
        self.write_pos = 0
        self.read_pos = 0
        self.data_available = 0
        self.lock = Event()
        self.lock.set()
    
    def write(self, data):
        """Writes data to the ring buffer (overwrites old data when full)."""
        data_len = len(data)
        if data_len >= self.size:
            # Data is larger than buffer - only keep the last bytes
            data = data[-self.size:]
            data_len = self.size
        
        self.lock.clear()
        try:
            for byte in data:
                self.buffer[self.write_pos] = byte
                self.write_pos = (self.write_pos + 1) % self.size
                self.data_available = min(self.data_available + 1, self.size)
        finally:
            self.lock.set()
    
    def read(self, size):
        """Reads data from the ring buffer."""
        self.lock.wait()
        read_size = min(size, self.data_available)
        if read_size == 0:
            return b''
        
        result = bytearray(read_size)
        for i in range(read_size):
            result[i] = self.buffer[self.read_pos]
            self.read_pos = (self.read_pos + 1) % self.size
        
        self.data_available -= read_size
        return bytes(result)
    
    def available(self):
        """Returns how many bytes are available."""
        return self.data_available


def reader_thread(input_pipe, ringbuffer, stop_event):
    """Thread that continuously reads from the input pipe."""
    print(f"Reader thread: Opening {input_pipe}", file=sys.stderr)
    
    try:
        with open(input_pipe, 'rb') as f:
            print(f"Reader thread: Pipe opened, reading data...", file=sys.stderr)
            while not stop_event.is_set():
                try:
                    chunk = f.read(CHUNK_SIZE)
                    if chunk:
                        ringbuffer.write(chunk)
                    else:
                        time.sleep(0.01)
                except Exception as e:
                    print(f"Reader thread error: {e}", file=sys.stderr)
                    time.sleep(0.1)
    except Exception as e:
        print(f"Reader thread: Cannot open pipe: {e}", file=sys.stderr)
        stop_event.set()


def writer_thread(output_pipe, ringbuffer, stop_event):
    """Thread that continuously writes to the output pipe."""
    print(f"Writer thread: Opening {output_pipe}", file=sys.stderr)
    
    # Create output pipe if it doesn't exist
    if not os.path.exists(output_pipe):
        os.mkfifo(output_pipe)
        print(f"Writer thread: Output pipe created: {output_pipe}", file=sys.stderr)
    
    try:
        with open(output_pipe, 'wb') as f:
            print(f"Writer thread: Output pipe opened, writing data...", file=sys.stderr)
            while not stop_event.is_set():
                if ringbuffer.available() > 0:
                    chunk = ringbuffer.read(CHUNK_SIZE)
                    if chunk:
                        f.write(chunk)
                        f.flush()
                else:
                    time.sleep(0.01)
    except Exception as e:
        print(f"Writer thread error: {e}", file=sys.stderr)
        stop_event.set()


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 pipe_buffer.py <input_pipe> <output_pipe>", file=sys.stderr)
        print("", file=sys.stderr)
        print("Example:", file=sys.stderr)
        print("  python3 pipe_buffer.py /tmp/tcpdump_fifo /tmp/tcpdump_buffer.fifo", file=sys.stderr)
        sys.exit(1)
    
    input_pipe = sys.argv[1]
    output_pipe = sys.argv[2]
    
    # Check if input pipe exists
    if not os.path.exists(input_pipe):
        print(f"ERROR: Input pipe '{input_pipe}' does not exist!", file=sys.stderr)
        print(f"Create it with: mkfifo {input_pipe}", file=sys.stderr)
        sys.exit(1)
    
    print("=" * 60, file=sys.stderr)
    print("Named Pipe Buffer Process", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"Input:  {input_pipe}", file=sys.stderr)
    print(f"Output: {output_pipe}", file=sys.stderr)
    print(f"Buffer: {BUFFER_SIZE / 1024 / 1024:.1f} MB", file=sys.stderr)
    print("", file=sys.stderr)
    print("Press Ctrl+C to stop", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    
    ringbuffer = RingBuffer(BUFFER_SIZE)
    stop_event = Event()
    
    # Start reader thread
    reader = Thread(target=reader_thread, args=(input_pipe, ringbuffer, stop_event), daemon=True)
    reader.start()
    
    # Start writer thread
    writer = Thread(target=writer_thread, args=(output_pipe, ringbuffer, stop_event), daemon=True)
    writer.start()
    
    # Signal handler
    def signal_handler(sig, frame):
        print("\nStopping buffer process...", file=sys.stderr)
        stop_event.set()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Wait for threads
    try:
        while reader.is_alive() and writer.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == '__main__':
    main()
