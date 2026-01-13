#!/usr/bin/env python3
"""
Minimalist HTTP server for WLAN packet streaming.
Uses only Python stdlib - no external dependencies!

tcpdump runs permanently in the background and writes to stdout.
This server streams filtered PCAP data live via HTTP.

Usage:
    # Terminal 1: Start tcpdump (as root/sudo)
    sudo tcpdump -i wlan0mon -w - -U | python3 capture_stream.py
    
    # Or with Named Pipe:
    mkfifo /tmp/tcpdump_fifo
    sudo tcpdump -i wlan0mon -w - -U > /tmp/tcpdump_fifo &
    python3 capture_stream.py --input /tmp/tcpdump_fifo

API:
    GET /stream?filter=<wireshark_filter>&duration=<seconds>
"""

import sys
import subprocess
import signal
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import os

# Configuration
DEFAULT_PORT = 8000
DEFAULT_INPUT = "/tmp/tcpdump_fifo"  # Named Pipe
CHUNK_SIZE = 8192


class StreamHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for PCAP streaming."""
    
    def log_message(self, format, *args):
        """Log with timestamp."""
        sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {format % args}\n")
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        
        if parsed_url.path == '/':
            self.send_info_page()
        elif parsed_url.path == '/stream':
            self.handle_stream(parsed_url.query)
        else:
            self.send_error(404, "Not found")
    
    def send_info_page(self):
        """Sends a simple info page."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>WLAN Packet Capture Stream</title>
    <style>
        body {{ font-family: monospace; padding: 20px; max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
        code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>WLAN Packet Capture Stream API</h1>
    <p>Server is running and receiving packets from tcpdump.</p>
    
    <h2>API Endpoint</h2>
    <p><code>GET /stream?filter=&lt;wireshark_filter&gt;&amp;duration=&lt;seconds&gt;</code></p>
    
    <h3>Parameters:</h3>
    <ul>
        <li><strong>filter</strong> (optional): Wireshark Display Filter<br>
            Example: <code>wlan.fc.type_subtype == 0x000e</code></li>
        <li><strong>duration</strong> (optional): Duration in seconds (default: unlimited)</li>
    </ul>
    
    <h3>Examples:</h3>
    <pre># All packets for 60 seconds
curl "http://localhost:8000/stream?duration=60" > capture.pcap

# Only Action Frames
curl "http://localhost:8000/stream?filter=wlan.fc.type_subtype%20%3D%3D%200x000e" > filtered.pcap

# With time limit and filter
curl "http://localhost:8000/stream?filter=wlan.fc.type_subtype%20%3D%3D%200x000e&duration=30" > capture.pcap</pre>
    
    <h3>Status:</h3>
    <p>Input source: <code>{input_source}</code></p>
</body>
</html>""".format(input_source=self.server.input_source)
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_stream(self, query_string):
        """Streams filtered PCAP data."""
        # Parse query parameters
        params = parse_qs(query_string)
        filter_expr = params.get('filter', [None])[0]
        duration = params.get('duration', [None])[0]
        
        self.log_message(f"Stream request: filter={filter_expr}, duration={duration}")
        
        # Validate duration
        timeout = None
        if duration:
            try:
                timeout = float(duration)
                if timeout <= 0:
                    self.send_error(400, "Duration must be positive")
                    return
            except ValueError:
                self.send_error(400, "Invalid duration")
                return
        
        # Open input source (Named Pipe or stdin)
        # IMPORTANT: For Named Pipes we need to reopen them for each request
        # To keep tcpdump alive, use pipe_buffer.py or tee
        try:
            if self.server.input_source == "stdin":
                # Read from stdin (tcpdump was started via pipe)
                input_fd = sys.stdin.buffer
            else:
                # Open Named Pipe for this request
                # If tcpdump terminates, use pipe_buffer.py or tee
                input_fd = open(self.server.input_source, 'rb')
        except Exception as e:
            self.log_message(f"Error opening input source: {e}")
            self.send_error(500, f"Cannot open input: {e}")
            return
        
        try:
            # Wenn Filter gesetzt ist, verwende tshark zum Filtern
            if filter_expr:
                self.stream_with_filter(input_fd, filter_expr, timeout)
            else:
                self.stream_raw(input_fd, timeout)
        except BrokenPipeError:
            self.log_message("Client closed connection")
        except Exception as e:
            self.log_message(f"Error during streaming: {e}")
        finally:
            # Close the pipe FD for this request
            if self.server.input_source != "stdin":
                try:
                    input_fd.close()
                except:
                    pass
    
    def stream_raw(self, input_fd, timeout):
        """Streams PCAP data without filter."""
        # Collect data first to determine Content-Length
        # Or use Chunked Encoding for unknown size
        start_time = time.time()
        bytes_sent = 0
        chunks = []
        
        # Read data with timeout
        while True:
            # Timeout check
            if timeout and (time.time() - start_time) >= timeout:
                self.log_message(f"Timeout reached ({timeout}s), ending stream")
                break
            
            # Read chunk
            chunk = input_fd.read(CHUNK_SIZE)
            if not chunk:
                # Check if more data is coming (short pause)
                time.sleep(0.01)
                # If timeout reached, end
                if timeout and (time.time() - start_time) >= timeout:
                    break
                continue
            
            chunks.append(chunk)
            bytes_sent += len(chunk)
        
        # Send response with all data
        total_size = sum(len(c) for c in chunks)
        self.send_response(200)
        self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
        self.send_header('Content-Disposition', 'attachment; filename="capture.pcap"')
        self.send_header('Content-Length', str(total_size))
        self.end_headers()
        
        # Send all chunks
        for chunk in chunks:
            self.wfile.write(chunk)
        
        self.wfile.flush()
        self.log_message(f"Stream ended: {bytes_sent} bytes sent")
    
    def stream_with_filter(self, input_fd, filter_expr, timeout):
        """Streams PCAP data with tshark filter."""
        self.log_message(f"Starting tshark with filter: {filter_expr}")
        
        # Build tshark command
        cmd = [
            'tshark',
            '-r', '-',           # Read from stdin
            '-Y', filter_expr,   # Display Filter
            '-w', '-',           # Write to stdout
        ]
        
        # Add time limit (tshark -a duration:X)
        if timeout:
            cmd.extend(['-a', f'duration:{int(timeout)}'])
        
        try:
            # Start tshark process
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Send HTTP response headers
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
            self.send_header('Content-Disposition', 'attachment; filename="filtered_capture.pcap"')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            
            # Thread to feed tshark with data
            def feed_tshark():
                try:
                    while True:
                        chunk = input_fd.read(CHUNK_SIZE)
                        if not chunk:
                            time.sleep(0.01)
                            continue
                        proc.stdin.write(chunk)
                        proc.stdin.flush()
                except (BrokenPipeError, IOError):
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except:
                        pass
            
            feeder = threading.Thread(target=feed_tshark, daemon=True)
            feeder.start()
            
            # Read filtered output from tshark and stream to client
            start_time = time.time()
            bytes_sent = 0
            
            while True:
                # Timeout check
                if timeout and (time.time() - start_time) >= timeout:
                    proc.terminate()
                    break
                
                # Check if tshark is still running
                if proc.poll() is not None:
                    break
                
                # Read chunk from tshark
                chunk = proc.stdout.read(CHUNK_SIZE)
                if not chunk:
                    time.sleep(0.01)
                    continue
                
                # Send chunk to client
                self.wfile.write(f"{len(chunk):X}\r\n".encode())
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
                
                bytes_sent += len(chunk)
            
            # End chunk
            self.wfile.write(b"0\r\n\r\n")
            
            # Wait for tshark
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            
            self.log_message(f"Stream ended: {bytes_sent} bytes sent (filtered)")
            
            # Show tshark stderr (errors/warnings)
            stderr = proc.stderr.read().decode('utf-8', errors='ignore')
            if stderr:
                self.log_message(f"tshark stderr: {stderr}")
        
        except FileNotFoundError:
            self.send_error(500, "tshark not found. Please install: sudo apt-get install tshark")
        except Exception as e:
            self.log_message(f"Error with tshark: {e}")
            self.send_error(500, f"Error during filtering: {e}")


class StreamingServer(HTTPServer):
    """HTTP Server with input source tracking."""
    
    def __init__(self, server_address, RequestHandlerClass, input_source):
        super().__init__(server_address, RequestHandlerClass)
        self.input_source = input_source


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='WLAN Packet Capture Streaming Server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                       help=f'Server port (default: {DEFAULT_PORT})')
    parser.add_argument('--input', default=DEFAULT_INPUT,
                       help=f'Input source: Named Pipe or "stdin" (default: {DEFAULT_INPUT})')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Server host (default: 0.0.0.0)')
    
    args = parser.parse_args()
    
    # Check if input source exists (except for stdin)
    if args.input != "stdin" and not os.path.exists(args.input):
        print(f"Warning: Input source '{args.input}' does not exist!", file=sys.stderr)
        print(f"Creating Named Pipe...", file=sys.stderr)
        try:
            os.mkfifo(args.input)
            print(f"Named Pipe created: {args.input}", file=sys.stderr)
            print(f"Start tcpdump with: sudo tcpdump -i wlan0mon -w - -U > {args.input} &", file=sys.stderr)
        except Exception as e:
            print(f"Error creating Named Pipe: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Start server
    server = StreamingServer((args.host, args.port), StreamHandler, args.input)
    
    print(f"WLAN Packet Capture Streaming Server", file=sys.stderr)
    print(f"=" * 50, file=sys.stderr)
    print(f"Server running on: http://{args.host}:{args.port}", file=sys.stderr)
    print(f"Input source: {args.input}", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"API endpoint: /stream?filter=<filter>&duration=<seconds>", file=sys.stderr)
    print(f"Info page: http://{args.host}:{args.port}/", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"Example:", file=sys.stderr)
    print(f'  curl "http://localhost:{args.port}/stream?duration=10" > capture.pcap', file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"Press Ctrl+C to stop", file=sys.stderr)
    print(f"=" * 50, file=sys.stderr)
    
    # Signal handler for clean shutdown
    def signal_handler(sig, frame):
        print("\nStopping server...", file=sys.stderr)
        server.shutdown()
        server.server_close()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # serve_forever with poll_interval so shutdown() is quickly recognized
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping server...", file=sys.stderr)
        server.shutdown()
        server.server_close()
    finally:
        print("Server stopped.", file=sys.stderr)


if __name__ == '__main__':
    main()
