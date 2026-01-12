#!/usr/bin/env python3
"""
Minimalistischer HTTP-Server für WLAN-Paket-Streaming.
Verwendet nur Python stdlib - keine externen Dependencies!

tcpdump läuft permanent im Hintergrund und schreibt auf stdout.
Dieser Server streamt gefilterte PCAP-Daten live über HTTP.

Verwendung:
    # Terminal 1: tcpdump starten (als root/sudo)
    sudo tcpdump -i wlan0mon -w - -U | python3 capture_stream.py
    
    # Oder mit Named Pipe:
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

# Konfiguration
DEFAULT_PORT = 8000
DEFAULT_INPUT = "/tmp/tcpdump_fifo"  # Named Pipe
CHUNK_SIZE = 8192


class StreamHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler für PCAP-Streaming."""
    
    def log_message(self, format, *args):
        """Log mit Zeitstempel."""
        sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {format % args}\n")
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        
        if parsed_url.path == '/':
            self.send_info_page()
        elif parsed_url.path == '/stream':
            self.handle_stream(parsed_url.query)
        else:
            self.send_error(404, "Nicht gefunden")
    
    def send_info_page(self):
        """Sendet eine einfache Info-Seite."""
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
    <p>Server läuft und empfängt Pakete von tcpdump.</p>
    
    <h2>API Endpunkt</h2>
    <p><code>GET /stream?filter=&lt;wireshark_filter&gt;&amp;duration=&lt;seconds&gt;</code></p>
    
    <h3>Parameter:</h3>
    <ul>
        <li><strong>filter</strong> (optional): Wireshark Display Filter<br>
            Beispiel: <code>wlan.fc.type_subtype == 0x000e</code></li>
        <li><strong>duration</strong> (optional): Dauer in Sekunden (default: unbegrenzt)</li>
    </ul>
    
    <h3>Beispiele:</h3>
    <pre># Alle Pakete für 60 Sekunden
curl "http://localhost:8000/stream?duration=60" > capture.pcap

# Nur Action Frames
curl "http://localhost:8000/stream?filter=wlan.fc.type_subtype%20%3D%3D%200x000e" > filtered.pcap

# Mit Zeitlimit und Filter
curl "http://localhost:8000/stream?filter=wlan.fc.type_subtype%20%3D%3D%200x000e&duration=30" > capture.pcap</pre>
    
    <h3>Status:</h3>
    <p>Input-Quelle: <code>{input_source}</code></p>
</body>
</html>""".format(input_source=self.server.input_source)
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_stream(self, query_string):
        """Streamt gefilterte PCAP-Daten."""
        # Parse Query-Parameter
        params = parse_qs(query_string)
        filter_expr = params.get('filter', [None])[0]
        duration = params.get('duration', [None])[0]
        
        self.log_message(f"Stream-Request: filter={filter_expr}, duration={duration}")
        
        # Validiere duration
        timeout = None
        if duration:
            try:
                timeout = float(duration)
                if timeout <= 0:
                    self.send_error(400, "Duration muss positiv sein")
                    return
            except ValueError:
                self.send_error(400, "Ungültige Duration")
                return
        
        # Öffne Input-Quelle (Named Pipe oder stdin)
        try:
            if self.server.input_source == "stdin":
                # Lese von stdin (tcpdump wurde via Pipe gestartet)
                input_fd = sys.stdin.buffer
            else:
                # Lese von Named Pipe
                input_fd = open(self.server.input_source, 'rb')
        except Exception as e:
            self.log_message(f"Fehler beim Öffnen der Input-Quelle: {e}")
            self.send_error(500, f"Kann Input nicht öffnen: {e}")
            return
        
        try:
            # Wenn Filter gesetzt ist, verwende tshark zum Filtern
            if filter_expr:
                self.stream_with_filter(input_fd, filter_expr, timeout)
            else:
                self.stream_raw(input_fd, timeout)
        except BrokenPipeError:
            self.log_message("Client hat Verbindung geschlossen")
        except Exception as e:
            self.log_message(f"Fehler beim Streaming: {e}")
        finally:
            if self.server.input_source != "stdin":
                input_fd.close()
    
    def stream_raw(self, input_fd, timeout):
        """Streamt PCAP-Daten ohne Filter."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
        self.send_header('Content-Disposition', 'attachment; filename="capture.pcap"')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        
        start_time = time.time()
        bytes_sent = 0
        
        while True:
            # Timeout-Check
            if timeout and (time.time() - start_time) >= timeout:
                self.log_message(f"Timeout erreicht ({timeout}s), beende Stream")
                break
            
            # Lese Chunk
            chunk = input_fd.read(CHUNK_SIZE)
            if not chunk:
                time.sleep(0.01)  # Kurze Pause wenn keine Daten
                continue
            
            # Sende Chunk
            self.wfile.write(f"{len(chunk):X}\r\n".encode())
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            
            bytes_sent += len(chunk)
        
        # End-Chunk
        self.wfile.write(b"0\r\n\r\n")
        self.log_message(f"Stream beendet: {bytes_sent} Bytes gesendet")
    
    def stream_with_filter(self, input_fd, filter_expr, timeout):
        """Streamt PCAP-Daten mit tshark-Filter."""
        self.log_message(f"Starte tshark mit Filter: {filter_expr}")
        
        # Baue tshark-Kommando
        cmd = [
            'tshark',
            '-r', '-',           # Lese von stdin
            '-Y', filter_expr,   # Display Filter
            '-w', '-',           # Schreibe zu stdout
        ]
        
        # Füge Zeitlimit hinzu (tshark -a duration:X)
        if timeout:
            cmd.extend(['-a', f'duration:{int(timeout)}'])
        
        try:
            # Starte tshark-Prozess
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # HTTP Response Headers senden
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
            self.send_header('Content-Disposition', 'attachment; filename="filtered_capture.pcap"')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            
            # Thread zum Füttern von tshark mit Daten
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
            
            # Lese gefilterte Ausgabe von tshark und streame zu Client
            start_time = time.time()
            bytes_sent = 0
            
            while True:
                # Timeout-Check
                if timeout and (time.time() - start_time) >= timeout:
                    proc.terminate()
                    break
                
                # Prüfe ob tshark noch läuft
                if proc.poll() is not None:
                    break
                
                # Lese Chunk von tshark
                chunk = proc.stdout.read(CHUNK_SIZE)
                if not chunk:
                    time.sleep(0.01)
                    continue
                
                # Sende Chunk zum Client
                self.wfile.write(f"{len(chunk):X}\r\n".encode())
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
                
                bytes_sent += len(chunk)
            
            # End-Chunk
            self.wfile.write(b"0\r\n\r\n")
            
            # Warte auf tshark
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            
            self.log_message(f"Stream beendet: {bytes_sent} Bytes gesendet (gefiltert)")
            
            # Zeige tshark stderr (Fehler/Warnungen)
            stderr = proc.stderr.read().decode('utf-8', errors='ignore')
            if stderr:
                self.log_message(f"tshark stderr: {stderr}")
        
        except FileNotFoundError:
            self.send_error(500, "tshark nicht gefunden. Bitte installieren: sudo apt-get install tshark")
        except Exception as e:
            self.log_message(f"Fehler bei tshark: {e}")
            self.send_error(500, f"Fehler beim Filtern: {e}")


class StreamingServer(HTTPServer):
    """HTTP Server mit Input-Source-Tracking."""
    
    def __init__(self, server_address, RequestHandlerClass, input_source):
        super().__init__(server_address, RequestHandlerClass)
        self.input_source = input_source


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='WLAN Packet Capture Streaming Server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                       help=f'Server-Port (default: {DEFAULT_PORT})')
    parser.add_argument('--input', default=DEFAULT_INPUT,
                       help=f'Input-Quelle: Named Pipe oder "stdin" (default: {DEFAULT_INPUT})')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Server-Host (default: 0.0.0.0)')
    
    args = parser.parse_args()
    
    # Prüfe ob Input-Quelle existiert (außer bei stdin)
    if args.input != "stdin" and not os.path.exists(args.input):
        print(f"Warnung: Input-Quelle '{args.input}' existiert nicht!", file=sys.stderr)
        print(f"Erstelle Named Pipe...", file=sys.stderr)
        try:
            os.mkfifo(args.input)
            print(f"Named Pipe erstellt: {args.input}", file=sys.stderr)
            print(f"Starte tcpdump mit: sudo tcpdump -i wlan0mon -w - -U > {args.input} &", file=sys.stderr)
        except Exception as e:
            print(f"Fehler beim Erstellen der Named Pipe: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Starte Server
    server = StreamingServer((args.host, args.port), StreamHandler, args.input)
    
    print(f"WLAN Packet Capture Streaming Server", file=sys.stderr)
    print(f"=" * 50, file=sys.stderr)
    print(f"Server läuft auf: http://{args.host}:{args.port}", file=sys.stderr)
    print(f"Input-Quelle: {args.input}", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"API-Endpunkt: /stream?filter=<filter>&duration=<seconds>", file=sys.stderr)
    print(f"Info-Seite: http://{args.host}:{args.port}/", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"Beispiel:", file=sys.stderr)
    print(f'  curl "http://localhost:{args.port}/stream?duration=10" > capture.pcap', file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"Drücke Ctrl+C zum Beenden", file=sys.stderr)
    print(f"=" * 50, file=sys.stderr)
    
    # Signal-Handler für sauberes Beenden
    def signal_handler(sig, frame):
        print("\nServer wird beendet...", file=sys.stderr)
        shutdown_flag.set()
        server.shutdown()
        server.server_close()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # serve_forever mit poll_interval, damit shutdown() schnell erkannt wird
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nServer wird beendet...", file=sys.stderr)
        server.shutdown()
        server.server_close()
    finally:
        print("Server beendet.", file=sys.stderr)


if __name__ == '__main__':
    main()
