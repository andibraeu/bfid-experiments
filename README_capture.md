# WLAN Packet Capture Streaming API

Minimalist HTTP server for live streaming of WLAN packets. Runs on Raspberry Pi and enables packet capture via HTTP - without writing files to the router.

## Advantages

✓ **No Dependencies** - only Python stdlib (http.server)  
✓ **No Disk I/O** - everything via Unix pipes in memory  
✓ **Single script** - easy to understand and customize  
✓ **tcpdump runs permanently** - no start/stop management  
✓ **Live streaming** - real-time data  
✓ **Wireshark filters** - thanks to tshark (e.g. `wlan.fc.type_subtype == 0x000e`)

## Architecture

```
WLAN Monitor → tcpdump → Named Pipe → HTTP Server → Client
                                   ↓
                                 tshark (when filtering)
```

**Flow:**
1. tcpdump runs permanently and writes to Named Pipe (no disk I/O!)
2. Client makes HTTP request with optional Wireshark filter
3. Server starts tshark process with filter (if specified)
4. PCAP data is streamed live to the client

## Installation

### 1. Install Prerequisites

```bash
# On the Raspberry Pi
sudo apt-get update
sudo apt-get install tcpdump tshark python3
```

### 2. Put WLAN Interface into Monitor Mode

```bash
# Bring interface down
sudo ip link set wlan0 down

# Enable monitor mode
sudo iw wlan0 set monitor none

# Bring interface back up
sudo ip link set wlan0 up

# Optional: Rename
sudo ip link set wlan0 name wlan0mon

# Verify
iwconfig wlan0mon
# Should show "Mode:Monitor"
```

### 3. Transfer Files

```bash
# From your PC to Raspberry Pi
scp capture_stream.py start_capture.sh pi@raspberrypi.local:~/

# Make executable on Raspberry Pi
ssh pi@raspberrypi.local "chmod +x ~/start_capture.sh ~/capture_stream.py"
```

## Usage

### Option 1: With Named Pipe and Buffer Process (recommended)

**Important:** Named Pipes only allow one reader at a time. To prevent tcpdump from terminating when no client is reading, use the `pipe_buffer.py` process.

```bash
# Terminal 1: Start tcpdump (as root)
sudo tcpdump -i wlan0mon -w - -U > /tmp/tcpdump_fifo &

# Terminal 2: Start buffer process (keeps pipe open)
python3 pipe_buffer.py /tmp/tcpdump_fifo /tmp/tcpdump_buffer.fifo

# Terminal 3: Start HTTP server (as regular user)
python3 capture_stream.py --input /tmp/tcpdump_buffer.fifo --port 8000
```

**Alternative:** Use `tee` to duplicate the pipe (allows multiple readers):

```bash
# Terminal 1: Start tcpdump with tee (as root)
mkfifo /tmp/tcpdump_fifo /tmp/tcpdump_fifo1
sudo tcpdump -i wlan0mon -w - -U | tee /tmp/tcpdump_fifo1 > /tmp/tcpdump_fifo &

# Terminal 2: Start HTTP server (as regular user)
python3 capture_stream.py --input /tmp/tcpdump_fifo1 --port 8000
```

### Option 2: With Direct Pipe

```bash
# Everything in one command (as root)
sudo tcpdump -i wlan0mon -w - -U | python3 capture_stream.py --input stdin
```

### Server is now accessible

```bash
# Open info page in browser
http://raspberrypi.local:8000/

# Or from another PC
http://<raspberry-pi-ip>:8000/
```

## API Endpoints

### `GET /`
Info page with documentation and examples.

### `GET /stream?filter=<filter>&duration=<seconds>`

Streams PCAP data live to the client.

**Parameters:**
- `filter` (optional): Wireshark Display Filter
  - Example: `wlan.fc.type_subtype == 0x000e`
- `duration` (optional): Duration in seconds (without = unlimited)

## Examples

### Capture all packets for 60 seconds

```bash
curl "http://raspberrypi.local:8000/stream?duration=60" > capture.pcap
```

### Capture only Action Frames (0x000e)

```bash
curl "http://raspberrypi.local:8000/stream?filter=wlan.fc.type_subtype%20%3D%3D%200x000e&duration=30" \
  > action_frames.pcap
```

### Only from specific MAC address

```bash
curl "http://raspberrypi.local:8000/stream?filter=wlan.ta%20%3D%3D%2036:26:06:7c:b1:24&duration=60" \
  > from_specific_mac.pcap
```

### Combining filters

```bash
# Action frames from specific MAC
filter="(wlan.fc.type_subtype == 0x000e) && (wlan.ta == 36:26:06:7c:b1:24)"
curl "http://raspberrypi.local:8000/stream?filter=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$filter'))")&duration=60" \
  > filtered.pcap
```

### Open directly in Wireshark

```bash
# Local (on Raspberry Pi)
curl -s "localhost:8000/stream?duration=30" | wireshark -k -i -

# Remote via SSH
ssh pi@raspberrypi.local "curl -s localhost:8000/stream?duration=30" | wireshark -k -i -
```

### With Python

```python
import requests

# Start stream
response = requests.get(
    'http://raspberrypi.local:8000/stream',
    params={
        'filter': 'wlan.fc.type_subtype == 0x000e',
        'duration': 60
    },
    stream=True  # Important!
)

# Write to file
with open('capture.pcap', 'wb') as f:
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:
            f.write(chunk)
```

### Integration with existing script

```bash
# Capture packets and analyze directly
curl "http://raspberrypi.local:8000/stream?filter=wlan.fc.type_subtype%20%3D%3D%200x000e&duration=120" \
  -o new_capture.pcapng

# Analyze with existing script
python3 extract_and_visualize.py --pcap new_capture.pcapng
```

## Wireshark Display Filter Reference

Some useful filters for WLAN:

```bash
# Action Frames
wlan.fc.type_subtype == 0x000e

# Management Frames
wlan.fc.type == 0

# From specific MAC
wlan.ta == 36:26:06:7c:b1:24

# To specific MAC
wlan.ra == 36:26:06:7c:b1:24

# Beacon Frames
wlan.fc.type_subtype == 0x0008

# Probe Request
wlan.fc.type_subtype == 0x0004

# Probe Response
wlan.fc.type_subtype == 0x0005

# Combinations with &&, ||, !
(wlan.fc.type_subtype == 0x000e) && (wlan.ta == 36:26:06:7c:b1:24)
```

Full reference: https://www.wireshark.org/docs/dfref/w/wlan.html

## Automatic Startup (Systemd)

### 1. Create Service Files

**tcpdump Service** (`/etc/systemd/system/wlan-tcpdump.service`):

```ini
[Unit]
Description=WLAN tcpdump Capture
After=network.target

[Service]
Type=simple
User=root
ExecStart=/home/pi/start_capture.sh wlan0mon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**HTTP Server Service** (`/etc/systemd/system/wlan-capture-api.service`):

```ini
[Unit]
Description=WLAN Packet Capture HTTP API
After=wlan-tcpdump.service
Requires=wlan-tcpdump.service

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi
ExecStart=/usr/bin/python3 /home/pi/capture_stream.py --input /tmp/tcpdump_fifo --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 2. Enable Services

```bash
# Load service files
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable wlan-tcpdump.service
sudo systemctl enable wlan-capture-api.service

# Start services
sudo systemctl start wlan-tcpdump.service
sudo systemctl start wlan-capture-api.service

# Check status
sudo systemctl status wlan-tcpdump.service
sudo systemctl status wlan-capture-api.service
```

### 3. View Logs

```bash
# tcpdump logs
sudo journalctl -u wlan-tcpdump.service -f

# HTTP server logs
sudo journalctl -u wlan-capture-api.service -f
```

## Troubleshooting

### tcpdump: Permission denied

```bash
# Solution 1: Run as root
sudo ./start_capture.sh

# Solution 2: Set capabilities (then without sudo)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
```

### tshark not found

```bash
sudo apt-get install tshark

# Select "Yes" at prompts
```

### Interface not in monitor mode

```bash
# Check
iwconfig wlan0mon

# Should show "Mode:Monitor"
# If not, see "Put WLAN Interface into Monitor Mode"
```

### Named Pipe does not exist

```bash
# Created automatically by start_capture.sh
# Create manually:
mkfifo /tmp/tcpdump_fifo
```

### No packets received

```bash
# Check if tcpdump is running
ps aux | grep tcpdump

# Check if packets are being received
sudo tcpdump -i wlan0mon -c 10

# Check if Named Pipe contains data
cat /tmp/tcpdump_fifo | head -c 100
```

## Security Notes

⚠️ **For internal experiments only!**

- **No authentication**: Anyone on the network can access
- **Root privileges**: tcpdump requires privileged rights
- **DoS risk**: Complex filters can stress the system
- **No encryption**: HTTP (not HTTPS)

**Recommendations:**
- Only use in trusted network
- Set firewall rules (only allow specific IPs)
- For production use: add authentication

## Performance Tips

### Adjust buffer size

```bash
# In capture_stream.py
CHUNK_SIZE = 16384  # Larger chunks = less overhead
```

### Reduce tcpdump snaplen

```bash
# Only capture headers (faster)
sudo tcpdump -i wlan0mon -s 128 -w - -U > /tmp/tcpdump_fifo &

# Or adjust SNAPLEN in start_capture.sh
```

### Reduce CPU load

```bash
# Increase tcpdump nice level (lower priority)
sudo nice -n 10 tcpdump -i wlan0mon -w - -U > /tmp/tcpdump_fifo &
```

## Extension Possibilities

- **Authentication**: Add HTTP Basic Auth
- **HTTPS**: SSL certificates for encrypted connection
- **Multiple streams**: Multiple clients simultaneously
- **WebSocket**: Bidirectional communication
- **Statistics**: Display packet counter, byte rate
- **Web UI**: Frontend for visualization (like `extract_and_visualize.py`)

## License

Free to use for internal experiments.
