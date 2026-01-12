#!/bin/bash
# Startet tcpdump im Monitor-Mode und schreibt in Named Pipe

set -e

# Konfiguration
INTERFACE="${1:-wlan0mon}"
FIFO_PATH="${2:-/tmp/tcpdump_fifo}"
SNAPLEN=2048

echo "=================================================="
echo "WLAN Packet Capture - tcpdump Starter"
echo "=================================================="
echo "Interface: $INTERFACE"
echo "Named Pipe: $FIFO_PATH"
echo ""

# Prüfe ob Script als root läuft
if [ "$EUID" -ne 0 ]; then
    echo "FEHLER: Dieses Script muss als root ausgeführt werden!"
    echo "Verwendung: sudo $0 [interface] [fifo_path]"
    exit 1
fi

# Prüfe ob Interface existiert
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo "FEHLER: Interface '$INTERFACE' nicht gefunden!"
    echo ""
    echo "Verfügbare Interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print "  - " $2}' | sed 's/:$//'
    echo ""
    echo "Um ein Interface in den Monitor-Mode zu versetzen:"
    echo "  sudo ip link set wlan0 down"
    echo "  sudo iw wlan0 set monitor none"
    echo "  sudo ip link set wlan0 up"
    echo "  sudo ip link set wlan0 name wlan0mon"
    exit 1
fi

# Prüfe ob tcpdump installiert ist
if ! command -v tcpdump &> /dev/null; then
    echo "FEHLER: tcpdump nicht gefunden!"
    echo "Installieren mit: sudo apt-get install tcpdump"
    exit 1
fi

# Erstelle Named Pipe falls nicht vorhanden
if [ ! -p "$FIFO_PATH" ]; then
    echo "Erstelle Named Pipe: $FIFO_PATH"
    mkfifo "$FIFO_PATH"
else
    echo "Named Pipe existiert bereits: $FIFO_PATH"
fi

# Cleanup-Funktion
cleanup() {
    echo ""
    echo "Beende tcpdump..."
    if [ -n "$TCPDUMP_PID" ]; then
        kill $TCPDUMP_PID 2>/dev/null || true
        wait $TCPDUMP_PID 2>/dev/null || true
    fi
    echo "tcpdump beendet."
}

trap cleanup EXIT INT TERM

# Starte tcpdump
echo ""
echo "Starte tcpdump..."
echo "Kommando: tcpdump -i $INTERFACE -s $SNAPLEN -w - -U"
echo ""
echo "tcpdump läuft. Pakete werden in Named Pipe geschrieben."
echo "Drücke Ctrl+C zum Beenden"
echo "=================================================="

# -i: Interface
# -s: Snaplen (Bytes pro Paket)
# -w -: Schreibe zu stdout
# -U: Unbuffered (wichtig für Streaming!)
tcpdump -i "$INTERFACE" -s "$SNAPLEN" -w - -U > "$FIFO_PATH" &
TCPDUMP_PID=$!

# Warte auf tcpdump-Prozess
wait $TCPDUMP_PID
