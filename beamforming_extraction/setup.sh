#!/bin/bash
# Setup script for beamforming extraction environment

set -e

echo "Setting up virtual environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

echo "Setup complete!"
echo ""
echo "To activate the virtual environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "Then you can run:"
echo "  python3 extract_beamforming.py --pcap <file.pcapng> --output <output.parquet>"
