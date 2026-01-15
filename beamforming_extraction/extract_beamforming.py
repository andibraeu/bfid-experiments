#!/usr/bin/env python3
"""
Extract 802.11ac Compressed Beamforming Feedback from PCAP files.

This script extracts φ (phi) and ψ (psi) angles from VHT Compressed Beamforming
Reports in PCAP files, normalizes them, and stores them in Parquet format.

Usage:
    python3 extract_beamforming.py --pcap <file.pcapng> --output <output.parquet>
"""

import subprocess
import re
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import pandas as pd
import numpy as np


# Maximum values for fixed feature vector schema (3×3 MIMO)
MAX_PHI = 6  # Nc × (Nr-1) = 2 × (3-1) = 4, but allow up to 6 for flexibility
MAX_PSI = 4  # (Nc-1) × (Nr-1) = (2-1) × (3-1) = 2, but allow up to 4

# Default bit widths for SU-MIMO (can be overridden from VHT MIMO Control)
DEFAULT_PHI_BITS = 6
DEFAULT_PSI_BITS = 3


def extract_packet_metadata(pcap_file: str, filter_str: str) -> List[Dict]:
    """
    Extract metadata (timestamp, MAC addresses) for each packet.
    
    Args:
        pcap_file: Path to PCAP file
        filter_str: Wireshark display filter
        
    Returns:
        List of dictionaries with metadata per packet
    """
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', filter_str,
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'frame.time_epoch',
        '-e', 'wlan.ta',
        '-e', 'wlan.ra',
        '-e', 'wlan.bssid'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets = []
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) >= 5:
                packets.append({
                    'frame_number': int(parts[0]),
                    'timestamp': float(parts[1]),
                    'ta': parts[2] if parts[2] else '',
                    'ra': parts[3] if parts[3] else '',
                    'bssid': parts[4] if len(parts) > 4 and parts[4] else parts[3] if parts[3] else ''
                })
        
        return packets
    except subprocess.CalledProcessError as e:
        print(f"Error extracting metadata: {e.stderr}", file=sys.stderr)
        return []


def extract_beamforming_verbose(pcap_file: str, frame_number: int) -> Optional[str]:
    """
    Extract verbose output for a specific frame.
    
    Args:
        pcap_file: Path to PCAP file
        frame_number: Frame number to extract
        
    Returns:
        Verbose output as string, or None if error
    """
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', f'frame.number == {frame_number}',
        '-V'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error extracting verbose output for frame {frame_number}: {e.stderr}", file=sys.stderr)
        return None


def parse_vht_mimo_control(verbose_output: str) -> Optional[Dict]:
    """
    Parse VHT MIMO Control field from verbose output.
    
    Args:
        verbose_output: tshark -V output
        
    Returns:
        Dictionary with nc, nr, channel_width, or None if not found
    """
    # Parse from the summary line: "Nc Index: 1 Column" means 1 Column, so Nc = 1
    # But wait - "Nc Index: 1 Column" actually means Index 1, which means 2 Columns (Nc = 2)
    # The format is confusing: the number is the index, not the count
    # "Nr Index: 3 Rows" means Index 2 (which represents 3 Rows), so Nr = 3 directly
    nc_pattern = r'Nc Index:\s*(\d+)\s+Column'
    nr_pattern = r'Nr Index:\s*(\d+)\s+Row'
    channel_width_pattern = r'Channel Width:\s*(\d+)\s+MHz'
    
    nc_match = re.search(nc_pattern, verbose_output)
    nr_match = re.search(nr_pattern, verbose_output)
    channel_width_match = re.search(channel_width_pattern, verbose_output)
    
    if not (nc_match and nr_match and channel_width_match):
        return None
    
    # Actually, looking at the data: "Nc Index: 1 Column" with hex 0x0 means Index 0 = 1 Column
    # But the summary says "1 Column" which is the count, not the index
    # Let's parse from the hex value line instead for accuracy
    nc_hex_pattern = r'Nc Index:.*?\(0x([0-9a-fA-F]+)\)'
    nr_hex_pattern = r'Nr Index:.*?\(0x([0-9a-fA-F]+)\)'
    
    nc_hex_match = re.search(nc_hex_pattern, verbose_output)
    nr_hex_match = re.search(nr_hex_pattern, verbose_output)
    
    if nc_hex_match and nr_hex_match:
        # For Nr: Parse from hex - Index 2 (0x2) = 3 Rows, so Nr = Index + 1
        nr_index = int(nr_hex_match.group(1), 16)
        nr = nr_index + 1
        
        # For Nc: The hex shows 0x0 but summary says "1 Column"
        # The summary line "Nc Index: 1 Column" means Index 1, so Nc = 2
        # Use the summary line value for Nc (more reliable)
        nc_index = int(nc_match.group(1))
        nc = nc_index + 1
    else:
        # Fallback: parse from summary line
        nc_index = int(nc_match.group(1))
        nc = nc_index + 1
        
        nr_count = int(nr_match.group(1))
        nr = nr_count  # Direct count from "3 Rows"
    
    channel_width = int(channel_width_match.group(1))
    
    return {
        'nc': nc,
        'nr': nr,
        'channel_width': channel_width
    }


def parse_feedback_matrices(verbose_output: str) -> List[Dict]:
    """
    Parse feedback matrices from verbose output.
    
    Each line format: "SCIDX: -122, φ11:14, φ21:62, ψ21:6, ψ31:0"
    
    Args:
        verbose_output: tshark -V output
        
    Returns:
        List of dictionaries, one per subcarrier
    """
    # Pattern to match: SCIDX: -122, φ11:14, φ21:62, ψ21:6, ψ31:0
    pattern = r'SCIDX:\s*(-?\d+),\s*φ11:(\d+),\s*φ21:(\d+),\s*ψ21:(\d+),\s*ψ31:(\d+)'
    
    matches = re.findall(pattern, verbose_output)
    subcarriers = []
    
    for match in matches:
        scidx = int(match[0])
        phi11 = int(match[1])
        phi21 = int(match[2])
        psi21 = int(match[3])
        psi31 = int(match[4])
        
        subcarriers.append({
            'scidx': scidx,
            'phi': [phi11, phi21],  # For Nc=2, Nr=3: φ11, φ21
            'psi': [psi21, psi31]   # For Nc=2, Nr=3: ψ21, ψ31
        })
    
    return subcarriers


def normalize_angles(values: List[int], bits: int) -> List[float]:
    """
    Normalize angle values to [0, 1] range.
    
    Args:
        values: List of raw quantized angle values
        bits: Number of bits used for quantization
        
    Returns:
        List of normalized values in [0, 1]
    """
    max_value = (2 ** bits) - 1
    if max_value == 0:
        return [0.0] * len(values)
    
    return [float(v) / max_value for v in values]


def pad_angles(phi: List[float], psi: List[float], nc: int, nr: int) -> Tuple[List[float], List[float], List[int], List[int]]:
    """
    Pad angle arrays to fixed size and create masks.
    
    Args:
        phi: List of normalized phi values
        psi: List of normalized psi values
        nc: Number of spatial streams
        nr: Number of antennas
        
    Returns:
        Tuple of (padded_phi, padded_psi, phi_mask, psi_mask)
    """
    # Expected sizes
    expected_phi_size = nc * (nr - 1)
    expected_psi_size = (nc - 1) * (nr - 1)
    
    # Pad phi
    padded_phi = phi[:MAX_PHI] + [-1.0] * (MAX_PHI - len(phi))
    phi_mask = [1] * len(phi) + [0] * (MAX_PHI - len(phi))
    phi_mask = phi_mask[:MAX_PHI]
    
    # Pad psi
    padded_psi = psi[:MAX_PSI] + [-1.0] * (MAX_PSI - len(psi))
    psi_mask = [1] * len(psi) + [0] * (MAX_PSI - len(psi))
    psi_mask = psi_mask[:MAX_PSI]
    
    return padded_phi, padded_psi, phi_mask, psi_mask


def create_feature_vector(metadata: Dict, mimo_params: Dict, subcarrier: Dict, 
                         first_timestamp: float, phi_bits: int = DEFAULT_PHI_BITS,
                         psi_bits: int = DEFAULT_PSI_BITS) -> Dict:
    """
    Create a feature vector entry for one subcarrier.
    
    Args:
        metadata: Packet metadata (frame_number, timestamp, ta, ra, bssid)
        mimo_params: MIMO parameters (nc, nr, channel_width)
        subcarrier: Subcarrier data (scidx, phi, psi)
        first_timestamp: Timestamp of first packet (for delta calculation)
        phi_bits: Bit width for phi quantization
        psi_bits: Bit width for psi quantization
        
    Returns:
        Dictionary representing one feature vector entry
    """
    # Normalize angles
    phi_norm = normalize_angles(subcarrier['phi'], phi_bits)
    psi_norm = normalize_angles(subcarrier['psi'], psi_bits)
    
    # Pad to fixed size
    phi_padded, psi_padded, phi_mask, psi_mask = pad_angles(
        phi_norm, psi_norm, mimo_params['nc'], mimo_params['nr']
    )
    
    return {
        'timestamp': metadata['timestamp'],
        'timestamp_delta': metadata['timestamp'] - first_timestamp,
        'frame_number': metadata['frame_number'],
        'scidx': subcarrier['scidx'],
        'ta': metadata['ta'],
        'ra': metadata['ra'],
        'bssid': metadata['bssid'],
        'nr': mimo_params['nr'],
        'nc': mimo_params['nc'],
        'channel_width': mimo_params['channel_width'],
        'phi': phi_padded,
        'psi': psi_padded,
        'phi_mask': phi_mask,
        'psi_mask': psi_mask
    }


def extract_beamforming_data(pcap_file: str, filter_str: str, 
                            phi_bits: int = DEFAULT_PHI_BITS,
                            psi_bits: int = DEFAULT_PSI_BITS) -> List[Dict]:
    """
    Extract beamforming data from PCAP file.
    
    Args:
        pcap_file: Path to PCAP file
        filter_str: Wireshark display filter
        phi_bits: Bit width for phi quantization
        psi_bits: Bit width for psi quantization
        
    Returns:
        List of feature vector dictionaries (one per subcarrier)
    """
    print("Extracting packet metadata...")
    packets_metadata = extract_packet_metadata(pcap_file, filter_str)
    
    if not packets_metadata:
        print("No packets found matching filter.", file=sys.stderr)
        return []
    
    print(f"Found {len(packets_metadata)} packets")
    
    first_timestamp = packets_metadata[0]['timestamp']
    all_entries = []
    
    for i, metadata in enumerate(packets_metadata):
        if (i + 1) % 10 == 0:
            print(f"Processing packet {i + 1}/{len(packets_metadata)}...")
        
        # Extract verbose output for this frame
        verbose_output = extract_beamforming_verbose(pcap_file, metadata['frame_number'])
        if not verbose_output:
            continue
        
        # Parse VHT MIMO Control
        mimo_params = parse_vht_mimo_control(verbose_output)
        if not mimo_params:
            print(f"Warning: Could not parse VHT MIMO Control for frame {metadata['frame_number']}", file=sys.stderr)
            continue
        
        # Parse feedback matrices
        subcarriers = parse_feedback_matrices(verbose_output)
        if not subcarriers:
            print(f"Warning: No subcarriers found for frame {metadata['frame_number']}", file=sys.stderr)
            continue
        
        # Create feature vector for each subcarrier
        for subcarrier in subcarriers:
            entry = create_feature_vector(
                metadata, mimo_params, subcarrier, first_timestamp, phi_bits, psi_bits
            )
            all_entries.append(entry)
    
    print(f"Extracted {len(all_entries)} subcarrier entries from {len(packets_metadata)} packets")
    return all_entries


def save_to_parquet(data: List[Dict], output_file: str):
    """
    Save extracted data to Parquet file.
    
    Args:
        data: List of feature vector dictionaries
        output_file: Output file path
    """
    if not data:
        print("No data to save.", file=sys.stderr)
        return
    
    df = pd.DataFrame(data)
    df.to_parquet(output_file, index=False, engine='pyarrow')
    print(f"Saved {len(data)} entries to {output_file}")


def export_to_json(parquet_file: str, json_file: str):
    """
    Export Parquet file to JSON.
    
    Args:
        parquet_file: Input Parquet file
        json_file: Output JSON file
    """
    df = pd.read_parquet(parquet_file)
    df.to_json(json_file, orient='records', lines=True)
    print(f"Exported {len(df)} entries to {json_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract 802.11ac Compressed Beamforming Feedback from PCAP files'
    )
    parser.add_argument('--pcap', required=True, help='Input PCAP file')
    parser.add_argument('--output', required=True, help='Output Parquet file')
    parser.add_argument('--filter', default='wlan.vht.compressed_beamforming_report',
                       help='Wireshark display filter (default: wlan.vht.compressed_beamforming_report)')
    parser.add_argument('--export-json', help='Also export to JSON file')
    parser.add_argument('--phi-bits', type=int, default=DEFAULT_PHI_BITS,
                       help=f'Bit width for phi quantization (default: {DEFAULT_PHI_BITS})')
    parser.add_argument('--psi-bits', type=int, default=DEFAULT_PSI_BITS,
                       help=f'Bit width for psi quantization (default: {DEFAULT_PSI_BITS})')
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.pcap).exists():
        print(f"Error: PCAP file not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)
    
    # Extract data
    data = extract_beamforming_data(args.pcap, args.filter, args.phi_bits, args.psi_bits)
    
    if not data:
        print("No data extracted. Exiting.", file=sys.stderr)
        sys.exit(1)
    
    # Save to Parquet
    save_to_parquet(data, args.output)
    
    # Export to JSON if requested
    if args.export_json:
        export_to_json(args.output, args.export_json)
    
    print("Done!")


if __name__ == '__main__':
    main()
