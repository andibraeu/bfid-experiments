#!/usr/bin/env python3
"""
Extrahiert Feedback-Matrizen aus WLAN-Paketen und erstellt ein Video.
Verwendet tshark direkt für die Extraktion.

Verwendung:
    python3 extract_and_visualize.py [--analyze] [--output OUTPUT_FILE] [--fps FPS] [--seconds-per-matrix SECONDS]
    
Optionen:
    --analyze              Analysiert die ersten Pakete detailliert
    --output FILE          Ausgabedatei für das Video (Standard: feedback_matrices_video.mp4)
    --fps FPS              Frames pro Sekunde (Standard: 10)
    --seconds-per-matrix   Wie viele Sekunden jede Matrix angezeigt wird (Standard: 1.0)
"""

import subprocess
import numpy as np
import cv2
from pathlib import Path
import sys
import re
import argparse

def parse_hex_dump(hex_dump):
    """Parst Hex-Dump von tshark -x zu Bytes."""
    bytes_list = []
    for line in hex_dump.split('\n'):
        # Suche nach Hex-Zeilen (Format: 0000  xx xx xx ...)
        match = re.match(r'^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}\s+){1,16})', line)
        if match:
            hex_part = match.group(1)
            hex_bytes = hex_part.split()
            for hex_byte in hex_bytes:
                try:
                    bytes_list.append(int(hex_byte, 16))
                except ValueError:
                    continue
    return bytes(bytes_list)

def extract_packet_data(pcap_file, filter_str):
    """Extrahiert Paketdaten mit tshark."""
    print(f"Extrahiere Pakete aus {pcap_file}...")
    
    # Zuerst: Zähle wie viele Pakete es gibt
    cmd_count = [
        'tshark', '-r', pcap_file,
        '-Y', filter_str,
        '-T', 'fields', '-e', 'frame.number'
    ]
    
    result = subprocess.run(cmd_count, capture_output=True, text=True)
    frame_numbers = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line and line.isdigit():
            frame_numbers.append(int(line))
    
    print(f"Gefunden: {len(frame_numbers)} Pakete")
    
    if not frame_numbers:
        return []
    
    # Extrahiere Daten für jedes Paket
    packets = []
    for i, frame_num in enumerate(frame_numbers):
        if (i + 1) % 50 == 0:
            print(f"Verarbeitet: {i + 1}/{len(frame_numbers)}")
        
        # Extrahiere Zeitstempel
        cmd_time = [
            'tshark', '-r', pcap_file,
            '-Y', f'frame.number == {frame_num}',
            '-T', 'fields', '-e', 'frame.time_relative'
        ]
        result = subprocess.run(cmd_time, capture_output=True, text=True)
        timestamp = float(result.stdout.strip()) if result.stdout.strip() else 0.0
        
        # Extrahiere Rohdaten direkt aus dem Frame (Hex-Dump)
        cmd_data = [
            'tshark', '-r', pcap_file,
            '-Y', f'frame.number == {frame_num}',
            '-x'
        ]
        result = subprocess.run(cmd_data, capture_output=True, text=True)
        hex_dump = result.stdout
        
        # Parse Hex-Dump zu Bytes
        data_bytes = parse_hex_dump(hex_dump)
        
        if data_bytes and len(data_bytes) > 50:
            packets.append((timestamp, data_bytes))
        else:
            print(f"Warnung: Konnte Daten für Frame {frame_num} nicht extrahieren")
            continue
    
    return packets

def extract_feedback_matrix(packet_data):
    """
    Extrahiert Feedback-Matrix aus Paketdaten.
    Versucht verschiedene Offset-Positionen und Matrix-Größen.
    """
    if len(packet_data) < 50:
        return None
    
    # Typische Offsets für 802.11 Action Frames:
    # - 802.11 Header: ~24-30 Bytes
    # - Action Frame Header: ~5 Bytes
    # - Feedback-Daten beginnen danach
    
    offsets = [30, 35, 40, 45, 50]
    sizes = [8, 16, 32, 64, 128]
    
    for offset in offsets:
        if len(packet_data) < offset:
            continue
        
        data_start = packet_data[offset:]
        
        for size in sizes:
            required_bytes = size * size
            if len(data_start) >= required_bytes:
                matrix_bytes = data_start[:required_bytes]
                matrix = np.frombuffer(matrix_bytes, dtype=np.uint8).reshape(size, size)
                
                # Prüfe ob die Matrix sinnvolle Daten enthält
                # (nicht nur Nullen oder identische Werte)
                if matrix.max() > matrix.min() and len(np.unique(matrix)) > 10:
                    return matrix
    
    # Fallback: Versuche dynamische Größe
    remaining_data = packet_data[35:]
    if len(remaining_data) >= 64:  # Mindestens 8x8
        matrix_size = int(np.sqrt(len(remaining_data)))
        if matrix_size >= 8:
            matrix_bytes = remaining_data[:matrix_size * matrix_size]
            matrix = np.frombuffer(matrix_bytes, dtype=np.uint8).reshape(matrix_size, matrix_size)
            return matrix
    
    return None

def create_video_images(matrices, output_file, fps=10, seconds_per_matrix=1):
    """Erstellt Video aus Matrizen durch Speichern als Bilder und Zusammenfügen mit ffmpeg.
    
    Args:
        matrices: Liste von Matrizen
        output_file: Ausgabedatei
        fps: Frames pro Sekunde
        seconds_per_matrix: Wie viele Sekunden jede Matrix angezeigt wird
    """
    import tempfile
    import shutil
    
    if not matrices:
        print("Keine Matrizen zum Erstellen des Videos gefunden!")
        return False
    
    print(f"Erstelle Video aus {len(matrices)} Matrizen...")
    print(f"Jede Matrix wird {seconds_per_matrix} Sekunde(n) angezeigt (bei {fps} fps)")
    
    first_matrix = matrices[0]
    height, width = first_matrix.shape
    
    all_values = np.concatenate([m.flatten() for m in matrices])
    global_min = all_values.min()
    global_max = all_values.max()
    
    print(f"Matrix-Größe: {width}x{height}")
    print(f"Werte-Bereich: {global_min} - {global_max}")
    
    # Erstelle temporäres Verzeichnis für Bilder
    temp_dir = Path(tempfile.mkdtemp(prefix='feedback_frames_'))
    print(f"Speichere Frames in: {temp_dir}")
    
    try:
        # Speichere jedes Frame als Bild
        scale_factor = max(32, 512 // max(width, height))
        scaled_width = width * scale_factor
        scaled_height = height * scale_factor
        
        frame_count = 0
        frames_per_matrix = int(fps * seconds_per_matrix)
        
        for i, matrix in enumerate(matrices):
            if global_max > global_min:
                normalized = ((matrix - global_min) / (global_max - global_min) * 255).astype(np.uint8)
            else:
                normalized = np.zeros_like(matrix, dtype=np.uint8)
            
            scaled = cv2.resize(normalized, (scaled_width, scaled_height), 
                               interpolation=cv2.INTER_NEAREST)
            
            # Speichere jedes Frame mehrfach (für seconds_per_matrix Sekunden)
            for repeat in range(frames_per_matrix):
                frame_file = temp_dir / f"frame_{frame_count:05d}.png"
                cv2.imwrite(str(frame_file), scaled)
                frame_count += 1
            
            if (i + 1) % 10 == 0:
                print(f"  Verarbeitet: {i + 1}/{len(matrices)} Matrizen ({frame_count} Frames)")
        
        print(f"Gesamt: {frame_count} Frames für {len(matrices)} Matrizen")
        
        # Erstelle Video mit ffmpeg
        print("Erstelle Video mit ffmpeg...")
        video_file = output_file
        if not video_file.endswith('.mp4'):
            video_file = output_file.rsplit('.', 1)[0] + '.mp4'
        
        cmd = [
            'ffmpeg', '-y', '-r', str(fps),
            '-i', str(temp_dir / 'frame_%05d.png'),
            '-c:v', 'libx264', '-pix_fmt', 'yuv420p',
            video_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            video_path = Path(video_file)
            if video_path.exists():
                size_mb = video_path.stat().st_size / (1024 * 1024)
                print(f"Video gespeichert: {video_file}")
                print(f"Video-Größe: {size_mb:.2f} MB")
                return True
            else:
                print("Fehler: Video-Datei wurde nicht erstellt!")
                return False
        else:
            print(f"Fehler beim Erstellen des Videos: {result.stderr}")
            return False
    
    finally:
        # Lösche temporäres Verzeichnis
        shutil.rmtree(temp_dir, ignore_errors=True)

def create_video(matrices, output_file, fps=10, seconds_per_matrix=1):
    """Erstellt ein Video aus den Feedback-Matrizen.
    
    Args:
        matrices: Liste von Matrizen
        output_file: Ausgabedatei
        fps: Frames pro Sekunde
        seconds_per_matrix: Wie viele Sekunden jede Matrix angezeigt wird
    """
    if not matrices:
        print("Keine Matrizen zum Erstellen des Videos gefunden!")
        return False
    
    print(f"Erstelle Video aus {len(matrices)} Matrizen...")
    print(f"Jede Matrix wird {seconds_per_matrix} Sekunde(n) angezeigt (bei {fps} fps)")
    
    # Bestimme die Größe der Matrizen
    first_matrix = matrices[0]
    height, width = first_matrix.shape
    
    # Normalisiere alle Matrizen gemeinsam für konsistente Visualisierung
    all_values = np.concatenate([m.flatten() for m in matrices])
    global_min = all_values.min()
    global_max = all_values.max()
    
    print(f"Matrix-Größe: {width}x{height}")
    print(f"Werte-Bereich: {global_min} - {global_max}")
    
    # Skaliere auf Video-Größe (mindestens 256x256 für Sichtbarkeit)
    scale_factor = max(1, 256 // max(width, height))
    video_width = width * scale_factor
    video_height = height * scale_factor
    
    # Erstelle Video-Writer (BGR für Farb-Video)
    # Versuche verschiedene Codecs
    codecs = [('mp4v', '.mp4'), ('XVID', '.avi'), ('MJPG', '.avi')]
    out = None
    video_file = output_file
    
    for codec_name, ext in codecs:
        if not video_file.endswith(ext):
            video_file = output_file.rsplit('.', 1)[0] + ext
        fourcc = cv2.VideoWriter_fourcc(*codec_name)
        out = cv2.VideoWriter(video_file, fourcc, fps, (video_width, video_height), True)
        if out.isOpened():
            print(f"Verwende Codec: {codec_name}")
            break
        out.release()
        out = None
    
    if out is None or not out.isOpened():
        print(f"Fehler: Konnte Video-Writer nicht öffnen!")
        return False
    
    # Schreibe Frames - jede Matrix wird für seconds_per_matrix Sekunden wiederholt
    frames_written = 0
    frames_per_matrix = int(fps * seconds_per_matrix)
    
    for i, matrix in enumerate(matrices):
        # Normalisiere Matrix
        if global_max > global_min:
            normalized = ((matrix - global_min) / (global_max - global_min) * 255).astype(np.uint8)
        else:
            normalized = np.zeros_like(matrix, dtype=np.uint8)
        
        # Skaliere auf Video-Größe (größer für bessere Sichtbarkeit)
        scale_factor = max(32, 512 // max(width, height))  # Mindestens 32x für 8x8 -> 256x256
        scaled_width = width * scale_factor
        scaled_height = height * scale_factor
        scaled = cv2.resize(normalized, (scaled_width, scaled_height), 
                           interpolation=cv2.INTER_NEAREST)
        
        # Konvertiere zu BGR für Video
        frame = cv2.cvtColor(scaled, cv2.COLOR_GRAY2BGR)
        
        # Stelle sicher, dass Frame die richtige Größe hat
        if frame.shape[1] != video_width or frame.shape[0] != video_height:
            frame = cv2.resize(frame, (video_width, video_height))
        
        # Schreibe Frame mehrfach (für seconds_per_matrix Sekunden)
        for repeat in range(frames_per_matrix):
            success = out.write(frame)
            if success:
                frames_written += 1
        
        if (i + 1) % 10 == 0:
            print(f"  Verarbeitet: {i + 1}/{len(matrices)} Matrizen ({frames_written} Frames geschrieben)")
    
    print(f"  Insgesamt {frames_written} Frames geschrieben")
    
    out.release()
    print(f"Video gespeichert: {video_file}")
    
    # Prüfe Dateigröße
    video_path = Path(video_file)
    if video_path.exists():
        size_mb = video_path.stat().st_size / (1024 * 1024)
        print(f"Video-Größe: {size_mb:.2f} MB")
        if size_mb < 0.01:
            print("Warnung: Video ist sehr klein, möglicherweise wurde es nicht korrekt geschrieben!")
    
    return True

def analyze_packets(pcap_file, filter_str, num_packets=5):
    """Analysiert die ersten N Pakete detailliert."""
    print(f"\n{'='*60}")
    print(f"Analysiere {num_packets} Pakete...")
    print(f"{'='*60}")
    
    # Verwende die gleiche Methode wie extract_packet_data
    cmd_count = [
        'tshark', '-r', pcap_file,
        '-Y', filter_str,
        '-T', 'fields', '-e', 'frame.number'
    ]
    
    result = subprocess.run(cmd_count, capture_output=True, text=True)
    frame_numbers = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line and line.isdigit():
            frame_numbers.append(int(line))
    
    # Begrenze auf num_packets
    frame_numbers = frame_numbers[:num_packets]
    
    if not frame_numbers:
        print("Keine Pakete gefunden!")
        return
    
    print(f"Gefunden: {len(frame_numbers)} Pakete\n")
    
    for i, frame_num in enumerate(frame_numbers):
        print(f"Paket #{i + 1} (Frame {frame_num}):")
        
        # Extrahiere Daten
        cmd_data = ['tshark', '-r', pcap_file, '-Y', f'frame.number == {frame_num}', '-x']
        result = subprocess.run(cmd_data, capture_output=True, text=True)
        data_bytes = parse_hex_dump(result.stdout)
        
        print(f"  Daten-Länge: {len(data_bytes)} Bytes")
        
        # Versuche Matrix zu extrahieren
        matrix = extract_feedback_matrix(data_bytes)
        if matrix is not None:
            print(f"  Matrix-Größe: {matrix.shape}")
            print(f"  Werte-Bereich: {matrix.min()} - {matrix.max()}")
            print(f"  Eindeutige Werte: {len(np.unique(matrix))}")
            print(f"  Matrix (erste 8x8):")
            print(f"    {matrix[:min(8, matrix.shape[0]), :min(8, matrix.shape[1])]}")
        else:
            print(f"  Keine Matrix extrahiert")
        print()

def main():
    parser = argparse.ArgumentParser(description='Extrahiert Feedback-Matrizen aus WLAN-Paketen und erstellt ein Video')
    parser.add_argument('--analyze', action='store_true', help='Analysiert die ersten Pakete detailliert')
    parser.add_argument('--output', default='feedback_matrices_video.mp4', help='Ausgabedatei für das Video')
    parser.add_argument('--fps', type=int, default=10, help='Frames pro Sekunde')
    parser.add_argument('--seconds-per-matrix', type=float, default=1.0, 
                       help='Wie viele Sekunden jede Matrix angezeigt wird (Standard: 1.0)')
    parser.add_argument('--pcap', default='ekin_kammi_full_of_people.pcapng', help='PCAP-Datei')
    parser.add_argument('--filter', default='(wlan.fc.type_subtype == 0x0e) && (wlan.ta == 36:26:06:7c:b1:24)', 
                       help='Wireshark Filter für Pakete')
    
    args = parser.parse_args()
    
    pcap_file = args.pcap
    filter_str = args.filter
    output_file = args.output
    
    if not Path(pcap_file).exists():
        print(f"Fehler: Datei {pcap_file} nicht gefunden!")
        sys.exit(1)
    
    # Analyse-Modus
    if args.analyze:
        analyze_packets(pcap_file, filter_str, num_packets=5)
        return
    
    # Extrahiere Pakete
    packets = extract_packet_data(pcap_file, filter_str)
    
    if not packets:
        print("Keine Pakete gefunden!")
        sys.exit(1)
    
    # Parse Feedback-Matrizen
    print(f"\nParse Feedback-Matrizen aus {len(packets)} Paketen...")
    matrices = []
    for i, (timestamp, data) in enumerate(packets):
        matrix = extract_feedback_matrix(data)
        if matrix is not None:
            matrices.append(matrix)
            if len(matrices) % 10 == 0:
                print(f"  Extrahiert: {len(matrices)} Matrizen (aus {i + 1} Paketen)")
    
    print(f"\nInsgesamt {len(matrices)} Matrizen extrahiert")
    
    if matrices:
        # Erstelle Video (versuche zuerst mit ffmpeg, dann mit OpenCV)
        ffmpeg_available = subprocess.run(['which', 'ffmpeg'], 
                                         capture_output=True).returncode == 0
        
        if ffmpeg_available:
            success = create_video_images(matrices, output_file, fps=args.fps, 
                                         seconds_per_matrix=args.seconds_per_matrix)
        else:
            print("ffmpeg nicht gefunden, verwende OpenCV...")
            success = create_video(matrices, output_file, fps=args.fps, 
                                 seconds_per_matrix=args.seconds_per_matrix)
        if success:
            print(f"\nFertig! Video erstellt: {output_file}")
        else:
            print("\nFehler beim Erstellen des Videos!")
            sys.exit(1)
    else:
        print("Keine Matrizen konnten extrahiert werden.")
        print("Möglicherweise müssen die Parsing-Parameter angepasst werden.")
        print("Verwende --analyze für eine detaillierte Analyse.")
        sys.exit(1)

if __name__ == "__main__":
    main()
