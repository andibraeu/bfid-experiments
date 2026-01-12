#!/usr/bin/env python3
"""
Erklärt die Interpretation der Feedback-Matrizen und erstellt eine
verbesserte Visualisierung mit Legende und Farbkodierung.
"""

import subprocess
import numpy as np
import cv2
from pathlib import Path
import re

def parse_hex_dump(hex_dump):
    """Parst Hex-Dump von tshark -x zu Bytes."""
    bytes_list = []
    for line in hex_dump.split('\n'):
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

def extract_feedback_matrix(packet_data):
    """Extrahiert Feedback-Matrix aus Paketdaten."""
    if len(packet_data) < 50:
        return None
    
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
                
                if matrix.max() > matrix.min() and len(np.unique(matrix)) > 10:
                    return matrix
    
    remaining_data = packet_data[35:]
    if len(remaining_data) >= 64:
        matrix_size = int(np.sqrt(len(remaining_data)))
        if matrix_size >= 8:
            matrix_bytes = remaining_data[:matrix_size * matrix_size]
            matrix = np.frombuffer(matrix_bytes, dtype=np.uint8).reshape(matrix_size, matrix_size)
            return matrix
    
    return None

def create_explanation_image(matrix, output_file):
    """Erstellt ein erklärendes Bild mit Legende."""
    height, width = matrix.shape
    
    # Skaliere Matrix für bessere Sichtbarkeit
    scale_factor = 64  # 8x8 -> 512x512
    scaled = cv2.resize(matrix, (width * scale_factor, height * scale_factor), 
                       interpolation=cv2.INTER_NEAREST)
    
    # Normalisiere für Visualisierung
    normalized = ((matrix - matrix.min()) / (matrix.max() - matrix.min()) * 255).astype(np.uint8)
    normalized_scaled = cv2.resize(normalized, (width * scale_factor, height * scale_factor), 
                                   interpolation=cv2.INTER_NEAREST)
    
    # Erstelle Farb-Version (Heatmap)
    colored = cv2.applyColorMap(normalized_scaled, cv2.COLORMAP_VIRIDIS)
    
    # Erstelle größeres Bild mit Platz für Legende
    # Platz für beide Bilder nebeneinander + Abstand
    img_height = scaled.shape[0] + 250
    img_width = max(scaled.shape[1] * 2 + 60, 1000)  # Zwei Bilder + Abstand
    img = np.ones((img_height, img_width, 3), dtype=np.uint8) * 255
    
    # Platziere Matrix-Bilder
    y_offset = 20
    x_offset = 20
    
    # Graustufen-Version
    gray_bgr = cv2.cvtColor(normalized_scaled, cv2.COLOR_GRAY2BGR)
    img[y_offset:y_offset+gray_bgr.shape[0], x_offset:x_offset+gray_bgr.shape[1]] = gray_bgr
    
    # Farb-Version (Heatmap)
    x_offset2 = x_offset + gray_bgr.shape[1] + 20
    img[y_offset:y_offset+colored.shape[0], x_offset2:x_offset2+colored.shape[1]] = colored
    
    # Füge Text hinzu
    font = cv2.FONT_HERSHEY_SIMPLEX
    font_scale = 0.6
    color = (0, 0, 0)
    thickness = 1
    
    # Titel
    cv2.putText(img, "Feedback Matrix Interpretation", (x_offset, 15), 
                font, 0.8, color, 2)
    
    # Legende unter den Bildern
    legend_y = y_offset + scaled.shape[0] + 30
    
    cv2.putText(img, "Graustufen:", (x_offset, legend_y), font, font_scale, color, thickness)
    cv2.putText(img, "Dunkel = niedrige Werte, Hell = hohe Werte", 
                (x_offset, legend_y + 25), font, 0.5, (100, 100, 100), thickness)
    
    cv2.putText(img, "Heatmap:", (x_offset2, legend_y), font, font_scale, color, thickness)
    cv2.putText(img, "Blau = niedrig, Gelb/Grun = hoch", 
                (x_offset2, legend_y + 25), font, 0.5, (100, 100, 100), thickness)
    
    # Matrix-Informationen
    info_y = legend_y + 60
    cv2.putText(img, f"Matrix-Groesse: {width}x{height}", 
                (x_offset, info_y), font, font_scale, color, thickness)
    cv2.putText(img, f"Werte-Bereich: {matrix.min()} - {matrix.max()}", 
                (x_offset, info_y + 25), font, font_scale, color, thickness)
    cv2.putText(img, f"Eindeutige Werte: {len(np.unique(matrix))}", 
                (x_offset, info_y + 50), font, font_scale, color, thickness)
    
    # Erklärung
    explanation_y = info_y + 90
    explanations = [
        "Interpretation:",
        "- Jede Zelle reprasentiert einen Kanalzustand",
        "- Hohe Werte = starkes Signal/geringe Interferenz",
        "- Niedrige Werte = schwaches Signal/hohe Interferenz",
        "- Aenderungen zeigen Kanalvariationen ueber die Zeit"
    ]
    
    for i, text in enumerate(explanations):
        cv2.putText(img, text, (x_offset, explanation_y + i * 20), 
                   font, 0.5, color, thickness)
    
    cv2.imwrite(output_file, img)
    print(f"Erklärungsbild gespeichert: {output_file}")

def main():
    pcap_file = "ekin_kammi_full_of_people.pcapng"
    filter_str = "(wlan.fc.type_subtype == 0x0e) && (wlan.ta == 36:26:06:7c:b1:24)"
    
    # Extrahiere erste Matrix
    cmd = ['tshark', '-r', pcap_file, '-Y', filter_str, '-T', 'fields', '-e', 'frame.number']
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    frame_numbers = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line and line.isdigit():
            frame_numbers.append(int(line))
    
    if not frame_numbers:
        print("Keine Pakete gefunden!")
        return
    
    frame_num = frame_numbers[0]
    
    # Extrahiere Daten
    cmd_data = ['tshark', '-r', pcap_file, '-Y', f'frame.number == {frame_num}', '-x']
    result = subprocess.run(cmd_data, capture_output=True, text=True)
    data_bytes = parse_hex_dump(result.stdout)
    
    matrix = extract_feedback_matrix(data_bytes)
    
    if matrix is not None:
        create_explanation_image(matrix, "matrix_explanation.png")
        
        print("\n" + "="*60)
        print("INTERPRETATION DER FEEDBACK-MATRIZEN")
        print("="*60)
        print("""
Was sind Feedback-Matrizen?
---------------------------
Feedback-Matrizen in WLAN (802.11) enthalten Channel State Information (CSI).
Sie beschreiben die Qualitaet des Funkkanals zwischen Sender und Empfaenger.

Matrix-Struktur (8x8):
-----------------------
- Jede Zelle (i,j) repraesentiert einen Subkanal oder Antennen-Paar
- Die Werte sind typischerweise quantisierte Kanalzustands-Werte
- Wertebereich: 0-255 (8 Bit Quantisierung)

Was bedeuten die Werte?
------------------------
- HOHE WERTE (hell/rot/gelb):
  * Starke Signalstaerke
  * Gute Kanalqualitaet
  * Geringe Interferenz
  
- NIEDRIGE WERTE (dunkel/blau):
  * Schwache Signalstaerke
  * Schlechte Kanalqualitaet
  * Hohe Interferenz oder Abschattung

Wie das Video interpretieren:
-------------------------------
1. Jede Matrix = 1 Sekunde im Video
2. Aenderungen zwischen Matrizen zeigen:
   - Kanalvariationen ueber die Zeit
   - Bewegung oder Umgebungsaenderungen
   - Interferenz-Schwankungen
   
3. Muster in der Matrix:
   - Gleichmaessige Verteilung = stabiler Kanal
   - Cluster/Inseln = lokale Interferenzquellen
   - Streifen = Richtungsabhaengige Effekte

4. Zeitliche Entwicklung:
   - Langsame Aenderungen = Bewegung oder Umgebungsaenderung
   - Schnelle Sprünge = ploetzliche Interferenz oder Handover
   - Periodische Muster = rotierende Interferenzquellen

Visualisierung im Video:
-------------------------
- Graustufen: Dunkel = niedrig, Hell = hoch
- Jede Matrix wird 1 Sekunde lang angezeigt
- Die Sequenz zeigt die Entwicklung ueber die Zeit
        """)
    else:
        print("Konnte Matrix nicht extrahieren!")

if __name__ == "__main__":
    main()
