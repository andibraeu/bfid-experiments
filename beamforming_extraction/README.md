# 802.11ac Beamforming Feedback Extraction

This tool extracts compressed beamforming feedback data (φ/ψ angles) from 802.11ac PCAP files for machine learning analysis.

## Overview

The tool processes VHT (Very High Throughput) Compressed Beamforming Reports from 802.11ac WLAN captures and extracts:

- **φ (phi) angles**: Quantized angle values for beamforming
- **ψ (psi) angles**: Quantized angle values for beamforming
- **Metadata**: Timestamps, MAC addresses, MIMO parameters
- **Per-subcarrier data**: Each subcarrier is stored as a separate entry

The extracted data is normalized to [0, 1] range and stored in Parquet format with a fixed feature vector schema.

## Requirements

- Python 3.8+
- tshark (Wireshark command-line tool)
- pandas >= 2.0.0
- pyarrow >= 14.0.0
- matplotlib >= 3.7.0 (for visualization)
- seaborn >= 0.12.0 (for advanced visualizations)
- jupyter >= 1.0.0 (for notebook analysis)
- plotly >= 5.14.0 (optional, for interactive plots)
- ipywidgets >= 8.0.0 (optional, for interactive widgets)

## Setup

### Using the setup script (recommended)

```bash
cd beamforming_extraction
./setup.sh
```

This will create a virtual environment and install all dependencies.

### Manual setup

```bash
cd beamforming_extraction
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**Important**: Always activate the virtual environment before running the script:
```bash
source venv/bin/activate
```

## Usage

**Always activate the virtual environment first:**
```bash
source venv/bin/activate
```

### Basic Usage

```bash
python3 extract_beamforming.py \
    --pcap ../actions-packets.pcapng \
    --output beamforming_data.parquet
```

### With Custom Filter

```bash
python3 extract_beamforming.py \
    --pcap ../capture.pcapng \
    --output output.parquet \
    --filter "wlan.vht.compressed_beamforming_report && wlan.ta == 36:26:06:7c:b1:24"
```

### Export to JSON

```bash
python3 extract_beamforming.py \
    --pcap ../actions-packets.pcapng \
    --output beamforming_data.parquet \
    --export-json beamforming_data.jsonl
```

### Custom Bit Widths

```bash
python3 extract_beamforming.py \
    --pcap ../actions-packets.pcapng \
    --output output.parquet \
    --phi-bits 6 \
    --psi-bits 3
```

## Output Format

Each entry in the Parquet file represents one subcarrier and contains:

- `timestamp`: Unix epoch timestamp (float, seconds)
- `timestamp_delta`: Time relative to first packet (float, seconds)
- `frame_number`: Frame number in PCAP file
- `scidx`: Subcarrier index (e.g., -122, -121, ...)
- `ta`: Transmitter address (MAC address)
- `ra`: Receiver address (MAC address)
- `bssid`: BSSID (MAC address)
- `nr`: Number of receive antennas (typically 3)
- `nc`: Number of spatial streams (typically 2)
- `channel_width`: Channel width in MHz (e.g., 80)
- `phi`: Array of normalized φ angles (max 6 values, padded with -1)
- `psi`: Array of normalized ψ angles (max 4 values, padded with -1)
- `phi_mask`: Mask indicating valid φ values (1=valid, 0=padded)
- `psi_mask`: Mask indicating valid ψ values (1=valid, 0=padded)

## Data Structure

### Normalization

Angle values are normalized using:
```
value_norm = value_raw / (2^bits - 1)
```

Default bit widths:
- φ (phi): 6 bits → range [0, 63] → normalized [0.0, 1.0]
- ψ (psi): 3 bits → range [0, 7] → normalized [0.0, 1.0]

### Padding

For a fixed feature vector schema, arrays are padded to maximum size:
- `phi`: Maximum 6 values (for 3×3 MIMO: Nc × (Nr-1) = 2 × 2 = 4, but allows up to 6)
- `psi`: Maximum 4 values (for 3×3 MIMO: (Nc-1) × (Nr-1) = 1 × 2 = 2, but allows up to 4)

Missing values are filled with `-1.0`, and corresponding mask values are set to `0`.

## Example Output

```json
{
  "timestamp": 1768160897.066249,
  "timestamp_delta": 0.0,
  "frame_number": 1,
  "scidx": -122,
  "ta": "36:26:06:7c:b1:24",
  "ra": "20:05:b6:ff:e4:49",
  "bssid": "20:05:b6:ff:e4:49",
  "nr": 3,
  "nc": 2,
  "channel_width": 80,
  "phi": [0.222222, 0.984127, -1.0, -1.0, -1.0, -1.0],
  "psi": [0.857143, 0.0, -1.0, -1.0],
  "phi_mask": [1, 1, 0, 0, 0, 0],
  "psi_mask": [1, 1, 0, 0]
}
```

## Technical Details

### Extraction Method

The tool uses `tshark -V` (verbose) output to extract beamforming data, as direct field extraction is not available in all tshark versions. The verbose output is parsed using regular expressions to extract:

1. **VHT MIMO Control**: Nc, Nr, Channel Width
2. **Feedback Matrices**: SCIDX, φ11, φ21, ψ21, ψ31 per subcarrier

### Subcarrier Storage

Each subcarrier is stored as a separate entry. For a typical packet with ~100 subcarriers, this results in ~100 entries per packet. This allows for detailed analysis of subcarrier-level variations.

## Data Analysis and Visualization

### Jupyter Notebook

After extracting the beamforming data to a Parquet file, you can analyze and visualize it using the provided Jupyter notebook.

#### Starting the Notebook

1. **Activate the virtual environment:**
   ```bash
   source venv/bin/activate
   ```

2. **Start Jupyter:**
   ```bash
   jupyter notebook
   ```

3. **Open the notebook:**
   - Navigate to `analyze_beamforming.ipynb` in the Jupyter interface
   - Or directly: `jupyter notebook analyze_beamforming.ipynb`

#### Available Visualizations

The notebook provides several types of visualizations:

**1. Time Series Plots**
   - Aggregated Phi/Psi values over time (mean per frame with standard deviation)
   - Individual subcarrier values over time
   - Combined view of all angle values

**2. 2D Heatmaps**
   - Time (X-axis) × Subcarrier (Y-axis) heatmaps
   - Separate heatmaps for phi[0], phi[1], psi[0], psi[1]
   - Color intensity represents angle values

**3. Statistical Analyses**
   - Correlation matrices between Phi/Psi values
   - Distribution histograms
   - Change rates over time (derivatives)

**4. Data Exploration**
   - Basic statistics and data quality checks
   - Frame-level aggregations
   - Subcarrier-specific analysis

**5. Spatial 2D Visualization and Animation**
   - 2D scatter plots showing subcarriers as points in Phi/Psi space
   - Animated visualization over time (1 frame = 1 second in video)
   - Video export as MP4 to detect movements in space
   - Alternative views: Phi[0] vs Phi[1], Phi[0] vs Psi[0]

#### Interpreting the Visualizations

- **Time Series**: Show how beamforming angles evolve over time. Look for patterns, trends, or sudden changes that might indicate movement or channel variations.

- **Heatmaps**: Provide an overview of how angles vary across both time and frequency (subcarriers). Bright areas indicate higher values, dark areas indicate lower values.

- **Correlation Analysis**: Helps understand relationships between different angle components. High correlation suggests coordinated changes.

- **Change Rates**: Indicate how quickly the beamforming parameters adapt. High change rates might indicate rapid movement or channel fluctuations.

- **Spatial 2D Animation**: Shows subcarriers as points moving in 2D space (Phi/Psi coordinates). Movement patterns can indicate physical movement in the environment. Each frame in the data corresponds to 1 second in the video, allowing direct time correlation.

#### Export Options

The notebook includes code for exporting:
- Aggregated statistics to CSV
- Visualizations as PNG/PDF files
- **Animated videos as MP4** (requires ffmpeg)

#### Video Animation Requirements

To export animated videos, you need `ffmpeg` installed on your system:

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install ffmpeg
```

**Linux (Arch):**
```bash
sudo pacman -S ffmpeg
```

**macOS:**
```bash
brew install ffmpeg
```

**Windows:**
Download from [ffmpeg.org](https://ffmpeg.org/download.html) or use:
```bash
choco install ffmpeg
```

The animation creates MP4 videos where:
- Each data frame = 1 second in the video (1 FPS)
- Subcarriers are shown as colored points in 2D space
- Movement patterns can reveal physical movement in the environment
- Videos are saved as `beamforming_animation_phi_phi.mp4` and `beamforming_animation_phi_psi.mp4`

**Note**: Video export can take several minutes for large datasets. The notebook will check for ffmpeg availability and provide warnings if it's not installed.

## Limitations

- Requires tshark to be installed and available in PATH
- Parsing relies on tshark verbose output format (may vary between versions)
- Default bit widths are used if not specified (may need adjustment for different configurations)

## Troubleshooting

### No packets found
- Check that the filter matches your PCAP file
- Verify that the PCAP contains VHT Compressed Beamforming Reports
- Try a broader filter: `wlan.vht.compressed_beamforming_report`

### Parsing errors
- Ensure tshark version is recent (tested with 4.6.2)
- Check that verbose output contains "VHT MIMO Control" and "Feedback Matrices"

### Missing dependencies
```bash
pip install pandas pyarrow matplotlib seaborn jupyter
```

### Video export not working
- Ensure `ffmpeg` is installed and available in PATH
- Check with: `ffmpeg -version`
- The notebook will detect if ffmpeg is missing and show a warning
- For large datasets, video export can take a long time - be patient

## License

See parent directory for license information.
