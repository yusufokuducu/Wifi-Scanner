# WiFi Scanner

## Overview

WiFi Scanner is a Python-based ARP network scanning application designed to quickly discover devices on your local network. With a user-friendly graphical interface built using CustomTkinter, this tool offers real-time scanning results, CSV export functionality, and robust error handling. It ensures secure operation by requiring administrative privileges for sensitive network operations.

## Features

- **ARP Scanning**: Leverages Scapy for fast and accurate ARP-based network scanning.
- **User-Friendly GUI**: A clean, responsive interface built with CustomTkinter.
- **Network Interface Selection**: Automatically detects and allows selection of available network interfaces.
- **MAC Vendor Lookup**: Identifies device manufacturers using MAC address lookup.
- **CSV Export**: Export scan results easily to CSV for further analysis.
- **Admin Checks**: Verifies administrative rights to ensure safe scanning operations.
- **Multi-Threaded Scanning**: Runs scans in a separate thread to keep the UI responsive.
- **Progress Indication**: Visual feedback during scanning operations.
- **Error Handling**: Robust error handling and logging for better diagnostics.

## Requirements

- Python 3.8 or later
- Dependencies (automatically installed via requirements.txt):
  - Scapy
  - CustomTkinter
  - psutil
  - requests

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/faust-lvii/Wifi-Scanner.git
   ```

2. **Navigate to the project directory**:
   ```bash
   cd Wifi-Scanner
   ```

3. **(Optional) Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix or MacOS:
   source venv/bin/activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run as Administrator** (recommended for full functionality):
   ```bash
   python main.py
   ```

2. **Select Network Interface**:
   Choose your network interface from the dropdown menu. The IP range will be automatically populated.

3. **Customize IP Range** (optional):
   Modify the IP range if needed (e.g., 192.168.1.0/24).

4. **Start Scanning**:
   Click "Ağı Tara" (Scan Network) to begin the scanning process.

5. **Export Results**:
   After scanning, you can save the results to a CSV file by clicking "Sonuçları CSV Olarak Kaydet" (Save Results as CSV).

## Troubleshooting

- **Admin Privileges Required**: The application needs administrator privileges for ARP scanning. If you see a warning about admin rights, restart the application as an administrator.
- **Missing Dependencies**: If you encounter dependency errors, make sure you've installed all required packages using `pip install -r requirements.txt`.
- **Scan Not Finding Devices**: Ensure you're using the correct network interface and IP range.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for bug fixes and improvements.

## License

This project is licensed under the MIT License.

## Acknowledgements

Special thanks to the developers of Scapy and CustomTkinter for providing the tools that make this project possible.