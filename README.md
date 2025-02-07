# WiFi Scanner

## Overview

WiFi Scanner is a Python-based ARP network scanning application designed to quickly discover devices on your local network. With a user-friendly graphical interface built using CustomTkinter, this tool offers real-time scanning results, CSV export functionality, and robust error handling. It ensures secure operation by requiring administrative privileges for sensitive network operations.

## Features

- **ARP Scanning**: Leverages Scapy for fast and accurate ARP-based network scanning.
- **User-Friendly GUI**: A clean, responsive interface built with CustomTkinter.
- **CSV Export**: Export scan results easily to CSV for further analysis.
- **Admin Checks**: Verifies administrative rights to ensure safe scanning operations.
- **Multi-Threaded Scanning**: Runs scans in a separate thread to keep the UI responsive.

## Requirements

- Python 3.8 or later
- [Scapy](https://scapy.readthedocs.io/en/latest/)
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- Standard Python libraries: `socket`, `csv`, `logging`, `threading`, `tkinter`

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
   *If `requirements.txt` is not available, manually install Scapy and CustomTkinter:* 
   ```bash
   pip install scapy customtkinter
   ```

## Usage

Run the application with:

```bash
python main.py
```

*Note: Ensure you run the application as an administrator for ARP scanning to function correctly.*

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for bug fixes and improvements.

## License

This project is licensed under the MIT License.

## Acknowledgements

Special thanks to the developers of Scapy and CustomTkinter for providing the tools that make this project possible.