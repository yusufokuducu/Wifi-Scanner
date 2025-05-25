# Network Scanner 2.0

![Version](https://img.shields.io/badge/version-2.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

A modern, feature-rich local network scanner application that helps you identify and analyze devices on your network. Built with Python and a customizable UI, Network Scanner makes it easy to monitor your local network and discover connected devices.

## Features

- **Modern UI**: Sleek, customizable interface with dark/light theme support
- **Enhanced Network Scanning**: Multiple scan types (standard, quick, detailed)
- **Device Management**: Table view with filtering and detailed device information
- **Visualization**: Generate network charts to analyze device distribution
- **MAC Vendor Lookup**: Automatically identify device manufacturers with offline caching
- **Auto-Refresh**: Schedule periodic network scans
- **Export Options**: Save scan results in various formats
- **Cross-Platform**: Works on Windows, Linux, and macOS

## What's New in Version 2.0

- Completely redesigned user interface with tabbed layout
- Added detailed device information view
- Implemented network visualization with charts
- Enhanced scanning performance with multi-threading
- Added device filtering capabilities
- Improved MAC vendor lookup with caching
- Added auto-refresh scanning feature
- Implemented theme customization
- Added dependency management

## Overview

Network Scanner is a Python-based ARP network scanning application designed to quickly discover devices on your local network. With a user-friendly graphical interface built using CustomTkinter, this tool offers real-time scanning results, CSV export functionality, and robust error handling. It ensures secure operation by requiring administrative privileges for sensitive network operations.

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
   git clone https://github.com/yourusername/network-scanner.git
   ```

2. **Navigate to the project directory**:
   ```bash
   cd network-scanner

The application will also prompt you to install missing dependencies when launched.

3. For Windows users, install [Npcap](https://npcap.com/) or [WinPcap](https://www.winpcap.org/) for packet capture capabilities.

## Usage

1. Run the application with administrator/root privileges for full functionality:

```bash
# Windows (PowerShell with admin rights)
python main.py

# Linux/macOS
sudo python main.py
```

2. Navigate through the tabbed interface:
   - **Network Scan**: Perform network scans and view basic results
   - **Device List**: View detailed device information in a table format
   - **Network Graph**: Visualize your network by vendor distribution
   - **Settings**: Configure application preferences

3. Scanning Your Network:
   - Select a network interface from the dropdown menu
   - Choose a scan type (Standard, Quick, or Detailed)
   - Click "Start Scan" to begin scanning
   - View results in either text or table format

4. Additional Features:
   - Double-click on any device in the table for detailed information
   - Right-click on devices for additional options (Ping, Open in browser)
   - Filter devices using the search box in the Device List tab
   - Generate network visualizations as pie or bar charts
   - Configure auto-refresh to periodically scan your network
   - Customize the application theme (light/dark)
   - Export scan results to CSV files

## Screenshots

*Interface screenshots will be added here*

## Troubleshooting

- **Admin Privileges Required**: The application needs administrator privileges for ARP scanning. If you see a warning about admin rights, restart the application as an administrator.
- **Missing Dependencies**: If you encounter dependency errors, make sure you've installed all required packages using `pip install -r requirements.txt`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for bug fixes and improvements.

## License

This project is licensed under the MIT License.

## Author

© 2025 Network Scanner

## Acknowledgements

Special thanks to the developers of Scapy and CustomTkinter for providing the tools that make this project possible.