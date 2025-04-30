import socket
import logging
import requests
import platform
import sys
import time
import threading
from scapy.all import ARP, Ether, srp, conf as scapy_conf

# Configure Scapy to be less verbose about warnings
scapy_conf.verbosity = 0

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_mac_vendor(mac_address):
    """
    Look up the vendor for a given MAC address using the macvendors.com API.
    Returns vendor name or "Bilinmeyen Üretici" if not found.
    """
    try:
        mac = mac_address.replace(':', '').replace('-', '').upper()[:6]
        response = requests.get(f'https://api.macvendors.com/{mac}', timeout=2)
        if response.status_code == 200:
            return response.text
        return "Bilinmeyen Üretici"
    except Exception as e:
        logger.debug(f"Error in vendor lookup: {e}")
        return "Bilinmeyen Üretici"

def perform_arp_scan(target_ip: str):
    """
    Perform an ARP scan on the target IP range and return a list of discovered devices.
    Each device is a dictionary with keys: ip, mac, vendor, hostname.
    """
    try:
        # Check if scapy is using pcap
        if not getattr(scapy_conf, 'use_pcap', True) and platform.system() == 'Windows':
            logger.warning("Libpcap not available. ARP scan may not be fully functional.")
        
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        logger.info(f"Starting ARP scan on {target_ip}")
        # Attempt scan with timeout
        answered, _ = srp(packet, timeout=3, verbose=0, retry=2)
        logger.info(f"Scan completed, found {len(answered)} devices")
        
        scan_results = []
        vendor_lookup_threads = []
        
        for sent, received in answered:
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except socket.herror:
                hostname = "Bilinmeyen Cihaz"
            
            device = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": "Bilinmeyen Üretici",  # Will be updated by lookup thread
                "hostname": hostname
            }
            
            # Create thread for vendor lookup to avoid slowing down the scan
            thread = threading.Thread(
                target=lambda d=device: d.update({"vendor": get_mac_vendor(d["mac"])}),
                daemon=True
            )
            vendor_lookup_threads.append(thread)
            thread.start()
            
            scan_results.append(device)
        
        # Wait for all vendor lookups to complete (max 3 seconds)
        wait_time = 0
        while any(t.is_alive() for t in vendor_lookup_threads) and wait_time < 3:
            time.sleep(0.1)
            wait_time += 0.1
            
        return scan_results
    except Exception as e:
        logger.error(f"Error in perform_arp_scan: {e}")
        return [] 