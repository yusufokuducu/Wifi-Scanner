import socket
import logging
from scapy.all import ARP, Ether, srp

logging.basicConfig(level=logging.INFO)


def perform_arp_scan(target_ip: str):
    """
    Perform an ARP scan on the target IP range and return a list of discovered devices.
    Each device is a dictionary with keys: ip, mac, vendor, hostname.
    """
    try:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        answered, _ = srp(packet, timeout=3, verbose=0)
        
        scan_results = []
        for sent, received in answered:
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except socket.herror:
                hostname = "Bilinmeyen Cihaz"
            
            device = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": "Bilinmeyen Üretici",
                "hostname": hostname
            }
            scan_results.append(device)
        return scan_results
    except Exception as e:
        logging.error(f"Error in perform_arp_scan: {e}")
        return [] 