import socket
import logging
import requests
import platform
import sys
import time
import threading
import os
import json
import re
from datetime import datetime
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Import core packages
from scapy.all import ARP, Ether, srp, conf as scapy_conf

# Import alternative scanning module
try:
    from .alternative_scan import perform_alternative_scan
    ALTERNATIVE_SCAN_AVAILABLE = True
except ImportError:
    ALTERNATIVE_SCAN_AVAILABLE = False

# Check for optional modules
try:
    import ipaddress
    IPADDRESS_AVAILABLE = True
except ImportError:
    IPADDRESS_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

try:
    from scapy.all import get_if_addr
    GET_IF_ADDR_AVAILABLE = True
except ImportError:
    GET_IF_ADDR_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

# Configure Scapy to be less verbose about warnings
scapy_conf.verbosity = 0

# Global vendor cache to avoid repeated API calls
VENDOR_CACHE = {}

# Check if scapy can be used properly (with libpcap)
SCAPY_AVAILABLE = True
try:
    # Attempt to use scapy's get_if_list function to check if it works properly
    from scapy.all import get_if_list
    get_if_list()
except Exception as e:
    logger.warning(f"Scapy/libpcap not properly initialized: {e}")
    SCAPY_AVAILABLE = False

# Cache for MAC vendor lookups to reduce API calls
VENDOR_CACHE = {}
# Cache expiration time in hours
CACHE_EXPIRATION = 24

def load_vendor_cache():
    """Load vendor cache from disk if available"""
    cache_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vendor_cache.json')
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
                # Convert timestamps back to datetime objects
                for mac, entry in cache_data.items():
                    entry['timestamp'] = datetime.fromisoformat(entry['timestamp'])
                return cache_data
        except Exception as e:
            logger.error(f"Error loading vendor cache: {e}")
    return {}

def save_vendor_cache(cache):
    """Save vendor cache to disk"""
    cache_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vendor_cache.json')
    try:
        # Convert datetime objects to ISO format strings for JSON serialization
        serializable_cache = {}
        for mac, entry in cache.items():
            serializable_cache[mac] = {
                'vendor': entry['vendor'],
                'timestamp': entry['timestamp'].isoformat()
            }
        
        with open(cache_path, 'w') as f:
            json.dump(serializable_cache, f)
    except Exception as e:
        logger.error(f"Error saving vendor cache: {e}")

# Initialize vendor cache
VENDOR_CACHE = load_vendor_cache()

def get_mac_vendor(mac_address):
    """
    Look up the vendor for a given MAC address using the macvendors.com API.
    Uses a cache to reduce API calls and handle offline scenarios.
    Returns vendor name or "Bilinmeyen Üretici" if not found.
    """
    try:
        mac = mac_address.replace(':', '').replace('-', '').upper()[:6]
        
        # Check cache first
        if mac in VENDOR_CACHE:
            cache_entry = VENDOR_CACHE[mac]
            cache_age = (datetime.now() - cache_entry['timestamp']).total_seconds() / 3600
            
            # Return cached value if it's not expired
            if cache_age < CACHE_EXPIRATION:
                return cache_entry['vendor']
        
        # If not in cache or expired, make API request
        try:
            response = requests.get(f'https://api.macvendors.com/{mac}', timeout=2)
            if response.status_code == 200:
                vendor = response.text
                # Update cache
                VENDOR_CACHE[mac] = {
                    'vendor': vendor,
                    'timestamp': datetime.now()
                }
                # Save cache asynchronously
                threading.Thread(target=save_vendor_cache, args=(VENDOR_CACHE,), daemon=True).start()
                return vendor
        except requests.RequestException:
            # Try alternative API if first one fails
            try:
                response = requests.get(f'https://api.maclookup.app/v2/macs/{mac}/vendor/name', timeout=2)
                if response.status_code == 200 and response.text:
                    vendor = response.text.strip()
                    if vendor and vendor != "N/A":
                        # Update cache
                        VENDOR_CACHE[mac] = {
                            'vendor': vendor,
                            'timestamp': datetime.now()
                        }
                        # Save cache asynchronously
                        threading.Thread(target=save_vendor_cache, args=(VENDOR_CACHE,), daemon=True).start()
                        return vendor
            except:
                pass
                
        # If API calls fail, check local MAC prefixes
        # For now return unknown
        return "Bilinmeyen Üretici"
    except Exception as e:
        logger.debug(f"Error in vendor lookup: {e}")
        return "Bilinmeyen Üretici"

def get_interface_details():
    """
    Get all network interfaces with their IP addresses, MAC addresses, and subnet masks.
    Returns a list of dictionaries containing interface details.
    """
    interface_details = []
    
    # Netifaces kütüphanesi kullanılabilir mi?
    if NETIFACES_AVAILABLE:
        try:
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:  # If interface has IPv4 address
                    for addr in addresses[netifaces.AF_INET]:
                        if 'addr' in addr:
                            details = {
                                'name': interface,
                                'ip': addr['addr'],
                                'netmask': addr.get('netmask', '255.255.255.0'),
                                'mac': None
                            }
                            
                            # Get MAC address if available
                            if netifaces.AF_LINK in addresses:
                                for link_addr in addresses[netifaces.AF_LINK]:
                                    if 'addr' in link_addr:
                                        details['mac'] = link_addr['addr']
                                        break
                            
                            interface_details.append(details)
            return interface_details
        except Exception as e:
            logger.error(f"Error getting interface details with netifaces: {e}")
    
    # Alternatif yöntem: psutil kullanarak ağ arayüzlerini al
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            ip_addr = None
            netmask = None
            mac_addr = None
            
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    ip_addr = addr.address
                    netmask = getattr(addr, 'netmask', '255.255.255.0')
                elif addr.family == psutil.AF_LINK:  # MAC address (Windows/Linux)
                    mac_addr = addr.address
            
            if ip_addr:  # Only include interfaces with IPv4 addresses
                interface_details.append({
                    'name': iface,
                    'ip': ip_addr,
                    'netmask': netmask,
                    'mac': mac_addr
                })
                
        return interface_details
    except Exception as e:
        logger.error(f"Error getting interface details with psutil: {e}")
    
    # Son çare: socket kullanarak yerel IP'yi al
    try:
        # Varsayılan IP'yi bulmak için basit bir yöntem
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS'e bağlan
        ip_addr = s.getsockname()[0]
        s.close()
        
        interface_details.append({
            'name': 'Default Interface',
            'ip': ip_addr,
            'netmask': '255.255.255.0',  # Varsayılan netmask
            'mac': None
        })
        
        return interface_details
    except Exception as e:
        logger.error(f"Error getting interface details with socket: {e}")
        
        # En son çare: localhost bilgilerini döndür
        return [{
            'name': 'localhost',
            'ip': '127.0.0.1',
            'netmask': '255.0.0.0',
            'mac': None
        }]

def get_subnet_from_ip_and_mask(ip, netmask):
    """
    Calculate the subnet CIDR notation from IP and netmask
    Example: 192.168.1.1, 255.255.255.0 -> 192.168.1.0/24
    """
    if IPADDRESS_AVAILABLE:
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception as e:
            logger.error(f"Error calculating subnet with ipaddress: {e}")
    
    # Manual calculation method
    try:
        # Netmask'i kontrol et ve prefix uzunluğunu hesapla
        if netmask == "255.255.255.0":
            prefix_length = 24
        elif netmask == "255.255.0.0":
            prefix_length = 16
        elif netmask == "255.0.0.0":
            prefix_length = 8
        elif netmask == "255.255.255.128":
            prefix_length = 25
        elif netmask == "255.255.255.192":
            prefix_length = 26
        elif netmask == "255.255.255.224":
            prefix_length = 27
        else:
            # Use default /24 for other netmasks
            prefix_length = 24
        
        # Calculate the network portion of the IP address
        ip_parts = ip.split('.')
        
        if prefix_length >= 24:  # /24 veya daha uzun
            network_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0"
        elif prefix_length >= 16:  # /16
            network_ip = f"{ip_parts[0]}.{ip_parts[1]}.0.0"
        elif prefix_length >= 8:  # /8
            network_ip = f"{ip_parts[0]}.0.0.0"
        else:
            network_ip = "0.0.0.0"
        
        return f"{network_ip}/{prefix_length}"
    except Exception as e:
        logger.error(f"Error calculating subnet manually: {e}")
        return f"{'.'.join(ip.split('.')[:3])}.0/24"  # Fallback to common /24 subnet

def resolve_hostname(ip):
    """
    Resolve IP address to hostname with timeout to avoid hanging
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        return "Bilinmeyen Cihaz"

def process_device(sent_packet, received_packet):
    """
    Process a single device discovered in the ARP scan
    """
    ip = received_packet.psrc
    mac = received_packet.hwsrc
    hostname = resolve_hostname(ip)
    vendor = get_mac_vendor(mac)
    
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "last_seen": datetime.now().isoformat(),
        "status": "active"
    }

def perform_arp_scan(target_ip: str, timeout=3, retry=2):
    """
    Perform an ARP scan on the target IP range and return a list of discovered devices.
    Each device is a dictionary with keys: ip, mac, vendor, hostname, last_seen, status.
    
    Args:
        target_ip: IP range to scan in CIDR notation (e.g., '192.168.1.0/24')
        timeout: Timeout for ARP requests in seconds
        retry: Number of retries for ARP requests
    
    Returns:
        List of dictionaries containing device information
    """
    try:
        # Check if scapy is using pcap
        if not getattr(scapy_conf, 'use_pcap', True) and platform.system() == 'Windows':
            logger.warning("Libpcap not available. ARP scan may not be fully functional.")
        
        # Validate and format IP range
        if '/' not in target_ip:
            # If simple IP without CIDR notation, add /24
            target_ip = f"{target_ip}/24"
        
        # Validate CIDR format if ipaddress module is available
        if IPADDRESS_AVAILABLE:
            try:
                ipaddress.IPv4Network(target_ip)
            except ValueError:
                logger.error(f"Invalid IP range: {target_ip}, using default format")
                # Extract the first three octets and use a /24 subnet
                ip_parts = target_ip.split('/')
                base_ip = ip_parts[0]
                target_ip = f"{'.'.join(base_ip.split('.')[:3])}.0/24"
        
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        logger.info(f"Starting ARP scan on {target_ip}")
        # Attempt scan with timeout
        answered, _ = srp(packet, timeout=timeout, verbose=0, retry=retry)
        logger.info(f"Scan completed, found {len(answered)} devices")
        
        # Use ThreadPoolExecutor for parallel processing
        try:
            with ThreadPoolExecutor(max_workers=min(10, len(answered) or 1)) as executor:
                scan_results = list(executor.map(
                    lambda pair: process_device(pair[0], pair[1]), 
                    answered
                ))
        except Exception as thread_error:
            # If ThreadPoolExecutor fails, fall back to serial processing
            logger.warning(f"Parallel processing failed, falling back to serial: {thread_error}")
            scan_results = [process_device(pair[0], pair[1]) for pair in answered]
        
        # Sort by IP address
        try:
            scan_results.sort(key=lambda x: [int(i) for i in x['ip'].split('.')])
        except Exception as sort_error:
            logger.warning(f"Error sorting results: {sort_error}")
            # If sorting fails, return results without sorting
            
        return scan_results
    except Exception as e:
        logger.error(f"Error in perform_arp_scan: {e}")
        return []

def ping_host(ip):
    """
    Ping a host to check if it's online
    Returns True if host responds to ping, False otherwise
    """
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '1', ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception as e:
        logger.error(f"Error pinging host {ip}: {e}")
        return False

def perform_alternative_scan(target_subnet):
    """Alternative scanning method using basic ping and socket, without requiring scapy/libpcap
    
    Args:
        target_subnet: Subnet to scan in CIDR notation (e.g., '192.168.1.0/24')
        
    Returns:
        List of dictionaries containing device information
    """
    devices = []
    logger.info(f"Starting alternative scan on {target_subnet}")
    
    # Parse the target subnet to get the base IP and subnet mask
    try:
        if '/' in target_subnet:
            base_ip, prefix = target_subnet.split('/')
            prefix = int(prefix)
        else:
            base_ip = target_subnet
            prefix = 24  # Default to /24 subnet
            
        # Get the IP parts
        ip_parts = base_ip.split('.')
        
        # Determine the range to scan based on prefix
        if prefix >= 24:  # Scan all IPs in the last octet
            ip_range = [f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}" for i in range(1, 255)]
        elif prefix >= 16:  # Scan a sample of IPs in the third octet
            # Just scan the .1.1 to .1.254 range as a sample
            ip_range = [f"{ip_parts[0]}.{ip_parts[1]}.1.{i}" for i in range(1, 255)]
        else:
            # For larger subnets, just scan a small sample
            ip_range = [f"{ip_parts[0]}.{i}.1.1" for i in range(1, 10)]
    except Exception as e:
        logger.error(f"Error parsing subnet in alternative scan: {e}")
        # Fallback to scanning localhost only
        ip_range = ["127.0.0.1"]
    
    # Get local IP to add it to the scan results
    local_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        logger.warning(f"Could not determine local IP: {e}")
        
    # Track already discovered IPs to avoid duplicates
    discovered_ips = set()
    
    # First add the local machine
    if local_ip and local_ip not in discovered_ips:
        discovered_ips.add(local_ip)
        hostname = "localhost"
        try:
            hostname = socket.gethostname()
        except:
            pass
            
        devices.append({
            'ip': local_ip,
            'mac': "00:00:00:00:00:00",  # Placeholder
            'vendor': "Local Machine",
            'hostname': hostname,
            'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'status': "up"
        })
    
    # Try to scan using ping
    ping_count = "1"
    ping_timeout = "500"  # milliseconds
    if platform.system().lower() == "windows":
        ping_cmd = ["ping", "-n", ping_count, "-w", ping_timeout]
    else:
        ping_cmd = ["ping", "-c", ping_count, "-W", ping_timeout]
    
    # Use thread pool for faster scanning
    def check_host(ip):
        if ip in discovered_ips:
            return None
            
        try:
            cmd = ping_cmd + [ip]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:  # Host is up
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""
                    
                discovered_ips.add(ip)
                return {
                    'ip': ip,
                    'mac': "Unknown",  # Can't get MAC without ARP
                    'vendor': "Unknown",
                    'hostname': hostname,
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'status': "up"
                }
        except Exception as e:
            logger.debug(f"Error scanning {ip}: {e}")
        return None
    
    # Use a smaller number of workers to avoid overwhelming the system
    max_workers = min(20, len(ip_range))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(check_host, ip_range))
    
    # Filter out None results and add to devices list
    for result in results:
        if result is not None:
            devices.append(result)
    
    # Try to scan gateway
    try:
        if local_ip:
            gateway = '.'.join(local_ip.split('.')[:3]) + '.1'  # Assume .1 is gateway
            if gateway not in discovered_ips:
                gateway_result = check_host(gateway)
                if gateway_result:
                    gateway_result['vendor'] = "Possible Gateway"
                    devices.append(gateway_result)
    except Exception as e:
        logger.debug(f"Error checking gateway: {e}")
        
    logger.info(f"Alternative scan completed, found {len(devices)} devices")
    return devices

def perform_quick_scan(target_ip: str):
    """
    Perform a quick scan on specific IP addresses without full ARP scan
    Useful for checking if specific devices are online
    """
    try:
        # If CIDR notation, convert to list of IPs
        ip_list = []
        if '/' in target_ip:
            network = ipaddress.IPv4Network(target_ip, strict=False)
            # Limit to first 10 hosts for quick scan
            ip_list = [str(ip) for ip in list(network.hosts())[:10]]
        else:
            ip_list = [target_ip]
        
        results = []
        with ThreadPoolExecutor(max_workers=min(10, len(ip_list))) as executor:
            ping_results = list(executor.map(ping_host, ip_list))
            
            # For IPs that respond to ping, get more info
            for ip, is_online in zip(ip_list, ping_results):
                if is_online:
                    # Try to get MAC and other details
                    try:
                        # ARP ping to get MAC
                        arp_result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=0)[0]
                        if arp_result:
                            _, received = arp_result[0]
                            mac = received.hwsrc
                            vendor = get_mac_vendor(mac)
                            hostname = resolve_hostname(ip)
                            
                            results.append({
                                "ip": ip,
                                "mac": mac,
                                "vendor": vendor,
                                "hostname": hostname,
                                "last_seen": datetime.now().isoformat(),
                                "status": "active"
                            })
                            continue
                    except Exception:
                        pass
                    
                    # If ARP doesn't work, add minimal information
                    results.append({
                        "ip": ip,
                        "mac": "Unknown",
                        "vendor": "Bilinmeyen Üretici",
                        "hostname": resolve_hostname(ip),
                        "last_seen": datetime.now().isoformat(),
                        "status": "active"
                    })
        
        return results
    except Exception as e:
        logger.error(f"Error in perform_quick_scan: {e}")
        return []