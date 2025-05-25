import socket
import logging
import platform
import subprocess
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

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
