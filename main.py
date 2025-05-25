import ctypes
import sys
import os
import logging
import tkinter as tk
from tkinter import messagebox
import platform
import json
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,  # Daha detaylı log seviyesi
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log',
    filemode='a'
)

# Create a console handler
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)  # Konsol çıktısını da detaylandır
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

def is_admin():
    """Check if the current process has admin privileges"""
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Root check for Unix systems (approximate)
            return os.geteuid() == 0
    except Exception as e:
        logging.error(f"Error checking admin status: {e}")
        return False

def check_libpcap():
    """Check if libpcap is properly installed/available"""
    try:
        # Add a global flag to track scapy status
        global SCAPY_WITH_PCAP
        SCAPY_WITH_PCAP = False
        
        import scapy.all
        # Redirect scapy warnings to our logger
        scapy.all.conf.logLevel = 40  # ERROR level
        
        # Test if libpcap is functional
        if hasattr(scapy.all, 'conf'):
            if getattr(scapy.all.conf, 'use_pcap', False) is True:
                SCAPY_WITH_PCAP = True
                logging.info("Libpcap is available and properly configured.")
                return True
            else:
                if platform.system() == 'Windows':
                    logging.warning("Libpcap not available. Using alternative scanning methods.")
                    return False
                else:
                    # On non-Windows systems, scapy can often work without libpcap
                    logging.warning("Libpcap may not be fully configured, but should work.")
                    return True
    except ImportError as e:
        logging.error(f"Scapy not properly installed: {e}")
        return False
    except Exception as e:
        logging.error(f"Error checking libpcap: {e}")
        return False
    
    return True

def show_libpcap_warning():
    """Show warning about missing libpcap and instructions to install it"""
    warning_root = tk.Tk()
    warning_root.withdraw()
    
    if platform.system() == 'Windows':
        message = (
            "Libpcap provider not found. Some features may not work properly.\n\n"
            "Follow these steps to resolve this issue:\n"
            "1. Install Npcap (https://npcap.com/) or WinPcap (https://www.winpcap.org/).\n"
            "2. During installation, check the 'Install Npcap in WinPcap API-compatible Mode' option.\n"
            "3. Restart your system.\n\n"
            "The program can run without Npcap/WinPcap, but network scanning features will be limited. "
            "Do you want to continue?"
        )
    else:
        message = (
            "Libpcap provider not found. Some features may not work properly.\n\n"
            "Follow these steps to resolve this issue:\n"
            "1. Linux: sudo apt-get install libpcap-dev\n"
            "2. macOS: brew install libpcap\n\n"
            "The program can run without libpcap, but network scanning features will be limited. "
            "Do you want to continue?"
        )
    
    result = messagebox.askquestion("Libpcap Warning", message)
    warning_root.destroy()
    
    return result == 'yes'

def check_dependencies():
    """Check and warn about missing dependencies"""
    try:
        # List of core required modules - these are essential
        core_modules = ['customtkinter', 'scapy', 'psutil', 'requests']
        
        # Additional modules that enhance functionality but aren't required
        optional_modules = ['matplotlib', 'pillow', 'netifaces', 'python-nmap']
        
        missing_core = []
        missing_optional = []
        
        # Check core modules
        for module in core_modules:
            try:
                __import__(module)
            except ImportError:
                missing_core.append(module)
        
        # Check optional modules
        for module in optional_modules:
            try:
                __import__(module)
            except ImportError:
                missing_optional.append(module)
        
        if missing_core:
            # Create a temporary hidden root to display the warning
            warning_root = tk.Tk()
            warning_root.withdraw()
            
            message = (
                f"Aşağıdaki temel kütüphaneler eksik:\n{', '.join(missing_core)}\n\n"
                "Program tam olarak çalışmayabilir. Yüklemek istiyor musunuz?\n\n"
                "Not: Yükleme başarısız olursa, komutu manuel olarak çalıştırabilirsiniz:\n"
                "pip install -r requirements.txt"
            )
            
            result = messagebox.askquestion("Eksik Temel Kütüphaneler", message)
            warning_root.destroy()
            
            if result == 'yes':
                try:
                    # Install missing modules using pip
                    import subprocess
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
                except Exception as e:
                    logging.error(f"Error installing dependencies: {e}")
                    warning_root = tk.Tk()
                    warning_root.withdraw()
                    messagebox.showwarning(
                        "Yükleme Hatası", 
                        f"Kütüphaneler yüklenirken hata oluştu: {str(e)}\n\n"
                        "Yönetici olarak çalıştırmayı veya manuel yüklemeyi deneyin.\n"
                        "pip install -r requirements.txt"
                    )
                    warning_root.destroy()
        
        # Just warn about optional modules if any are missing
        if missing_optional and not missing_core:
            logging.warning(f"Optional modules missing: {missing_optional}")
            print(f"Not: Bazı isteğe bağlı özellikler eksik kütüphaneler nedeniyle devre dışı: {', '.join(missing_optional)}")
        
        # Return True as long as core dependencies are present
        return len(missing_core) == 0
    except Exception as e:
        logging.error(f"Error checking dependencies: {e}")
        return True  # Continue anyway

def show_version_info():
    """Display version information at startup"""
    version_info = {
        "app": "WiFi Scanner",
        "version": "2.0",
        "update_date": "2025-05-25",
        "python_version": sys.version.split()[0],
        "platform": platform.system() + " " + platform.release()
    }
    
    logging.info(f"Starting {version_info['app']} v{version_info['version']} on {version_info['platform']} with Python {version_info['python_version']}")
    return version_info

def main():
    """Main application entry point"""
    try:
        # Show version info
        version_info = show_version_info()
        
        # Check for administrative privileges
        if not is_admin():
            # Create a temporary hidden root to display the warning
            warning_root = tk.Tk()
            warning_root.withdraw()
            
            result = messagebox.askquestion(
                "Administrator Privileges Required", 
                "Administrator privileges are required for ARP scanning. Do you want to continue?\n\n"
                "Warning: Some features may be limited without administrator privileges."
            )
            
            warning_root.destroy()
            
            if result != 'yes':
                print("Program terminated by user.")
                sys.exit(1)
            
            print("WARNING: Running without administrator privileges. Some features may be limited.")
        
        # Check dependencies
        if not check_dependencies():
            print("Required libraries could not be loaded. Program is terminating.")
            sys.exit(1)
        
        # Check for libpcap but continue regardless
        libpcap_available = check_libpcap()
        if not libpcap_available:
            if not show_libpcap_warning():
                print("Program terminated by user.")
                sys.exit(1)
            else:
                # Continue without libpcap, using alternative scanning methods
                print("Continuing without libpcap. Alternative scanning methods will be used.")
                logging.warning("Continuing without libpcap. Using alternative scanning methods.")
        
        # Set a global flag that can be accessed from other modules
        os.environ['WIFI_SCANNER_LIBPCAP_AVAILABLE'] = str(libpcap_available)
        
        # Import GUI libraries after checks
        import customtkinter as ctk
        from network_scanner.gui import NetworkScannerApp
        
        # Set initial theme based on system preference if available
        try:
            settings_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.json')
            if os.path.exists(settings_path):
                with open(settings_path, 'r') as f:
                    settings = json.load(f)
                    if 'theme' in settings:
                        ctk.set_appearance_mode(settings['theme'])
                    else:
                        ctk.set_appearance_mode("dark")
            else:
                ctk.set_appearance_mode("dark")
        except:
            ctk.set_appearance_mode("dark")
            
        ctk.set_default_color_theme("blue")
        
        # Create main window
        root = ctk.CTk()
        root.title(f"WiFi Scanner v{version_info['version']}")
        
        # Create icon if available
        try:
            # If icon.ico exists, set it as window icon
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.ico')
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        except Exception as e:
            logging.warning(f"Could not load icon: {e}")
        
        # Initialize app
        app = NetworkScannerApp(root)
        root.mainloop()
        
    except ImportError as e:
        logging.error(f"Missing dependency: {e}")
        tk.Tk().withdraw()
        messagebox.showerror(
            "Missing Dependency", 
            f"The required libraries for the application could not be found: {e}\n\n"
            "You can install the necessary libraries using the following command:\n"
            "pip install -r requirements.txt"
        )
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        try:
            tk.Tk().withdraw()
            messagebox.showerror("Hata", f"Beklenmeyen bir hata oluştu: {e}")
        except:
            print(f"Kritik hata: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 