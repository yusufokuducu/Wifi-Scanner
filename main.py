import ctypes
import sys
import os
import logging
import tkinter as tk
from tkinter import messagebox
import platform

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log',
    filemode='a'
)

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
        import scapy.all
        # Redirect scapy warnings to our logger
        scapy.all.conf.logLevel = 40  # ERROR level
        
        # Test if libpcap is functional
        if hasattr(scapy.all, 'conf') and getattr(scapy.all.conf, 'use_pcap', False) is False:
            if platform.system() == 'Windows':
                logging.warning("Libpcap not available. Some features may not work correctly.")
                return False
    except ImportError:
        logging.error("Scapy not properly installed")
        return False
    
    return True

def show_libpcap_warning():
    """Show warning about missing libpcap and instructions to install it"""
    warning_root = tk.Tk()
    warning_root.withdraw()
    
    if platform.system() == 'Windows':
        message = (
            "libpcap sağlayıcısı bulunamadı. Bazı özellikler düzgün çalışmayabilir.\n\n"
            "Bu sorunu çözmek için şu adımları izleyin:\n"
            "1. Npcap (https://npcap.com/) veya WinPcap (https://www.winpcap.org/) yükleyin.\n"
            "2. Yükleme sırasında 'Install Npcap in WinPcap API-compatible Mode' seçeneğini işaretleyin.\n"
            "3. Sisteminizi yeniden başlatın.\n\n"
            "Devam etmek istiyor musunuz?"
        )
    else:
        message = (
            "libpcap sağlayıcısı bulunamadı. Bazı özellikler düzgün çalışmayabilir.\n\n"
            "Bu sorunu çözmek için şu adımları izleyin:\n"
            "1. Linux: sudo apt-get install libpcap-dev\n"
            "2. macOS: brew install libpcap\n\n"
            "Devam etmek istiyor musunuz?"
        )
    
    result = messagebox.askquestion("Libpcap Uyarısı", message)
    warning_root.destroy()
    
    return result == 'yes'

def main():
    """Main application entry point"""
    try:
        # Check for administrative privileges
        if not is_admin():
            # Create a temporary hidden root to display the warning
            warning_root = tk.Tk()
            warning_root.withdraw()
            
            result = messagebox.askquestion(
                "Yönetici İzni Gerekli", 
                "ARP taraması için yönetici izinleri gereklidir. Devam etmek istiyor musunuz?\n\n"
                "Uyarı: Yönetici olmadan bazı işlevler sınırlı olabilir."
            )
            
            warning_root.destroy()
            
            if result != 'yes':
                print("Program kullanıcı tarafından sonlandırıldı.")
                sys.exit(1)
            
            print("UYARI: Yönetici izinleri olmadan çalışılıyor. Bazı işlevler sınırlı olabilir.")
        
        # Check for libpcap
        if not check_libpcap():
            if not show_libpcap_warning():
                print("Program kullanıcı tarafından sonlandırıldı.")
                sys.exit(1)
        
        # Import GUI libraries after checks
        import customtkinter as ctk
        from network_scanner.gui import NetworkScannerApp
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        root = ctk.CTk()
        app = NetworkScannerApp(root)
        root.mainloop()
        
    except ImportError as e:
        logging.error(f"Missing dependency: {e}")
        tk.Tk().withdraw()
        messagebox.showerror(
            "Eksik Bağımlılık", 
            f"Uygulama için gereken kütüphaneler bulunamadı: {e}\n\n"
            "Aşağıdaki komutu kullanarak gerekli kütüphaneleri yükleyebilirsiniz:\n"
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