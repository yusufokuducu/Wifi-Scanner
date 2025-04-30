import ctypes
import sys
import os
import logging
import tkinter as tk
from tkinter import messagebox

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
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"Error checking admin status: {e}")
        return False

def main():
    """Main application entry point"""
    try:
        # Check for administrative privileges on Windows
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
        
        # Import GUI libraries after admin check
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