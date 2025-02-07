import ctypes
import sys
import tkinter as tk
from tkinter import messagebox

# Check for administrative privileges on Windows
try:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
except Exception as e:
    is_admin = False

if not is_admin:
    # Create a temporary hidden root to display the warning
    warning_root = tk.Tk()
    warning_root.withdraw()
    messagebox.showwarning("Yönetici İzni Gerekli", "ARP taraması için yönetici izinleri gereklidir. Lütfen uygulamayı yönetici olarak çalıştırın.")
    warning_root.destroy()
    print("WARNING: Yönetici izinleri bulunamadı. ARP taraması için yönetici haklarına ihtiyaç vardır. Lütfen uygulamayı yönetici olarak çalıştırın.")
    # Optionally, exit the program if admin rights are required:
    # sys.exit(1)

import customtkinter as ctk
from network_scanner.gui import NetworkScannerApp


def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    app = NetworkScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main() 