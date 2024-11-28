import tkinter as tk
import customtkinter as ctk
from scapy.all import ARP, Ether, srp

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Tarayıcı")
        self.root.geometry("400x400")

        self.output_text = ctk.CTkTextbox(self.root, width=380, height=200)
        self.output_text.pack(pady=10)

        self.device_count_text = ctk.CTkTextbox(self.root, width=380, height=50)
        self.device_count_text.pack(pady=10)

        self.scan_button = ctk.CTkButton(self.root, text="Ağı Tara", command=self.scan_network)
        self.scan_button.pack(pady=10)

    def scan_network(self):
        self.output_text.delete("1.0", tk.END)
        self.device_count_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "Tarama başlatılıyor...\n")

        target_ip = "192.168.1.1/24"
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]

        device_count = 0
        with open("network_scan_results.txt", "w") as f:
            for sent, received in result:
                device_count += 1
                try:
                    from mac_vendor_lookup import MacLookup
                    mac_lookup = MacLookup()
                    vendor = mac_lookup.lookup(received.hwsrc)
                except:
                    vendor = "Bilinmeyen Üretici"

                try:
                    import socket
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except:
                    hostname = "Bilinmeyen Cihaz"

                output = f"IP: {received.psrc}\nMAC: {received.hwsrc}\nÜretici: {vendor}\nCihaz Adı: {hostname}\n{'='*40}\n"
                self.output_text.insert(tk.END, output)
                f.write(output)

        count_text = f"Toplam Bulunan Cihaz Sayısı: {device_count}"
        self.device_count_text.insert(tk.END, count_text)
        
        self.output_text.insert(tk.END, "\nTarama tamamlandı. Sonuçlar 'network_scan_results.txt' dosyasına kaydedildi.\n")

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # Karanlık mod
    ctk.set_default_color_theme("blue")  # Renk teması
    root = ctk.CTk()
    app = NetworkScannerApp(root)
    root.mainloop()
