import tkinter as tk
import customtkinter as ctk
from scapy.all import ARP, Ether, srp

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Tarayıcı")
        self.root.geometry("400x300")

        self.output_text = ctk.CTkTextbox(self.root, width=380, height=200)
        self.output_text.pack(pady=10)

        self.scan_button = ctk.CTkButton(self.root, text="Ağı Tara", command=self.scan_network)
        self.scan_button.pack(pady=10)

    def scan_network(self):
        self.output_text.delete("1.0", tk.END)  # Önceki çıktıyı temizle
        self.output_text.insert(tk.END, "Tarama başlatılıyor...\n")

        # Ağ taraması
        target_ip = "192.168.1.1/24"  # Hedef IP aralığı
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]

        # Sonuçları yazma
        with open("network_scan_results.txt", "w") as f:
            for sent, received in result:
                output = f"IP: {received.psrc}, MAC: {received.hwsrc}\n"
                self.output_text.insert(tk.END, output)
                f.write(output)

        self.output_text.insert(tk.END, "Tarama tamamlandı. Sonuçlar 'network_scan_results.txt' dosyasına kaydedildi.\n")

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # Karanlık mod
    ctk.set_default_color_theme("blue")  # Renk teması
    root = ctk.CTk()
    app = NetworkScannerApp(root)
    root.mainloop()
