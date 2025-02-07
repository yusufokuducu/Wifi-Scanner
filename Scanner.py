import tkinter as tk
import customtkinter as ctk
from scapy.all import ARP, Ether, srp
import socket
import csv
import logging

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Tarayıcı")
        self.root.geometry("400x600")

        self.output_text = ctk.CTkTextbox(self.root, width=380, height=200)
        self.output_text.pack(pady=10)

        self.device_count_text = ctk.CTkTextbox(self.root, width=380, height=50)
        self.device_count_text.pack(pady=10)

        self.ip_entry = ctk.CTkEntry(self.root, placeholder_text="IP Aralığı (örn: 192.168.1.1/24)")
        self.ip_entry.pack(pady=10)

        self.device_type_entry = ctk.CTkEntry(self.root, placeholder_text="Cihaz Türü (örn: Bilgisayar)")
        self.device_type_entry.pack(pady=10)

        self.device_location_entry = ctk.CTkEntry(self.root, placeholder_text="Cihaz Konumu (örn: Ofis)")
        self.device_location_entry.pack(pady=10)

        self.device_description_entry = ctk.CTkEntry(self.root, placeholder_text="Açıklama")
        self.device_description_entry.pack(pady=10)

        self.device_os_entry = ctk.CTkEntry(self.root, placeholder_text="İşletim Sistemi (örn: Windows)")
        self.device_os_entry.pack(pady=10)

        self.device_owner_entry = ctk.CTkEntry(self.root, placeholder_text="Cihaz Sahibi")
        self.device_owner_entry.pack(pady=10)

        self.scan_button = ctk.CTkButton(self.root, text="Ağı Tara", command=self.scan_network)
        self.scan_button.pack(pady=10)

        self.clear_button = ctk.CTkButton(self.root, text="Sonuçları Temizle", command=self.clear_results)
        self.clear_button.pack(pady=10)

        self.save_button = ctk.CTkButton(self.root, text="Sonuçları CSV Olarak Kaydet", command=self.save_results)
        self.save_button.pack(pady=10)

        self.history = []  # Tarama geçmişi

        self.loading_label = ctk.CTkLabel(self.root, text="")
        self.loading_label.pack(pady=10)

        logging.basicConfig(level=logging.INFO)

    def scan_network(self):
        try:
            self.output_text.delete("1.0", tk.END)
            self.device_count_text.delete("1.0", tk.END)
            self.loading_label.configure(text="Tarama başlatılıyor...")
            self.loading_label.update()

            target_ip = self.ip_entry.get() or "192.168.1.1/24"
            self.loading_animation()
            self.root.after(100, self.perform_scan, target_ip)
        except Exception as e:
            logging.error(f"Error during network scan: {e}")
            self.output_text.insert(tk.END, "Tarama sırasında bir hata oluştu.\n")

    def loading_animation(self):
        for i in range(3):
            self.loading_label.configure(text="Tarama başlatılıyor" + "." * (i + 1))
            self.root.update()
            self.root.after(500)

    def perform_scan(self, target_ip):
        try:
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]

            device_count = 0
            scan_results = []

            for sent, received in result:
                device_count += 1
                vendor = "Bilinmeyen Üretici"

                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    hostname = "Bilinmeyen Cihaz"

                device_type = self.device_type_entry.get() or "Bilinmeyen Tür"
                device_location = self.device_location_entry.get() or "Bilinmeyen Konum"
                device_description = self.device_description_entry.get() or "Açıklama Yok"
                device_os = self.device_os_entry.get() or "Bilinmeyen OS"
                device_owner = self.device_owner_entry.get() or "Bilinmeyen Sahip"

                output = (f"IP: {received.psrc}\nMAC: {received.hwsrc}\nÜretici: {vendor}\n"
                          f"Cihaz Adı: {hostname}\nCihaz Türü: {device_type}\n"
                          f"Cihaz Konumu: {device_location}\nAçıklama: {device_description}\n"
                          f"İşletim Sistemi: {device_os}\nCihaz Sahibi: {device_owner}\n"
                          f"{'='*40}\n")
                self.output_text.insert(tk.END, output)
                scan_results.append((received.psrc, received.hwsrc, vendor, hostname, device_type, device_location, device_description, device_os, device_owner))

            self.history.append(scan_results)
            count_text = f"Toplam Bulunan Cihaz Sayısı: {device_count}"
            self.device_count_text.insert(tk.END, count_text)

            self.output_text.insert(tk.END, "\nTarama tamamlandı.\n")
            self.loading_label.configure(text="")
        except Exception as e:
            logging.error(f"Error during perform scan: {e}")
            self.output_text.insert(tk.END, "Tarama sırasında bir hata oluştu.\n")

    def clear_results(self):
        self.output_text.delete("1.0", tk.END)
        self.device_count_text.delete("1.0", tk.END)
        self.ip_entry.delete(0, tk.END)
        self.device_type_entry.delete(0, tk.END)
        self.device_location_entry.delete(0, tk.END)
        self.device_description_entry.delete(0, tk.END)
        self.device_os_entry.delete(0, tk.END)
        self.device_owner_entry.delete(0, tk.END)

    def save_results(self):
        try:
            with open("network_scan_results.csv", "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "MAC", "Üretici", "Cihaz Adı", "Cihaz Türü", "Cihaz Konumu", "Açıklama", "İşletim Sistemi", "Cihaz Sahibi"])
                for scan in self.history:
                    for device in scan:
                        writer.writerow(device)

            self.output_text.insert(tk.END, "Sonuçlar 'network_scan_results.csv' dosyasına kaydedildi.\n")
        except Exception as e:
            logging.error(f"Error saving results: {e}")
            self.output_text.insert(tk.END, "Sonuçlar kaydedilirken bir hata oluştu.\n")

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # Karanlık mod
    ctk.set_default_color_theme("blue")  # Renk teması
    root = ctk.CTk()
    app = NetworkScannerApp(root)
    root.mainloop()
