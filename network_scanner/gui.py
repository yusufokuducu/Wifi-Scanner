import os
import threading
import csv
import logging
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from network_scanner.scanner import perform_arp_scan

logging.basicConfig(level=logging.INFO)


class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Tarayıcı")
        self.root.geometry("600x600")

        # IP range entry
        self.ip_entry = ctk.CTkEntry(self.root, placeholder_text="IP Aralığı (örn: 192.168.1.1/24)", width=400)
        self.ip_entry.pack(pady=10)

        # Scan button
        self.scan_button = ctk.CTkButton(self.root, text="Ağı Tara", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Clear button
        self.clear_button = ctk.CTkButton(self.root, text="Sonuçları Temizle", command=self.clear_results)
        self.clear_button.pack(pady=10)

        # Save button
        self.save_button = ctk.CTkButton(self.root, text="Sonuçları CSV Olarak Kaydet", command=self.save_results)
        self.save_button.pack(pady=10)

        # Output textbox
        self.output_text = ctk.CTkTextbox(self.root, width=560, height=300)
        self.output_text.pack(pady=10)

        # Status label
        self.status_label = ctk.CTkLabel(self.root, text="")
        self.status_label.pack(pady=5)

        # List to hold scan results
        self.devices = []

    def start_scan(self):
        # Clear previous output and update status
        self.clear_results()
        self.update_status("Tarama başlatılıyor...")
        
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            ip_range = "192.168.1.1/24"
        
        # Start scan in a new thread to avoid UI blocking
        scan_thread = threading.Thread(target=self.run_scan, args=(ip_range,), daemon=True)
        scan_thread.start()

    def run_scan(self, ip_range):
        try:
            devices = perform_arp_scan(ip_range)
            self.devices = devices  # Save results for later use (e.g., saving to CSV)
            self.display_results(devices)
            self.update_status("Tarama tamamlandı.")
        except Exception as e:
            logging.error(f"Error during scanning: {e}")
            self.update_status("Tarama sırasında bir hata oluştu.")

    def display_results(self, devices):
        # Ensure UI updates happen in the main thread using after()
        def update_ui():
            self.output_text.delete("1.0", tk.END)
            if devices:
                for device in devices:
                    output = (f"IP: {device['ip']}\nMAC: {device['mac']}\nÜretici: {device['vendor']}\nCihaz Adı: {device['hostname']}\n" 
                              f"{'='*40}\n")
                    self.output_text.insert(tk.END, output)
            else:
                self.output_text.insert(tk.END, "Cihaz bulunamadı.\n")
        
        self.root.after(0, update_ui)

    def clear_results(self):
        self.output_text.delete("1.0", tk.END)
        self.status_label.configure(text="")

    def save_results(self):
        if not self.devices:
            messagebox.showwarning("Uyarı", "Kayıt edilecek herhangi bir tarama sonucu bulunamadı.")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", 
                                                 filetypes=[("CSV Dosyaları", "*.csv")], 
                                                 title="Sonuçları Kaydet")
        if file_path:
            try:
                with open(file_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP", "MAC", "Üretici", "Cihaz Adı"])
                    for device in self.devices:
                        writer.writerow([device["ip"], device["mac"], device["vendor"], device["hostname"]])
                messagebox.showinfo("Başarılı", f"Sonuçlar {os.path.basename(file_path)} dosyasına kaydedildi.")
            except Exception as e:
                logging.error(f"Error saving results: {e}")
                messagebox.showerror("Hata", "Sonuçlar kaydedilirken bir hata oluştu.")

    def update_status(self, message):
        def update_label():
            self.status_label.configure(text=message)
        self.root.after(0, update_label) 