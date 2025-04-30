import os
import threading
import csv
import logging
import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import time
import psutil

import customtkinter as ctk
from network_scanner.scanner import perform_arp_scan

logging.basicConfig(level=logging.INFO)


class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Tarayıcı")
        self.root.geometry("700x650")
        self.root.minsize(600, 600)
        
        # Create a header frame
        self.header_frame = ctk.CTkFrame(self.root)
        self.header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="WiFi Scanner", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(pady=5)
        
        # Create an input frame
        self.input_frame = ctk.CTkFrame(self.root)
        self.input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Network interfaces dropdown
        self.interfaces_var = tk.StringVar()
        self.interfaces_label = ctk.CTkLabel(self.input_frame, text="Ağ Arayüzü:")
        self.interfaces_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.interfaces = self.get_network_interfaces()
        self.interface_menu = ctk.CTkOptionMenu(
            self.input_frame, 
            values=self.interfaces,
            variable=self.interfaces_var,
            command=self.on_interface_change
        )
        self.interface_menu.grid(row=0, column=1, padx=5, pady=5, sticky="we")
        if self.interfaces:
            self.interface_menu.set(self.interfaces[0])
        
        # IP range entry
        ip_label = ctk.CTkLabel(self.input_frame, text="IP Aralığı:")
        ip_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        self.ip_entry = ctk.CTkEntry(self.input_frame, placeholder_text="örn: 192.168.1.1/24", width=200)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky="we")
        
        # Button frame
        self.button_frame = ctk.CTkFrame(self.root)
        self.button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Scan button
        self.scan_button = ctk.CTkButton(self.button_frame, text="Ağı Tara", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Clear button
        self.clear_button = ctk.CTkButton(self.button_frame, text="Sonuçları Temizle", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Save button
        self.save_button = ctk.CTkButton(self.button_frame, text="Sonuçları CSV Olarak Kaydet", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Progress bar frame
        self.progress_frame = ctk.CTkFrame(self.root)
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        self.progress_bar.set(0)
        
        # Status label
        self.status_label = ctk.CTkLabel(self.progress_frame, text="")
        self.status_label.pack(pady=5)
        
        # Output frame
        self.output_frame = ctk.CTkFrame(self.root)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Device count label
        self.device_count_label = ctk.CTkLabel(self.output_frame, text="Bulunan Cihazlar: 0")
        self.device_count_label.pack(anchor=tk.W, padx=5, pady=5)
        
        # Output textbox
        self.output_text = ctk.CTkTextbox(self.output_frame, width=660, height=300)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initialize variables
        self.devices = []
        self.scan_thread = None
        self.is_scanning = False
        self.progress_value = 0
        self.animation_id = None
        
        # Set initial IP address
        self.on_interface_change(self.interfaces_var.get())
    
    def get_network_interfaces(self):
        """Get available network interfaces with their IP addresses"""
        interfaces = []
        try:
            for interface, addresses in psutil.net_if_addrs().items():
                for address in addresses:
                    if address.family == socket.AF_INET:  # IPv4
                        interfaces.append(f"{interface} ({address.address})")
            return interfaces
        except Exception as e:
            logging.error(f"Error getting network interfaces: {e}")
            return ["Default"]
    
    def on_interface_change(self, selected_interface):
        """Update IP entry when interface is changed"""
        try:
            if "(" in selected_interface and ")" in selected_interface:
                ip = selected_interface.split("(")[1].split(")")[0]
                network = ".".join(ip.split(".")[:3]) + ".0/24"
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, network)
        except Exception as e:
            logging.error(f"Error updating IP from interface: {e}")
    
    def start_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Bilgi", "Tarama zaten devam ediyor.")
            return
        
        # Clear previous output and update status
        self.clear_results()
        self.update_status("Tarama başlatılıyor...")
        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            ip_range = "192.168.1.1/24"
        
        # Start scan in a new thread to avoid UI blocking
        self.scan_thread = threading.Thread(target=self.run_scan, args=(ip_range,), daemon=True)
        self.scan_thread.start()
        
        # Reset progress value and start animation
        self.progress_value = 0
        self.progress_bar.set(0)
        self.update_progress_animation()
    
    def update_progress_animation(self):
        # Cancel any existing animation
        if self.animation_id:
            self.root.after_cancel(self.animation_id)
            self.animation_id = None
            
        if self.is_scanning:
            # Increment progress value slowly between 0 and 0.95
            if self.progress_value < 0.95:
                self.progress_value += 0.01
                if self.progress_value > 0.95:
                    self.progress_value = 0.95
            
            self.progress_bar.set(self.progress_value)
            # Schedule next update after 100ms
            self.animation_id = self.root.after(100, self.update_progress_animation)
    
    def run_scan(self, ip_range):
        try:
            devices = perform_arp_scan(ip_range)
            self.devices = devices  # Save results for later use (e.g., saving to CSV)
            self.display_results(devices)
            self.update_status(f"Tarama tamamlandı. {len(devices)} cihaz bulundu.")
        except Exception as e:
            logging.error(f"Error during scanning: {e}")
            self.update_status("Tarama sırasında bir hata oluştu.")
        finally:
            self.is_scanning = False
            # Complete the progress bar and re-enable the scan button in the main thread
            self.root.after(0, self.complete_scan)
    
    def complete_scan(self):
        """Complete the scanning process by updating UI elements"""
        self.progress_bar.set(1)
        self.scan_button.configure(state="normal")
        # Cancel any ongoing animation
        if self.animation_id:
            self.root.after_cancel(self.animation_id)
            self.animation_id = None

    def display_results(self, devices):
        # Ensure UI updates happen in the main thread using after()
        def update_ui():
            self.output_text.delete("1.0", tk.END)
            if devices:
                for device in devices:
                    output = (f"IP: {device['ip']}\nMAC: {device['mac']}\nÜretici: {device['vendor']}\nCihaz Adı: {device['hostname']}\n" 
                              f"{'='*40}\n")
                    self.output_text.insert(tk.END, output)
                
                self.device_count_label.configure(text=f"Bulunan Cihazlar: {len(devices)}")
            else:
                self.output_text.insert(tk.END, "Cihaz bulunamadı.\n")
                self.device_count_label.configure(text="Bulunan Cihazlar: 0")
        
        self.root.after(0, update_ui)

    def clear_results(self):
        self.output_text.delete("1.0", tk.END)
        self.status_label.configure(text="")
        self.device_count_label.configure(text="Bulunan Cihazlar: 0")
        self.progress_bar.set(0)
        
        # Cancel any ongoing animation
        if self.animation_id:
            self.root.after_cancel(self.animation_id)
            self.animation_id = None

    def save_results(self):
        if not self.devices:
            messagebox.showwarning("Uyarı", "Kayıt edilecek herhangi bir tarama sonucu bulunamadı.")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", 
                                                 filetypes=[("CSV Dosyaları", "*.csv"), ("Tüm Dosyalar", "*.*")], 
                                                 initialfile="network_scan_results.csv",
                                                 title="Sonuçları Kaydet")
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
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