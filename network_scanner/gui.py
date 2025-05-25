import os
import threading
import csv
import json
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import time
import datetime
import psutil

# İsteğe bağlı modülleri kontrol et
try:
    import webbrowser
except ImportError:
    webbrowser = None

# Matplotlib için koşullu import
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# PIL için koşullu import
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ipaddress için koşullu import
try:
    import ipaddress
    IPADDRESS_AVAILABLE = True
except ImportError:
    IPADDRESS_AVAILABLE = False

import customtkinter as ctk

# Bağımlılıklara göre işlevleri içe aktar
from network_scanner.scanner import perform_arp_scan

# İsteğe bağlı işlevleri kontrol et
try:
    from network_scanner.scanner import perform_quick_scan, get_interface_details, get_subnet_from_ip_and_mask, ping_host
    ADVANCED_SCAN_AVAILABLE = True
except ImportError:
    ADVANCED_SCAN_AVAILABLE = False
    # Kullanılamayan işlevler için basit alternatifler
    def perform_quick_scan(target_ip):
        return perform_arp_scan(target_ip)
        
    def ping_host(ip):
        try:
            return socket.gethostbyname(ip) == ip
        except:
            return False
            
    def get_subnet_from_ip_and_mask(ip, netmask):
        return f"{'.'.join(ip.split('.')[:3])}.0/24"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("900x700")
        self.root.minsize(800, 650)
        
        # Create a header frame
        self.header_frame = ctk.CTkFrame(self.root)
        self.header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="Network Scanner", font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.pack(pady=5)
        self.subtitle_label = ctk.CTkLabel(self.header_frame, text="Local Network Device Scanner", font=ctk.CTkFont(size=14))
        self.subtitle_label.pack(pady=2)
        
        # Create a tabview for different sections
        self.tabview = ctk.CTkTabview(self.root)
        self.tabview.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Add tabs
        self.tabview.add("Network Scan")
        self.tabview.add("Device List")
        self.tabview.add("Network Graph")
        self.tabview.add("Settings")
        self.tabview.set("Network Scan")
        
        # === Scan Tab Setup ===
        scan_tab = self.tabview.tab("Network Scan")
        
        # Create an input frame
        self.input_frame = ctk.CTkFrame(scan_tab)
        self.input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Network interfaces dropdown
        self.interfaces_var = tk.StringVar()
        self.interfaces_label = ctk.CTkLabel(self.input_frame, text="Network Interface:")
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
        
        # Refresh interfaces button
        self.refresh_button = ctk.CTkButton(
            self.input_frame, 
            text="Refresh", 
            width=30, 
            command=self.refresh_interfaces
        )
        self.refresh_button.grid(row=0, column=2, padx=5, pady=5)
        
        # IP range entry
        ip_label = ctk.CTkLabel(self.input_frame, text="Target IP/Network:")
        ip_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        self.ip_entry = ctk.CTkEntry(self.input_frame, placeholder_text="e.g. 192.168.1.1/24", width=200)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky="we")
        
        # Scan type selection
        scan_type_label = ctk.CTkLabel(self.input_frame, text="Scan Type:")
        scan_type_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        
        self.scan_type_var = tk.StringVar(value="Standard Scan")
        self.scan_type_menu = ctk.CTkOptionMenu(
            self.input_frame,
            values=["Standard Scan", "Quick Scan", "Detailed Scan"],
            variable=self.scan_type_var
        )
        self.scan_type_menu.grid(row=2, column=1, padx=5, pady=5, sticky="we")
        
        # Button frame
        self.button_frame = ctk.CTkFrame(scan_tab)
        self.button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Scan button
        self.scan_button = ctk.CTkButton(
            self.button_frame, 
            text="Start Scan", 
            command=self.start_scan,
            fg_color="#2E8B57",
            hover_color="#3CB371"
        )
        self.scan_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Clear button
        self.clear_button = ctk.CTkButton(self.button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Save button
        self.save_button = ctk.CTkButton(self.button_frame, text="Save Results", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # View as table button
        self.view_table_button = ctk.CTkButton(
            self.button_frame, 
            text="View as Table", 
            command=lambda: self.tabview.set("Device List")
        )
        self.view_table_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Progress bar frame
        self.progress_frame = ctk.CTkFrame(scan_tab)
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        self.progress_bar.set(0)
        
        # Status label
        self.status_label = ctk.CTkLabel(self.progress_frame, text="")
        self.status_label.pack(pady=5)
        
        # Output frame
        self.output_frame = ctk.CTkFrame(scan_tab)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Device count label
        self.device_count_label = ctk.CTkLabel(self.output_frame, text="Devices Found: 0")
        self.device_count_label.pack(anchor=tk.W, padx=5, pady=5)
        
        # Output textbox
        self.output_text = ctk.CTkTextbox(self.output_frame, width=660, height=300)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # === Device List Tab Setup ===
        device_tab = self.tabview.tab("Device List")
        
        # Filter frame
        self.filter_frame = ctk.CTkFrame(device_tab)
        self.filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Filter label
        filter_label = ctk.CTkLabel(self.filter_frame, text="Filter:")
        filter_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Filter entry
        self.filter_entry = ctk.CTkEntry(self.filter_frame, width=200)
        self.filter_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.filter_entry.bind("<KeyRelease>", self.filter_devices)
        
        # Refresh button for device list
        self.refresh_list_button = ctk.CTkButton(
            self.filter_frame, 
            text="Refresh List", 
            command=self.refresh_device_list
        )
        self.refresh_list_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Create device treeview
        self.tree_frame = ctk.CTkFrame(device_tab)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Use a Treeview inside the CTkFrame
        self.device_tree = ttk.Treeview(
            self.tree_frame, 
            columns=("ip", "mac", "vendor", "hostname", "status"),
            show="headings"
        )
        
        # Configure column headings
        self.device_tree.heading("ip", text="IP Address")
        self.device_tree.heading("mac", text="MAC Address")
        self.device_tree.heading("vendor", text="Vendor")
        self.device_tree.heading("hostname", text="Hostname")
        self.device_tree.heading("status", text="Status")
        
        # Configure column widths
        self.device_tree.column("ip", width=120)
        self.device_tree.column("mac", width=150)
        self.device_tree.column("vendor", width=150)
        self.device_tree.column("hostname", width=200)
        self.device_tree.column("status", width=80)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscroll=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event for device details
        self.device_tree.bind("<Double-1>", self.show_device_details)
        
        # Context menu for device list
        self.device_tree.bind("<Button-3>", self.show_context_menu)
        
        # === Network Graph Tab Setup ===
        graph_tab = self.tabview.tab("Network Graph")
        
        # Graph control frame
        self.graph_control_frame = ctk.CTkFrame(graph_tab)
        self.graph_control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Generate graph button
        self.generate_graph_button = ctk.CTkButton(
            self.graph_control_frame, 
            text="Generate Network Graph", 
            command=self.generate_network_graph
        )
        self.generate_graph_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Chart type selection
        chart_type_label = ctk.CTkLabel(self.graph_control_frame, text="Chart Type:")
        chart_type_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.chart_type_var = tk.StringVar(value="Pie Chart")
        self.chart_type_menu = ctk.CTkOptionMenu(
            self.graph_control_frame,
            values=["Pie Chart", "Bar Chart"],
            variable=self.chart_type_var
        )
        self.chart_type_menu.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Graph frame for matplotlib
        self.graph_frame = ctk.CTkFrame(graph_tab)
        self.graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # === Settings Tab Setup ===
        settings_tab = self.tabview.tab("Settings")
        
        # Settings frame
        self.settings_frame = ctk.CTkFrame(settings_tab)
        self.settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Theme selection
        theme_label = ctk.CTkLabel(self.settings_frame, text="Theme:", font=ctk.CTkFont(weight="bold"))
        theme_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.appearance_mode_var = tk.StringVar(value="dark")
        self.appearance_mode_menu = ctk.CTkOptionMenu(
            self.settings_frame,
            values=["light", "dark", "system"],
            variable=self.appearance_mode_var,
            command=self.change_appearance_mode
        )
        self.appearance_mode_menu.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        # Scan timeout setting
        timeout_label = ctk.CTkLabel(self.settings_frame, text="Scan Timeout (seconds):", font=ctk.CTkFont(weight="bold"))
        timeout_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.timeout_var = tk.StringVar(value="3")
        self.timeout_entry = ctk.CTkEntry(
            self.settings_frame, 
            width=100,
            textvariable=self.timeout_var
        )
        self.timeout_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        
        # Auto-refresh setting
        auto_refresh_label = ctk.CTkLabel(
            self.settings_frame, 
            text="Auto Refresh:", 
            font=ctk.CTkFont(weight="bold")
        )
        auto_refresh_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        self.auto_refresh_var = tk.BooleanVar(value=False)
        self.auto_refresh_switch = ctk.CTkSwitch(
            self.settings_frame,
            text="Enabled",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        )
        self.auto_refresh_switch.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        
        auto_refresh_interval_label = ctk.CTkLabel(self.settings_frame, text="Refresh Interval (minutes):")
        auto_refresh_interval_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        
        self.auto_refresh_interval_var = tk.StringVar(value="5")
        self.auto_refresh_interval_entry = ctk.CTkEntry(
            self.settings_frame, 
            width=100,
            textvariable=self.auto_refresh_interval_var
        )
        self.auto_refresh_interval_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")
        
        # About section
        about_label = ctk.CTkLabel(
            self.settings_frame, 
            text="About:", 
            font=ctk.CTkFont(weight="bold")
        )
        about_label.grid(row=4, column=0, padx=10, pady=10, sticky="w")
        
        about_text = ctk.CTkLabel(
            self.settings_frame, 
            text="Network Scanner v2.0\nScan and analyze devices on your local network.\nCopyright 2025 Network Scanner")
        about_text.grid(row=4, column=1, padx=10, pady=10, sticky="w")
        
        # Save settings button
        self.save_settings_button = ctk.CTkButton(
            self.settings_frame, 
            text="Save Settings", 
            command=self.save_settings
        )
        self.save_settings_button.grid(row=5, column=0, columnspan=2, padx=10, pady=20)
        
        # Footer frame
        self.footer_frame = ctk.CTkFrame(self.root)
        self.footer_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Status bar in footer
        self.footer_status = ctk.CTkLabel(self.footer_frame, text="Ready")
        self.footer_status.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Version info in footer
        version_info = ctk.CTkLabel(self.footer_frame, text="v2.0")
        version_info.pack(side=tk.RIGHT, padx=5, pady=2)
        
        # Initialize variables
        self.devices = []
        self.filtered_devices = []
        self.scan_thread = None
        self.is_scanning = False
        self.progress_value = 0
        self.animation_id = None
        self.auto_refresh_job = None
        
        # Load settings from file
        self.load_settings()
        
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
            messagebox.showinfo("Information", "Scan in progress...")
            return
        
        # Clear previous output and update status
        self.clear_results()
        self.update_status("Starting scan...")
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
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        self.interfaces = self.get_network_interfaces()
        self.interface_menu.configure(values=self.interfaces)
        if self.interfaces:
            self.interface_menu.set(self.interfaces[0])
            self.on_interface_change(self.interfaces[0])
        self.update_status("Network interfaces refreshed.")
    
    def run_scan(self, ip_range):
        try:
            # Get scan type
            scan_type = self.scan_type_var.get()
            timeout = int(self.timeout_var.get()) if self.timeout_var.get().isdigit() else 3
            
            if scan_type == "Quick Scan":
                devices = perform_quick_scan(ip_range)
            elif scan_type == "Detailed Scan":
                # Detailed scan uses longer timeout and more retries
                devices = perform_arp_scan(ip_range, timeout=timeout+2, retry=3)
            else:  # Standard scan
                devices = perform_arp_scan(ip_range, timeout=timeout)
            
            self.devices = devices  # Save results for later use
            self.display_results(devices)
            self.update_device_list(devices)  # Update the table view
            self.update_status(f"Scan completed. {len(devices)} devices found.")
            self.footer_status.configure(text=f"Last scan: {datetime.datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            logging.error(f"Error during scanning: {e}")
            self.update_status(f"Error during scan: {str(e)}")
        finally:
            self.is_scanning = False
            # Complete the progress bar and re-enable the scan button in the main thread
            self.root.after(0, self.complete_scan)
    
    def update_device_list(self, devices):
        """Update the device list in the table view"""
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
            
        # Add devices to the tree
        for device in devices:
            status = device.get("status", "active")
            self.device_tree.insert(
                "", 
                "end", 
                values=(
                    device["ip"],
                    device["mac"],
                    device["vendor"],
                    device["hostname"],
                    status
                )
            )
        
        # Save filtered devices
        self.filtered_devices = devices
    
    def filter_devices(self, event=None):
        """Filter devices based on the search text"""
        search_text = self.filter_entry.get().lower()
        
        # If no search text, show all devices
        if not search_text:
            self.update_device_list(self.devices)
            return
            
        # Filter devices based on search text
        filtered = []
        for device in self.devices:
            if (search_text in device["ip"].lower() or 
                search_text in device["mac"].lower() or
                search_text in device["vendor"].lower() or
                search_text in device["hostname"].lower()):
                filtered.append(device)
                
        # Update the tree with filtered devices
        self.update_device_list(filtered)
    
    def refresh_device_list(self):
        """Refresh the device list with current data"""
        if not self.devices:
            messagebox.showinfo("Information", "No scan has been performed yet.")
            return
            
        self.update_device_list(self.devices)
        self.filter_devices()  # Apply any current filter
    
    def show_device_details(self, event):
        """Show detailed information about a selected device"""
        # Get selected item
        selected_item = self.device_tree.selection()
        if not selected_item:
            return
            
        # Get values of selected item
        item_values = self.device_tree.item(selected_item[0], "values")
        ip_address = item_values[0]
        
        # Find the device in our list
        device = None
        for d in self.devices:
            if d["ip"] == ip_address:
                device = d
                break
                
        if not device:
            return
            
        # Create a details window
        details_window = ctk.CTkToplevel(self.root)
        details_window.title(f"Device Details: {ip_address}")
        details_window.geometry("500x400")
        details_window.grab_set()  # Make the window modal
        
        # Device info frame
        info_frame = ctk.CTkFrame(details_window)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add device information
        device_info = (
            f"IP Address: {device['ip']}\n"
            f"MAC Address: {device['mac']}\n"
            f"Vendor: {device['vendor']}\n"
            f"Hostname: {device['hostname']}\n"
            f"Status: {device.get('status', 'active')}\n"
            f"Last Seen: {device.get('last_seen', 'Unknown')}"
        )
        
        info_text = ctk.CTkTextbox(info_frame, width=480, height=300)
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        info_text.insert("1.0", device_info)
        info_text.configure(state="disabled")  # Make read-only
        
        # Actions frame
        actions_frame = ctk.CTkFrame(details_window)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Ping button
        ping_button = ctk.CTkButton(
            actions_frame, 
            text="Ping", 
            command=lambda: self.ping_device(device['ip'])
        )
        ping_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Close button
        close_button = ctk.CTkButton(
            actions_frame, 
            text="Close", 
            command=details_window.destroy
        )
        close_button.pack(side=tk.RIGHT, padx=5, pady=5)
    
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
                    output = (f"IP: {device['ip']}\nMAC: {device['mac']}\nVendor: {device['vendor']}\nHostname: {device['hostname']}\n" 
                              f"{'='*40}\n")
                    self.output_text.insert(tk.END, output)
                
                self.device_count_label.configure(text=f"Devices Found: {len(devices)}")
            else:
                self.output_text.insert(tk.END, "No devices found.\n")
                self.device_count_label.configure(text="Devices Found: 0")
        
        self.root.after(0, update_ui)

    def clear_results(self):
        self.output_text.delete("1.0", tk.END)
        self.status_label.configure(text="")
        self.device_count_label.configure(text="Devices Found: 0")
        self.progress_bar.set(0)
        
        # Cancel any ongoing animation
        if self.animation_id:
            self.root.after_cancel(self.animation_id)
            self.animation_id = None

    def save_results(self):
        if not self.devices:
            messagebox.showwarning("Warning", "No scan results to save.")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", 
                                                 filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")], 
                                                 initialfile="network_scan_results.csv",
                                                 title="Save Results")
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP", "MAC", "Vendor", "Hostname"])
                    for device in self.devices:
                        writer.writerow([device["ip"], device["mac"], device["vendor"], device["hostname"]])
                messagebox.showinfo("Success", f"Results saved to {os.path.basename(file_path)}")
            except Exception as e:
                logging.error(f"Error saving results: {e}")
                messagebox.showerror("Error", "Error saving results.")
                messagebox.showerror("Error", "An error occurred while saving results.")
    
    def update_status(self, message):
        def update_label():
            self.status_label.configure(text=message)
        self.root.after(0, update_label)
    
    def ping_device(self, ip_address):
        """Ping a device and show the result"""
        try:
            # Create a progress window
            progress_window = ctk.CTkToplevel(self.root)
            progress_window.title(f"Ping {ip_address}")
            progress_window.geometry("400x300")
            progress_window.grab_set()
            
            # Progress text
            progress_text = ctk.CTkTextbox(progress_window, width=380, height=250)
            progress_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            progress_text.insert("1.0", f"Pinging {ip_address}...\n\n")
            
            # Button frame
            button_frame = ctk.CTkFrame(progress_window)
            button_frame.pack(fill=tk.X, padx=10, pady=5)
            
            # Close button
            close_button = ctk.CTkButton(
                button_frame, 
                text="Close", 
                command=progress_window.destroy
            )
            close_button.pack(side=tk.RIGHT, padx=5, pady=5)
            
            # Run ping in a separate thread
            def run_ping():
                try:
                    is_reachable = ping_host(ip_address)
                    if is_reachable:
                        result = f"{ip_address} ping başarılı! Cihaz aktif.\n"
                    else:
                        result = f"{ip_address} ping başarısız. Cihaz yanıt vermiyor.\n"
                    
                    # Update UI in main thread
                    self.root.after(0, lambda: progress_text.insert(tk.END, result))
                except Exception as e:
                    error_msg = f"Ping işlemi sırasında hata oluştu: {str(e)}\n"
                    self.root.after(0, lambda: progress_text.insert(tk.END, error_msg))
            
            ping_thread = threading.Thread(target=run_ping, daemon=True)
            ping_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error starting ping operation: {str(e)}")
    
    def show_context_menu(self, event):
        """Show context menu for device list"""
        # Get item under cursor
        item = self.device_tree.identify_row(event.y)
        if not item:
            return
            
        # Select the item
        self.device_tree.selection_set(item)
        
        # Get device IP
        item_values = self.device_tree.item(item, "values")
        ip_address = item_values[0]
        
        # Create context menu
        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="Details", command=lambda: self.show_device_details(None))
        context_menu.add_command(label="Ping", command=lambda: self.ping_device(ip_address))
        context_menu.add_separator()
        
        # webbrowser modülü mevcutsa tarayıcıda açma seçeneğini ekle
        if webbrowser is not None:
            context_menu.add_command(label="Open in Browser", command=lambda: self.open_in_browser(ip_address))
        
        # Display context menu
        context_menu.tk_popup(event.x_root, event.y_root)
    
    def open_in_browser(self, ip_address):
        """Open the IP address in a web browser"""
        try:
            if webbrowser is not None:
                webbrowser.open(f"http://{ip_address}")
            else:
                messagebox.showinfo("Information", "Web browser module is not loaded.")
        except Exception as e:
            messagebox.showerror("Error", f"Error opening browser: {str(e)}")
            logging.error(f"Error opening browser: {e}")

    def generate_network_graph(self):
        """Generate and display network graph based on scan results"""
        if not self.devices:
            messagebox.showinfo("Information", "No scan has been performed yet.")
            return
            
        # Clear previous graph
        for widget in self.graph_frame.winfo_children():
            widget.destroy()
        
        # Check if matplotlib is available
        if not MATPLOTLIB_AVAILABLE:
            # Create a text widget to display the data in text format
            info_text = ctk.CTkTextbox(self.graph_frame, width=660, height=300)
            info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Group devices by vendor
            vendor_counts = {}
            for device in self.devices:
                vendor = device["vendor"]
                if vendor in vendor_counts:
                    vendor_counts[vendor] += 1
                else:
                    vendor_counts[vendor] = 1
            
            # Format the data as text
            info_text.insert("1.0", "Cihazların Üreticilere Göre Dağılımı\n\n")
            info_text.insert(tk.END, "==========================================\n")
            total_devices = sum(vendor_counts.values())
            
            # Sort vendors by count (descending)
            sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
            
            for vendor, count in sorted_vendors:
                percentage = (count / total_devices) * 100
                info_text.insert(tk.END, f"{vendor}: {count} cihaz ({percentage:.1f}%)\n")
                
            info_text.insert(tk.END, "\n\nNot: Grafik görüntülemek için 'matplotlib' kütüphanesini yükleyin.")
            info_text.configure(state="disabled")  # Make it read-only
            return
        
        # If matplotlib is available, create proper charts
        try:
            # Create matplotlib figure
            fig = plt.figure(figsize=(8, 6))
            ax = fig.add_subplot(111)
            
            # Get chart type
            chart_type = self.chart_type_var.get()
            
            # Group devices by vendor
            vendor_counts = {}
            for device in self.devices:
                vendor = device["vendor"]
                if vendor in vendor_counts:
                    vendor_counts[vendor] += 1
                else:
                    vendor_counts[vendor] = 1
                    
            # Prepare data for plotting
            labels = list(vendor_counts.keys())
            sizes = list(vendor_counts.values())
            
            # Generate appropriate chart
            if chart_type == "Pasta Grafiği":
                ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
                ax.set_title('Cihazların Üreticilere Göre Dağılımı')
            else:  # Bar chart
                ax.bar(labels, sizes)
                ax.set_xlabel('Üreticiler')
                ax.set_ylabel('Cihaz Sayısı')
                ax.set_title('Cihazların Üreticilere Göre Dağılımı')
                plt.xticks(rotation=45, ha='right')
                
            # Adjust layout
            plt.tight_layout()
            
            # Embed matplotlib figure in tkinter
            canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        except Exception as e:
            logging.error(f"Error creating chart: {e}")
            error_label = ctk.CTkLabel(self.graph_frame, text=f"Grafik oluşturulurken hata oluştu: {str(e)}")
            error_label.pack(padx=20, pady=20)
    
    def load_settings(self):
        """Load application settings from file"""
        settings_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'settings.json')
        
        if os.path.exists(settings_path):
            try:
                with open(settings_path, 'r') as f:
                    settings = json.load(f)
                    
                    # Apply settings
                    if 'theme' in settings:
                        self.appearance_mode_var.set(settings['theme'])
                        self.change_appearance_mode(settings['theme'])
                        
                    if 'timeout' in settings:
                        self.timeout_var.set(str(settings['timeout']))
                        
                    if 'auto_refresh' in settings:
                        self.auto_refresh_var.set(settings['auto_refresh'])
                        
                    if 'auto_refresh_interval' in settings:
                        self.auto_refresh_interval_var.set(str(settings['auto_refresh_interval']))
                        
                    # Apply auto-refresh if enabled
                    if self.auto_refresh_var.get():
                        self.toggle_auto_refresh()
                        
                    logger.info("Settings loaded successfully")
            except Exception as e:
                logger.error(f"Error loading settings: {e}")
    
    def save_settings(self):
        """Save application settings to file"""
        settings_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'settings.json')
        
        try:
            # Prepare settings
            settings = {
                'theme': self.appearance_mode_var.get(),
                'timeout': int(self.timeout_var.get()) if self.timeout_var.get().isdigit() else 3,
                'auto_refresh': self.auto_refresh_var.get(),
                'auto_refresh_interval': int(self.auto_refresh_interval_var.get()) if self.auto_refresh_interval_var.get().isdigit() else 5
            }
            
            # Save settings to file
            with open(settings_path, 'w') as f:
                json.dump(settings, f, indent=4)
                
            messagebox.showinfo("Information", "Settings saved.")
            logger.info("Settings saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Ayarlar kaydedilirken bir hata oluştu: {str(e)}")
            logger.error(f"Error saving settings: {e}")
    
    def change_appearance_mode(self, mode):
        """Change the application theme"""
        ctk.set_appearance_mode(mode)
    
    def toggle_auto_refresh(self):
        """Toggle automatic refresh scanning"""
        if self.auto_refresh_var.get():
            # Start auto-refresh
            self.start_auto_refresh()
        else:
            # Cancel auto-refresh
            self.cancel_auto_refresh()
    
    def start_auto_refresh(self):
        """Start automatic refresh scanning"""
        # Cancel any existing auto-refresh job
        self.cancel_auto_refresh()
        
        # Calculate interval in milliseconds
        try:
            interval_min = int(self.auto_refresh_interval_var.get())
            interval_ms = interval_min * 60 * 1000  # Convert minutes to milliseconds
        except ValueError:
            interval_ms = 5 * 60 * 1000  # Default: 5 minutes
            
        # Schedule scan
        def auto_scan():
            # Only start scan if not already scanning
            if not self.is_scanning:
                self.start_scan()
                
            # Schedule next scan
            self.auto_refresh_job = self.root.after(interval_ms, auto_scan)
            
        # Start first scan after the interval
        self.auto_refresh_job = self.root.after(interval_ms, auto_scan)
        self.update_status(f"Otomatik tarama aktif. Her {interval_min} dakikada bir tarama yapılacak.")
    
    def cancel_auto_refresh(self):
        """Cancel automatic refresh scanning"""
        if self.auto_refresh_job:
            self.root.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None
            self.update_status("Otomatik tarama devre dışı bırakıldı.")