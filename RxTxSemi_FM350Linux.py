#!/usr/bin/env python3
"""
Fibocom FM350-GL Monitor - Linux Version
Replicates the Windows Fibocom Connect FM350 tool functionality
"""

import tkinter as tk
from tkinter import ttk, messagebox
import serial
import threading
import time
import re
import subprocess
import os
from datetime import datetime, timedelta
import queue
import signal
import tkinter.simpledialog
from PIL import Image, ImageTk
import webbrowser
import sys
import shlex

try:
    import psutil
except ImportError:
    psutil = None

# Handle LANCZOS resampling for compatibility
try:
    resample_lanczos = Image.Resampling.LANCZOS
except AttributeError:
    try:
        resample_lanczos = getattr(Image, 'LANCZOS', 1)
    except Exception:
        try:
            resample_lanczos = getattr(Image, 'BICUBIC', 3)
        except Exception:
            resample_lanczos = 1  # Fallback value for LANCZOS

class FibocomMonitor:

    def update_cells_tab(self):
        """Updates the cells tab with current signal information."""
        # This is a placeholder. You need to fill this with the logic
        # to update your specific Tkinter widgets.
        if self.debug_mode:
            print("DEBUG: Updating cells tab UI.")
            
        # Example of how you would update a label for an LTE cell
        lte_info = next((cell for cell in self.cells_info if cell['rat'] == 'LTE'), None)
        if lte_info:
            # Example: self.lte_label.config(text=f"RSRP: {lte_info['rsrp']}")
            pass
            
        # Example of how you would update a label for an NR cell
        nr_info = next((cell for cell in self.cells_info if cell['rat'] == 'NR'), None)
        if nr_info:
            # Example: self.nr_label.config(text=f"RSRP: {nr_info['rsrp']}")
            pass


    def __init__(self, root):
        self.serial_lock = threading.Lock()
        self.root = root
        self.root.title("RxTxSemi FM350gl Connect")
        self.root.geometry("800x500")
        self.root.minsize(700, 400)
        # Remove custom bg from root window for native look
        self.root.configure(bg=None)
        
        # Serial port configuration
        self.serial_port = None
        self.monitoring = False
        self.data_queue = queue.Queue()
        self.debug_mode = True  # Enable debug output
        
        # Modem data storage
        self.modem_info = {}
        self.connection_info = {}
        self.status_info = {}
        self.cells_info = []
        self.ca_info = []
        
        # Start time for uptime calculation
        self.start_time = datetime.now()
        
        # Track if we changed DNS or ModemManager
        self.dns_changed = False
        self.modemmanager_stopped = False
        self.network_configured = False
        
        # Data usage and speed monitoring
        self.data_history = {'tx': [], 'rx': []}
        self.data_last = {'tx': 0, 'rx': 0, 'time': time.time()}
        self.data_total = {'tx': 0, 'rx': 0}
        self.data_speed = {'tx': 0, 'rx': 0}
        self.data_history_len = 60  # seconds
        self.interface_name = None # To store the interface name for data usage
        
        # Setup signal handlers for cleanup
        signal.signal(signal.SIGTERM, self.handle_exit)
        signal.signal(signal.SIGINT, self.handle_exit)
        
        self.setup_ui()
        self.setup_styles()
        
    def setup_styles(self):
        """Configure native styles for the GUI"""
        style = ttk.Style()
        # Use the system's default theme for native look
        try:
            style.theme_use('default')
        except Exception:
            pass  # fallback if 'default' is not available
        # Only apply minimal custom styles for status labels
        style.configure('Status.TLabel', foreground='#008000', font=('Arial', 10, 'bold'))
        style.configure('Warning.TLabel', foreground='#b8860b', font=('Arial', 10))
        style.configure('Error.TLabel', foreground='#b22222', font=('Arial', 10))
        
        # Configure Treeview
        style.configure('Treeview', 
                       background='#3b3b3b', 
                       foreground='#ffffff', 
                       fieldbackground='#3b3b3b')
        
        style.configure('Treeview.Heading', 
                       background='#4b4b4b', 
                       foreground='#ffffff')
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="RxTxSemi FM350gl Connect", style='Title.TLabel')
        title_label.grid(row=1, column=0, columnspan=5, pady=(0, 10), sticky="ew")
        # RxTxSemi logo (top-right, above title)
        try:
            logo_img = Image.open('rxtxsemi_logo.png')
            logo_img = logo_img.resize((120, 56), resample_lanczos)
            self.logo_photo = ImageTk.PhotoImage(logo_img)
            logo_label = ttk.Label(main_frame, image=self.logo_photo)
            logo_label.grid(row=0, column=5, sticky="ne", padx=(0, 5), pady=(0, 0))
        except Exception as e:
            # If PIL or image fails, fallback to text branding
            branding_label = ttk.Label(main_frame, text="RxTxSemi", font=("Arial", 10, "italic"), foreground="#888")
            branding_label.grid(row=0, column=5, sticky="e", padx=(0, 5), pady=(0, 10))
        
        # Control frame
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(0, 10))
        for i in range(6):
            control_frame.grid_columnconfigure(i, weight=1)
        
        # Port selection
        ttk.Label(control_frame, text="Modem Port:", style='Info.TLabel').grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.port_var = tk.StringVar()
        self.port_dropdown = ttk.Combobox(control_frame, textvariable=self.port_var, width=15, state="readonly")
        self.port_dropdown.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        refresh_btn = ttk.Button(control_frame, text="Refresh Ports", command=self.refresh_ports)
        refresh_btn.grid(row=0, column=2, sticky="ew", padx=(0, 5))
        self.port_status_label = ttk.Label(control_frame, text="", style='Info.TLabel', wraplength=350, anchor="w", justify="left")
        self.port_status_label.grid(row=0, column=3, columnspan=3, sticky="ew", padx=(10, 0))
        self.refresh_ports()
        self.port_var.trace_add('write', lambda *args: self.update_port_status())
        
        # APN configuration
        ttk.Label(control_frame, text="APN:", style='Info.TLabel').grid(row=1, column=0, sticky="w", padx=(0, 5))
        self.apn_var = tk.StringVar(value="airtelgprs.com")
        apn_entry = ttk.Entry(control_frame, textvariable=self.apn_var, width=15)
        apn_entry.grid(row=1, column=1, sticky="ew", padx=(0, 10))
        
        # Connect/Disconnect button
        self.connect_btn = ttk.Button(control_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=1, column=2, sticky="ew", padx=(0, 10))
        
        # Debug button
        self.debug_btn = ttk.Button(control_frame, text="Debug: ON", command=self.toggle_debug)
        self.debug_btn.grid(row=1, column=3, sticky="ew", padx=(0, 10))
        
        # ModemManager control button
        self.modemmanager_btn = ttk.Button(control_frame, text="...", command=self.toggle_modemmanager)
        self.modemmanager_btn.grid(row=1, column=4, sticky="ew", padx=(0, 10))
        self.update_modemmanager_btn()
        
        # Status indicator
        self.status_label = ttk.Label(control_frame, text="Disconnected", style='Error.TLabel', wraplength=200, anchor="center", justify="center")
        self.status_label.grid(row=1, column=5, columnspan=1, sticky="ew", padx=(10, 0))
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, columnspan=6, sticky="nsew")
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Create tabs
        self.create_modem_info_tab()
        self.create_connection_tab()
        self.create_status_tab()
        self.create_cells_tab()
        self.create_ca_tab()
        
        # Donation section (bottom right)
        donation_frame = ttk.Frame(main_frame)
        donation_frame.grid(row=3, column=5, sticky="se", padx=10, pady=10)
        # About button (left of Donate in donation section)
        about_btn = ttk.Button(donation_frame, text="About", command=self.show_about)
        about_btn.grid(row=0, column=0, padx=(0, 5))
        donate_btn = ttk.Button(donation_frame, text="Donate", command=lambda: webbrowser.open('https://coff.ee/oDbCfFNAJ'))
        donate_btn.grid(row=0, column=1, padx=(0, 5))
        try:
            qr_img = Image.open('bmc_qr.png')
            qr_img = qr_img.resize((64, 64), resample_lanczos)
            self.qr_photo = ImageTk.PhotoImage(qr_img)
            qr_label = ttk.Label(donation_frame, image=self.qr_photo)
            qr_label.grid(row=0, column=2)
        except Exception as e:
            import os
            print(f"Error loading QR code: {e}")
            print(f"Current working directory: {os.getcwd()}")
            qr_label = ttk.Label(donation_frame, text="QR not found")
            qr_label.grid(row=0, column=2)
        
    def create_modem_info_tab(self):
        """Create the modem information tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Modem Info")
        
        # Modem info section
        info_frame = ttk.LabelFrame(frame, text="Modem Information", padding=10)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.modem_info_labels = {}
        modem_fields = [
            ("Manufacturer", "manufacturer"),
            ("Model", "model"),
            ("Firmware", "firmware"),
            ("Serial", "serial"),
            ("IMEI", "imei"),
            ("IMSI", "imsi"),
            ("ICCID", "iccid"),
            ("SIM Type", "sim_type")
        ]
        
        for i, (label, key) in enumerate(modem_fields):
            row = i // 2
            col = (i % 2) * 2
            
            ttk.Label(info_frame, text=f"{label}:", style='Info.TLabel').grid(row=row, column=col, sticky='w', padx=(0, 5))
            self.modem_info_labels[key] = ttk.Label(info_frame, text="--", style='Info.TLabel')
            self.modem_info_labels[key].grid(row=row, column=col+1, sticky='w')
            
        # Data usage and speed
        data_frame = ttk.LabelFrame(frame, text="Data Usage & Speed", padding=10)
        data_frame.pack(fill=tk.X, padx=10, pady=5)
        self.data_usage_labels = {}
        ttk.Label(data_frame, text="Upload:").grid(row=0, column=0, sticky='w')
        self.data_usage_labels['tx'] = ttk.Label(data_frame, text="--")
        self.data_usage_labels['tx'].grid(row=0, column=1, sticky='w')
        ttk.Label(data_frame, text="Download:").grid(row=1, column=0, sticky='w')
        self.data_usage_labels['rx'] = ttk.Label(data_frame, text="--")
        self.data_usage_labels['rx'].grid(row=1, column=1, sticky='w')
        ttk.Label(data_frame, text="Up Speed:").grid(row=0, column=2, sticky='w')
        self.data_usage_labels['tx_speed'] = ttk.Label(data_frame, text="--")
        self.data_usage_labels['tx_speed'].grid(row=0, column=3, sticky='w')
        ttk.Label(data_frame, text="Down Speed:").grid(row=1, column=2, sticky='w')
        self.data_usage_labels['rx_speed'] = ttk.Label(data_frame, text="--")
        self.data_usage_labels['rx_speed'].grid(row=1, column=3, sticky='w')
        # Graphs
        self.data_canvas = tk.Canvas(data_frame, width=240, height=60, bg='#222')
        self.data_canvas.grid(row=2, column=0, columnspan=4, pady=(8, 0))
        if not psutil:
            self.data_canvas.create_text(120, 30, text="psutil not installed", fill="red")
            
    def create_connection_tab(self):
        """Create the connection information tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Connection")
        
        # Connection info section
        conn_frame = ttk.LabelFrame(frame, text="Connection Information", padding=10)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.conn_info_labels = {}
        conn_fields = [
            ("IP Address", "ip"),
            ("Subnet Mask", "mask"),
            ("Gateway", "gateway"),
            ("DNS 1", "dns1"),
            ("DNS 2", "dns2")
        ]
        
        for i, (label, key) in enumerate(conn_fields):
            ttk.Label(conn_frame, text=f"{label}:", style='Info.TLabel').grid(row=i, column=0, sticky='w', padx=(0, 10))
            self.conn_info_labels[key] = ttk.Label(conn_frame, text="--", style='Info.TLabel')
            self.conn_info_labels[key].grid(row=i, column=1, sticky='w')
            
    def create_status_tab(self):
        """Create the status monitoring tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Status")
        
        # Status info section
        status_frame = ttk.LabelFrame(frame, text="Status Information", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_info_labels = {}
        status_fields = [
            ("Uptime", "uptime"),
            ("Temperature", "temperature"),
            ("Operator", "operator"),
            ("Technology", "technology"),
            ("Signal Strength", "signal"),
            ("SINR", "sinr"),
            ("RSRP", "rsrp"),
            ("RSRQ", "rsrq")
        ]
        
        for i, (label, key) in enumerate(status_fields):
            ttk.Label(status_frame, text=f"{label}:", style='Info.TLabel').grid(row=i, column=0, sticky='w', padx=(0, 10))
            self.status_info_labels[key] = ttk.Label(status_frame, text="--", style='Info.TLabel')
            self.status_info_labels[key].grid(row=i, column=1, sticky='w')
            
        # Progress bars for signal metrics
        self.progress_bars = {}
        signal_metrics = ["signal", "sinr", "rsrp", "rsrq"]
        
        for i, metric in enumerate(signal_metrics):
            row = i + len(status_fields)
            ttk.Label(status_frame, text=f"{metric.title()} Bar:", style='Info.TLabel').grid(row=row, column=0, sticky='w', padx=(0, 10))
            
            self.progress_bars[metric] = ttk.Progressbar(status_frame, length=200, mode='determinate')
            self.progress_bars[metric].grid(row=row, column=1, sticky='w', pady=2)
            
    def create_cells_tab(self):
        """Create the cells information tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Cells")
        
        # Cells treeview
        columns = ("RAT", "Cell ID", "PCI", "Band", "EARFCN", "RSRP", "RSRQ", "SINR", "Service")
        self.cells_tree = ttk.Treeview(frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        for col in columns:
            self.cells_tree.heading(col, text=col)
            self.cells_tree.column(col, width=100)
            
        # Scrollbar
        cells_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.cells_tree.yview)
        self.cells_tree.configure(yscrollcommand=cells_scrollbar.set)
        
        self.cells_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        cells_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
    def create_ca_tab(self):
        """Create the carrier aggregation tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Carrier Aggregation")
        
        # CA treeview
        columns = ("Component", "PCI", "Band", "EARFCN", "DL Bandwidth", "UL Bandwidth", "DL Modulation", "UL Modulation")
        self.ca_tree = ttk.Treeview(frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        for col in columns:
            self.ca_tree.heading(col, text=col)
            self.ca_tree.column(col, width=120)
            
        # Scrollbar
        ca_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.ca_tree.yview)
        self.ca_tree.configure(yscrollcommand=ca_scrollbar.set)
        
        self.ca_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        ca_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
    def toggle_connection(self):
        """Toggle connection to the modem"""
        if not self.monitoring:
            self.connect_to_modem()
        else:
            self.disconnect_from_modem()
            
    def toggle_debug(self):
        """Toggle debug mode"""
        self.debug_mode = not self.debug_mode
        self.debug_btn.config(text=f"Debug: {'ON' if self.debug_mode else 'OFF'}")
        print(f"Debug mode: {'ON' if self.debug_mode else 'OFF'}")
            
    def run_privileged_command(self, cmd, input_data=None):
        """Run a command as root via pkexec – SAFE version."""
        if isinstance(cmd, str):
            # If it's a complex batch (contains &&, |, >), run via shell
            if any(op in cmd for op in ["&&", "|", ">", "<"]):
                return subprocess.run(["pkexec", "bash", "-c", cmd],
                                      capture_output=True, text=True, input=input_data)
            cmd = shlex.split(cmd)

        if cmd[0] == 'sudo':
            cmd[0] = 'pkexec'
        elif cmd[0] != 'pkexec':
            cmd = ['pkexec'] + cmd
        return subprocess.run(cmd, capture_output=True, text=True, input=input_data)
            
    def connect_to_modem(self):
        """Connect to the modem and configure network"""
        try:
            # Step 1: Check for Fibocom FM350-GL device and USB connection
            self.update_status("Checking for Fibocom FM350-GL...")
            if not self.check_fibocom_device():
                messagebox.showerror("Device Error", "Fibocom FM350-GL device not found or not connected via USB")
                return

            # Step 2: Check if selected port is available
            self.update_status("Checking port availability...")
            port = self.port_var.get()
            if not os.path.exists(port):
                messagebox.showerror("Port Error", f"{port} not available")
                return

            # Step 3: Connect to selected port
            self.update_status("Connecting to modem...")
            self.serial_port = serial.Serial(port, 115200, timeout=1)

            # Initialize modem
            self.send_at_command("ATE1")        # Enable echo
            self.send_at_command("AT+CMEE=2")   # Enable error reporting

            # Step 4: Configure APN and activate connection
            self.update_status("Configuring APN...")
            apn = self.apn_var.get()
            if not self.configure_apn(apn):
                messagebox.showerror("APN Error", f"Failed to configure APN: {apn}")
                return

            # Step 5: Get IP address
            self.update_status("Getting IP address...")
            ip_address = self.get_ip_address()
            if not ip_address:
                messagebox.showerror("IP Error", "Failed to get IP address from modem")
                return

            # Derive gateway (assume .1)
            gateway = ".".join(ip_address.split(".")[:3]) + ".1"

            # Step 6: Find interface
            self.update_status("Finding modem interface...")
            interface = self.find_modem_interface()
            if not interface:
                messagebox.showerror("Network Error", "Could not find modem network interface")
                return

            # Step 6.1: Get DNS from modem
            self.update_status("Getting DNS servers...")
            dns1, dns2 = "8.8.8.8", "1.1.1.1"  # fallback
            try:
                self.serial_port.write(b"AT+GTDNS=1\r")
                time.sleep(0.5)
                dns_resp = self.serial_port.read(200).decode(errors="ignore")
                for line in dns_resp.splitlines():
                    if "+GTDNS" in line:
                        parts = line.split('"')
                        if len(parts) >= 4:
                            dns1, dns2 = parts[1], parts[3]
                            break
            except Exception:
                pass

            # Step 7: Batch all privileged commands
            self.update_status("Configuring system (network, DNS, services)...")
            batch_cmd = (
                f"systemctl stop ModemManager && "
                f"ip addr flush dev {interface} && "
                f"ip route flush dev {interface} && "
                f"ip addr add {ip_address}/24 dev {interface} && "
                f"ip link set {interface} up && "
                f"ip route add default via {gateway} dev {interface} metric 100 && "
                f"cp /etc/resolv.conf /etc/resolv.conf.backup || true && "
                f"echo -e 'nameserver {dns1}\\nnameserver {dns2}' | tee /etc/resolv.conf"
            )
            result = self.run_privileged_command(batch_cmd)
            if result.returncode != 0:
                messagebox.showerror("Sudo Error", f"Failed to configure system: {result.stderr}\nAre you running as root or with passwordless sudo?")
                return

            self.modemmanager_stopped = True
            self.network_configured = True
            self.dns_changed = True
            self.interface_name = interface  # Set interface name for data usage

            # Get modem information
            self.get_modem_info()

            # Start monitoring thread
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.monitor_thread.start()

            # Update UI
            self.connect_btn.config(text="Disconnect")
            self.status_label.config(text="Connected", style='Status.TLabel')
            self.update_status("Connection established successfully!")

        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to modem: {str(e)}")
            self.update_status("Connection failed")


    
    def check_fibocom_device(self):
        """Check if Fibocom FM350-GL device is connected via USB"""
        try:
            # Check USB devices for Fibocom FM350
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Fibocom' in line or 'FM350' in line or 'MediaTek' in line:
                        return True
            # Also check /proc/bus/usb/devices
            try:
                with open('/proc/bus/usb/devices', 'r') as f:
                    content = f.read()
                    if 'Fibocom' in content or 'FM350' in content or 'MediaTek' in content:
                        return True
            except:
                pass
            
            return False
        except Exception as e:
            print(f"Error checking Fibocom device: {e}")
            return False    
    def check_ttyusb3_availability(self):
        """Check if /dev/ttyUSB3 available"""
        try:
            return os.path.exists('/dev/ttyUSB3')
        except Exception as e:
            print(f"Error checking ttyUSB3: {e}")
            return False
    def configure_apn(self, apn):
        """Configure APN on the modem"""
        try:
            # Set PDP context
            response = self.send_at_command(f'AT+CGDCONT=1,"IP","{apn}"')
            if "ERROR" in response:
                return False
            
            # Activate PDP context
            response = self.send_at_command("AT+CGACT=1,1")
            if "ERROR" in response:
                # Context might already be activated, try to get IP address anyway
                if self.debug_mode:
                    print(f"DEBUG: CGACT failed, but context might already be active. Continuing...")
                # Don't return False here, continue to next step
            else:
                if self.debug_mode:
                    print(f"DEBUG: CGACT successful")
            
            return True
        except Exception as e:
            print(f"Error configuring APN: {e}")
            return False
    
    def get_ip_address(self):
        """Get IP address from modem (IPv4 only)"""
        try:
            response = self.send_at_command("AT+CGPADDR=1")
            if "ERROR" in response:
                return None

            if self.debug_mode:
                print(f"DEBUG: CGPADDR raw response: {repr(response)}")

            ip_address = None
            for line in response.splitlines():
                line = line.strip()
                if "+CGPADDR" in line:
                    if self.debug_mode:
                        print(f"DEBUG: Found CGPADDR line: {repr(line)}")
                    parts = line.split('"')
                    if len(parts) >= 2:
                        candidate = parts[1]
                        if self.debug_mode:
                            print(f"DEBUG: Extracted candidate: {candidate}")
                        # Validate IPv4
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate) and candidate != "0.0.0.0":
                            ip_address = candidate
                            break

            if ip_address:
                if self.debug_mode:
                    print(f"DEBUG: Valid IP address: {ip_address}")
                return ip_address
            else:
                if self.debug_mode:
                    print("DEBUG: No valid IPv4 address found")
                return None

        except Exception as e:
            print(f"Error getting IP address: {e}")
            return None


    def configure_network(self, ip_address):
        """Configure network interface with IP address"""
        try:
            # Find the modem network interface
            interface = self.find_modem_interface()
            if not interface:
                print("Could not find modem network interface")
                return False

            # Check if IP address is already assigned to the interface
            result = subprocess.run(['ip', '-4', 'addr', 'show', interface], capture_output=True, text=True)
            ip_already_assigned = False
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('inet') and ip_address in line:
                        ip_already_assigned = True
                        print(f"IP address {ip_address} is already assigned to {interface}")
                        break

            # Add IP address to interface only if not already assigned
            if not ip_already_assigned:
                cmd = f"sudo ip addr add {ip_address}/32 dev {interface}"
                result = self.run_privileged_command(cmd)
                if result.returncode != 0:
                    messagebox.showerror("Sudo Error", f"Failed to add IP address: {result.stderr}\nAre you running as root or with passwordless sudo?")
                    return False
            else:
                print(f"IP address {ip_address} already configured on {interface}")

            # Bring interface up
            cmd = f"sudo ip link set {interface} up"
            result = self.run_privileged_command(cmd)
            if result.returncode != 0:
                messagebox.showerror("Sudo Error", f"Failed to bring interface up: {result.stderr}\nAre you running as root or with passwordless sudo?")
                return False

            # Add default route through the modem interface (no gateway)
            # First, remove any existing default routes to avoid conflicts
            self.run_privileged_command('ip route del default')

            # Add default route via interface (no gateway)
            cmd = f"sudo ip route add default dev {interface}"
            result = self.run_privileged_command(cmd)
            if result.returncode != 0:
                print(f"Warning: Could not add default route: {result.stderr}")
                # Don't return false here, as the route might already exist

            return True
        except Exception as e:
            print(f"Error configuring network: {e}")
            return False
    
    def find_modem_interface(self):
        """Find the modem network interface"""
        try:
            # Look for common modem interface patterns
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'enx' in line or 'wwan' in line or 'usb' in line:
                        # Extract interface name
                        parts = line.split(':')
                        if len(parts) >= 2:
                            interface = parts[1].strip()
                            if interface.startswith('enx') or interface.startswith('wwan'):
                                return interface
            
            # Fallback to checking /sys/class/net
            try:
                for item in os.listdir('/sys/class/net'):
                    if item.startswith('enx') or item.startswith('wwan'):
                        return item
            except:
                pass
            
            return None
        except Exception as e:
            print(f"Error finding modem interface: {e}")
            return None
    
    def configure_dns(self):
        """Configure DNS servers"""
        try:
            # Backup current resolv.conf
            if os.path.exists('/etc/resolv.conf'):
                result = self.run_privileged_command('cp /etc/resolv.conf /etc/resolv.conf.backup')
                if result.returncode != 0:
                    messagebox.showerror("Sudo Error", f"Failed to backup resolv.conf: {result.stderr}\nAre you running as root or with passwordless sudo?")
                    return False
            # Set DNS servers to 8.8.8.8 and 1.1.1.1
            dns_config = "nameserver 8.8.8.8\nnameserver 1.1.1.1"
            result = self.run_privileged_command('tee /etc/resolv.conf', input_data=dns_config)
            if result.returncode != 0:
                messagebox.showerror("Sudo Error", f"Failed to configure DNS: {result.stderr}\nAre you running as root or with passwordless sudo?")
                return False

            return True
        except Exception as e:
            print(f"Error configuring DNS: {e}")
            return False   
    def update_status(self, message):
        """Update status message in GUI"""
        self.status_label.config(text=message)
        self.root.update()
        print(f"Status: {message}")
    
    def disconnect_from_modem(self):
        """Disconnect from the modem and restore previous settings"""
        try:
            self.update_status("Disconnecting...")

            # Stop monitoring
            self.monitoring = False
            if self.serial_port:
                self.serial_port.close()
                self.serial_port = None

            batch_cmd = ""

            # Restore DNS
            if self.dns_changed:
                batch_cmd += "mv /etc/resolv.conf.backup /etc/resolv.conf || true && "

            # Clean up network interface
            if self.network_configured and self.interface_name:
                batch_cmd += (
                    f"ip addr flush dev {self.interface_name} && "
                    f"ip route flush dev {self.interface_name} && "
                    f"ip link set {self.interface_name} down && "
                )

            # Restart ModemManager reliably
            if self.modemmanager_stopped:
                batch_cmd += "systemctl unmask ModemManager || true && systemctl enable --now ModemManager && "

            # Trim trailing &&
            if batch_cmd.endswith("&& "):
                batch_cmd = batch_cmd[:-3]

            # Run teardown if needed
            if batch_cmd:
                result = self.run_privileged_command(batch_cmd)
                if result.returncode != 0:
                    print(f"Warning: Failed to fully restore system: {result.stderr}")

            # Reset flags
            self.network_configured = False
            self.dns_changed = False
            self.modemmanager_stopped = False
            self.interface_name = None

            # Update UI
            self.connect_btn.config(text="Connect")
            self.status_label.config(text="Disconnected", style='Error.TLabel')
            self.update_status("Disconnected successfully")

        except Exception as e:
            print(f"Error during disconnect: {e}")
            self.connect_btn.config(text="Connect")
            self.status_label.config(text="Disconnected", style='Error.TLabel')

            
    def send_at_command(self, command, timeout=2):
        """Send an AT command and return the whole response."""
        if not self.serial_port or not self.serial_port.is_open:
            raise RuntimeError("serial port not open")

        self.serial_port.reset_input_buffer()
        cmd_line = (command + "\r").encode()
        self.serial_port.write(cmd_line)

        lines, echo_seen = [], False
        end_time = time.time() + timeout
        while time.time() < end_time:
            raw = self.serial_port.readline()
            if not raw:
                time.sleep(0.01)
                continue
            line = raw.decode(errors="ignore").strip()
            if not line:
                continue

            # skip the echo of the command itself (only once)
            if not echo_seen and line == command:
                echo_seen = True
                continue

            lines.append(line)

            # stop on real result code
            if line in {"OK", "ERROR"} or line.startswith("+CME ERROR"):
                break

        return "\n".join(lines)
            
    def parse_at_response(self, response, command):
        """Parse AT command response"""
        if not response:
            return None
            
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if f"+{command}:" in line:
                # Handle different response formats
                if command in ["CGMI", "CGMM", "CGMR", "CGSN", "CIMI", "CCID"]:
                    # These commands return the value directly after the command
                    return line.split(':', 1)[1].strip().strip('"')
                elif command == "COPS":
                    # COPS returns: +COPS: <mode>,<format>,<oper>
                    parts = line.split(':', 1)[1].strip().split(',')
                    if len(parts) >= 3:
                        return parts[2].strip('"')
                elif command == "CSQ":
                    # CSQ returns: +CSQ: <rssi>,<ber>
                    parts = line.split(':', 1)[1].strip().split(',')
                    if len(parts) >= 1:
                        return parts[0]
                elif command == "CESQ":
                    # CESQ returns: +CESQ: <LTE_rssi>,<LTE_rsrp>,<LTE_rsrq>,<LTE_sinr>,<GSM_rssi>,<UMTS_rssi>
                    return line.split(':', 1)[1].strip()
                elif command == "GTSENRDTEMP":
                    # GTSENRDTEMP returns: +GTSENRDTEMP: 1,<temp>
                    parts = line.split(':', 1)[1].strip().split(',')
                    if len(parts) >= 2:
                        return parts[1]  # Return just the temperature value
                    return None
                elif command == "CGPADDR":
                    # CGPADDR returns: +CGPADDR: <cid>,<PDP_addr>,<PDP_type>
                    parts = line.split(':', 1)[1].strip().split(',')
                    if len(parts) >= 2:
                        return parts[1].strip('"')
                elif command == "GTDNS":
                    # GTDNS returns: +GTDNS: <dns1>,<dns2>
                    return line.split(':', 1)[1].strip()
            elif command in ["CGMI", "CGMM", "CGMR", "CGSN", "CIMI", "CCID"] and line and not line.startswith("AT") and not line.startswith("OK") and not line.startswith("ERROR"):
                # For commands that return data on a separate line
                return line.strip()
        return None
        
    def get_modem_info(self):
        """Get basic modem information"""
        try:
            # Get manufacturer and model
            response = self.send_at_command("AT+CGMI")
            manufacturer = self.parse_at_response(response, "CGMI")
            
            response = self.send_at_command("AT+CGMM")
            model = self.parse_at_response(response, "CGMM")
            
            # Get firmware version
            response = self.send_at_command("AT+CGMR")
            firmware = self.parse_at_response(response, "CGMR")
            
            # Get IMEI
            response = self.send_at_command("AT+CGSN")
            imei = self.parse_at_response(response, "CGSN")
            
            # Get IMSI
            response = self.send_at_command("AT+CIMI")
            imsi = self.parse_at_response(response, "CIMI")
            
            # Get ICCID
            response = self.send_at_command("AT+CCID")
            iccid = self.parse_at_response(response, "CCID")
            
            # Get serial number (if available)
            response = self.send_at_command("AT+CGSN")
            serial = self.parse_at_response(response, "CGSN")
            
            # Try Fibocom-specific commands
            response = self.send_at_command("AT+QDEVINFO")
            devinfo = self.parse_at_response(response, "QDEVINFO")
            
            response = self.send_at_command("AT+QVER")
            qver = self.parse_at_response(response, "QVER")
            
            # Determine SIM type based on IMSI
            sim_type = "Unknown"
            if imsi:
                if imsi.startswith("250"):
                    sim_type = "MTS"
                elif imsi.startswith("99"):
                    sim_type = "Beeline"
                elif imsi.startswith("1"):
                    sim_type = "US"
                else:
                    sim_type = "Other"
            
            # Update UI
            self.modem_info_labels["manufacturer"].config(text=manufacturer or "--")
            self.modem_info_labels["model"].config(text=model or "--")
            self.modem_info_labels["firmware"].config(text=firmware or qver or "--")
            self.modem_info_labels["serial"].config(text=serial or "--")
            self.modem_info_labels["imei"].config(text=imei or "--")
            self.modem_info_labels["imsi"].config(text=imsi or "--")
            self.modem_info_labels["iccid"].config(text=iccid or "--")
            self.modem_info_labels["sim_type"].config(text=sim_type)
            
        except Exception as e:
            print(f"Error getting modem info: {e}")
            
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Get connection information
                self.get_connection_info()
                
                # Get status information
                self.get_status_info()
                
                # Get cells information
                self.get_cells_info()
                
                # Update signal metrics from cells if CESQ was invalid
                self.update_signal_from_cells()
                
                # Get carrier aggregation info
                self.get_ca_info()
                
                # Update UI
                self.root.after(0, self.update_ui)
                
                time.sleep(2)  # Update every 2 seconds
                
                self.update_data_usage() # Update data usage periodically
                
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(5)
                
    def get_connection_info(self):
        """Get connection information"""
        try:
            # Get IP address and DNS using the correct commands
            response = self.send_at_command("AT+CGPADDR=1; +GTDNS=1")
            
            # Parse IP address
            ip_addr = None
            dns1 = "8.8.8.8"  # Default DNS
            dns2 = "8.8.4.4"  # Default DNS
            
            if response:
                lines = response.split('\n')
                for line in lines:
                    line = line.strip()
                    if "+CGPADDR:" in line:
                        # Parse IP address from CGPADDR response
                        parts = line.split(',')
                        if len(parts) >= 2:
                            ip_match = re.search(r'"([^"]+)"', parts[1])
                            if ip_match:
                                ip_addr = ip_match.group(1)
                    elif "+GTDNS:" in line:
                        # Parse DNS from GTDNS response
                        parts = line.split(',')
                        if len(parts) >= 3:
                            dns1 = parts[1].strip('"') if parts[1] != '""' else "8.8.8.8"
                            dns2 = parts[2].strip('"') if parts[2] != '""' else "8.8.4.4"
            
            if ip_addr:
                self.connection_info["ip"] = ip_addr
                self.connection_info["mask"] = "255.255.255.0"  # Default
                self.connection_info["gateway"] = ".".join(ip_addr.split('.')[:-1]) + ".1"  # Default gateway
                self.connection_info["dns1"] = dns1
                self.connection_info["dns2"] = dns2
            else:
                # Fallback if no IP address found
                self.connection_info["ip"] = "--"
                self.connection_info["mask"] = "--"
                self.connection_info["gateway"] = "--"
                self.connection_info["dns1"] = dns1
                self.connection_info["dns2"] = dns2
                    
        except Exception as e:
            print(f"Error getting connection info: {e}")
            
    def get_status_info(self):
        """Get status information"""
        try:
            # Get operator
            response = self.send_at_command("AT+COPS?")
            operator = self.parse_at_response(response, "COPS")
            
            # Get signal quality
            response = self.send_at_command("AT+CSQ")
            csq = self.parse_at_response(response, "CSQ")
            
            # Get temperature using the correct command
            response = self.send_at_command("AT+GTSENRDTEMP=1")
            temp = self.parse_at_response(response, "GTSENRDTEMP")
            
            # Get extended signal info (LTE)
            response = self.send_at_command("AT+CESQ")
            cesq = self.parse_at_response(response, "CESQ")
            
            # Parse signal metrics
            signal_percent = 0
            sinr = None
            rsrp = None
            rsrq = None
            
            # Try to get signal from CESQ first
            if cesq:
                try:
                    parts = cesq.split(',')
                    if len(parts) >= 6:
                        # CESQ format: <LTE_rssi>,<LTE_rsrp>,<LTE_rsrq>,<LTE_sinr>,<GSM_rssi>,<UMTS_rssi>
                        # LTE metrics are at positions 1, 2, 3 (0-indexed)
                        rsrp_val = int(parts[1]) if parts[1] != '255' and parts[1] != '99' else None
                        rsrq_val = int(parts[2]) if parts[2] != '255' and parts[2] != '99' else None
                        sinr_val = int(parts[3]) if parts[3] != '255' and parts[3] != '99' else None
                        
                        print(f"CESQ raw values - RSRP: {parts[1]}, RSRQ: {parts[2]}, SINR: {parts[3]}")  # Debug
                        
                        if rsrp_val is not None and rsrp_val != 255 and rsrp_val != 99:
                            rsrp = rsrp_val - 141  # Convert to dBm
                            # Calculate signal percentage from RSRP (-140 to -44 dBm range)
                            signal_percent = max(0, min(100, int((rsrp - (-140)) / ((-44) - (-140)) * 100)))
                            print(f"Converted RSRP: {rsrp}dBm, Signal: {signal_percent}%")  # Debug
                        if rsrq_val is not None and rsrq_val != 255 and rsrq_val != 99:
                            rsrq = (rsrq_val / 2) - 20  # Convert to dB
                            print(f"Converted RSRQ: {rsrq}dB")  # Debug
                        if sinr_val is not None and sinr_val != 255 and sinr_val != 99:
                            sinr = sinr_val / 2  # Convert to dB
                            print(f"Converted SINR: {sinr}dB")  # Debug
                except Exception as e:
                    print(f"Error parsing CESQ: {e}")
                    pass
            
            # Fallback to CSQ if CESQ didn't provide valid RSRP
            if signal_percent == 0 and csq:
                try:
                    csq_val = int(csq.split(',')[0])
                    if csq_val == 99:
                        signal_percent = 0  # No signal
                    else:
                        signal_percent = min(100, (csq_val / 31) * 100)
                        print(f"Using CSQ fallback: {csq_val} -> {signal_percent}%")
                except:
                    pass
                    
            # Parse temperature correctly
            temperature_str = "--"
            if temp and temp != "255":
                try:
                    # GTSENRDTEMP returns format like "56736" (temperature in 0.001°C)
                    temp_val = int(temp)
                    temperature_celsius = temp_val / 1000.0
                    temperature_str = f"{temperature_celsius:.1f}°C"
                except Exception as e:
                    print(f"Temperature parsing error: {e} for value: {temp}")
                    temperature_str = "--"
                    
            # Update status info
            self.status_info["uptime"] = str(datetime.now() - self.start_time).split('.')[0]
            self.status_info["temperature"] = temperature_str
            self.status_info["operator"] = operator or "--"
            self.status_info["technology"] = "LTE"  # Default, could be enhanced
            self.status_info["signal"] = f"{signal_percent:.0f}%"
            self.status_info["sinr"] = f"{sinr:.1f}dB" if sinr else "--"
            self.status_info["rsrp"] = f"{rsrp:.0f}dBm" if rsrp else "--"
            self.status_info["rsrq"] = f"{rsrq:.1f}dB" if rsrq else "--"
            
        except Exception as e:
            print(f"Error getting status info: {e}")
            
    def update_signal_from_cells(self):
        """Update signal metrics from cells data if CESQ is invalid"""
        if self.cells_info:
            # Find the serving cell (service = "Yes")
            serving_cell = None
            for cell in self.cells_info:
                if cell.get("service") == "Yes":
                    serving_cell = cell
                    break
            
            if serving_cell:
                # Update signal metrics from the serving cell
                rsrp = serving_cell.get("rsrp")
                rsrq = serving_cell.get("rsrq")
                sinr = serving_cell.get("sinr")
                
                if rsrp and rsrp != "N/A":
                    self.status_info["rsrp"] = rsrp
                    # Update signal percentage from RSRP if not already set
                    if self.status_info.get("signal", "0%") == "0%":
                        try:
                            rsrp_val = float(rsrp.replace("dBm", ""))
                            signal_percent = max(0, min(100, int((rsrp_val - (-140)) / ((-44) - (-140)) * 100)))
                            self.status_info["signal"] = f"{signal_percent}%"
                            print(f"Updated signal from cells RSRP: {rsrp_val}dBm -> {signal_percent}%")
                        except:
                            pass
                if rsrq and rsrq != "N/A":
                    self.status_info["rsrq"] = rsrq
                if sinr and sinr != "N/A":
                    self.status_info["sinr"] = sinr
                    
      
    def get_cells_info(self):
        """Get cells information using GTCCINFO command"""
        if self.debug_mode:
            print("DEBUG: Getting cell info...")
        
        try:
            response = self.send_at_command("AT+GTCCINFO?")
            new_cells = []
            if response:
                lines = response.split('\n')
                parsing_cells = False
                for line in lines:
                    line = line.strip()
                    if line.startswith("+GTCCINFO:"):
                        parsing_cells = True
                        continue
                    if parsing_cells and line and not line.startswith("OK"):
                        if self.debug_mode:
                            print(f"DEBUG: Received line: {line}")
                        try:
                            parts = line.split(',')
                            if len(parts) >= 13:
                                is_service = parts[0] == "1"
                                rat_code = parts[1]
                                cell_id = parts[5] if parts[5] not in ('0xFFFFFFF', '00FFFFFFF', '') else "N/A"
                                pci = parts[7] if parts[7] not in ('0xFFFFFFF', '00FFFFFFF', '') else "N/A"
                                arfcn = parts[6] if parts[6] != '0' and parts[6] != '' else "N/A"
                                band = parts[8] if parts[8] != '' else "N/A"
                                
                                rat_name = "LTE" if rat_code == "4" else "UMTS" if rat_code == "2" else "NR" if rat_code == "9" else "Unknown"
                                
                                sinr_val = int(parts[10]) if len(parts) > 10 and parts[10] not in ('255', '') else None
                                rsrp_val = int(parts[11]) if len(parts) > 11 and parts[11] not in ('255', '') else None
                                rsrq_val = int(parts[12]) if len(parts) > 12 and parts[12] not in ('255', '') else None
                                
                                sinr = (sinr_val / 2) if sinr_val is not None else "N/A"
                                rsrp = (rsrp_val - 141) if rsrp_val is not None else "N/A"
                                rsrq = ((rsrq_val / 2) - 20) if rsrq_val is not None else "N/A"
                                
                                cell_info = {
                                    "rat": rat_name,
                                    "cell_id": cell_id,
                                    "pci": pci,
                                    "band": band,
                                    "earfcn": arfcn,
                                    "rsrp": f"{rsrp:.0f}dBm" if rsrp != "N/A" else "N/A",
                                    "rsrq": f"{rsrq:.1f}dB" if rsrq != "N/A" else "N/A",
                                    "sinr": f"{sinr:.1f}dB" if sinr != "N/A" else "N/A",
                                    "service": "Yes" if is_service else "No"
                                }
                                new_cells.append(cell_info)
                                if self.debug_mode:
                                    print(f"Parsed cell: {cell_info}")
                        except Exception as e:
                            if self.debug_mode:
                                print(f"Error parsing cell info line '{line}': {e}")
                    elif parsing_cells and line.startswith("OK"):
                        parsing_cells = False
                        
            if not new_cells:
                if self.debug_mode:
                    print("No cells found, using fallback")
                response = self.send_at_command("AT+CSQ")
                csq_match = re.search(r'\+CSQ: (\d+),(\d+)', response)
                if csq_match:
                    csq = int(csq_match.group(1))
                    signal_pct = (csq * 100) / 31
                    new_cells.append({
                        "rat": "LTE",
                        "cell_id": "N/A",
                        "pci": "N/A",
                        "band": "N/A",
                        "earfcn": "N/A",
                        "rsrp": "N/A",
                        "rsrq": "N/A",
                        "sinr": "N/A",
                        "service": "Yes"
                    })
                    if self.debug_mode:
                        print(f"Using CSQ fallback: {csq} -> {signal_pct:.2f}%")
            
            updated_cells = self.cells_info[:]
            for new_cell in new_cells:
                found = False
                for i, existing_cell in enumerate(updated_cells):
                    if existing_cell['rat'] == new_cell['rat']:
                        updated_cells[i].update(new_cell)
                        found = True
                        break
                if not found:
                    updated_cells.append(new_cell)

            self.cells_info = updated_cells
            if self.debug_mode:
                print(f"Total cells found: {len(self.cells_info)}")
            self.update_cells_tab()
            
        except Exception as e:
            if self.debug_mode:
                print(f"Error getting cells info: {e}")

                

    def get_ca_info(self):
        """Get Carrier Aggregation information and update the instance variable."""
        self.ca_tree.delete(*self.ca_tree.get_children())
        self.ca_info = {}  # Initialize the instance variable
        try:
            response = self.send_at_command("AT+GTCAINFO?")
            if self.debug_mode:
                print(f"DEBUG: Raw CA command response:\n{response}")
            
            if response:
                lines = response.split('\r\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith("PCC:"):
                        # Parse Primary Component Carrier (PCC)
                        parts = line.split(':')[-1].split(',')
                        if len(parts) >= 8:
                            self.ca_info['PCC'] = {
                                'band': parts[0],
                                'dl_earfcn': parts[1],
                                'ul_earfcn': parts[2],
                                'bandwidth': parts[3],
                                'pci': parts[4],
                                'mimo': parts[5],
                                'mod_dl': parts[6],
                                'mod_ul': parts[7]
                            }
                    elif re.match(r"SCC\d+:", line):
                        # Parse Secondary Component Carrier (SCC)
                        scc_num = re.search(r"SCC(\d+):", line).group(1)
                        parts = line.split(':')[-1].split(',')
                        if len(parts) >= 14:
                            self.ca_info[f'SCC{scc_num}'] = {
                                'band': parts[0],
                                'dl_earfcn': parts[1],
                                'ul_earfcn': parts[2],
                                'pci': parts[3],
                                'bandwidth': parts[4],
                                'rsrp': parts[5],
                                'rsrq': parts[6],
                                'snr': parts[7],
                                'mimo': parts[8],
                                'mod_dl': parts[9],
                                'mod_ul': parts[10],
                                'additional_info': parts[11:]
                            }
        except Exception as e:
            if self.debug_mode:
                print(f"DEBUG: Error getting CA info: {e}")
            return

        # Display the parsed information in the Treeview
        if self.ca_info:
            if 'PCC' in self.ca_info:
                pcc_data = self.ca_info['PCC']
                self.ca_tree.insert('', 'end', text="Primary Component Carrier (PCC)", open=True)
                self.ca_tree.insert('', 'end', values=("Band", pcc_data['band']))
                self.ca_tree.insert('', 'end', values=("DL EARFCN", pcc_data['dl_earfcn']))
                self.ca_tree.insert('', 'end', values=("UL EARFCN", pcc_data['ul_earfcn']))
                self.ca_tree.insert('', 'end', values=("PCI", pcc_data['pci']))
                self.ca_tree.insert('', 'end', values=("Bandwidth", f"{pcc_data['bandwidth']} MHz"))
                self.ca_tree.insert('', 'end', values=("MIMO", pcc_data['mimo']))
                self.ca_tree.insert('', 'end', values=("DL Modulation", pcc_data['mod_dl']))
                self.ca_tree.insert('', 'end', values=("UL Modulation", pcc_data['mod_ul']))
                self.ca_tree.insert('', 'end', values=("", ""))
            
            scc_keys = sorted([k for k in self.ca_info if k.startswith('SCC')], key=lambda x: int(x.replace('SCC', '')))
            for scc_key in scc_keys:
                scc_data = self.ca_info[scc_key]
                scc_num = scc_key.replace('SCC', '')
                self.ca_tree.insert('', 'end', text=f"Secondary Component Carrier (SCC{scc_num})", open=True)
                self.ca_tree.insert('', 'end', values=("Band", scc_data['band']))
                self.ca_tree.insert('', 'end', values=("DL EARFCN", scc_data['dl_earfcn']))
                self.ca_tree.insert('', 'end', values=("UL EARFCN", scc_data['ul_earfcn']))
                self.ca_tree.insert('', 'end', values=("PCI", scc_data['pci']))
                self.ca_tree.insert('', 'end', values=("Bandwidth", f"{scc_data['bandwidth']} MHz"))
                self.ca_tree.insert('', 'end', values=("RSRP", scc_data['rsrp']))
                self.ca_tree.insert('', 'end', values=("RSRQ", scc_data['rsrq']))
                self.ca_tree.insert('', 'end', values=("SNR", scc_data['snr']))
                self.ca_tree.insert('', 'end', values=("MIMO", scc_data['mimo']))
                self.ca_tree.insert('', 'end', values=("DL Modulation", scc_data['mod_dl']))
                self.ca_tree.insert('', 'end', values=("UL Modulation", scc_data['mod_ul']))
                if 'additional_info' in scc_data:
                    self.ca_tree.insert('', 'end', values=("Additional Info", ', '.join(scc_data['additional_info'])))
                self.ca_tree.insert('', 'end', values=("", ""))
            
    def get_signal_bars(self, value, min_val, max_val):
        """Convert signal value to visual bars and percent"""
        if value is None or value == 255 or value == 99 or value == "N/A":
            return "▁▁▁▁", 0
        try:
            value = float(value)
        except:
            return "▁▁▁▁", 0
        # Clamp value
        if value < min_val:
            percent = 0
        elif value > max_val:
            percent = 100
        else:
            percent = int((value - min_val) / (max_val - min_val) * 100)
        # Map to 0-4 bars
        bar_count = int(percent / 25)
        bar_count = max(0, min(4, bar_count))
        bar_chars = ["▁", "▂", "▃", "▄", "█"]
        bars = "".join([bar_chars[bar_count]] * 4)
        return bars, percent

    def update_ui(self):
        """Update the UI with current data"""
        try:
            # Update connection info
            for key, label in self.conn_info_labels.items():
                value = self.connection_info.get(key, "--")
                label.config(text=str(value))

            # Use serving cell RSRP/RSRQ/SINR for status if available
            serving_cell = None
            for cell in self.cells_info:
                if cell.get("service") == "Yes":
                    serving_cell = cell
                    break
            # Default values
            rsrp_val = rsrq_val = sinr_val = None
            if serving_cell:
                rsrp_val = serving_cell.get("rsrp", "N/A").replace("dBm", "").replace("N/A", "").strip()
                rsrq_val = serving_cell.get("rsrq", "N/A").replace("dB", "").replace("N/A", "").strip()
                sinr_val = serving_cell.get("sinr", "N/A").replace("dB", "").replace("N/A", "").strip()

            # Update status info
            for key, label in self.status_info_labels.items():
                value = self.status_info.get(key, "--")
                # For signal, use RSRP for percent/bar if available
                if key == "signal":
                    # Use the same RSRP value for both percentage and bars to ensure consistency
                    if rsrp_val:
                        bars, percent = self.get_signal_bars(rsrp_val, -140, -44)
                        # Update the signal percentage to match the RSRP-based calculation
                        signal_percent = percent
                        value = f"{signal_percent}%"
                    else:
                        bars, percent = ("▁▁▁▁", 0)
                    label.config(text=f"{value} {bars}")
                    self.progress_bars["signal"].config(value=percent)
                elif key == "rsrp":
                    bars, percent = self.get_signal_bars(rsrp_val, -140, -44) if rsrp_val else ("▁▁▁▁", 0)
                    label.config(text=f"{serving_cell.get('rsrp', '--') if serving_cell else value} {bars}")
                    self.progress_bars["rsrp"].config(value=percent)
                elif key == "rsrq":
                    bars, percent = self.get_signal_bars(rsrq_val, -20, -3) if rsrq_val else ("▁▁▁▁", 0)
                    label.config(text=f"{serving_cell.get('rsrq', '--') if serving_cell else value} {bars}")
                    self.progress_bars["rsrq"].config(value=percent)
                elif key == "sinr":
                    bars, percent = self.get_signal_bars(sinr_val, -20, 30) if sinr_val else ("▁▁▁▁", 0)
                    label.config(text=f"{serving_cell.get('sinr', '--') if serving_cell else value} {bars}")
                    self.progress_bars["sinr"].config(value=percent)
                else:
                    label.config(text=str(value))

            # Update cells treeview
            self.cells_tree.delete(*self.cells_tree.get_children())
            for cell in self.cells_info:
                rsrp_display, _ = self.get_signal_bars(cell.get('rsrp', "N/A").replace("dBm", "").replace("N/A", "").strip(), -140, -44)
                sinr_display, _ = self.get_signal_bars(cell.get('sinr', "N/A").replace("dB", "").replace("N/A", "").strip(), -20, 30)
                self.cells_tree.insert("", "end", values=(
                    cell.get("rat", "--"),
                    cell.get("cell_id", "--"),
                    cell.get("pci", "--"),
                    cell.get("band", "--"),
                    cell.get("earfcn", "--"),
                    f"{cell.get('rsrp', '--')} {rsrp_display}",
                    cell.get("rsrq", "--"),
                    f"{cell.get('sinr', '--')} {sinr_display}",
                    cell.get("service", "--")
                ))


        except Exception as e:
            print(f"Error updating UI: {e}")
            
    def refresh_ports(self):
        """Refresh the list of available serial ports and update status. Auto-select AT-responsive port."""
        import glob
        ports = glob.glob('/dev/ttyUSB*')
        at_port = None
        for port in ports:
            try:
                ser = serial.Serial(port, 115200, timeout=1)
                ser.write(b'AT\r\n')
                ser.flush()
                response = ser.read(64).decode(errors='ignore')
                ser.close()
                if 'OK' in response:
                    at_port = port
                    break
            except Exception:
                continue
        if not ports:
            ports = ["/dev/ttyUSB3"]  # fallback
        self.port_dropdown['values'] = ports
        if at_port:
            self.port_var.set(at_port)
            self.at_port_detected = at_port
        else:
            self.port_var.set(ports[0])
            self.at_port_detected = None
        self.update_port_status()

    def update_port_status(self):
        """Update the port status label to show if Fibocom FM350-GL is detected, if ports are available, and which port is AT-responsive."""
        import glob
        ports = glob.glob('/dev/ttyUSB*')
        port_available = any(os.path.exists(p) for p in ports)
        selected_port = self.port_var.get()
        # Check for Fibocom FM350-GL device
        fibocom_found = self.check_fibocom_device()
        status = []
        if port_available:
            status.append("USB ports found")
        else:
            status.append("No USB ports found")
        if fibocom_found:
            status.append("Fibocom FM350-GL detected")
        else:
            status.append("Fibocom FM350-GL not detected")
        if hasattr(self, 'at_port_detected') and self.at_port_detected:
            status.append(f"AT port: {self.at_port_detected} (auto-selected)")
        elif selected_port and os.path.exists(selected_port):
            status.append(f"Selected: {selected_port}")
        else:
            status.append("No valid port selected")
        self.port_status_label.config(text=" | ".join(status))
            
    def on_closing(self):
        """Handle application closing"""
        self.disconnect_from_modem()
        self.root.destroy()

    def handle_exit(self, signum, frame):
        """Handle forced exit or crash to restore system state"""
        self.disconnect_from_modem()
        os._exit(0)

    def show_about(self):
        about = tk.Toplevel(self.root)
        about.title("About RxTxSemi FM350gl Connect")
        about.transient(self.root)
        about.grab_set()
        about.resizable(False, False)
        frame = ttk.Frame(about, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="RxTxSemi FM350gl Connect", font=("Arial", 14, "bold")).pack(pady=(0, 10))
        ttk.Label(frame, text="A Linux GUI for monitoring and managing Fibocom FM350 modems.").pack(pady=(0, 10))
        # YouTube link
        def open_yt():
            webbrowser.open('https://youtube.com/tech4tress')
        yt_link = ttk.Label(frame, text="YouTube: youtube.com/tech4tress", foreground="blue", cursor="hand2")
        yt_link.pack(pady=(10, 0))
        yt_link.bind("<Button-1>", lambda e: open_yt())
        # Designed by
        ttk.Label(frame, text="Designed with love by Vamsi", font=("Arial", 10, "italic")).pack(pady=(20, 0))
        # Close button
        ttk.Button(frame, text="Close", command=about.destroy).pack(pady=(20, 0))

    def update_data_usage(self):
        if not psutil or not self.interface_name:
            return
        try:
            stats = psutil.net_io_counters(pernic=True)
            iface = self.interface_name
            if iface not in stats:
                # Try fallback: look for renamed interface
                for k in stats:
                    if k.lower().startswith('rxtxsemi'):
                        iface = k
                        break
            s = stats.get(iface)
            if not s:
                return
            now = time.time()
            tx, rx = s.bytes_sent, s.bytes_recv
            # On first call, initialize
            if self.data_last['tx'] == 0 and self.data_last['rx'] == 0:
                self.data_last['tx'] = tx
                self.data_last['rx'] = rx
                self.data_last['time'] = now
                self.data_total['tx'] = 0
                self.data_total['rx'] = 0
                self.data_speed['tx'] = 0
                self.data_speed['rx'] = 0
            else:
                dt = now - self.data_last['time']
                dtx = tx - self.data_last['tx']
                drx = rx - self.data_last['rx']
                self.data_speed['tx'] = dtx / dt if dt > 0 else 0
                self.data_speed['rx'] = drx / dt if dt > 0 else 0
                self.data_total['tx'] += dtx
                self.data_total['rx'] += drx
                self.data_last['tx'] = tx
                self.data_last['rx'] = rx
                self.data_last['time'] = now
            # Keep history for graph
            self.data_history['tx'].append(self.data_speed['tx'])
            self.data_history['rx'].append(self.data_speed['rx'])
            if len(self.data_history['tx']) > self.data_history_len:
                self.data_history['tx'] = self.data_history['tx'][-self.data_history_len:]
                self.data_history['rx'] = self.data_history['rx'][-self.data_history_len:]
            # Update labels
            self.data_usage_labels['tx'].config(text=self.format_bytes(self.data_total['tx']))
            self.data_usage_labels['rx'].config(text=self.format_bytes(self.data_total['rx']))
            self.data_usage_labels['tx_speed'].config(text=self.format_speed(self.data_speed['tx']))
            self.data_usage_labels['rx_speed'].config(text=self.format_speed(self.data_speed['rx']))
            # Update graph
            self.draw_data_graph()
        except Exception as e:
            print(f"Error updating data usage: {e}")

    def draw_data_graph(self):
        c = self.data_canvas
        c.delete('all')
        w, h = 240, 60
        tx_hist = self.data_history['tx'][-self.data_history_len:]
        rx_hist = self.data_history['rx'][-self.data_history_len:]
        if not tx_hist or not rx_hist:
            return
        max_val = max(max(tx_hist), max(rx_hist), 1)
        # Draw upload (red)
        for i in range(1, len(tx_hist)):
            x1 = (i-1) * w // self.data_history_len
            y1 = h - int(tx_hist[i-1] / max_val * (h-4))
            x2 = i * w // self.data_history_len
            y2 = h - int(tx_hist[i] / max_val * (h-4))
            c.create_line(x1, y1, x2, y2, fill='#ff5555', width=2)
        # Draw download (green)
        for i in range(1, len(rx_hist)):
            x1 = (i-1) * w // self.data_history_len
            y1 = h - int(rx_hist[i-1] / max_val * (h-4))
            x2 = i * w // self.data_history_len
            y2 = h - int(rx_hist[i] / max_val * (h-4))
            c.create_line(x1, y1, x2, y2, fill='#55ff55', width=2)
        # Legend
        c.create_text(30, 10, text='Up', fill='#ff5555', anchor='w')
        c.create_text(70, 10, text='Down', fill='#55ff55', anchor='w')

    def format_bytes(self, n):
        for unit in ['B','KB','MB','GB','TB']:
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"
    def format_speed(self, n):
        for unit in ['B/s','KB/s','MB/s','GB/s']:
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB/s"

    def update_modemmanager_btn(self):
        """Update the ModemManager control button label based on current status."""
        try:
            result = subprocess.run(["systemctl", "is-active", "ModemManager"], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == "active":
                self.modemmanager_btn.config(text="Stop ModemManager")
            else:
                self.modemmanager_btn.config(text="Start ModemManager")
        except Exception as e:
            self.modemmanager_btn.config(text="ModemManager Error")

    def toggle_modemmanager(self):
        """Start or stop ModemManager depending on its current state."""
        try:
            result = subprocess.run(["systemctl", "is-active", "ModemManager"], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == "active":
                # Stop ModemManager
                res = self.run_privileged_command(["systemctl", "stop", "ModemManager"])
                if res.returncode == 0:
                    messagebox.showinfo("ModemManager", "ModemManager stopped successfully.")
                else:
                    messagebox.showerror("ModemManager", f"Failed to stop ModemManager: {res.stderr}")
            else:
                # Start ModemManager
                res = self.run_privileged_command(["systemctl", "start", "ModemManager"])
                if res.returncode == 0:
                    messagebox.showinfo("ModemManager", "ModemManager started successfully.")
                else:
                    messagebox.showerror("ModemManager", f"Failed to start ModemManager: {res.stderr}")
        except Exception as e:
            messagebox.showerror("ModemManager", f"Error: {e}")
        self.update_modemmanager_btn()

def main():
    root = tk.Tk()
    app = FibocomMonitor(root)
    
    # Set up closing handler
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main() 
