import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from socket import *
from threading import Thread
import time
import os
import requests
import speech_recognition as sr 
import nmap
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import networkx as nx
import matplotlib

matplotlib.use("TkAgg")


class PortScannerApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Port Scanner")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")

        self.scanning = False
        self.scan_threads = []
        self.ports_scanned = 0
        self.total_ports = 0

        self.common_ports = {
            20: "FTP-data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            115: "SFTP",
            119: "NNTP",
            123: "NTP",
            143: "IMAP",
            161: "SNMP",
            194: "IRC",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }

       
        self.scan_results = {
            "target": "",
            "start_time": "",
            "end_time": "",
            "open_ports": [],
            "closed_ports": [],
            "vulnerabilities": []
        }

   
        self.setup_ui()

        # Initialize speech recognition
        self.recognizer = sr.Recognizer()

        # Initialize nmap scanner
        self.nmap_scanner = nmap.PortScanner()

        # Get Shodan API key from environment variable
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "WRuYW5cGmq1DR5FIt82ctTlghwiuRqOR")

    def setup_ui(self):
        # Main frame with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Scanner tab
        self.scanner_tab = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.scanner_tab, text=" Scanner ")

        # Results tab
        self.results_tab = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.results_tab, text=" Results ")

        # Visualization tab
        self.visual_tab = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.visual_tab, text=" Visualization ")

        # Vulnerabilities tab
        self.vuln_tab = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.vuln_tab, text=" Vulnerabilities ")

        # Setup each tab
        self.setup_scanner_tab()
        self.setup_results_tab()
        self.setup_visualization_tab()
        self.setup_vulnerabilities_tab()

        # Status bar at the bottom
        self.status_bar = ttk.Label(self.root,
                                    text="Ready",
                                    relief=tk.SUNKEN,
                                    anchor=tk.W,
                                    padding=(5, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Set style
        self.configure_styles()

    def setup_scanner_tab(self):
        # Title
        title_label = ttk.Label(self.scanner_tab,
                                text="Advanced Network Port Scanner",
                                font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 15))

        # Input frame
        input_frame = ttk.LabelFrame(self.scanner_tab,
                                     text="Scan Settings",
                                     padding="10 10 10 10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # Host input
        host_frame = ttk.Frame(input_frame)
        host_frame.pack(fill=tk.X, pady=5)

        ttk.Label(host_frame, text="Target Host:", width=15).pack(side=tk.LEFT)
        self.host_entry = ttk.Entry(host_frame)
        self.host_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # Example label
        ttk.Label(host_frame, text="(IP or domain)",
                  foreground="gray").pack(side=tk.LEFT)

        # Ports input
        ports_frame = ttk.Frame(input_frame)
        ports_frame.pack(fill=tk.X, pady=5)

        ttk.Label(ports_frame, text="Ports:", width=15).pack(side=tk.LEFT)
        self.ports_entry = ttk.Entry(ports_frame)
        self.ports_entry.pack(side=tk.LEFT,
                              fill=tk.X,
                              expand=True,
                              padx=(0, 5))
        self.ports_entry.insert(0, "1-1000")  # Default port range

        # Example label
        ttk.Label(ports_frame,
                  text="(e.g., 22,80,443 or 1-1000)",
                  foreground="gray").pack(side=tk.LEFT)

        # Timeout input
        timeout_frame = ttk.Frame(input_frame)
        timeout_frame.pack(fill=tk.X, pady=5)

        ttk.Label(timeout_frame, text="Timeout (sec):",
                  width=15).pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value="1.0")
        self.timeout_entry = ttk.Spinbox(timeout_frame,
                                         from_=0.1,
                                         to=10.0,
                                         increment=0.1,
                                         textvariable=self.timeout_var,
                                         width=10)
        self.timeout_entry.pack(side=tk.LEFT)

        # Scan type frame
        scan_type_frame = ttk.Frame(input_frame)
        scan_type_frame.pack(fill=tk.X, pady=5)

        ttk.Label(scan_type_frame, text="Scan Type:",
                  width=15).pack(side=tk.LEFT)
        self.scan_type_var = tk.StringVar(value="Quick Scan")
        scan_types = [
            "Quick Scan", "Full Scan", "Vulnerability Scan", "Stealth Scan"
        ]
        scan_type_combobox = ttk.Combobox(scan_type_frame,
                                          textvariable=self.scan_type_var,
                                          values=scan_types,
                                          state="readonly",
                                          width=15)
        scan_type_combobox.pack(side=tk.LEFT)

        # Advanced options
        advanced_frame = ttk.LabelFrame(self.scanner_tab,
                                        text="Advanced Options",
                                        padding="10 10 10 10")
        advanced_frame.pack(fill=tk.X, pady=(0, 10))

        # Service detection option
        self.service_detect_var = tk.BooleanVar(value=True)
        service_check = ttk.Checkbutton(advanced_frame,
                                        text="Detect Services",
                                        variable=self.service_detect_var)
        service_check.pack(side=tk.LEFT, padx=5)

        # OS detection option
        self.os_detect_var = tk.BooleanVar(value=False)
        os_check = ttk.Checkbutton(advanced_frame,
                                   text="OS Detection",
                                   variable=self.os_detect_var)
        os_check.pack(side=tk.LEFT, padx=5)

        # Vulnerability check option
        self.vuln_check_var = tk.BooleanVar(value=False)
        vuln_check = ttk.Checkbutton(advanced_frame,
                                     text="Vulnerability Check",
                                     variable=self.vuln_check_var)
        vuln_check.pack(side=tk.LEFT, padx=5)

        # Shodan intelligence option
        self.shodan_var = tk.BooleanVar(value=False)
        shodan_check = ttk.Checkbutton(advanced_frame,
                                       text="Shodan Intelligence",
                                       variable=self.shodan_var)
        shodan_check.pack(side=tk.LEFT, padx=5)

        # Buttons frame
        buttons_frame = ttk.Frame(self.scanner_tab)
        buttons_frame.pack(fill=tk.X, pady=10)

        # Scan button
        self.scan_button = ttk.Button(buttons_frame,
                                      text="Start Scan",
                                      command=self.start_scan,
                                      style="Accent.TButton")
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # Stop button
        self.stop_button = ttk.Button(buttons_frame,
                                      text="Stop Scan",
                                      command=self.stop_scan,
                                      state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Clear button
        self.clear_button = ttk.Button(buttons_frame,
                                       text="Clear Results",
                                       command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Export button
        self.export_button = ttk.Button(buttons_frame,
                                        text="Export to PDF",
                                        command=self.export_to_pdf)
        self.export_button.pack(side=tk.LEFT, padx=5)

        # Voice command button
        self.voice_button = ttk.Button(buttons_frame,
                                       text="🎤 Voice Command",
                                       command=self.start_voice_recognition)
        self.voice_button.pack(side=tk.LEFT, padx=5)

        # Progress frame
        progress_frame = ttk.Frame(self.scanner_tab)
        progress_frame.pack(fill=tk.X, pady=(0, 10))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame,
                                            orient=tk.HORIZONTAL,
                                            length=100,
                                            mode='determinate',
                                            variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X)

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(progress_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, pady=(5, 0))

        # Results frame
        results_frame = ttk.LabelFrame(self.scanner_tab,
                                       text="Scan Results",
                                       padding="10 10 10 10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Output box (Scrollable)
        self.output_box = scrolledtext.ScrolledText(results_frame,
                                                    width=60,
                                                    height=15,
                                                    font=("Consolas", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True)

        # Configure tags for colored output
        self.output_box.tag_configure("open", foreground="green")
        self.output_box.tag_configure("closed", foreground="red")
        self.output_box.tag_configure("info", foreground="blue")
        self.output_box.tag_configure("header",
                                      foreground="purple",
                                      font=("Consolas", 10, "bold"))
        self.output_box.tag_configure("warning", foreground="orange")
        self.output_box.tag_configure("vulnerability",
                                      foreground="red",
                                      font=("Consolas", 10, "bold"))

    def setup_results_tab(self):
        # Create a frame for the treeview
        tree_frame = ttk.Frame(self.results_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Create a notebook for different results views
        results_notebook = ttk.Notebook(tree_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True)

        # Open ports tab
        open_ports_frame = ttk.Frame(results_notebook)
        results_notebook.add(open_ports_frame, text="Open Ports")

        # Create treeview for open ports
        columns = ("Port", "Service", "Version", "State", "Protocol")
        self.open_ports_tree = ttk.Treeview(open_ports_frame,
                                            columns=columns,
                                            show="headings")

        # Define headings
        for col in columns:
            self.open_ports_tree.heading(col, text=col)
            self.open_ports_tree.column(col, width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(open_ports_frame,
                                  orient="vertical",
                                  command=self.open_ports_tree.yview)
        self.open_ports_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.open_ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Service details tab
        service_frame = ttk.Frame(results_notebook)
        results_notebook.add(service_frame, text="Service Details")

        # Text widget for service details
        self.service_details_text = scrolledtext.ScrolledText(service_frame,
                                                              width=60,
                                                              height=15,
                                                              font=("Consolas",
                                                                    10))
        self.service_details_text.pack(fill=tk.BOTH, expand=True)

        # Host information tab
        host_info_frame = ttk.Frame(results_notebook)
        results_notebook.add(host_info_frame, text="Host Information")

        # Host information text widget
        self.host_info_text = scrolledtext.ScrolledText(host_info_frame,
                                                        width=60,
                                                        height=15,
                                                        font=("Consolas", 10))
        self.host_info_text.pack(fill=tk.BOTH, expand=True)

        # Summary statistics
        summary_frame = ttk.LabelFrame(self.results_tab, text="Scan Summary")
        summary_frame.pack(fill=tk.X, pady=10)

        # Grid for summary stats
        self.summary_labels = {}
        stats = [
            "Target", "Start Time", "Duration", "Open Ports", "Closed Ports",
            "Vulnerabilities"
        ]

        for i, stat in enumerate(stats):
            row, col = divmod(i, 3)
            ttk.Label(summary_frame, text=f"{stat}:").grid(row=row,
                                                           column=col * 2,
                                                           padx=5,
                                                           pady=5,
                                                           sticky=tk.W)
            value_label = ttk.Label(summary_frame, text="-")
            value_label.grid(row=row,
                             column=col * 2 + 1,
                             padx=5,
                             pady=5,
                             sticky=tk.W)
            self.summary_labels[stat.lower().replace(" ", "_")] = value_label

        # Make the grid columns expandable
        for i in range(6):
            summary_frame.columnconfigure(i, weight=1)

    def setup_visualization_tab(self):
        # Create a frame for visualization controls
        control_frame = ttk.Frame(self.visual_tab)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Visualization type selector
        ttk.Label(control_frame, text="Visualization Type:").pack(side=tk.LEFT,
                                                                  padx=5)
        self.viz_type_var = tk.StringVar(value="3D Network")
        viz_types = ["3D Network", "Port Distribution", "Service Map"]

        viz_type_combobox = ttk.Combobox(control_frame,
                                         textvariable=self.viz_type_var,
                                         values=viz_types,
                                         state="readonly",
                                         width=15)
        viz_type_combobox.pack(side=tk.LEFT, padx=5)

        # Button to generate visualization
        generate_btn = ttk.Button(control_frame,
                                  text="Generate Visualization",
                                  command=self.generate_visualization)
        generate_btn.pack(side=tk.LEFT, padx=5)

        # Frame for the visualization
        self.viz_frame = ttk.Frame(self.visual_tab)
        self.viz_frame.pack(fill=tk.BOTH, expand=True)

        # Default empty figure
        self.fig = plt.Figure(figsize=(5, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.viz_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def setup_vulnerabilities_tab(self):
        # Top frame for controls
        control_frame = ttk.Frame(self.vuln_tab)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Treeview for vulnerabilities
        columns = ("CVE ID", "Severity", "Port", "Service", "Description")
        self.vuln_tree = ttk.Treeview(self.vuln_tab,
                                      columns=columns,
                                      show="headings")

        # Define headings
        for col in columns:
            self.vuln_tree.heading(col, text=col)

        # Adjust column widths
        self.vuln_tree.column("CVE ID", width=120)
        self.vuln_tree.column("Severity", width=80)
        self.vuln_tree.column("Port", width=60)
        self.vuln_tree.column("Service", width=100)
        self.vuln_tree.column("Description", width=400)

        # Create scrollbar
        scrollbar = ttk.Scrollbar(self.vuln_tab,
                                  orient="vertical",
                                  command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_tree.pack(fill=tk.BOTH, expand=True)

        # Vulnerability details frame
        vuln_details_frame = ttk.LabelFrame(self.vuln_tab,
                                            text="Vulnerability Details")
        vuln_details_frame.pack(fill=tk.X, pady=10, padx=5)

        # Text widget for vulnerability details
        self.vuln_details_text = scrolledtext.ScrolledText(vuln_details_frame,
                                                           width=60,
                                                           height=10,
                                                           font=("Consolas",
                                                                 10))
        self.vuln_details_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Bind click event to show details
        self.vuln_tree.bind("<<TreeviewSelect>>",
                            self.show_vulnerability_details)

    def configure_styles(self):
        # Configure ttk styles
        style = ttk.Style()

        # Create a custom button style
        style.configure("Accent.TButton", font=("Helvetica", 10, "bold"))

        # Set theme if available
        try:
            style.theme_use(
                "clam")  # Try to use a more modern theme if available
        except:
            pass

    def conn_scan(self, tgt_host, tgt_port):
        "Function to check if a port is open"
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(float(self.timeout_var.get()))
            result = sock.connect_ex((tgt_host, tgt_port))
            service_name = self.common_ports.get(tgt_port, "unknown")

            if result == 0:
                # Port is open
                version = "Unknown"

                # Detect service version if enabled
                if self.service_detect_var.get():
                    try:
                        sock.send(b"HELLO\r\n")
                        banner = sock.recv(1024).decode(
                            'utf-8', errors='ignore').strip()
                        if banner:
                            version = banner
                    except:
                        pass

                result_text = f"[+] {tgt_port}/tcp open - {service_name}\n"
                if version != "Unknown":
                    result_text += f"    Version: {version}\n"

                self.output_box.insert(tk.END, result_text, "open")

                # Add to scan results
                port_info = {
                    "port": tgt_port,
                    "service": service_name,
                    "version": version,
                    "state": "open",
                    "protocol": "tcp"
                }
                self.scan_results["open_ports"].append(port_info)

                # Add to treeview in Results tab
                self.root.after(
                    10, lambda: self.open_ports_tree.insert(
                        "",
                        "end",
                        values=(tgt_port, service_name, version, "open", "tcp"
                                )))
            else:
                # Port is closed
                result_text = f"[-] {tgt_port}/tcp closed\n"
                self.output_box.insert(tk.END, result_text, "closed")
                self.scan_results["closed_ports"].append(tgt_port)

            sock.close()
        except Exception as e:
            result_text = f"[-] {tgt_port}/tcp error: {str(e)}\n"
            self.output_box.insert(tk.END, result_text, "closed")
            self.scan_results["closed_ports"].append(tgt_port)

        # Update progress
        self.ports_scanned += 1
        progress = (self.ports_scanned / self.total_ports) * 100
        self.progress_var.set(progress)
        self.status_var.set(
            f"Scanning: {self.ports_scanned}/{self.total_ports} ports completed"
        )
        self.status_bar.config(text=f"Scanning port {tgt_port}...")

    def port_scan(self, tgt_host, tgt_ports):
        "Function to scan multiple ports on a target"
        scan_start_time = time.time()
        self.scan_results["start_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
        self.scan_results["target"] = tgt_host

        try:
            tgt_ip = gethostbyname(tgt_host)
        except:
            messagebox.showerror("Error", f"Unknown Host {tgt_host}")
            self.scanning = False
            self.update_ui_after_scan()
            return

        self.output_box.insert(tk.END, f"[+] Scan results for: {tgt_ip}\n",
                               "header")
        self.output_box.insert(
            tk.END, f"[+] Started at: {time.strftime('%H:%M:%S')}\n", "info")
        setdefaulttimeout(float(self.timeout_var.get()))

        # Update host information in results tab
        self.update_host_info(tgt_host, tgt_ip)

        # Reset scan results
        self.scan_results["open_ports"] = []
        self.scan_results["closed_ports"] = []
        self.scan_results["vulnerabilities"] = []

        # Clear existing treeview data
        for item in self.open_ports_tree.get_children():
            self.open_ports_tree.delete(item)

        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        # Basic port scanning with multithreading
        self.scan_threads = []

        # Determine scan type and behavior
        scan_type = self.scan_type_var.get()
        if scan_type == "Quick Scan":
            # Just do basic TCP scan
            pass
        elif scan_type == "Full Scan":
            # Will add Nmap scanning after basic TCP scan
            pass
        elif scan_type == "Vulnerability Scan":
            # Sets the vulnerability flag to true
            self.vuln_check_var.set(True)
        elif scan_type == "Stealth Scan":
            # Will use Nmap's SYN scan after basic scan
            pass

        # Perform socket-based scan first
        for tgt_port in tgt_ports:
            if not self.scanning:
                break

            t = Thread(target=self.conn_scan, args=(tgt_host, tgt_port))
            self.scan_threads.append(t)
            t.start()

            # Limit concurrent threads to avoid overwhelming the system
            if len(self.scan_threads) >= 50:
                for thread in self.scan_threads:
                    thread.join()
                self.scan_threads = []

        # Wait for remaining threads
        for thread in self.scan_threads:
            thread.join()

        # Perform additional Nmap scans if selected options require it
        if self.scanning and (self.service_detect_var.get()
                              or self.os_detect_var.get()
                              or scan_type in ["Full Scan", "Stealth Scan"]):
            self.status_var.set("Running detailed service/OS detection...")

            try:
                # Build arguments for Nmap scan
                arguments = "-T4"  # Speed template (0-5, higher is faster)

                if scan_type == "Stealth Scan":
                    arguments += " -sS"  # SYN scan
                else:
                    arguments += " -sV"  # Version detection

                if self.os_detect_var.get():
                    arguments += " -O"  # OS detection

                # Convert open ports to a string for Nmap to scan
                open_port_numbers = [
                    p["port"] for p in self.scan_results["open_ports"]
                ]
                if open_port_numbers:
                    port_str = ",".join(map(str, open_port_numbers))

                    self.output_box.insert(
                        tk.END,
                        f"[*] Running Nmap scan for detailed service detection...\n",
                        "info")
                    self.nmap_scanner.scan(tgt_host,
                                           port_str,
                                           arguments=arguments)

                    # Parse Nmap results
                    if tgt_ip in self.nmap_scanner.all_hosts():
                        for proto in self.nmap_scanner[tgt_ip].all_protocols():
                            ports = sorted(
                                self.nmap_scanner[tgt_ip][proto].keys())

                            for port in ports:
                                port_info = self.nmap_scanner[tgt_ip][proto][
                                    port]
                                service = port_info.get('name', 'unknown')
                                version = port_info.get(
                                    'product', '') + ' ' + port_info.get(
                                        'version', '')
                                version = version.strip()

                                # Update in results list
                                for op in self.scan_results["open_ports"]:
                                    if op["port"] == port:
                                        op["service"] = service
                                        op["version"] = version if version else "Unknown"

                                # Update treeview
                                for item in self.open_ports_tree.get_children(
                                ):
                                    if int(
                                            self.open_ports_tree.item(
                                                item, "values")[0]) == port:
                                        self.open_ports_tree.item(
                                            item,
                                            values=(port, service, version,
                                                    "open", proto))

                                result_text = f"[+] Nmap: {port}/{proto} - {service} {version}\n"
                                self.output_box.insert(tk.END, result_text,
                                                       "info")

                        # Get OS information if available
                        if 'osmatch' in self.nmap_scanner[tgt_ip]:
                            os_matches = self.nmap_scanner[tgt_ip]['osmatch']
                            if os_matches:
                                best_match = os_matches[0]
                                os_info = f"OS: {best_match['name']} (Accuracy: {best_match['accuracy']}%)"
                                self.output_box.insert(tk.END,
                                                       f"[+] {os_info}\n",
                                                       "info")
                                self.update_host_info_text(
                                    f"Operating System: {best_match['name']}\n"
                                )
            except Exception as e:
                self.output_box.insert(tk.END,
                                       f"[!] Nmap scan error: {str(e)}\n",
                                       "warning")

        # Check for vulnerabilities if enabled
        if self.scanning and self.vuln_check_var.get():
            self.check_vulnerabilities()

        # Check Shodan intelligence if enabled
        if self.scanning and self.shodan_var.get():
            self.check_shodan_intel(tgt_ip)

        if self.scanning:
            scan_end_time = time.time()
            scan_duration = round(scan_end_time - scan_start_time, 2)
            self.scan_results["end_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
            self.scan_results["duration"] = scan_duration

            self.output_box.insert(
                tk.END,
                f"[+] Scan completed at: {time.strftime('%H:%M:%S')}\n",
                "info")
            self.output_box.insert(
                tk.END, f"[+] Scan duration: {scan_duration} seconds\n",
                "info")
            self.output_box.insert(
                tk.END,
                f"[+] Open ports: {len(self.scan_results['open_ports'])}\n",
                "info")

            # Update summary information
            self.update_summary_info()
        else:
            self.output_box.insert(
                tk.END, f"[!] Scan stopped at: {time.strftime('%H:%M:%S')}\n",
                "info")

        self.scanning = False
        self.update_ui_after_scan()

    def check_vulnerabilities(self):
        "Check for vulnerabilities based on detected services and versions"
        self.output_box.insert(tk.END, "[*] Checking for vulnerabilities...\n",
                               "info")
        self.status_var.set("Checking for vulnerabilities...")

        # Clear existing entries
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        # Find vulnerabilities for each open port
        vulnerability_count = 0

        for port_info in self.scan_results["open_ports"]:
            port = port_info["port"]
            service = port_info["service"]
            version = port_info["version"]

            # Skip if service is unknown
            if service == "unknown":
                continue

            try:
                # Construct API query to search for CVEs
                # Note: In a real implementation, you would connect to a vulnerability database
                # We'll use a mock response for demonstration

                # Simulated vulnerabilities for common services
                vulnerabilities = []

                if service.lower() == "http" or service.lower() == "https":
                    vulnerabilities.append({
                        "cve_id":
                        "CVE-2021-44228",
                        "severity":
                        "Critical",
                        "description":
                        "Log4j Remote Code Execution Vulnerability"
                    })
                    vulnerabilities.append({
                        "cve_id":
                        "CVE-2019-0211",
                        "severity":
                        "High",
                        "description":
                        "Apache HTTP Server privilege escalation from modules' scripts"
                    })

                elif service.lower() == "ssh" and "openssh" in version.lower():
                    vulnerabilities.append({
                        "cve_id":
                        "CVE-2020-14145",
                        "severity":
                        "Medium",
                        "description":
                        "OpenSSH through 8.3p1 has an Observable Discrepancy leading to an information leak in the algorithm negotiation."
                    })

                elif service.lower() == "ftp":
                    vulnerabilities.append({
                        "cve_id":
                        "CVE-2019-5418",
                        "severity":
                        "High",
                        "description":
                        "FTP service may allow directory traversal attacks"
                    })

                elif service.lower() == "smtp":
                    vulnerabilities.append({
                        "cve_id":
                        "CVE-2020-13777",
                        "severity":
                        "High",
                        "description":
                        "Exim before 4.94 vulnerable to TLS traffic interception"
                    })

                # Add found vulnerabilities to results
                for vuln in vulnerabilities:
                    vulnerability_count += 1

                    # Add to scan results
                    vuln_info = {
                        "cve_id": vuln["cve_id"],
                        "severity": vuln["severity"],
                        "port": port,
                        "service": service,
                        "description": vuln["description"]
                    }
                    self.scan_results["vulnerabilities"].append(vuln_info)

                    # Add to tree view
                    self.vuln_tree.insert(
                        "",
                        "end",
                        values=(vuln["cve_id"], vuln["severity"], port,
                                service, vuln["description"]))

                    # Add to output box
                    self.output_box.insert(
                        tk.END,
                        f"[!] Vulnerability found: {vuln['cve_id']} ({vuln['severity']}) on port {port}/{service}\n",
                        "vulnerability")
                    self.output_box.insert(
                        tk.END, f"    Description: {vuln['description']}\n")

            except Exception as e:
                self.output_box.insert(
                    tk.END, f"[!] Error checking vulnerabilities: {str(e)}\n",
                    "warning")

        # Update summary
        if vulnerability_count == 0:
            self.output_box.insert(tk.END, "[+] No vulnerabilities found\n",
                                   "info")
        else:
            self.output_box.insert(
                tk.END, f"[!] Found {vulnerability_count} vulnerabilities\n",
                "vulnerability")

    def check_shodan_intel(self, ip_address):
        "Check Shodan for intelligence about the target IP"
        if not self.shodan_api_key:
            self.output_box.insert(
                tk.END,
                "[!] Shodan API key not configured. Set SHODAN_API_KEY environment variable.\n",
                "warning")
            return

        self.output_box.insert(tk.END, "[*] Checking Shodan intelligence...\n",
                               "info")
        self.status_var.set("Checking Shodan intelligence...")

        try:
            # API endpoint
            url = f"https://api.shodan.io/shodan/host/{ip_address}?key={self.shodan_api_key}"

            # Make the request
            response = requests.get(url)

            # If successful
            if response.status_code == 200:
                data = response.json()

                # Extract useful information
                country = data.get('country_name', 'Unknown')
                org = data.get('org', 'Unknown')
                isp = data.get('isp', 'Unknown')
                os = data.get('os', 'Unknown')
                tags = data.get('tags', [])
                hostnames = data.get('hostnames', [])

                # Update host information
                self.update_host_info_text(f"Country: {country}\n")
                self.update_host_info_text(f"Organization: {org}\n")
                self.update_host_info_text(f"ISP: {isp}\n")
                self.update_host_info_text(f"Operating System: {os}\n")
                if hostnames:
                    self.update_host_info_text(
                        f"Hostnames: {', '.join(hostnames)}\n")
                if tags:
                    self.update_host_info_text(f"Tags: {', '.join(tags)}\n")

                # Add to output
                self.output_box.insert(
                    tk.END,
                    f"[+] Shodan - Country: {country}, Organization: {org}\n",
                    "info")
                if os != 'Unknown':
                    self.output_box.insert(tk.END, f"[+] Shodan - OS: {os}\n",
                                           "info")
                if tags:
                    self.output_box.insert(
                        tk.END, f"[+] Shodan - Tags: {', '.join(tags)}\n",
                        "info")

                # Look for potential security issues from Shodan data
                if 'vulns' in data:
                    vuln_count = len(data['vulns'])
                    self.output_box.insert(
                        tk.END,
                        f"[!] Shodan reports {vuln_count} vulnerabilities for this IP\n",
                        "vulnerability")

                    # Add top 3 vulnerabilities
                    for i, (cve_id,
                            vuln_info) in enumerate(data['vulns'].items()):
                        if i >= 3:  # Limit to top 3
                            break

                        cvss = vuln_info.get('cvss', 'N/A')
                        severity = "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"

                        self.output_box.insert(
                            tk.END,
                            f"    {cve_id} (CVSS: {cvss}) - {severity}\n",
                            "vulnerability")

                        # Add to scan results and treeview
                        vuln_info = {
                            "cve_id": cve_id,
                            "severity": severity,
                            "port": "N/A",
                            "service": "N/A",
                            "description": f"Reported by Shodan (CVSS: {cvss})"
                        }
                        self.scan_results["vulnerabilities"].append(vuln_info)

                        self.vuln_tree.insert(
                            "",
                            "end",
                            values=(cve_id, severity, "N/A", "N/A",
                                    f"Reported by Shodan (CVSS: {cvss})"))
            else:
                self.output_box.insert(
                    tk.END, f"[!] Shodan API error: {response.status_code}\n",
                    "warning")

        except Exception as e:
            self.output_box.insert(tk.END,
                                   f"[!] Error checking Shodan: {str(e)}\n",
                                   "warning")

    def update_host_info(self, hostname, ip):
        "Update host information in the Results tab"
        # Clear existing info
        self.host_info_text.delete(1.0, tk.END)

        # Add basic info
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        self.host_info_text.insert(tk.END, f"Hostname: {hostname}\n")
        self.host_info_text.insert(tk.END, f"IP Address: {ip}\n")
        self.host_info_text.insert(tk.END, f"Scan Time: {current_time}\n")

        # Try to get additional info
        try:
            # Try to get WHOIS info (simulated)
            self.host_info_text.insert(tk.END,
                                       f"\n--- Network Information ---\n")
            self.host_info_text.insert(tk.END, f"Resolved By: DNS Lookup\n")

            # Reverse DNS (if hostname was an IP)
            if hostname != ip:
                try:
                    reverse_dns = gethostbyaddr(ip)
                    self.host_info_text.insert(
                        tk.END, f"Reverse DNS: {reverse_dns[0]}\n")
                except:
                    pass
        except:
            pass

    def update_host_info_text(self, text):
        "Add text to the host info text widget"
        self.host_info_text.insert(tk.END, text)

    def update_summary_info(self):
        "Update the summary information in the Results tab"
        # Update labels with scan results
        self.summary_labels["target"].config(text=self.scan_results["target"])
        self.summary_labels["start_time"].config(
            text=self.scan_results["start_time"])
        self.summary_labels["duration"].config(
            text=f"{self.scan_results.get('duration', 0)} seconds")
        self.summary_labels["open_ports"].config(
            text=str(len(self.scan_results["open_ports"])))
        self.summary_labels["closed_ports"].config(
            text=str(len(self.scan_results["closed_ports"])))
        self.summary_labels["vulnerabilities"].config(
            text=str(len(self.scan_results["vulnerabilities"])))

    def start_scan(self):
        "Handles user input and starts scanning"
        tgt_host = self.host_entry.get().strip()
        ports_input = self.ports_entry.get().strip()

        if not tgt_host or not ports_input:
            messagebox.showerror("Error",
                                 "Please enter both Target Host and Ports.")
            return

        tgt_ports = []
        try:
            for part in ports_input.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    tgt_ports.extend(range(start, end + 1))
                else:
                    tgt_ports.append(int(part))
        except ValueError:
            messagebox.showerror(
                "Error",
                "Invalid port format. Use numbers or ranges (e.g., 22,80,443 or 1-1000)."
            )
            return

        # Switch to Scanner tab to show progress
        self.notebook.select(0)

        # Update UI for scanning state
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        self.voice_button.config(state=tk.DISABLED)

        # Reset progress tracking
        self.ports_scanned = 0
        self.total_ports = len(tgt_ports)
        self.progress_var.set(0)

        # Clear previous results
        self.output_box.delete(1.0, tk.END)

        # Start scanning in a separate thread
        scan_thread = Thread(target=self.port_scan, args=(tgt_host, tgt_ports))
        scan_thread.daemon = True
        scan_thread.start()

    def stop_scan(self):
        "Stop the current scan"
        self.scanning = False
        self.status_var.set("Stopping scan...")
        self.status_bar.config(text="Stopping scan...")

    def clear_results(self):
        "Clear the results box and treeviews"
        self.output_box.delete(1.0, tk.END)
        self.host_info_text.delete(1.0, tk.END)
        self.service_details_text.delete(1.0, tk.END)
        self.vuln_details_text.delete(1.0, tk.END)

        # Clear treeviews
        for item in self.open_ports_tree.get_children():
            self.open_ports_tree.delete(item)

        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        # Reset progress bar and status
        self.progress_var.set(0)
        self.status_var.set("Ready")
        self.status_bar.config(text="Ready")

        # Reset summary labels
        for key, label in self.summary_labels.items():
            label.config(text="-")

        # Clear visualization
        self.fig.clear()
        self.canvas.draw()

    def update_ui_after_scan(self):
        "Update UI elements after scan completes or is stopped"
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)
        self.voice_button.config(state=tk.NORMAL)

        if self.ports_scanned == self.total_ports:
            self.status_var.set(
                f"Scan complete: {self.ports_scanned} ports scanned")
            self.status_bar.config(text="Scan complete")
        else:
            self.status_var.set(
                f"Scan stopped: {self.ports_scanned}/{self.total_ports} ports scanned"
            )
            self.status_bar.config(text="Scan stopped")

    def generate_visualization(self):
        "Generate visualization based on the selected type"
        if not self.scan_results["open_ports"]:
            messagebox.showinfo(
                "Information",
                "No scan results available for visualization. Please run a scan first."
            )
            return

        viz_type = self.viz_type_var.get()

        # Clear previous figure
        self.fig.clear()

        if viz_type == "3D Network":
            self.generate_3d_network_viz()
        elif viz_type == "Port Distribution":
            self.generate_port_distribution_viz()
        elif viz_type == "Service Map":
            self.generate_service_map_viz()

        # Redraw the canvas
        self.canvas.draw()

        # Switch to Visualization tab
        self.notebook.select(2)

    def generate_3d_network_viz(self):
        "Generate a 3D network visualization"
        # Create a subplot with 3D projection
        ax = self.fig.add_subplot(111, projection='3d')

        # Get data
        ports = [p["port"] for p in self.scan_results["open_ports"]]
        services = [p["service"] for p in self.scan_results["open_ports"]]

        # Generate unique service colors
        unique_services = list(set(services))
        colors = plt.cm.tab10(np.linspace(0, 1, len(unique_services)))
        service_colors = {
            service: colors[i]
            for i, service in enumerate(unique_services)
        }

        # Create the 3D network visualization
        x = np.ones(len(ports))
        y = np.array(range(len(ports)))
        z = np.array(ports)

        # Create scatter plot
        for i, (x_val, y_val, z_val) in enumerate(zip(x, y, z)):
            service = services[i]
            ax.scatter([x_val], [y_val], [z_val],
                       color=service_colors[service],
                       s=100)
            ax.text(x_val, y_val, z_val, f"{z_val}\n{service}", size=8)

        # Add lines from origin to each point (like a star network)
        origin = [0, 0, 0]
        for i, (x_val, y_val, z_val) in enumerate(zip(x, y, z)):
            ax.plot([origin[0], x_val], [origin[1], y_val], [origin[2], z_val],
                    color=service_colors[services[i]],
                    alpha=0.5)

        # Set labels and title
        ax.set_xlabel('Host')
        ax.set_ylabel('Node Index')
        ax.set_zlabel('Port Number')
        ax.set_title(f'3D Network Map: {self.scan_results["target"]}')

        # Add a legend
        legend_elements = [
            plt.Line2D([0], [0],
                       marker='o',
                       color='w',
                       label=service,
                       markerfacecolor=service_colors[service],
                       markersize=10) for service in unique_services
        ]
        ax.legend(handles=legend_elements, bbox_to_anchor=(0.95, 0.95))

        # Set the view angle
        ax.view_init(30, 45)

        self.fig.tight_layout()

    def generate_port_distribution_viz(self):
        "Generate a port distribution visualization"
        ax = self.fig.add_subplot(111)

        # Get data
        ports = [p["port"] for p in self.scan_results["open_ports"]]

        # Group ports by ranges
        ranges = [(1, 1023), (1024, 5000), (5001, 10000), (10001, 65535)]
        range_names = [
            "Well-Known (1-1023)", "Registered (1024-5000)",
            "Dynamic (5001-10000)", "Private (10001-65535)"
        ]
        range_counts = [
            sum(1 for p in ports if r[0] <= p <= r[1]) for r in ranges
        ]

        # Create pie chart
        wedges, texts, autotexts = ax.pie(
            range_counts,
            autopct='%1.1f%%',
            textprops={'fontsize': 9},
            colors=plt.cm.tab10.colors[:len(ranges)])

        # Add legend
        ax.legend(wedges, [
            f"{name} ({count})"
            for name, count in zip(range_names, range_counts)
        ],
                  loc="center left",
                  bbox_to_anchor=(0.91, 0, 0.5, 1))

        ax.set_title(f'Port Distribution: {self.scan_results["target"]}')

        self.fig.tight_layout()

    def generate_service_map_viz(self):
        "Generate a service map visualization"
        ax = self.fig.add_subplot(111)

        # Get data
        services = [p["service"] for p in self.scan_results["open_ports"]]

        # Count occurrences of each service
        service_counts = {}
        for service in services:
            service_counts[service] = service_counts.get(service, 0) + 1

        # Sort services by count
        sorted_services = sorted(service_counts.items(),
                                 key=lambda x: x[1],
                                 reverse=True)

        # Create horizontal bar chart
        services = [s[0] for s in sorted_services]
        counts = [s[1] for s in sorted_services]

        y_pos = np.arange(len(services))
        ax.barh(y_pos,
                counts,
                align='center',
                color=plt.cm.Paired(np.linspace(0, 1, len(services))))
        ax.set_yticks(y_pos)
        ax.set_yticklabels(services)
        ax.invert_yaxis()  # labels read top-to-bottom
        ax.set_xlabel('Number of Open Ports')
        ax.set_title(f'Services Distribution: {self.scan_results["target"]}')

        # Add count annotations
        for i, v in enumerate(counts):
            ax.text(v + 0.1, i, str(v), color='black', va='center')

        self.fig.tight_layout()

    def export_to_pdf(self):
        "Export scan results to PDF"
        if not self.scan_results["open_ports"]:
            messagebox.showinfo(
                "Information",
                "No scan results available to export. Please run a scan first."
            )
            return

        # Ask user for a location to save the PDF
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                                 filetypes=[
                                                     ("PDF files", "*.pdf"),
                                                     ("All files", "*.*")
                                                 ],
                                                 title="Save Scan Report")

        if not file_path:
            return  # User cancelled

        try:
            # Create the PDF document
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()

            # Add custom styles
            styles.add(
                ParagraphStyle(name='SectionTitle',
                               parent=styles['Heading2'],
                               fontName='Helvetica-Bold',
                               spaceAfter=10))

            # Content elements
            elements = []

            # Title
            title = Paragraph(
                f"Network Scan Report: {self.scan_results['target']}",
                styles['Title'])
            elements.append(title)
            elements.append(Spacer(1, 12))

            # Summary
            elements.append(Paragraph("Scan Summary", styles['SectionTitle']))
            summary_data = [
                ["Target", self.scan_results['target']],
                ["Scan Start", self.scan_results['start_time']],
                ["Scan End", self.scan_results['end_time']],
                [
                    "Duration",
                    f"{self.scan_results.get('duration', 0)} seconds"
                ], ["Open Ports",
                    str(len(self.scan_results['open_ports']))],
                ["Closed Ports",
                 str(len(self.scan_results['closed_ports']))],
                [
                    "Vulnerabilities",
                    str(len(self.scan_results['vulnerabilities']))
                ]
            ]

            summary_table = Table(summary_data, colWidths=[120, 350])
            summary_table.setStyle(
                TableStyle([('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                            ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('TOPPADDING', (0, 0), (-1, -1), 6),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
            elements.append(summary_table)
            elements.append(Spacer(1, 20))

            # Open Ports
            elements.append(Paragraph("Open Ports", styles['SectionTitle']))

            if self.scan_results['open_ports']:
                port_data = [[
                    "Port", "Service", "Version", "State", "Protocol"
                ]]
                for port in self.scan_results['open_ports']:
                    port_data.append([
                        str(port['port']), port['service'], port['version'],
                        port['state'], port['protocol']
                    ])

                port_table = Table(port_data, colWidths=[50, 100, 150, 60, 60])
                port_table.setStyle(
                    TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                elements.append(port_table)
            else:
                elements.append(
                    Paragraph("No open ports found.", styles['Normal']))

            elements.append(Spacer(1, 20))

            # Vulnerabilities
            elements.append(
                Paragraph("Vulnerabilities", styles['SectionTitle']))

            if self.scan_results['vulnerabilities']:
                vuln_data = [[
                    "CVE ID", "Severity", "Port", "Service", "Description"
                ]]
                for vuln in self.scan_results['vulnerabilities']:
                    vuln_data.append([
                        vuln['cve_id'], vuln['severity'],
                        str(vuln['port']), vuln['service'], vuln['description']
                    ])

                vuln_table = Table(vuln_data, colWidths=[80, 60, 50, 80, 250])
                vuln_table.setStyle(
                    TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        # Color-code severity
                        ('TEXTCOLOR', (1, 1), (1, -1), colors.green
                         ),  # Default: Low
                    ]))

                # Apply color coding for severity
                for i in range(1, len(vuln_data)):
                    severity = vuln_data[i][1]
                    if severity == "Critical":
                        vuln_table.setStyle(
                            TableStyle([('TEXTCOLOR', (1, i), (1, i),
                                         colors.red)]))
                    elif severity == "High":
                        vuln_table.setStyle(
                            TableStyle([('TEXTCOLOR', (1, i), (1, i),
                                         colors.orangered)]))
                    elif severity == "Medium":
                        vuln_table.setStyle(
                            TableStyle([('TEXTCOLOR', (1, i), (1, i),
                                         colors.orange)]))

                elements.append(vuln_table)
            else:
                elements.append(
                    Paragraph("No vulnerabilities found.", styles['Normal']))

            # Build the PDF
            doc.build(elements)

            messagebox.showinfo("Success", f"Report saved to {file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create PDF: {str(e)}")

    def show_vulnerability_details(self, event):
        "Show details for the selected vulnerability"
        selected_items = self.vuln_tree.selection()
        if not selected_items:
            return

        # Get selected vulnerability
        item = selected_items[0]
        values = self.vuln_tree.item(item, "values")
        cve_id = values[0]
        severity = values[1]
        port = values[2]
        service = values[3]
        description = values[4]

        # Clear the details text
        self.vuln_details_text.delete(1.0, tk.END)

        # Display details
        self.vuln_details_text.insert(tk.END, f"CVE ID: {cve_id}\n", "header")
        self.vuln_details_text.insert(tk.END, f"Severity: {severity}\n")
        self.vuln_details_text.insert(tk.END, f"Affected Port: {port}\n")
        self.vuln_details_text.insert(tk.END, f"Service: {service}\n")
        self.vuln_details_text.insert(tk.END,
                                      f"\nDescription: {description}\n")

        # Add simulated CVSS information
        if severity == "Critical":
            cvss = "9.8"
        elif severity == "High":
            cvss = "8.2"
        elif severity == "Medium":
            cvss = "6.5"
        else:
            cvss = "3.2"

        self.vuln_details_text.insert(tk.END, f"\nCVSS Score: {cvss}\n")

        # Add simulated remediation steps
        self.vuln_details_text.insert(tk.END, "\nRecommended Actions:\n")
        if "openssh" in description.lower():
            self.vuln_details_text.insert(
                tk.END, "- Update OpenSSH to latest version\n")
            self.vuln_details_text.insert(
                tk.END, "- Implement stronger encryption settings\n")
            self.vuln_details_text.insert(
                tk.END, "- Consider IP-based access restrictions\n")
        elif "apache" in description.lower() or "http" in service.lower():
            self.vuln_details_text.insert(tk.END,
                                          "- Apply latest security patches\n")
            self.vuln_details_text.insert(
                tk.END, "- Review web server configuration\n")
            self.vuln_details_text.insert(tk.END,
                                          "- Consider implementing a WAF\n")
        elif "log4j" in description.lower():
            self.vuln_details_text.insert(
                tk.END, "- Update to latest Java/Log4j version\n")
            self.vuln_details_text.insert(
                tk.END, "- Implement firewall rules to block exploitation\n")
            self.vuln_details_text.insert(
                tk.END, "- Scan for vulnerable instances in your network\n")
        else:
            self.vuln_details_text.insert(
                tk.END, "- Update the affected service to latest version\n")
            self.vuln_details_text.insert(
                tk.END, "- Review service configuration for security issues\n")
            self.vuln_details_text.insert(
                tk.END, "- Monitor for suspicious activities\n")

        # Add reference links
        self.vuln_details_text.insert(tk.END, "\nReferences:\n")
        self.vuln_details_text.insert(
            tk.END, f"- https://nvd.nist.gov/vuln/detail/{cve_id}\n")
        self.vuln_details_text.insert(
            tk.END,
            f"- https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}\n")

    def start_voice_recognition(self):
        "Start listening for voice commands"
        self.voice_button.config(state=tk.DISABLED)
        self.status_var.set("Listening for voice commands...")
        self.status_bar.config(text="Listening...")

        # Start voice recognition in a separate thread
        voice_thread = Thread(target=self.listen_for_commands)
        voice_thread.daemon = True
        voice_thread.start()

    def listen_for_commands(self):
        "Listen for voice commands and execute them"
        with sr.Microphone() as source:
            try:
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = self.recognizer.listen(source,
                                               timeout=5,
                                               phrase_time_limit=5)

                # Recognize speech
                command = self.recognizer.recognize_google(audio).lower()

                # Update status
                self.status_var.set(f"Command recognized: {command}")

                # Process command
                self.process_voice_command(command)

            except sr.WaitTimeoutError:
                self.status_var.set("No speech detected. Please try again.")
            except sr.UnknownValueError:
                self.status_var.set(
                    "Could not understand audio. Please try again.")
            except sr.RequestError as e:
                self.status_var.set(f"Could not request results; {e}")
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
            finally:
                # Re-enable the voice button
                self.voice_button.config(state=tk.NORMAL)
                self.status_bar.config(text="Ready")

    def process_voice_command(self, command):
        "Process the recognized voice command"
        command = command.lower().strip()

        # Check for scan commands
        if "scan" in command:
            # Extract target
            target = None
            words = command.split()
            if "scan" in words and words.index("scan") < len(words) - 1:
                target = words[words.index("scan") + 1]

            if target:
                # Set the target in the UI
                self.host_entry.delete(0, tk.END)
                self.host_entry.insert(0, target)

                # Set default port range if not specified
                if not self.ports_entry.get():
                    self.ports_entry.delete(0, tk.END)
                    self.ports_entry.insert(0, "1-1000")

                # Start the scan
                self.start_scan()
            else:
                self.status_var.set("Please specify a target to scan.")

        # Check for stop command
        elif "stop" in command:
            if self.scanning:
                self.stop_scan()
            else:
                self.status_var.set("No scan in progress to stop.")

        # Check for clear command
        elif "clear" in command:
            self.clear_results()
            self.status_var.set("Results cleared.")

        # Check for export command
        elif "export" in command or "save" in command or "report" in command:
            self.export_to_pdf()

        # Check for visualization command
        elif "visual" in command or "chart" in command or "graph" in command:
            self.generate_visualization()

        # Check for switch tab commands
        elif "tab" in command:
            if "scanner" in command or "scan" in command:
                self.notebook.select(0)
            elif "result" in command:
                self.notebook.select(1)
            elif "visual" in command or "chart" in command:
                self.notebook.select(2)
            elif "vuln" in command:
                self.notebook.select(3)

        # Help command
        elif "help" in command:
            messagebox.showinfo(
                "Voice Commands Help", "Available commands:\n\n"
                "- 'scan [target]': Start a scan on the specified target\n"
                "- 'stop': Stop the current scan\n"
                "- 'clear': Clear all results\n"
                "- 'export' or 'save report': Export results to PDF\n"
                "- 'visualization': Generate visualization\n"
                "- 'tab scanner/results/visual/vulnerabilities': Switch tabs\n"
                "- 'help': Show this help message")

        else:
            self.status_var.set(f"Command not recognized: {command}")


# Create the GUI window
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)

    # Set icon if available
    try:
        svg_icon = """
        <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">
            <circle cx="24" cy="24" r="22" fill="#3498db" />
            <circle cx="24" cy="24" r="18" fill="#2980b9" />
            <circle cx="24" cy="24" r="3" fill="#ecf0f1" />
            <path d="M24 6 L24 13" stroke="#ecf0f1" stroke-width="2" />
            <path d="M24 35 L24 42" stroke="#ecf0f1" stroke-width="2" />
            <path d="M6 24 L13 24" stroke="#ecf0f1" stroke-width="2" />
            <path d="M35 24 L42 24" stroke="#ecf0f1" stroke-width="2" />
            <path d="M12 12 L17 17" stroke="#ecf0f1" stroke-width="2" />
            <path d="M31 31 L36 36" stroke="#ecf0f1" stroke-width="2" />
            <path d="M12 36 L17 31" stroke="#ecf0f1" stroke-width="2" />
            <path d="M31 17 L36 12" stroke="#ecf0f1" stroke-width="2" />
        </svg>
        """
        # Cannot directly set SVG as icon in Tkinter
        root.title("Advanced Network Port Scanner")
    except:
        pass

    root.mainloop()
