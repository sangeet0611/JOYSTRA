import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
from scapy.all import sniff, IP, TCP, UDP
import re
import time
import threading
import csv
from PIL import Image, ImageTk, ImageSequence
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from queue import Queue
import winsound
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import random

# DLP: Data Loss Prevention
def detect_sensitive_data(packet):
    payload = str(packet)
    credit_card_pattern = r'\b(?:\d[ -]*?){13,16}\b'
    if re.search(credit_card_pattern, payload):
        return True
    return False

# JOYSTRA-themed GUI
class Joystra_App:
    def __init__(self, root):
        self.root = root
        self.root.title("JOYSTRA")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0A1E2F")

        # Thread-safe queue for packet data
        self.packet_queue = Queue()
        self.lock = threading.Lock()

        # Style Configuration
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 12), background="#FF007A", foreground="#0A1E2F")
        style.map("TButton", background=[("active", "#00FFCC")])

        # Load and display the GIF background animation
        self.gif_path = "ezgif.com-video-to-gif-converter.gif"  # Replace with the path to your GIF file
        self.gif_frames = self.load_gif(self.gif_path)
        self.gif_label = tk.Label(root, bg="#0A1E2F")
        self.gif_label.place(x=0, y=0, relwidth=1, relheight=1)
        self.animate_gif(0)

        # Custom Font
        self.custom_font = ("Helvetica", 12)

        # Taskbar on the left side
        self.taskbar = tk.Frame(root, bg="#0A1E2F", width=60)
        self.taskbar.pack(side=tk.LEFT, fill=tk.Y)

        # Taskbar icons with updated colors
        self.sniffing_icon = tk.Label(self.taskbar, text="📡", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.sniffing_icon.pack(pady=10)
        self.sniffing_icon.bind("<Button-1>", lambda e: self.show_sniffing_screen())

        self.profile_icon = tk.Label(self.taskbar, text="👤", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.profile_icon.pack(pady=10)
        self.profile_icon.bind("<Button-1>", lambda e: self.show_profile_screen())

        self.graph_icon = tk.Label(self.taskbar, text="📊", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.graph_icon.pack(pady=10)
        self.graph_icon.bind("<Button-1>", lambda e: self.show_graph_screen())

        self.monitoring_icon = tk.Label(self.taskbar, text="📶", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.monitoring_icon.pack(pady=10)
        self.monitoring_icon.bind("<Button-1>", lambda e: self.show_monitoring_screen())

        self.analysis_icon = tk.Label(self.taskbar, text="🌊", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.analysis_icon.pack(pady=10)
        self.analysis_icon.bind("<Button-1>", lambda e: self.show_analysis_screen())

        self.history_icon = tk.Label(self.taskbar, text="📜", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.history_icon.pack(pady=10)
        self.history_icon.bind("<Button-1>", lambda e: self.show_history_screen())

        self.progress_icon = tk.Label(self.taskbar, text="⏳", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.progress_icon.pack(pady=10)
        self.progress_icon.bind("<Button-1>", lambda e: self.show_progress_bar())

        self.save_icon = tk.Label(self.taskbar, text="💾", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.save_icon.pack(pady=10)
        self.save_icon.bind("<Button-1>", lambda e: self.save_captured_packets())

        self.encryption_icon = tk.Label(self.taskbar, text="🔒", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.encryption_icon.pack(pady=10)
        self.encryption_icon.bind("<Button-1>", lambda e: self.show_encryption_screen())

        self.filter_icon = tk.Label(self.taskbar, text="🔍", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.filter_icon.pack(pady=10)
        self.filter_icon.bind("<Button-1>", lambda e: self.show_filter_screen())

        # Add Real-Time Clock and Calendar to Taskbar
        self.clock_label = tk.Label(self.taskbar, font=("Helvetica", 12), fg="#00FFCC", bg="#0A1E2F")
        self.clock_label.pack(side=tk.BOTTOM, pady=10)
        self.update_clock()

        # Initialize history list
        self.history = []

        # Real-Time Graph Data
        self.graph_data = {"TCP": 0, "UDP": 0, "SMTP": 0, "HTTP": 0, "HTTPS": 0, "Other": 0}

        # Profile Data
        self.profile_data = {}

        # Hacker Mode
        self.hacker_mode = False
        self.matrix_canvas = None

        # Theme Configuration
        self.theme = "Cyberpunk"
        self.theme_colors = {
            "Cyberpunk": {"bg": "#0A1E2F", "fg": "#00FFCC", "accent": "#FF007A"},
            "Dark": {"bg": "#0A1E2F", "fg": "#ffffff", "accent": "#00FFCC"},
            "Classic": {"bg": "#ffffff", "fg": "#000000", "accent": "#FF007A"}
        }

        # Theme Toggle Icon
        self.theme_icon = tk.Label(self.taskbar, text="🎨", font=("Arial", 24), bg="#0A1E2F", fg="#FF007A")
        self.theme_icon.pack(pady=15)
        self.theme_icon.bind("<Button-1>", lambda e: self.toggle_theme())

        # Encryption Key
        self.encryption_key = b"16bytesecretkey!"

        # Filter Rules
        self.filter_rules = {"IP": [], "Protocol": []}

        self.sniffing = False
        self.sniff_thread = None

    def add_tooltip(self, widget, text):
        """Add a tooltip to a widget."""
        tooltip = tk.Toplevel(widget, bg="#0A1E2F", bd=1)
        tooltip.wm_overrideredirect(True)
        label = tk.Label(tooltip, text=text, bg="#0A1E2F", fg="#00FFCC", font=("Helvetica", 10))
        label.pack()
        tooltip.withdraw()
        widget.bind("<Enter>", lambda e: tooltip.place(x=widget.winfo_rootx() + 20, y=widget.winfo_rooty() + 20) or tooltip.deiconify())
        widget.bind("<Leave>", lambda e: tooltip.withdraw())

    def animate_button(self, canvas, button, disabled=False):
        """Animate the button with a pulsing glow effect."""
        if not disabled and not self.sniffing if canvas == self.start_button_canvas else self.sniffing:
            current_color = canvas.itemcget(button, "fill")
            new_color = "#00FFCC" if current_color == "#FF007A" and random.random() > 0.9 else "#FF007A"
            canvas.itemconfig(button, fill=new_color)
        self.root.after(500, self.animate_button, canvas, button, disabled)

    def load_gif(self, gif_path):
        """Load the GIF and extract its frames."""
        try:
            gif = Image.open(gif_path)
            frames = []
            for frame in ImageSequence.Iterator(gif):
                frame = frame.resize((self.root.winfo_screenwidth(), self.root.winfo_screenheight()),
                                     Image.Resampling.LANCZOS)
                frames.append(ImageTk.PhotoImage(frame))
            return frames
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load GIF: {e}")
            return []

    def animate_gif(self, frame_index):
        """Animate the GIF by updating the frame."""
        if self.gif_frames:
            frame = self.gif_frames[frame_index]
            self.gif_label.config(image=frame)
            self.gif_label.image = frame  # Keep a reference to avoid garbage collection
            self.root.after(100, self.animate_gif, (frame_index + 1) % len(self.gif_frames))

    def update_clock(self):
        """Update the real-time clock."""
        current_time = time.strftime("%H:%M:%S")
        current_date = time.strftime("%Y-%m-%d")
        self.clock_label.config(text=f"{current_date}\n{current_time}")
        self.root.after(1000, self.update_clock)

    def show_sniffing_screen(self):
        """Show the sniffing screen with threat intelligence detection."""
        sniffing_window = tk.Toplevel(self.root)
        sniffing_window.title("Sniffing with Threat Intelligence")
        sniffing_window.geometry("800x600")
        sniffing_window.configure(bg="#0A1E2F")
        sniffing_window.attributes('-alpha', 0.95)

        sniffing_frame = tk.Frame(sniffing_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN, highlightbackground="#FF007A")
        sniffing_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Title
        tk.Label(sniffing_frame, text="Sniffing with Threat Intelligence", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 16, "bold")).pack(pady=10)

        # Threat Intelligence Section
        threat_frame = tk.Frame(sniffing_frame, bg="#0A1E2F")
        threat_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        tk.Label(threat_frame, text="Detected Threats:", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 12, "bold")).pack(pady=5)

        # ScrolledText for displaying threats
        self.threat_text = scrolledtext.ScrolledText(threat_frame, width=90, height=20, font=("Courier New", 12),
                                                     fg="#FF007A", bg="#0A1E2F", insertbackground="#00FFCC",
                                                     wrap=tk.WORD)
        self.threat_text.pack(pady=5)
        self.add_tooltip(self.threat_text, "List of detected threats based on threat intelligence")

        # Status Label
        self.sniffing_status = tk.Label(sniffing_frame, text="Monitoring Moved to Monitoring Screen", bg="#0A1E2F",
                                        fg="#00FFCC", font=("Helvetica", 10, "italic"))
        self.sniffing_status.pack(pady=10)

        # Simulated threat intelligence feed (replace with real feed in production)
        self.threat_feed = {
            "malicious_ips": ["192.168.1.100", "10.0.0.13", "172.16.254.1"],
            "malicious_domains": ["malware.example.com", "phishing.site"]
        }

        # Update status and start threat detection based on sniffing state
        if self.sniffing:
            self.sniffing_status.config(text="Sniffing Active")
            self.update_threat_detection()
        else:
            self.threat_text.insert(tk.END, "Start sniffing from the Monitoring screen to enable threat detection.\n")
            self.sniffing_status.config(text="Sniffing Not Active")

    def update_threat_detection(self):
        """Update the threat detection display based on sniffed packets."""
        if not self.sniffing or not hasattr(self, 'threat_text') or not self.threat_text.winfo_exists():
            return

        while not self.packet_queue.empty():
            packet_data = self.packet_queue.get()
            ip_src, ip_dst, sport, dport, length, protocol = packet_data

            # Check against threat intelligence feed
            threat_detected = False
            threat_message = ""

            if ip_src in self.threat_feed["malicious_ips"]:
                threat_detected = True
                threat_message = f"Threat Detected - Malicious Source IP: {ip_src} | Dest: {ip_dst} | Protocol: {protocol}\n"
            elif ip_dst in self.threat_feed["malicious_ips"]:
                threat_detected = True
                threat_message = f"Threat Detected - Malicious Destination IP: {ip_dst} | Src: {ip_src} | Protocol: {protocol}\n"

            # Simulate domain check (requires DNS packet parsing, simplified here)
            if protocol in ["UDP", "TCP"] and (sport == 53 or dport == 53):  # DNS traffic
                simulated_domain = "malware.example.com" if random.random() < 0.1 else "safe.site"
                if simulated_domain in self.threat_feed["malicious_domains"]:
                    threat_detected = True
                    threat_message = f"Threat Detected - Malicious Domain: {simulated_domain} | Src: {ip_src} | Dest: {ip_dst}\n"

            if threat_detected:
                self.threat_text.insert(tk.END, threat_message)
                self.threat_text.see(tk.END)
                self.sniffing_status.config(text="Threat Detected!")
                winsound.Beep(2000, 500)  # Alert sound for threat detection

        # Schedule the next update
        self.root.after(100, self.update_threat_detection)
    def start_sniffing(self):
        self.sniffing = True
        self.start_button_canvas.itemconfig(self.start_button, fill="#666666")
        self.start_button_canvas.itemconfig(self.start_text, fill="#999999")
        self.stop_button_canvas.itemconfig(self.stop_button, fill="#FF007A")
        self.stop_button_canvas.itemconfig(self.stop_text, fill="#FFFFFF")
        self.monitoring_status.config(text="Sniffing Started")

        # Start sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self.sniff_traffic)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        # Start GUI updates
        self.update_gui()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button_canvas.itemconfig(self.start_button, fill="#FF007A")
        self.start_button_canvas.itemconfig(self.start_text, fill="#FFFFFF")
        self.stop_button_canvas.itemconfig(self.stop_button, fill="#666666")
        self.stop_button_canvas.itemconfig(self.stop_text, fill="#999999")
        self.monitoring_status.config(text="Sniffing Stopped")

    def sync_sniffing_status(self):
        """Sync sniffing status across open screens."""
        if hasattr(self, 'sniffing_status') and self.sniffing_status.winfo_exists():
            if self.sniffing:
                self.sniffing_status.config(text="Sniffing Active")
                self.update_threat_detection()  # Start threat detection if not already running
            else:
                self.sniffing_status.config(text="Sniffing Stopped")

    def sniff_traffic(self):
        """Sniff network traffic continuously until stopped."""
        try:
            sniff(prn=self.analyze_traffic, store=False, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            messagebox.showerror("Sniffing Error", f"An error occurred while sniffing: {e}")
            self.stop_sniffing()

    def analyze_traffic(self, packet):
        """Analyze network traffic and add packet data to the queue."""
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet.sprintf("%IP.proto%")
            length = len(packet)

            # Apply filter rules
            if ip_src in self.filter_rules["IP"] or protocol in self.filter_rules["Protocol"]:
                return  # Skip filtered packets

            # Extract source and destination ports if TCP or UDP
            sport = None
            dport = None
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            # Add packet data to the queue
            self.packet_queue.put((ip_src, ip_dst, sport, dport, length, protocol))

            # Check for sensitive data
            if detect_sensitive_data(packet):
                winsound.Beep(1000, 500)  # Beep sound for sensitive data
                messagebox.showwarning("Sensitive Data Detected", "Potential sensitive data found in the packet!")

            # Intrusion Detection System (IDS) Alert
            if TCP in packet and packet[TCP].flags == 0x12:  # SYN-ACK packet (potential port scan)
                self.packet_queue.put(("ALERT: Port Scan Detected", packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, len(packet), "TCP"))
                winsound.Beep(1500, 500)  # Alert sound

    def update_gui(self):
        """Update the GUI with packet data from the queue."""
        while not self.packet_queue.empty():
            packet_data = self.packet_queue.get()
            ip_src, ip_dst, sport, dport, length, protocol = packet_data

            # Update traffic table
            if hasattr(self, 'traffic_table'):
                row = (len(self.traffic_table.get_children()) + 1, ip_src, ip_dst, sport, dport, length, protocol)
                self.traffic_table.insert("", tk.END, values=row)

            # Update history
            history_entry = f"Source: {ip_src}:{sport} -> Destination: {ip_dst}:{dport} | Protocol: {protocol} | Length: {length}"
            self.history.append(history_entry)
            if hasattr(self, 'history_text'):
                self.history_text.insert(tk.END, history_entry + "\n")
                self.history_text.see(tk.END)

        # Schedule the next GUI update
        if self.sniffing:
            self.root.after(100, self.update_gui)

    def show_monitoring_screen(self):
        """Show the monitoring screen with traffic log and sniffing buttons."""
        monitoring_window = tk.Toplevel(self.root)
        monitoring_window.title("Monitoring")
        monitoring_window.geometry("1200x600")
        monitoring_window.configure(bg="#0A1E2F")
        monitoring_window.attributes('-alpha', 0.95)

        monitoring_frame = tk.Frame(monitoring_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN,
                                    highlightbackground="#FF007A")
        monitoring_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Title
        tk.Label(monitoring_frame, text="Network Traffic Monitoring", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 16, "bold")).pack(pady=5)

        # Traffic Log Table with Scrollbar
        table_frame = tk.Frame(monitoring_frame, bg="#0A1E2F")
        table_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        # Add Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Traffic Log Table
        columns = ("#", "Source IP", "Destination IP", "Source Port", "Destination Port", "Packet Size", "Protocol")
        self.traffic_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=20,
                                          yscrollcommand=scrollbar.set)
        self.traffic_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure Scrollbar
        scrollbar.config(command=self.traffic_table.yview)

        # Set column headings
        for col in columns:
            self.traffic_table.heading(col, text=col, anchor=tk.CENTER)

        # Configure column colors
        style = ttk.Style()
        style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"), background="#FF007A", foreground="#0A1E2F")
        style.configure("Treeview", font=("Helvetica", 11), background="#0A1E2F", foreground="#00FFCC",
                        fieldbackground="#0A1E2F")
        style.map("Treeview", background=[("selected", "#FF007A")], foreground=[("selected", "#0A1E2F")])

        # Set column widths
        self.traffic_table.column("#", width=50, anchor=tk.CENTER)
        self.traffic_table.column("Source IP", width=150, anchor=tk.CENTER)
        self.traffic_table.column("Destination IP", width=150, anchor=tk.CENTER)
        self.traffic_table.column("Source Port", width=100, anchor=tk.CENTER)
        self.traffic_table.column("Destination Port", width=100, anchor=tk.CENTER)
        self.traffic_table.column("Packet Size", width=100, anchor=tk.CENTER)
        self.traffic_table.column("Protocol", width=100, anchor=tk.CENTER)

        # Start and Stop Sniffing Buttons with Animation
        button_frame = tk.Frame(monitoring_frame, bg="#0A1E2F")
        button_frame.pack(pady=10)

        # Start Button
        self.start_button_canvas = tk.Canvas(button_frame, bg="#0A1E2F", highlightthickness=0, width=120, height=40)
        self.start_button_canvas.pack(side=tk.LEFT, padx=5)
        self.start_button = self.start_button_canvas.create_rectangle(0, 0, 120, 40, fill="#FF007A", outline="")
        self.start_text = self.start_button_canvas.create_text(60, 20, text="Start Sniffing", fill="#FFFFFF",
                                                               font=("Helvetica", 12, "bold"))
        self.start_button_canvas.tag_bind(self.start_button, "<Button-1>", lambda e: self.start_sniffing())
        self.start_button_canvas.tag_bind(self.start_text, "<Button-1>", lambda e: self.start_sniffing())
        self.start_button_canvas.tag_bind(self.start_button, "<Enter>",
                                          lambda e: self.start_button_canvas.itemconfig(self.start_button,
                                                                                        fill="#00FFCC"))
        self.start_button_canvas.tag_bind(self.start_text, "<Enter>",
                                          lambda e: self.start_button_canvas.itemconfig(self.start_button,
                                                                                        fill="#00FFCC"))
        self.start_button_canvas.tag_bind(self.start_button, "<Leave>",
                                          lambda e: self.start_button_canvas.itemconfig(self.start_button,
                                                                                        fill="#FF007A"))
        self.start_button_canvas.tag_bind(self.start_text, "<Leave>",
                                          lambda e: self.start_button_canvas.itemconfig(self.start_button,
                                                                                        fill="#FF007A"))
        self.animate_button(self.start_button_canvas, self.start_button)
        self.add_tooltip(self.start_button_canvas, "Begin capturing network traffic")

        # Stop Button (Initially Disabled)
        self.stop_button_canvas = tk.Canvas(button_frame, bg="#0A1E2F", highlightthickness=0, width=120, height=40)
        self.stop_button_canvas.pack(side=tk.LEFT, padx=5)
        self.stop_button = self.stop_button_canvas.create_rectangle(0, 0, 120, 40, fill="#FF007A", outline="")
        self.stop_text = self.stop_button_canvas.create_text(60, 20, text="Stop Sniffing", fill="#FFFFFF",
                                                             font=("Helvetica", 12, "bold"))
        self.stop_button_canvas.tag_bind(self.stop_button, "<Button-1>",
                                         lambda e: self.stop_sniffing() if self.sniffing else None)
        self.stop_button_canvas.tag_bind(self.stop_text, "<Button-1>",
                                         lambda e: self.stop_sniffing() if self.sniffing else None)
        self.stop_button_canvas.tag_bind(self.stop_button, "<Enter>",
                                         lambda e: self.stop_button_canvas.itemconfig(self.stop_button,
                                                                                      fill="#00FFCC") if self.sniffing else None)
        self.stop_button_canvas.tag_bind(self.stop_text, "<Enter>",
                                         lambda e: self.stop_button_canvas.itemconfig(self.stop_button,
                                                                                      fill="#00FFCC") if self.sniffing else None)
        self.stop_button_canvas.tag_bind(self.stop_button, "<Leave>",
                                         lambda e: self.stop_button_canvas.itemconfig(self.stop_button,
                                                                                      fill="#FF007A") if self.sniffing else None)
        self.stop_button_canvas.tag_bind(self.stop_text, "<Leave>",
                                         lambda e: self.stop_button_canvas.itemconfig(self.stop_button,
                                                                                      fill="#FF007A") if self.sniffing else None)
        # Set initial state based on self.sniffing
        if self.sniffing:
            self.start_button_canvas.itemconfig(self.start_button, fill="#666666")
            self.start_button_canvas.itemconfig(self.start_text, fill="#999999")
            self.stop_button_canvas.itemconfig(self.stop_button, fill="#FF007A")
            self.stop_button_canvas.itemconfig(self.stop_text, fill="#FFFFFF")
        else:
            self.stop_button_canvas.itemconfig(self.stop_button, fill="#666666")
            self.stop_button_canvas.itemconfig(self.stop_text, fill="#999999")
        self.animate_button(self.stop_button_canvas, self.stop_button, disabled=not self.sniffing)
        self.add_tooltip(self.stop_button_canvas, "Stop capturing network traffic")

        # Status Bar
        self.monitoring_status = tk.Label(monitoring_frame, text="Ready", bg="#0A1E2F", fg="#00FFCC",
                                          font=("Helvetica", 10, "italic"))
        self.monitoring_status.pack(pady=5)

        # Update status based on current sniffing state
        if self.sniffing:
            self.monitoring_status.config(text="Sniffing Active")
        else:
            self.monitoring_status.config(text="Sniffing Not Active")

        # Override start/stop to update button states and status
        self.start_button_monitoring = self.start_button_canvas
        self.stop_button_monitoring = self.stop_button_canvas

    def show_graph_screen(self):
        """Show the graph screen with enhanced options to visualize network traffic data."""
        if hasattr(self, 'graph_window') and self.graph_window.winfo_exists():
            self.graph_window.lift()
            return

        self.graph_window = tk.Toplevel(self.root)
        self.graph_window.title("Network Traffic Visualization")
        self.graph_window.geometry("900x700")
        self.graph_window.configure(bg="#0A1E2F")
        self.graph_window.attributes('-alpha', 0.95)

        # Main frame with neon border
        graph_frame = tk.Frame(self.graph_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN,
                               highlightbackground="#FF007A")
        graph_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Title
        tk.Label(graph_frame, text="Traffic Analysis Graphs", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 16, "bold")).pack(pady=10)

        # Control frame for graph selection
        control_frame = tk.Frame(graph_frame, bg="#0A1E2F")
        control_frame.pack(pady=10)

        # Enhanced dropdown with descriptive options
        self.graph_options = [
            "Bar Chart - Packet Size by Protocol",
            "Line Chart - Traffic Trend Over Time",
            "Pie Chart - Protocol Distribution"
        ]
        self.graph_var = tk.StringVar(value=self.graph_options[0])
        self.graph_dropdown = ttk.Combobox(control_frame, textvariable=self.graph_var,
                                           values=self.graph_options, font=self.custom_font,
                                           state="readonly", width=30)
        self.graph_dropdown.grid(row=0, column=0, padx=10, pady=5)

        # Animated button
        self.show_graph_button_canvas = tk.Canvas(control_frame, bg="#0A1E2F", highlightthickness=0,
                                                  width=120, height=40)
        self.show_graph_button_canvas.grid(row=0, column=1, padx=10, pady=5)
        self.show_graph_button = self.show_graph_button_canvas.create_rectangle(0, 0, 120, 40,
                                                                                fill="#FF007A", outline="")
        self.show_graph_text = self.show_graph_button_canvas.create_text(60, 20, text="Generate Graph",
                                                                         fill="#FFFFFF",
                                                                         font=("Helvetica", 12, "bold"))
        self.show_graph_button_canvas.tag_bind(self.show_graph_button, "<Button-1>",
                                               lambda e: self.show_selected_graph())
        self.show_graph_button_canvas.tag_bind(self.show_graph_text, "<Button-1>",
                                               lambda e: self.show_selected_graph())
        self.show_graph_button_canvas.tag_bind(self.show_graph_button, "<Enter>",
                                               lambda e: self.show_graph_button_canvas.itemconfig(
                                                   self.show_graph_button,
                                                   fill="#00FFCC"))
        self.show_graph_button_canvas.tag_bind(self.show_graph_text, "<Enter>",
                                               lambda e: self.show_graph_button_canvas.itemconfig(
                                                   self.show_graph_button,
                                                   fill="#00FFCC"))
        self.show_graph_button_canvas.tag_bind(self.show_graph_button, "<Leave>",
                                               lambda e: self.show_graph_button_canvas.itemconfig(
                                                   self.show_graph_button,
                                                   fill="#FF007A"))
        self.show_graph_button_canvas.tag_bind(self.show_graph_text, "<Leave>",
                                               lambda e: self.show_graph_button_canvas.itemconfig(
                                                   self.show_graph_button,
                                                   fill="#FF007A"))
        self.animate_button(self.show_graph_button_canvas, self.show_graph_button)
        self.add_tooltip(self.show_graph_button_canvas, "Generate the selected graph type")

        # Status label
        self.graph_status = tk.Label(graph_frame, text="Ready", bg="#0A1E2F", fg="#00FFCC",
                                     font=("Helvetica", 10, "italic"))
        self.graph_status.pack(pady=5)

        # Initial graph display
        self.show_selected_graph()

    def show_selected_graph(self):
        """Display the selected graph based on the dropdown choice with error handling."""
        if not hasattr(self, 'traffic_table') or not self.traffic_table.get_children():
            self.graph_status.config(text="No traffic data available")
            messagebox.showwarning("No Data", "Please capture some traffic first!")
            return

        try:
            selected_graph = self.graph_var.get()
            self.graph_status.config(text="Generating graph...")
            if "Bar Chart" in selected_graph:
                self.show_bar_chart()
            elif "Line Chart" in selected_graph:
                self.show_line_chart()
            elif "Pie Chart" in selected_graph:
                self.show_pie_chart()
            self.graph_status.config(text="Graph displayed successfully")
        except Exception as e:
            self.graph_status.config(text="Error generating graph")
            messagebox.showerror("Graph Error", f"Failed to generate graph: {e}")

    def show_bar_chart(self):
        """Display an enhanced bar chart for packet size by protocol."""
        try:
            # Aggregate data
            protocol_data = {}
            for child in self.traffic_table.get_children():
                row = self.traffic_table.item(child)['values']
                protocol = row[6]
                packet_size = int(row[5])
                protocol_data[protocol] = protocol_data.get(protocol, 0) + packet_size

            if not protocol_data:
                raise ValueError("No valid data for bar chart")

            labels = list(protocol_data.keys())
            sizes = list(protocol_data.values())

            # Create enhanced bar chart
            fig, ax = plt.subplots(figsize=(10, 6))
            bars = ax.bar(labels, sizes, color="#FF007A", edgecolor="#00FFCC", linewidth=1.5)
            ax.set_title("Packet Size by Protocol", color="#00FFCC", fontsize=14, pad=15)
            ax.set_xlabel("Protocol", color="#00FFCC", fontsize=12)
            ax.set_ylabel("Total Packet Size (Bytes)", color="#00FFCC", fontsize=12)
            ax.tick_params(axis='x', colors="#00FFCC", rotation=45, labelsize=10)
            ax.tick_params(axis='y', colors="#00FFCC", labelsize=10)
            ax.grid(True, axis='y', linestyle='--', alpha=0.3)
            ax.set_facecolor("#0A1E2F")
            fig.patch.set_facecolor("#0A1E2F")
            self.display_chart(fig)

        except Exception as e:
            self.graph_status.config(text="Error in bar chart")
            raise Exception(f"Bar chart error: {e}")

    def show_line_chart(self):
        """Display an enhanced line chart for packet size over time."""
        try:
            packet_sizes = [int(self.traffic_table.item(child)['values'][5])
                            for child in self.traffic_table.get_children()]

            if not packet_sizes:
                raise ValueError("No valid data for line chart")

            # Create enhanced line chart
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.plot(range(len(packet_sizes)), packet_sizes, color="#FF007A", marker="o",
                    linestyle='-', linewidth=2, markersize=6, markeredgecolor="#00FFCC")
            ax.set_title("Traffic Trend Over Time", color="#00FFCC", fontsize=14, pad=15)
            ax.set_xlabel("Packet Sequence", color="#00FFCC", fontsize=12)
            ax.set_ylabel("Packet Size (Bytes)", color="#00FFCC", fontsize=12)
            ax.tick_params(axis='x', colors="#00FFCC", labelsize=10)
            ax.tick_params(axis='y', colors="#00FFCC", labelsize=10)
            ax.grid(True, linestyle='--', alpha=0.3)
            ax.set_facecolor("#0A1E2F")
            fig.patch.set_facecolor("#0A1E2F")
            self.display_chart(fig)

        except Exception as e:
            self.graph_status.config(text="Error in line chart")
            raise Exception(f"Line chart error: {e}")

    def show_pie_chart(self):
        """Display an enhanced pie chart for protocol distribution."""
        try:
            protocol_counts = {}
            for child in self.traffic_table.get_children():
                protocol = self.traffic_table.item(child)['values'][6]
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            if not protocol_counts:
                raise ValueError("No valid data for pie chart")

            labels = list(protocol_counts.keys())
            counts = list(protocol_counts.values())

            # Create enhanced pie chart
            fig, ax = plt.subplots(figsize=(8, 8))
            explode = [0.1] + [0] * (len(counts) - 1)  # Explode first slice
            ax.pie(counts, labels=labels, autopct="%1.1f%%",
                   colors=["#FF007A", "#00FFCC", "#FFD700", "#6B5B95", "#FF4500"],
                   startangle=90, explode=explode, shadow=True, textprops={'color': "#FFFFFF", 'fontsize': 10})
            ax.set_title("Protocol Distribution", color="#00FFCC", fontsize=14, pad=20)
            fig.patch.set_facecolor("#0A1E2F")
            self.display_chart(fig)

        except Exception as e:
            self.graph_status.config(text="Error in pie chart")
            raise Exception(f"Pie chart error: {e}")

    def display_chart(self, fig):
        """Display the chart in a new window with improved handling."""
        if hasattr(self, 'chart_window') and self.chart_window.winfo_exists():
            self.chart_window.destroy()

        self.chart_window = tk.Toplevel(self.graph_window)
        self.chart_window.title("Traffic Visualization")
        self.chart_window.geometry("800x600")
        self.chart_window.configure(bg="#0A1E2F")
        canvas = FigureCanvasTkAgg(fig, master=self.chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def show_profile_screen(self):
        """Show the profile screen with enhanced UI and animations, without picture upload."""
        if hasattr(self, 'profile_window') and self.profile_window.winfo_exists():
            self.profile_window.lift()
            return

        self.profile_window = tk.Toplevel(self.root)
        self.profile_window.title("User Profile")
        self.profile_window.geometry("800x600")
        self.profile_window.configure(bg="#0A1E2F")
        self.profile_window.attributes('-alpha', 0.95)

        # Main frame with neon border
        profile_frame = tk.Frame(self.profile_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN,
                                 highlightbackground="#FF007A", highlightthickness=2)
        profile_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Title
        tk.Label(profile_frame, text="Profile Settings", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 16, "bold")).pack(pady=10)

        # Input fields frame
        input_frame = tk.Frame(profile_frame, bg="#0A1E2F")
        input_frame.pack(pady=10)

        # Name
        self.name_label = tk.Label(input_frame, text="Name:", font=self.custom_font,
                                   fg="#00FFCC", bg="#0A1E2F")
        self.name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.name_entry = ttk.Entry(input_frame, font=self.custom_font, width=30)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5)
        self.add_tooltip(self.name_entry, "Enter your full name")

        # Age
        self.age_label = tk.Label(input_frame, text="Age:", font=self.custom_font,
                                  fg="#00FFCC", bg="#0A1E2F")
        self.age_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.age_entry = ttk.Entry(input_frame, font=self.custom_font, width=30)
        self.age_entry.grid(row=1, column=1, padx=5, pady=5)
        self.add_tooltip(self.age_entry, "Enter your age (numeric)")

        # Email
        self.email_label = tk.Label(input_frame, text="Email:", font=self.custom_font,
                                    fg="#00FFCC", bg="#0A1E2F")
        self.email_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.email_entry = ttk.Entry(input_frame, font=self.custom_font, width=30)
        self.email_entry.grid(row=2, column=1, padx=5, pady=5)
        self.add_tooltip(self.email_entry, "Enter your email address")

        # Phone
        self.phone_label = tk.Label(input_frame, text="Phone:", font=self.custom_font,
                                    fg="#00FFCC", bg="#0A1E2F")
        self.phone_label.grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.phone_entry = ttk.Entry(input_frame, font=self.custom_font, width=30)
        self.phone_entry.grid(row=3, column=1, padx=5, pady=5)
        self.add_tooltip(self.phone_entry, "Enter your phone number")

        # Buttons frame with animations
        button_frame = tk.Frame(profile_frame, bg="#0A1E2F")
        button_frame.pack(pady=20)

        # Update Profile button
        self.update_button_canvas = tk.Canvas(button_frame, bg="#0A1E2F", highlightthickness=0,
                                              width=150, height=40)
        self.update_button_canvas.pack(pady=5)
        self.update_button = self.update_button_canvas.create_rectangle(0, 0, 150, 40, fill="#FF007A", outline="")
        self.update_text = self.update_button_canvas.create_text(75, 20, text="Update Profile",
                                                                 fill="#FFFFFF", font=("Helvetica", 12, "bold"))
        self.update_button_canvas.tag_bind(self.update_button, "<Button-1>", lambda e: self.update_profile())
        self.update_button_canvas.tag_bind(self.update_text, "<Button-1>", lambda e: self.update_profile())
        self.update_button_canvas.tag_bind(self.update_button, "<Enter>",
                                           lambda e: self.update_button_canvas.itemconfig(self.update_button,
                                                                                          fill="#00FFCC"))
        self.update_button_canvas.tag_bind(self.update_text, "<Enter>",
                                           lambda e: self.update_button_canvas.itemconfig(self.update_button,
                                                                                          fill="#00FFCC"))
        self.update_button_canvas.tag_bind(self.update_button, "<Leave>",
                                           lambda e: self.update_button_canvas.itemconfig(self.update_button,
                                                                                          fill="#FF007A"))
        self.update_button_canvas.tag_bind(self.update_text, "<Leave>",
                                           lambda e: self.update_button_canvas.itemconfig(self.update_button,
                                                                                          fill="#FF007A"))
        self.animate_button(self.update_button_canvas, self.update_button)
        self.add_tooltip(self.update_button_canvas, "Save profile changes")

        # Logout button
        self.logout_button_canvas = tk.Canvas(button_frame, bg="#0A1E2F", highlightthickness=0,
                                              width=150, height=40)
        self.logout_button_canvas.pack(pady=5)
        self.logout_button = self.logout_button_canvas.create_rectangle(0, 0, 150, 40, fill="#FF007A", outline="")
        self.logout_text = self.logout_button_canvas.create_text(75, 20, text="Logout",
                                                                 fill="#FFFFFF", font=("Helvetica", 12, "bold"))
        self.logout_button_canvas.tag_bind(self.logout_button, "<Button-1>", lambda e: self.logout())
        self.logout_button_canvas.tag_bind(self.logout_text, "<Button-1>", lambda e: self.logout())
        self.logout_button_canvas.tag_bind(self.logout_button, "<Enter>",
                                           lambda e: self.logout_button_canvas.itemconfig(self.logout_button,
                                                                                          fill="#00FFCC"))
        self.logout_button_canvas.tag_bind(self.logout_text, "<Enter>",
                                           lambda e: self.logout_button_canvas.itemconfig(self.logout_button,
                                                                                          fill="#00FFCC"))
        self.logout_button_canvas.tag_bind(self.logout_button, "<Leave>",
                                           lambda e: self.logout_button_canvas.itemconfig(self.logout_button,
                                                                                          fill="#FF007A"))
        self.logout_button_canvas.tag_bind(self.logout_text, "<Leave>",
                                           lambda e: self.logout_button_canvas.itemconfig(self.logout_button,
                                                                                          fill="#FF007A"))
        self.animate_button(self.logout_button_canvas, self.logout_button)
        self.add_tooltip(self.logout_button_canvas, "Exit the application")

        # Status label
        self.profile_status = tk.Label(profile_frame, text="Ready", bg="#0A1E2F", fg="#00FFCC",
                                       font=("Helvetica", 10, "italic"))
        self.profile_status.pack(pady=10)

        # Load saved profile data when opening the screen
        self.load_profile_from_file()

    def update_profile(self):
        """Update the profile information with validation and save to file."""
        name = self.name_entry.get().strip()
        age = self.age_entry.get().strip()
        email = self.email_entry.get().strip()
        phone = self.phone_entry.get().strip()

        # Validation
        if not all([name, age, email, phone]):
            self.profile_status.config(text="Error: All fields required")
            messagebox.showerror("Validation Error", "Please fill in all fields!")
            return

        if not age.isdigit() or int(age) < 0 or int(age) > 150:
            self.profile_status.config(text="Error: Invalid age")
            messagebox.showerror("Validation Error", "Age must be a number between 0 and 150!")
            return

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            self.profile_status.config(text="Error: Invalid email")
            messagebox.showerror("Validation Error", "Please enter a valid email address!")
            return

        if not re.match(r"^\+?\d{8,15}$", phone):
            self.profile_status.config(text="Error: Invalid phone")
            messagebox.showerror("Validation Error", "Phone number must be 8-15 digits, optionally starting with '+'!")
            return

        # Update profile data
        self.profile_data = {
            "name": name,
            "age": age,
            "email": email,
            "phone": phone
        }

        # Save to file immediately after update
        self.save_profile_to_file()

        self.profile_status.config(text="Profile updated and saved")
        self.update_button_canvas.itemconfig(self.update_button, fill="#FFD700")  # Flash gold on success
        self.root.after(200, lambda: self.update_button_canvas.itemconfig(self.update_button, fill="#FF007A"))
        messagebox.showinfo("Profile Updated",
                            f"Profile updated and saved successfully!\n\nName: {name}\nAge: {age}\nEmail: {email}\nPhone: {phone}")

    def save_profile_to_file(self):
        """Save profile data to a JSON file persistently."""
        profile_file = "profile_data.json"
        try:
            # Ensure profile_data is initialized
            if not hasattr(self, 'profile_data'):
                self.profile_data = {
                    "name": "",
                    "age": "",
                    "email": "",
                    "phone": ""
                }

            with open(profile_file, "w") as f:
                json.dump(self.profile_data, f, indent=4)
            self.profile_status.config(text="Profile saved successfully")
        except Exception as e:
            self.profile_status.config(text=f"Error saving profile: {e}")
            messagebox.showerror("Save Error", f"Failed to save profile: {e}")

    def load_profile_from_file(self):
        """Load profile data from a JSON file and populate fields."""
        profile_file = "profile_data.json"
        try:
            if os.path.exists(profile_file):
                with open(profile_file, "r") as f:
                    self.profile_data = json.load(f)
                    # Ensure all required keys exist
                    for key in ["name", "age", "email", "phone"]:
                        if key not in self.profile_data:
                            self.profile_data[key] = ""
            else:
                # Initialize empty profile if no file exists
                self.profile_data = {
                    "name": "",
                    "age": "",
                    "email": "",
                    "phone": ""
                }

            # Populate fields with loaded or default data
            self.name_entry.delete(0, tk.END)
            self.name_entry.insert(0, self.profile_data["name"])
            self.age_entry.delete(0, tk.END)
            self.age_entry.insert(0, self.profile_data["age"])
            self.email_entry.delete(0, tk.END)
            self.email_entry.insert(0, self.profile_data["email"])
            self.phone_entry.delete(0, tk.END)
            self.phone_entry.insert(0, self.profile_data["phone"])

            self.profile_status.config(text="Profile loaded successfully")
        except Exception as e:
            self.profile_status.config(text=f"Error loading profile: {e}")
            messagebox.showwarning("Load Error", f"Failed to load profile: {e}")
            # Fallback to empty profile on error
            self.profile_data = {
                "name": "",
                "age": "",
                "email": "",
                "phone": ""
            }
            # Populate with empty values
            self.name_entry.delete(0, tk.END)
            self.age_entry.delete(0, tk.END)
            self.email_entry.delete(0, tk.END)
            self.phone_entry.delete(0, tk.END)

    def logout(self):
        """Logout the user with confirmation and ensure profile is saved."""
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout? All changes will be saved."):
            self.profile_status.config(text="Saving profile...")
            # Update profile_data with current entry values before saving
            self.profile_data = {
                "name": self.name_entry.get().strip(),
                "age": self.age_entry.get().strip(),
                "email": self.email_entry.get().strip(),
                "phone": self.phone_entry.get().strip()
            }
            self.save_profile_to_file()
            self.profile_status.config(text="Logging out...")
            self.logout_button_canvas.itemconfig(self.logout_button, fill="#FFD700")  # Flash gold
            self.root.after(200, lambda: [self.profile_window.destroy(), self.root.destroy()])
        else:
            self.profile_status.config(text="Logout cancelled")

    def delete_profile_data(self):
        """Delete the saved profile data file and reset fields."""
        profile_file = "profile_data.json"
        try:
            if os.path.exists(profile_file):
                os.remove(profile_file)
                self.profile_data = {
                    "name": "",
                    "age": "",
                    "email": "",
                    "phone": ""
                }
                # Clear the entry fields
                self.name_entry.delete(0, tk.END)
                self.age_entry.delete(0, tk.END)
                self.email_entry.delete(0, tk.END)
                self.phone_entry.delete(0, tk.END)
                self.profile_status.config(text="Profile data deleted")
                messagebox.showinfo("Profile Deleted", "Saved profile data has been deleted.")
            else:
                self.profile_status.config(text="No profile data to delete")
                messagebox.showinfo("No Data", "There is no saved profile data to delete.")
        except Exception as e:
            self.profile_status.config(text=f"Error deleting profile: {e}")
            messagebox.showerror("Delete Error", f"Failed to delete profile: {e}")

    def show_analysis_screen(self):
        """Show the analysis screen with wave transmission visualization based on packet data."""
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Analysis")
        analysis_window.geometry("800x600")
        analysis_window.configure(bg="#0A1E2F")
        analysis_window.attributes('-alpha', 0.95)

        analysis_frame = tk.Frame(analysis_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN, highlightbackground="#FF007A")
        analysis_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Title
        tk.Label(analysis_frame, text="Wave Transmission Analysis", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 16, "bold")).pack(pady=10)

        # Create a figure and axis for the wave transmission visualization
        self.fig, self.ax = plt.subplots(figsize=(10, 5))
        self.canvas = FigureCanvasTkAgg(self.fig, master=analysis_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Status label
        self.analysis_status = tk.Label(analysis_frame, text="Ready", bg="#0A1E2F", fg="#00FFCC",
                                        font=("Helvetica", 10, "italic"))
        self.analysis_status.pack(pady=5)

        # Start the wave transmission visualization
        self.update_wave_transmission()

    def update_wave_transmission(self):
        """Update the wave transmission visualization based on real-time packet data."""
        try:
            if not hasattr(self, 'traffic_table') or not self.traffic_table.get_children():
                self.ax.clear()
                self.ax.plot([], [], color="#FF007A")  # Empty plot if no data
                self.ax.set_title("Wave Transmission (No Data)", color="#00FFCC")
                self.ax.set_xlabel("Time", color="#00FFCC")
                self.ax.set_ylabel("Packet Size (Bytes)", color="#00FFCC")
                self.ax.tick_params(colors="#00FFCC")
                self.ax.set_facecolor("#0A1E2F")
                self.fig.patch.set_facecolor("#0A1E2F")
                if hasattr(self, 'analysis_status'):
                    self.analysis_status.config(text="No traffic data available")
            else:
                # Use recent packet sizes for visualization
                packet_sizes = [int(self.traffic_table.item(child)['values'][5])
                                for child in self.traffic_table.get_children()][-100:]  # Last 100 packets
                x = np.linspace(0, 2 * np.pi, len(packet_sizes)) if packet_sizes else np.linspace(0, 2 * np.pi, 100)
                y = np.sin(x + time.time()) * (max(packet_sizes) if packet_sizes else 1) if packet_sizes else np.sin(
                    x + time.time())

                self.ax.clear()
                self.ax.plot(x, y, color="#FF007A", linewidth=2)
                self.ax.set_title("Wave Transmission (Packet Size Influence)", color="#00FFCC", fontsize=14)
                self.ax.set_xlabel("Time", color="#00FFCC", fontsize=12)
                self.ax.set_ylabel("Amplitude (Scaled Packet Size)", color="#00FFCC", fontsize=12)
                self.ax.tick_params(colors="#00FFCC")
                self.ax.grid(True, linestyle='--', alpha=0.3)
                self.ax.set_facecolor("#0A1E2F")
                self.fig.patch.set_facecolor("#0A1E2F")
                if hasattr(self, 'analysis_status'):
                    self.analysis_status.config(
                        text="Visualizing packet data" if self.sniffing else "Displaying last captured data")

            self.canvas.draw()
        except Exception as e:
            if hasattr(self, 'analysis_status'):
                self.analysis_status.config(text=f"Error: {e}")
            print(f"Wave transmission update error: {e}")

        # Schedule the next update
        self.root.after(100, self.update_wave_transmission)

    def show_progress_bar(self):
        """Show the progress bar as a loading bar for the sniffer with enhanced UI."""
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Sniffing Progress")
        progress_window.geometry("400x100")
        progress_window.configure(bg="#0A1E2F")
        progress_window.attributes('-alpha', 0.95)

        progress_frame = tk.Frame(progress_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN, highlightbackground="#FF007A")
        progress_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        self.progress_label = tk.Label(progress_frame, text="Sniffing Progress", font=self.custom_font,
                                       fg="#00FFCC", bg="#0A1E2F")
        self.progress_label.pack()

        # Style the progress bar with theme colors
        style = ttk.Style()
        style.configure("Sniffer.Horizontal.TProgressbar", troughcolor="#0A1E2F", background="#FF007A",
                        bordercolor="#00FFCC")
        self.progress_bar_sniffer = ttk.Progressbar(progress_frame, orient="horizontal", length=300,
                                                    mode="determinate", style="Sniffer.Horizontal.TProgressbar")
        self.progress_bar_sniffer.pack(pady=5)

        # Initial value based on sniffing state
        self.progress_bar_sniffer["value"] = 0
        if self.sniffing:
            self.progress_bar_sniffer["value"] = 10  # Start with a small value when sniffing

        # Update progress bar dynamically
        self.update_progress_bar_sniffer()

    def update_progress_bar_sniffer(self):
        """Update the progress bar dynamically based on sniffing activity and packet count."""
        if self.sniffing:
            # Increment based on packet queue size or a fixed rate
            if not self.packet_queue.empty():
                increment = min(self.packet_queue.qsize(), 10)  # Cap increment to avoid overflow
                self.progress_bar_sniffer["value"] += increment
            else:
                self.progress_bar_sniffer["value"] += 1  # Slow increment when no packets

            if self.progress_bar_sniffer["value"] >= 100:
                self.progress_bar_sniffer["value"] = 0  # Reset to loop
            self.progress_label.config(text=f"Sniffing Progress: {int(self.progress_bar_sniffer['value'])}%")
        else:
            self.progress_bar_sniffer["value"] = 0
            self.progress_label.config(text="Sniffing Progress: Idle")

        # Schedule the next update
        self.root.after(100, self.update_progress_bar_sniffer)

    def save_captured_packets(self):
        """Save captured packets to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(
                    ["#", "Source IP", "Destination IP", "Source Port", "Destination Port", "Packet Size",
                     "Protocol"])
                for child in self.traffic_table.get_children():
                    row = self.traffic_table.item(child)['values']
                    writer.writerow(row)
            messagebox.showinfo("Save Successful", f"Captured packets saved to {file_path}")

    def show_history_screen(self):
        """Show the history screen and update it in real-time with enhanced UI."""
        history_window = tk.Toplevel(self.root)
        history_window.title("Sniffing History")
        history_window.geometry("800x600")
        history_window.configure(bg="#0A1E2F")
        history_window.attributes('-alpha', 0.95)

        # Main frame with neon border
        history_frame = tk.Frame(history_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN, highlightbackground="#FF007A")
        history_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Title
        self.history_label = tk.Label(history_frame, text="Sniffing History", font=self.custom_font, fg="#00FFCC",
                                      bg="#0A1E2F")
        self.history_label.pack(pady=5)

        # ScrolledText for history display
        self.history_text = scrolledtext.ScrolledText(history_frame, width=90, height=30, font=("Courier New", 12),
                                                      fg="#00FFCC", bg="#0A1E2F", insertbackground="#00FFCC",
                                                      wrap=tk.WORD)
        self.history_text.pack(pady=10)

        # Status label
        self.history_status = tk.Label(history_frame, text="Displaying history", bg="#0A1E2F", fg="#00FFCC",
                                       font=("Helvetica", 10, "italic"))
        self.history_status.pack(pady=5)

        # Enable hacker mode if active
        self.enable_hacker_mode(history_window)

        # Display existing history entries
        for entry in self.history:
            self.history_text.insert(tk.END, entry + "\n")
        self.history_text.see(tk.END)  # Scroll to the end

        # Start real-time update
        self.update_history_real_time()

    def update_history_real_time(self):
        """Update the history screen in real-time while sniffing."""
        if self.sniffing and hasattr(self, 'history_text'):
            # Check if new entries have been added to self.history
            current_text = self.history_text.get(1.0, tk.END).strip()
            current_entries = current_text.split("\n") if current_text else []
            if len(self.history) > len(current_entries):
                new_entries = self.history[len(current_entries):]
                for entry in new_entries:
                    self.history_text.insert(tk.END, entry + "\n")
                self.history_text.see(tk.END)
                self.history_status.config(text=f"Updated: {len(self.history)} entries")

        # Schedule the next update
        self.root.after(500, self.update_history_real_time)  # Slower update rate to reduce CPU load

    def enable_hacker_mode(self, window):
        """Enable hacker mode with an optimized matrix-like animation."""
        if not self.hacker_mode:
            return

        self.matrix_canvas = tk.Canvas(window, bg="#0A1E2F", highlightthickness=0)
        self.matrix_canvas.place(x=0, y=0, relwidth=1, relheight=1)

        # Move canvas behind other widgets
        self.matrix_canvas.lower()

        self.matrix_text = []  # List of (char, x, y, speed) tuples
        self.matrix_columns = max(50,
                                  int(window.winfo_screenwidth() / 20))  # Dynamic column count based on screen width
        self.matrix_speed = 50  # Base speed in milliseconds
        self.create_matrix_effect()

    def create_matrix_effect(self):
        """Create an optimized matrix-like falling text effect."""
        if not self.hacker_mode or not self.matrix_canvas:
            return

        self.matrix_canvas.delete("all")
        screen_height = self.matrix_canvas.winfo_height() or 600  # Use actual height or default

        # Update existing drops
        for i in range(len(self.matrix_text) - 1, -1, -1):
            char, x, y, speed = self.matrix_text[i]
            y += speed  # Move down based on speed
            fade = max(0.3, 1.0 - y / screen_height)  # Fade effect as it falls
            self.matrix_canvas.create_text(x, y, text=char, fill=f"#00FFCC{int(fade * 255):02x}",
                                           font=("Courier New", 10), anchor=tk.NW)

            if y > screen_height:
                self.matrix_text.pop(i)  # Remove drops that fall off screen
            else:
                self.matrix_text[i] = (char, x, y, speed)

        # Add new drops if below column limit
        while len(self.matrix_text) < self.matrix_columns and random.random() < 0.2:  # Probabilistic spawning
            x = random.randint(0, self.matrix_canvas.winfo_width() or 800) // 10 * 10  # Snap to grid
            speed = random.uniform(5, 15)  # Random speed for variety
            self.matrix_text.append((self.generate_random_char(), x, -20, speed))

        # Schedule the next update
        self.root.after(self.matrix_speed, self.create_matrix_effect)

    def generate_random_char(self):
        """Generate random characters for the matrix effect, favoring hacker-like symbols."""
        # Bias towards numbers, letters, and hacker-style symbols
        chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?"
        return random.choice(chars)

    def toggle_theme(self):
        """Toggle between Cyberpunk, Dark, and Classic themes with visual feedback."""
        themes = list(self.theme_colors.keys())
        current_index = themes.index(self.theme)
        next_index = (current_index + 1) % len(themes)
        self.theme = themes[next_index]
        self.apply_theme()

        # Visual feedback
        self.theme_icon.config(fg="#FFD700")  # Flash gold
        self.root.after(200, lambda: self.theme_icon.config(fg=self.theme_colors[self.theme]["accent"]))

    def apply_theme(self):
        """Apply the selected theme to the UI comprehensively."""
        colors = self.theme_colors[self.theme]

        # Root and taskbar
        self.root.configure(bg=colors["bg"])
        self.taskbar.configure(bg=colors["bg"])
        for widget in self.taskbar.winfo_children():
            widget.configure(bg=colors["bg"], fg=colors["accent"])

        # Update history screen if open
        if hasattr(self, 'history_text') and self.history_text.winfo_exists():
            self.history_text.configure(bg=colors["bg"], fg=colors["fg"], insertbackground=colors["accent"])
            self.history_label.configure(bg=colors["bg"], fg=colors["fg"])
            self.history_status.configure(bg=colors["bg"], fg=colors["fg"])
            self.history_text.master.configure(bg=colors["bg"])  # Update frame

        # Update matrix effect color if active
        if hasattr(self, 'matrix_canvas') and self.matrix_canvas.winfo_exists():
            self.matrix_canvas.configure(bg=colors["bg"])

    def show_encryption_screen(self):
        """Show the encryption/decryption screen with advanced functionality."""
        encryption_window = tk.Toplevel(self.root)
        encryption_window.title("Advanced Encryption/Decryption")
        encryption_window.geometry("600x600")
        encryption_window.configure(bg="#0A1E2F")
        encryption_window.attributes('-alpha', 0.95)

        encryption_frame = tk.Frame(encryption_window, bg="#0A1E2F")
        encryption_frame.pack(pady=20)

        # Key Management Section
        key_frame = tk.Frame(encryption_frame, bg="#0A1E2F")
        key_frame.pack(pady=10)

        tk.Label(key_frame, text="Key Management", bg="#0A1E2F", fg="#00FFCC", font=("Helvetica", 14, "bold")).pack()

        ttk.Button(key_frame, text="Generate Key", command=self.generate_key, style="TButton").pack(side=tk.LEFT,
                                                                                                    padx=5)
        ttk.Button(key_frame, text="Save Key", command=self.save_key, style="TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="Load Key", command=self.load_key, style="TButton").pack(side=tk.LEFT, padx=5)

        # Algorithm and Key Size Selection
        algorithm_frame = tk.Frame(encryption_frame, bg="#0A1E2F")
        algorithm_frame.pack(pady=10)

        tk.Label(algorithm_frame, text="Encryption Algorithm", bg="#0A1E2F", fg="#00FFCC").pack()
        self.algorithm_var = tk.StringVar(value="AES")  # Default algorithm
        ttk.Combobox(algorithm_frame, textvariable=self.algorithm_var, values=["AES", "DES", "RSA"],
                     state="readonly").pack()

        tk.Label(algorithm_frame, text="Key Size (Bits)", bg="#0A1E2F", fg="#00FFCC").pack()
        self.key_size_var = tk.StringVar(value="256")  # Default key size
        ttk.Combobox(algorithm_frame, textvariable=self.key_size_var, values=["128", "192", "256"],
                     state="readonly").pack()

        # Text Encryption/Decryption Section
        text_frame = tk.Frame(encryption_frame, bg="#0A1E2F")
        text_frame.pack(pady=10)

        tk.Label(text_frame, text="Text Encryption/Decryption", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 14, "bold")).pack()

        tk.Label(text_frame, text="Enter Text:", bg="#0A1E2F", fg="#00FFCC").pack()
        self.encrypt_entry = ttk.Entry(text_frame, width=50)
        self.encrypt_entry.pack()

        ttk.Button(text_frame, text="Encrypt Text", command=self.encrypt_data, style="TButton").pack(pady=5)
        ttk.Button(text_frame, text="Decrypt Text", command=self.decrypt_data, style="TButton").pack(pady=5)

        tk.Label(text_frame, text="Encrypted Text:", bg="#0A1E2F", fg="#00FFCC").pack()
        self.encrypted_text = tk.Text(text_frame, height=4, width=50, bg="#0A1E2F", fg="#00FFCC")
        self.encrypted_text.pack()

        tk.Label(text_frame, text="Decrypted Text:", bg="#0A1E2F", fg="#00FFCC").pack()
        self.decrypted_text = tk.Text(text_frame, height=4, width=50, bg="#0A1E2F", fg="#00FFCC")
        self.decrypted_text.pack()

        # File Encryption/Decryption Section
        file_frame = tk.Frame(encryption_frame, bg="#0A1E2F")
        file_frame.pack(pady=10)

        tk.Label(file_frame, text="File Encryption/Decryption", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 14, "bold")).pack()

        ttk.Button(file_frame, text="Encrypt File", command=self.encrypt_file, style="TButton").pack(side=tk.LEFT,
                                                                                                     padx=5)
        ttk.Button(file_frame, text="Decrypt File", command=self.decrypt_file, style="TButton").pack(side=tk.LEFT,
                                                                                                     padx=5)

        # Status Bar
        self.status_label = tk.Label(encryption_frame, text="Ready", bg="#0A1E2F", fg="#00FFCC", font=("Helvetica", 10))
        self.status_label.pack(pady=10)

    def generate_key(self):
        """Generate a new encryption key based on selected algorithm and key size."""
        algorithm = self.algorithm_var.get()
        key_size = int(self.key_size_var.get())

        if algorithm == "AES":
            self.encryption_key = os.urandom(key_size // 8)  # Generate key in bytes
        elif algorithm == "DES":
            self.encryption_key = os.urandom(8)  # DES uses 56-bit keys (8 bytes)
        elif algorithm == "RSA":
            from Crypto.PublicKey import RSA
            key = RSA.generate(key_size)
            self.encryption_key = key.export_key()  # Export RSA key
        else:
            messagebox.showerror("Error", "Unsupported algorithm selected.")
            return

        self.status_label.config(text=f"Key generated for {algorithm} ({key_size}-bit).")

    def save_key(self):
        """Save the encryption key to a file."""
        if not self.encryption_key:
            messagebox.showerror("Error", "No encryption key generated yet.")
            return

        key_file = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if key_file:
            with open(key_file, "wb") as f:
                f.write(self.encryption_key)
            self.status_label.config(text=f"Key saved to {key_file}.")

    def load_key(self):
        """Load an encryption key from a file."""
        key_file = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if key_file:
            with open(key_file, "rb") as f:
                self.encryption_key = f.read()
            self.status_label.config(text=f"Key loaded from {key_file}.")

    def encrypt_data(self):
        """Encrypt the entered text."""
        if not self.encryption_key:
            messagebox.showerror("Error", "No encryption key loaded.")
            return

        data = self.encrypt_entry.get()
        if data:
            try:
                encrypted_data = self.encrypt_data_aes(data)
                self.encrypted_text.delete(1.0, tk.END)
                self.encrypted_text.insert(tk.END, encrypted_data)
                self.status_label.config(text="Text encrypted successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        else:
            messagebox.showerror("Error", "Please enter text to encrypt!")

    def decrypt_data(self):
        """Decrypt the entered text."""
        if not self.encryption_key:
            messagebox.showerror("Error", "No encryption key loaded.")
            return

        encrypted_data = self.encrypted_text.get(1.0, tk.END).strip()
        if encrypted_data:
            try:
                decrypted_data = self.decrypt_data_aes(encrypted_data)
                self.decrypted_text.delete(1.0, tk.END)
                self.decrypted_text.insert(tk.END, decrypted_data)
                self.status_label.config(text="Text decrypted successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            messagebox.showerror("Error", "Please enter encrypted text to decrypt!")

    def encrypt_file(self):
        """Encrypt a file."""
        if not self.encryption_key:
            messagebox.showerror("Error", "No encryption key loaded.")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    data = f.read()

                encrypted_data = self.encrypt_data_aes(data.decode())
                save_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                         filetypes=[("Encrypted Files", "*.enc")])
                if save_path:
                    with open(save_path, "w") as f:
                        f.write(encrypted_data)
                    self.status_label.config(text=f"File encrypted and saved to {save_path}.")
            except Exception as e:
                messagebox.showerror("Error", f"File encryption failed: {e}")

    def decrypt_file(self):
        """Decrypt a file."""
        if not self.encryption_key:
            messagebox.showerror("Error", "No encryption key loaded.")
            return

        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if file_path:
            try:
                with open(file_path, "r") as f:
                    encrypted_data = f.read()

                decrypted_data = self.decrypt_data_aes(encrypted_data)
                save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
                if save_path:
                    with open(save_path, "w") as f:
                        f.write(decrypted_data)
                    self.status_label.config(text=f"File decrypted and saved to {save_path}.")
            except Exception as e:
                messagebox.showerror("Error", f"File decryption failed: {e}")

    def encrypt_data_aes(self, data):
        """Encrypt data using AES."""
        cipher = AES.new(self.encryption_key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(encrypted_data).decode()

    def decrypt_data_aes(self, encrypted_data):
        """Decrypt data using AES."""
        cipher = AES.new(self.encryption_key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
        return decrypted_data.decode()

    def show_filter_screen(self):
        """Show the packet filtering screen with modern UI and animated effects."""
        filter_window = tk.Toplevel(self.root)
        filter_window.title("Packet Filtering")
        filter_window.geometry("400x300")
        filter_window.configure(bg="#0A1E2F")  # Neon theme background
        filter_window.attributes('-alpha', 0.95)  # Slight transparency for futuristic feel

        # Main Frame with Gradient Background
        filter_frame = tk.Frame(filter_window, bg="#0A1E2F", bd=2, relief=tk.SUNKEN, highlightbackground="#FF007A")
        filter_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Title
        tk.Label(filter_frame, text="Packet Filter Settings", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 16, "bold")).pack(pady=5)

        # IP Address Filter
        tk.Label(filter_frame, text="IP Address:", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 12, "bold")).pack(pady=2)
        self.ip_filter_entry = ttk.Entry(filter_frame, width=25, font=("Helvetica", 10))
        self.ip_filter_entry.pack()
        self.add_tooltip(self.ip_filter_entry, "Enter an IP address to filter (e.g., 192.168.1.1)")

        # Protocol Filter
        tk.Label(filter_frame, text="Protocol:", bg="#0A1E2F", fg="#00FFCC",
                 font=("Helvetica", 12, "bold")).pack(pady=2)
        self.protocol_filter_entry = ttk.Entry(filter_frame, width=25, font=("Helvetica", 10))
        self.protocol_filter_entry.pack()
        self.add_tooltip(self.protocol_filter_entry, "Enter a protocol to filter (e.g., TCP, UDP)")

        # Animated Add Filter Button
        self.add_button_canvas = tk.Canvas(filter_frame, bg="#0A1E2F", highlightthickness=0, width=120, height=40)
        self.add_button_canvas.pack(pady=10)
        self.add_button = self.add_button_canvas.create_rectangle(0, 0, 120, 40, fill="#FF007A", outline="")
        self.add_text = self.add_button_canvas.create_text(60, 20, text="Add Filter", fill="#FFFFFF",
                                                           font=("Helvetica", 12, "bold"))
        self.add_button_canvas.tag_bind(self.add_button, "<Button-1>", lambda e: self.add_filter())
        self.add_button_canvas.tag_bind(self.add_text, "<Button-1>", lambda e: self.add_filter())
        self.add_button_canvas.tag_bind(self.add_button, "<Enter>",
                                        lambda e: self.add_button_canvas.itemconfig(self.add_button, fill="#00FFCC"))
        self.add_button_canvas.tag_bind(self.add_text, "<Enter>",
                                        lambda e: self.add_button_canvas.itemconfig(self.add_button, fill="#00FFCC"))
        self.add_button_canvas.tag_bind(self.add_button, "<Leave>",
                                        lambda e: self.add_button_canvas.itemconfig(self.add_button, fill="#FF007A"))
        self.add_button_canvas.tag_bind(self.add_text, "<Leave>",
                                        lambda e: self.add_button_canvas.itemconfig(self.add_button, fill="#FF007A"))
        self.animate_button(self.add_button_canvas, self.add_button)  # Start button animation

        # Status Bar
        self.filter_status = tk.Label(filter_frame, text="Ready", bg="#0A1E2F", fg="#00FFCC",
                                      font=("Helvetica", 10, "italic"))
        self.filter_status.pack(pady=5)

    def add_filter(self):
        """Add a filter rule with validation and feedback."""
        ip = self.ip_filter_entry.get().strip()
        protocol = self.protocol_filter_entry.get().strip()

        # Basic IP Validation
        ip_valid = False
        if ip:
            try:
                parts = ip.split('.')
                if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                    self.filter_rules["IP"].append(ip)
                    ip_valid = True
            except ValueError:
                messagebox.showerror("Invalid IP", "Please enter a valid IP address (e.g., 192.168.1.1)")
                return

        # Protocol Validation (simple check for common protocols)
        protocol_valid = False
        if protocol:
            valid_protocols = ["TCP", "UDP", "HTTP", "HTTPS", "ICMP"]
            if protocol.upper() in valid_protocols:
                self.filter_rules["Protocol"].append(protocol.upper())
                protocol_valid = True
            else:
                messagebox.showerror("Invalid Protocol", "Please enter a valid protocol (e.g., TCP, UDP)")
                return

        if ip_valid or protocol_valid:
            self.filter_status.config(text="Adding filter...")
            self.add_button_canvas.itemconfig(self.add_button, fill="#FFD700")  # Flash gold on click
            self.root.after(200, lambda: self.add_button_canvas.itemconfig(self.add_button, fill="#FF007A"))  # Reset
            self.root.after(400, lambda: self.filter_status.config(
                text=f"Filter added: IP={ip or 'None'}, Protocol={protocol or 'None'}"))
            messagebox.showinfo("Filter Added",
                                f"Filter rules updated:\nIP: {self.filter_rules['IP']}\nProtocol: {self.filter_rules['Protocol']}")
            self.ip_filter_entry.delete(0, tk.END)
            self.protocol_filter_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("No Filter", "Please enter at least one filter criterion (IP or Protocol)")

# Main Entry Point
if __name__ == "__main__":
    root = tk.Tk()
    app = Joystra_App(root)
    root.mainloop()