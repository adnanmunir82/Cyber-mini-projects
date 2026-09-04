import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import threading
import queue
from datetime import datetime
from collections import Counter

from packet_sniffer_core import list_interfaces, capture_packets, parse_packet, get_layer_breakdown

APP_NAME = "Adnan's Network Packet Sniffer"
DB_FILE = "sniffer_history.db"

PROTOCOL_COLORS = {
    "TCP": "#2980b9",
    "UDP": "#27ae60",
    "ICMP": "#e67e22",
    "ARP": "#8e44ad",
}


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_capture(interface, packet_count):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO captures (interface, packet_count, timestamp) VALUES (?, ?, ?)",
                (interface, packet_count, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("700x750")
        self.root.resizable(False, False)

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.dark_mode = False
        self.colors = self.colors_light

        self.packet_queue = queue.Queue()
        self.error_queue = queue.Queue()
        self.raw_packets = {}  # tree_item_id -> raw scapy packet, for the inspector
        self.capture_thread = None
        self.is_capturing = False
        self.packet_count = 0

        init_db()
        self.build_ui()
        self.poll_queue()

    def build_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.configure(bg=self.colors["bg"])

        top_bar = tk.Frame(self.root, bg=self.colors["bg"])
        top_bar.pack(fill="x", pady=(10, 0), padx=15)
        tk.Label(top_bar, text=APP_NAME, font=("Segoe UI", 13, "bold"),
                 bg=self.colors["bg"], fg=self.colors["fg"]).pack(side="left")
        tk.Button(top_bar, text="🌙 Dark Mode", command=self.toggle_theme, font=("Segoe UI", 9)).pack(side="right")

        disclaimer = tk.Label(
            self.root,
            text="⚠ LEGAL NOTICE: Only capture traffic on networks and devices you own or\n"
                 "have explicit written authorization to monitor. Intercepting network traffic\n"
                 "without permission is illegal in most jurisdictions. This tool is for learning\n"
                 "on your own machine/network only.",
            font=("Segoe UI", 8, "bold"), fg="#c0392b", bg=self.colors["bg"], justify="center"
        )
        disclaimer.pack(pady=(5, 5))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=5)

        self.capture_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.stats_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.history_tab = tk.Frame(self.notebook, bg=self.colors["card"])

        self.notebook.add(self.capture_tab, text="Capture")
        self.notebook.add(self.stats_tab, text="Statistics")
        self.notebook.add(self.history_tab, text="History")

        self.build_capture_tab()
        self.build_stats_tab()
        self.build_history_tab()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()

    # ---------- Capture tab ----------

    def build_capture_tab(self):
        f = self.capture_tab

        form = tk.Frame(f, bg=self.colors["card"])
        form.pack(pady=10, fill="x", padx=15)

        tk.Label(form, text="Interface:", bg=self.colors["card"], fg=self.colors["fg"]).grid(row=0, column=0, sticky="w")
        interfaces = list_interfaces()
        self.interface_var = tk.StringVar(value=interfaces[0] if interfaces else "")
        ttk.Combobox(form, textvariable=self.interface_var, values=interfaces, width=20, state="readonly").grid(
            row=0, column=1, padx=(5, 20))

        tk.Label(form, text="Protocol filter:", bg=self.colors["card"], fg=self.colors["fg"]).grid(row=0, column=2, sticky="w")
        self.protocol_var = tk.StringVar(value="All")
        ttk.Combobox(form, textvariable=self.protocol_var, values=["All", "TCP", "UDP", "ICMP", "ARP"],
                     width=10, state="readonly").grid(row=0, column=3, padx=5)

        tk.Label(form, text="IP filter (optional):", bg=self.colors["card"], fg=self.colors["fg"]).grid(
            row=1, column=0, sticky="w", pady=(10, 0))
        self.ip_filter_entry = tk.Entry(form, width=18)
        self.ip_filter_entry.grid(row=1, column=1, sticky="w", pady=(10, 0), padx=(5, 20))

        tk.Label(form, text="Max packets:", bg=self.colors["card"], fg=self.colors["fg"]).grid(
            row=1, column=2, sticky="w", pady=(10, 0))
        self.count_var = tk.IntVar(value=50)
        tk.Spinbox(form, from_=1, to=1000, textvariable=self.count_var, width=8).grid(
            row=1, column=3, pady=(10, 0), padx=5)

        btn_row = tk.Frame(f, bg=self.colors["card"])
        btn_row.pack(pady=10)
        self.start_btn = tk.Button(btn_row, text="Start Capture", command=self.handle_start,
                                    font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=15)
        self.start_btn.pack(side="left", padx=5)
        tk.Button(btn_row, text="Export Summary", command=self.handle_export,
                  font=("Segoe UI", 10), width=15).pack(side="left", padx=5)

        self.status_label = tk.Label(f, text="Ready", font=("Segoe UI", 9, "bold"),
                                      bg=self.colors["card"], fg="#7f8c8d")
        self.status_label.pack(pady=5)

        columns = ("time", "src", "dst", "protocol", "port", "size")
        self.packet_tree = ttk.Treeview(f, columns=columns, show="headings", height=15)
        widths = (70, 130, 130, 70, 80, 60)
        for col, width in zip(columns, widths):
            self.packet_tree.heading(col, text=col.capitalize())
            self.packet_tree.column(col, width=width)
        self.packet_tree.pack(padx=15, pady=10, fill="both", expand=True)
        self.packet_tree.bind("<Double-Button-1>", self.show_packet_detail)

        for proto, color in PROTOCOL_COLORS.items():
            self.packet_tree.tag_configure(proto, foreground=color)

    def handle_start(self):
        try:
            self._do_start()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_start(self):
        if self.is_capturing:
            return

        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("No interface", "No network interface selected.")
            return

        for row in self.packet_tree.get_children():
            self.packet_tree.delete(row)
        self.raw_packets.clear()
        self.packet_count = 0
        self.captured_protocol_counts = Counter()
        self.captured_ip_counts = Counter()

        from packet_sniffer_core import build_bpf_filter
        bpf = build_bpf_filter(self.protocol_var.get(), self.ip_filter_entry.get().strip())

        self.is_capturing = True
        self.start_btn.config(state="disabled", text="Capturing...")
        self.status_label.config(text=f"Capturing on {interface}...")
        self.current_interface = interface

        def on_packet(pkt):
            self.packet_queue.put(pkt)

        def on_error(msg):
            self.error_queue.put(msg)

        self.capture_thread = threading.Thread(
            target=capture_packets,
            kwargs=dict(
                interface=interface, count=self.count_var.get(), timeout=30,
                bpf_filter=bpf, on_packet=on_packet, on_error=on_error
            ),
            daemon=True
        )
        self.capture_thread.start()

    def poll_queue(self):
        try:
            while True:
                pkt = self.packet_queue.get_nowait()
                info = parse_packet(pkt)
                self.packet_count += 1
                self.captured_protocol_counts[info["protocol"]] += 1
                if info["src"] != "-":
                    self.captured_ip_counts[info["src"]] += 1

                tag = info["protocol"] if info["protocol"] in PROTOCOL_COLORS else ""
                item_id = self.packet_tree.insert(
                    "", "end",
                    values=(info["timestamp"], info["src"], info["dst"], info["protocol"],
                            info["dst_port"], info["size"]),
                    tags=(tag,)
                )
                self.raw_packets[item_id] = pkt
                self.status_label.config(text=f"Capturing... {self.packet_count} packets so far")
        except queue.Empty:
            pass

        try:
            while True:
                err = self.error_queue.get_nowait()
                self.status_label.config(text=f"Note: {err}")
        except queue.Empty:
            pass

        if self.is_capturing and self.capture_thread is not None and not self.capture_thread.is_alive():
            self.is_capturing = False
            self.start_btn.config(state="normal", text="Start Capture")
            self.status_label.config(text=f"Capture complete — {self.packet_count} packets captured")
            log_capture(self.current_interface, self.packet_count)
            self.refresh_history()
            self.refresh_stats()

        self.root.after(150, self.poll_queue)

    def show_packet_detail(self, event):
        selected = self.packet_tree.selection()
        if not selected:
            return
        item_id = selected[0]
        pkt = self.raw_packets.get(item_id)
        if pkt is None:
            return

        win = tk.Toplevel(self.root)
        win.title("Packet Detail")
        win.geometry("500x450")
        text = tk.Text(win, font=("Consolas", 9), wrap="word")
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.insert("1.0", get_layer_breakdown(pkt))
        text.config(state="disabled")

    def handle_export(self):
        if self.packet_count == 0:
            messagebox.showinfo("Nothing to export", "Run a capture first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="capture_summary.txt")
        if not path:
            return
        with open(path, "w") as f:
            f.write(f"Packet Capture Summary — {self.current_interface}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total packets: {self.packet_count}\n\n")
            f.write("Protocol breakdown:\n")
            for proto, count in self.captured_protocol_counts.most_common():
                f.write(f"  {proto}: {count}\n")
            f.write("\nTop source IPs:\n")
            for ip, count in self.captured_ip_counts.most_common(10):
                f.write(f"  {ip}: {count} packets\n")
        messagebox.showinfo("Exported", f"Summary saved to:\n{path}")

    # ---------- Stats tab ----------

    def build_stats_tab(self):
        f = self.stats_tab
        tk.Label(f, text="Traffic Statistics (Last Capture)", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        self.stats_container = tk.Frame(f, bg=self.colors["card"])
        self.stats_container.pack(fill="both", expand=True, padx=20)
        self.refresh_stats()

    def refresh_stats(self):
        if not hasattr(self, "stats_container"):
            return
        for widget in self.stats_container.winfo_children():
            widget.destroy()

        if not hasattr(self, "captured_protocol_counts") or not self.captured_protocol_counts:
            tk.Label(self.stats_container, text="No capture data yet. Run a capture first.",
                     bg=self.colors["card"], fg="#7f8c8d").pack(pady=20)
            return

        tk.Label(self.stats_container, text=f"Total packets: {self.packet_count}",
                 font=("Segoe UI", 11, "bold"), bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(10, 15))

        tk.Label(self.stats_container, text="By Protocol", font=("Segoe UI", 10, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w")
        for proto, count in self.captured_protocol_counts.most_common():
            pct = (count / self.packet_count) * 100
            row = tk.Frame(self.stats_container, bg=self.colors["card"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=proto, width=10, anchor="w", bg=self.colors["card"],
                     fg=PROTOCOL_COLORS.get(proto, self.colors["fg"])).pack(side="left")
            tk.Label(row, text=f"{count} ({pct:.1f}%)", bg=self.colors["card"], fg=self.colors["fg"]).pack(side="left")

        tk.Label(self.stats_container, text="Top Source IPs", font=("Segoe UI", 10, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", pady=(20, 5))
        for ip, count in self.captured_ip_counts.most_common(8):
            row = tk.Frame(self.stats_container, bg=self.colors["card"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=ip, width=18, anchor="w", bg=self.colors["card"], fg=self.colors["fg"]).pack(side="left")
            tk.Label(row, text=f"{count} packets", bg=self.colors["card"], fg="#7f8c8d").pack(side="left")

    # ---------- History tab ----------

    def build_history_tab(self):
        f = self.history_tab
        tk.Label(f, text="Capture History", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("interface", "packet_count", "timestamp")
        self.history_tree = ttk.Treeview(f, columns=columns, show="headings", height=16)
        for col, width in zip(columns, (150, 120, 160)):
            self.history_tree.heading(col, text=col.replace("_", " ").title())
            self.history_tree.column(col, width=width)
        self.history_tree.pack(padx=15, pady=5, fill="both", expand=True)

        tk.Button(f, text="Refresh", command=self.refresh_history, font=("Segoe UI", 9)).pack(pady=5)
        self.refresh_history()

    def refresh_history(self):
        if not hasattr(self, "history_tree"):
            return
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT interface, packet_count, timestamp FROM captures ORDER BY id DESC LIMIT 50")
        for row in cur.fetchall():
            self.history_tree.insert("", "end", values=row)
        conn.close()


if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()