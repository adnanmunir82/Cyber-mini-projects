import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import threading
import queue
import time
from datetime import datetime

from port_scanner_core import (
    scan_ports_threaded, parse_port_range, resolve_target, TOP_PORTS
)

APP_NAME = "Adnan's Port Scanner"
DB_FILE = "scan_history.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            ports_scanned INTEGER NOT NULL,
            open_ports_found INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_scan(target, ports_scanned, open_ports_found):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (target, ports_scanned, open_ports_found, timestamp) VALUES (?, ?, ?, ?)",
                (target, ports_scanned, open_ports_found, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("680x720")
        self.root.resizable(False, False)

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.dark_mode = False
        self.colors = self.colors_light

        self.scan_thread = None
        self.stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self.current_results = []
        self.is_scanning = False

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
            text="⚠ Only scan systems you own or have explicit written permission to test.\n"
                 "Unauthorized scanning may be illegal in your jurisdiction.",
            font=("Segoe UI", 8), fg="#c0392b", bg=self.colors["bg"], justify="center"
        )
        disclaimer.pack(pady=(5, 0))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=10)

        self.scan_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.history_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.notebook.add(self.scan_tab, text="Scan")
        self.notebook.add(self.history_tab, text="History")

        self.build_scan_tab()
        self.build_history_tab()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()

    # ---------- Scan tab ----------

    def build_scan_tab(self):
        f = self.scan_tab

        form = tk.Frame(f, bg=self.colors["card"])
        form.pack(pady=10, fill="x", padx=20)

        tk.Label(form, text="Target (IP or hostname)", bg=self.colors["card"], fg=self.colors["fg"]).grid(
            row=0, column=0, sticky="w", pady=(0, 2))
        self.target_entry = tk.Entry(form, font=("Segoe UI", 10), width=30)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.grid(row=1, column=0, sticky="w", padx=(0, 15))

        tk.Label(form, text="Ports (e.g. 'common', '1-1024', '22,80,443')",
                 bg=self.colors["card"], fg=self.colors["fg"]).grid(row=0, column=1, sticky="w", pady=(0, 2))
        self.ports_entry = tk.Entry(form, font=("Segoe UI", 10), width=30)
        self.ports_entry.insert(0, "common")
        self.ports_entry.grid(row=1, column=1, sticky="w")

        options = tk.Frame(f, bg=self.colors["card"])
        options.pack(pady=10, fill="x", padx=20)

        tk.Label(options, text="Threads:", bg=self.colors["card"], fg=self.colors["fg"]).grid(row=0, column=0, sticky="w")
        self.threads_var = tk.IntVar(value=100)
        tk.Scale(options, from_=10, to=300, orient="horizontal", variable=self.threads_var,
                 bg=self.colors["card"], length=150).grid(row=0, column=1, padx=(5, 20))

        tk.Label(options, text="Timeout (s):", bg=self.colors["card"], fg=self.colors["fg"]).grid(row=0, column=2, sticky="w")
        self.timeout_var = tk.DoubleVar(value=1.0)
        tk.Scale(options, from_=0.2, to=3.0, resolution=0.1, orient="horizontal", variable=self.timeout_var,
                 bg=self.colors["card"], length=150).grid(row=0, column=3, padx=5)

        self.banner_var = tk.BooleanVar(value=True)
        tk.Checkbutton(f, text="Attempt banner grabbing on open ports", variable=self.banner_var,
                        bg=self.colors["card"], fg=self.colors["fg"], selectcolor=self.colors["card"]).pack(pady=5)

        btn_row = tk.Frame(f, bg=self.colors["card"])
        btn_row.pack(pady=10)
        self.scan_btn = tk.Button(btn_row, text="Start Scan", command=self.handle_start_scan,
                                   font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=15)
        self.scan_btn.pack(side="left", padx=5)
        self.stop_btn = tk.Button(btn_row, text="Stop", command=self.handle_stop_scan,
                                   font=("Segoe UI", 10), width=10, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        tk.Button(btn_row, text="Export Results", command=self.handle_export,
                  font=("Segoe UI", 10), width=15).pack(side="left", padx=5)

        self.progress = ttk.Progressbar(f, length=500, mode="determinate")
        self.progress.pack(pady=10, padx=20)
        self.status_label = tk.Label(f, text="Ready", font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d")
        self.status_label.pack()

        columns = ("port", "status", "service", "banner")
        self.results_tree = ttk.Treeview(f, columns=columns, show="headings", height=13)
        widths = (60, 70, 110, 260)
        for col, width in zip(columns, widths):
            self.results_tree.heading(col, text=col.capitalize())
            self.results_tree.column(col, width=width)
        self.results_tree.pack(padx=20, pady=10, fill="both", expand=True)
        self.results_tree.tag_configure("open", foreground="#27ae60")

    def handle_start_scan(self):
        try:
            self._do_start_scan()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_start_scan(self):
        if self.is_scanning:
            return

        target = self.target_entry.get().strip()
        try:
            ip = resolve_target(target)
        except ValueError as e:
            messagebox.showerror("Invalid Target", str(e))
            return

        try:
            ports = parse_port_range(self.ports_entry.get())
        except ValueError as e:
            messagebox.showerror("Invalid Port Range", str(e))
            return

        for row in self.results_tree.get_children():
            self.results_tree.delete(row)
        self.current_results = []
        self.progress["value"] = 0
        self.progress["maximum"] = len(ports)
        self.status_label.config(text=f"Scanning {target} ({ip}) — {len(ports)} ports...")

        self.stop_event.clear()
        self.is_scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        self.scan_target_display = f"{target} ({ip})"
        self.scan_ports_count = len(ports)

        self.scan_thread = threading.Thread(
            target=scan_ports_threaded,
            kwargs=dict(
                ip=ip, ports=ports, timeout=self.timeout_var.get(),
                max_workers=self.threads_var.get(), grab_banners=self.banner_var.get(),
                result_queue=self.result_queue, stop_event=self.stop_event
            ),
            daemon=True
        )
        self.scan_thread.start()

    def handle_stop_scan(self):
        self.stop_event.set()
        self.status_label.config(text="Stopping...")

    def poll_queue(self):
        try:
            while True:
                result = self.result_queue.get_nowait()
                self.current_results.append(result)
                self.progress["value"] += 1
                if result["is_open"]:
                    self.results_tree.insert(
                        "", "end",
                        values=(result["port"], "OPEN", result["service"], result["banner"] or "-"),
                        tags=("open",)
                    )
        except queue.Empty:
            pass

        if self.is_scanning and self.scan_thread is not None and not self.scan_thread.is_alive():
            self.is_scanning = False
            self.scan_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            open_count = sum(1 for r in self.current_results if r["is_open"])
            self.status_label.config(
                text=f"Scan complete — {len(self.current_results)} ports checked, {open_count} open"
            )
            log_scan(self.scan_target_display, self.scan_ports_count, open_count)
            self.refresh_history()

        self.root.after(100, self.poll_queue)

    def handle_export(self):
        if not self.current_results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="scan_report.txt")
        if not path:
            return
        with open(path, "w") as f:
            f.write(f"Port Scan Report — {self.scan_target_display}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            open_ports = [r for r in self.current_results if r["is_open"]]
            f.write(f"Ports scanned: {len(self.current_results)}\n")
            f.write(f"Open ports found: {len(open_ports)}\n\n")
            for r in sorted(open_ports, key=lambda x: x["port"]):
                f.write(f"Port {r['port']:>5}  {r['service']:<15}  {r['banner'] or ''}\n")
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    # ---------- History tab ----------

    def build_history_tab(self):
        f = self.history_tab
        tk.Label(f, text="Scan History", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("target", "ports_scanned", "open_found", "timestamp")
        self.history_tree = ttk.Treeview(f, columns=columns, show="headings", height=16)
        for col, width in zip(columns, (200, 110, 100, 150)):
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
        cur.execute("SELECT target, ports_scanned, open_ports_found, timestamp FROM scans ORDER BY id DESC LIMIT 50")
        for row in cur.fetchall():
            self.history_tree.insert("", "end", values=row)
        conn.close()


if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()