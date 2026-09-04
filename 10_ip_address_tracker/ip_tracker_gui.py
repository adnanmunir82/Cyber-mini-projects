import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import webbrowser
import threading
import queue
from datetime import datetime

from ip_tracker_core import lookup_ip, get_public_ip

APP_NAME = "Adnan's IP Address Tracker"
DB_FILE = "ip_tracker_history.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            country TEXT,
            city TEXT,
            isp TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_lookup(query, country, city, isp):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO history (query, country, city, isp, timestamp) VALUES (?, ?, ?, ?, ?)",
                (query, country, city, isp, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


class IPTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("620x680")
        self.root.resizable(False, False)

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.dark_mode = False
        self.colors = self.colors_light

        self.last_result = None
        self.task_queue = queue.Queue()

        init_db()
        self.build_ui()
        self.poll_queue()

    def poll_queue(self):
        try:
            while True:
                task_type, payload = self.task_queue.get_nowait()
                if task_type == "my_ip":
                    ip, error = payload
                    self._on_my_ip_result(ip, error)
                elif task_type == "lookup":
                    self._on_lookup_result(payload)
                elif task_type == "batch_row":
                    target, result = payload
                    self._add_batch_row(target, result)
                elif task_type == "batch_done":
                    self.batch_status.config(text="Done")
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    def build_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.configure(bg=self.colors["bg"])

        top_bar = tk.Frame(self.root, bg=self.colors["bg"])
        top_bar.pack(fill="x", pady=(10, 0), padx=15)
        tk.Label(top_bar, text=APP_NAME, font=("Segoe UI", 13, "bold"),
                 bg=self.colors["bg"], fg=self.colors["fg"]).pack(side="left")
        tk.Button(top_bar, text="🌙 Dark Mode", command=self.toggle_theme, font=("Segoe UI", 9)).pack(side="right")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=15)

        self.single_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.batch_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.history_tab = tk.Frame(self.notebook, bg=self.colors["card"])

        self.notebook.add(self.single_tab, text="Lookup")
        self.notebook.add(self.batch_tab, text="Batch Lookup")
        self.notebook.add(self.history_tab, text="History")

        self.build_single_tab()
        self.build_batch_tab()
        self.build_history_tab()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()

    # ---------- Single lookup tab ----------

    def build_single_tab(self):
        f = self.single_tab
        tk.Label(f, text="Look Up an IP or Domain", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 10))

        input_row = tk.Frame(f, bg=self.colors["card"])
        input_row.pack(pady=5)
        self.target_entry = tk.Entry(input_row, font=("Segoe UI", 11), width=30)
        self.target_entry.pack(side="left", padx=(0, 8))
        self.target_entry.bind("<Return>", lambda e: self.handle_lookup())
        tk.Button(input_row, text="My IP", command=self.handle_my_ip, font=("Segoe UI", 9)).pack(side="left")

        tk.Button(f, text="Look Up", command=self.handle_lookup, font=("Segoe UI", 11, "bold"),
                  bg="#2980b9", fg="white", width=20).pack(pady=10)

        self.status_label = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"], fg="#c0392b")
        self.status_label.pack(pady=5)

        self.result_frame = tk.Frame(f, bg=self.colors["card"], relief="solid", bd=1)
        self.result_frame.pack(pady=10, padx=30, fill="both", expand=True)
        self._render_empty_result()

        btn_row = tk.Frame(f, bg=self.colors["card"])
        btn_row.pack(pady=10)
        tk.Button(btn_row, text="View on Map", command=self.handle_view_map,
                  font=("Segoe UI", 9), width=15).pack(side="left", padx=5)
        tk.Button(btn_row, text="Copy Result", command=self.handle_copy,
                  font=("Segoe UI", 9), width=15).pack(side="left", padx=5)

    def _render_empty_result(self):
        for widget in self.result_frame.winfo_children():
            widget.destroy()
        tk.Label(self.result_frame, text="No lookup yet", font=("Segoe UI", 10),
                 bg=self.colors["card"], fg="#7f8c8d").pack(pady=30)

    def _render_result(self, result):
        for widget in self.result_frame.winfo_children():
            widget.destroy()

        header = tk.Frame(self.result_frame, bg=self.colors["card"])
        header.pack(pady=(15, 10))
        tk.Label(header, text=result["flag"], font=("Segoe UI", 28), bg=self.colors["card"]).pack(side="left", padx=10)
        title_col = tk.Frame(header, bg=self.colors["card"])
        title_col.pack(side="left")
        tk.Label(title_col, text=result["query"], font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w")
        tk.Label(title_col, text=f"{result['city']}, {result['region']}, {result['country']}",
                 font=("Segoe UI", 10), bg=self.colors["card"], fg="#7f8c8d").pack(anchor="w")

        fields = [
            ("ISP", result["isp"]),
            ("Organization", result["org"] or "-"),
            ("AS", result["as_info"] or "-"),
            ("Timezone", result["timezone"]),
            ("Coordinates", f"{result['lat']}, {result['lon']}"),
            ("Reverse DNS", result["hostname"]),
        ]
        for label, value in fields:
            row = tk.Frame(self.result_frame, bg=self.colors["card"])
            row.pack(fill="x", padx=30, pady=3)
            tk.Label(row, text=label, font=("Segoe UI", 9, "bold"), width=14, anchor="w",
                     bg=self.colors["card"], fg=self.colors["fg"]).pack(side="left")
            tk.Label(row, text=str(value), font=("Segoe UI", 9), anchor="w",
                     bg=self.colors["card"], fg="#7f8c8d", wraplength=350, justify="left").pack(side="left")

    def handle_my_ip(self):
        self.status_label.config(text="Fetching your public IP...", fg="#7f8c8d")
        self.root.update_idletasks()

        def worker():
            ip, error = get_public_ip()
            self.task_queue.put(("my_ip", (ip, error)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_my_ip_result(self, ip, error):
        if error:
            self.status_label.config(text=error, fg="#c0392b")
            return
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, ip)
        self.status_label.config(text="", fg="#c0392b")
        self.handle_lookup()

    def handle_lookup(self):
        try:
            self._do_lookup()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_lookup(self):
        target = self.target_entry.get().strip()
        if not target:
            return

        self.status_label.config(text="Looking up...", fg="#7f8c8d")
        self.root.update_idletasks()

        def worker():
            result = lookup_ip(target)
            self.task_queue.put(("lookup", result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_lookup_result(self, result):
        if result.get("error"):
            self.status_label.config(text=result["error"], fg="#c0392b")
            self._render_empty_result()
            return

        self.status_label.config(text="", fg="#c0392b")
        self.last_result = result
        self._render_result(result)
        log_lookup(result["query"], result["country"], result["city"], result["isp"])
        self.refresh_history()

    def handle_view_map(self):
        if not self.last_result or self.last_result.get("lat") is None:
            messagebox.showinfo("No data", "Look up an address first.")
            return
        lat, lon = self.last_result["lat"], self.last_result["lon"]
        webbrowser.open(f"https://www.google.com/maps?q={lat},{lon}")

    def handle_copy(self):
        if not self.last_result:
            messagebox.showinfo("No data", "Look up an address first.")
            return
        r = self.last_result
        text = (f"{r['query']} ({r['hostname']})\n"
                f"{r['city']}, {r['region']}, {r['country']}\n"
                f"ISP: {r['isp']}\nOrg: {r['org']}\nAS: {r['as_info']}\n"
                f"Timezone: {r['timezone']}\nCoordinates: {r['lat']}, {r['lon']}")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_label.config(text="Copied to clipboard", fg="#27ae60")

    # ---------- Batch lookup tab ----------

    def build_batch_tab(self):
        f = self.batch_tab
        tk.Label(f, text="Batch Lookup", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 10))
        tk.Label(f, text="Paste one IP or domain per line:", font=("Segoe UI", 9),
                 bg=self.colors["card"], fg="#7f8c8d").pack()

        self.batch_input = tk.Text(f, height=6, width=55, font=("Segoe UI", 9))
        self.batch_input.pack(pady=10)

        tk.Button(f, text="Look Up All", command=self.handle_batch_lookup,
                  font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=20).pack(pady=5)

        self.batch_status = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d")
        self.batch_status.pack()

        columns = ("query", "country", "city", "isp")
        self.batch_tree = ttk.Treeview(f, columns=columns, show="headings", height=10)
        for col, width in zip(columns, (130, 120, 110, 160)):
            self.batch_tree.heading(col, text=col.capitalize())
            self.batch_tree.column(col, width=width)
        self.batch_tree.pack(padx=15, pady=15, fill="both", expand=True)

    def handle_batch_lookup(self):
        raw = self.batch_input.get("1.0", tk.END).strip()
        if not raw:
            return
        targets = [line.strip() for line in raw.splitlines() if line.strip()]

        for row in self.batch_tree.get_children():
            self.batch_tree.delete(row)
        self.batch_status.config(text=f"Looking up {len(targets)} addresses...")
        self.root.update_idletasks()

        def worker():
            for target in targets:
                result = lookup_ip(target)
                self.task_queue.put(("batch_row", (target, result)))
            self.task_queue.put(("batch_done", None))

        threading.Thread(target=worker, daemon=True).start()

    def _add_batch_row(self, target, result):
        if result.get("error"):
            self.batch_tree.insert("", "end", values=(target, "Error", result["error"][:40], "-"))
        else:
            self.batch_tree.insert("", "end", values=(result["query"], result["country"], result["city"], result["isp"]))
            log_lookup(result["query"], result["country"], result["city"], result["isp"])
        self.refresh_history()

    # ---------- History tab ----------

    def build_history_tab(self):
        f = self.history_tab
        tk.Label(f, text="Lookup History", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("query", "country", "city", "isp", "timestamp")
        self.history_tree = ttk.Treeview(f, columns=columns, show="headings", height=16)
        for col, width in zip(columns, (110, 100, 90, 130, 140)):
            self.history_tree.heading(col, text=col.capitalize())
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
        cur.execute("SELECT query, country, city, isp, timestamp FROM history ORDER BY id DESC LIMIT 50")
        for row in cur.fetchall():
            self.history_tree.insert("", "end", values=row)
        conn.close()


if __name__ == "__main__":
    root = tk.Tk()
    app = IPTrackerApp(root)
    root.mainloop()