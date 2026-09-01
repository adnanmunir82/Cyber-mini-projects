import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime

from phishing_core import analyze_url

APP_NAME = "Adnan's Phishing Website Detector"
DB_FILE = "phishing_history.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_check(url, score, verdict):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO history (url, score, verdict, timestamp) VALUES (?, ?, ?, ?)",
                (url, score, verdict, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


class PhishingApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("640x680")
        self.root.resizable(False, False)

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.dark_mode = False
        self.colors = self.colors_light

        init_db()
        self.build_ui()

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

        self.notebook.add(self.single_tab, text="Check URL")
        self.notebook.add(self.batch_tab, text="Batch Check")
        self.notebook.add(self.history_tab, text="History")

        self.build_single_tab()
        self.build_batch_tab()
        self.build_history_tab()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()

    # ---------- Single URL check ----------

    def build_single_tab(self):
        f = self.single_tab
        tk.Label(f, text="Check a URL", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 10))

        self.url_entry = tk.Entry(f, font=("Segoe UI", 11), width=50)
        self.url_entry.pack(pady=5)
        self.url_entry.bind("<Return>", lambda e: self.handle_check())
        self.url_entry.insert(0, "https://")

        self.check_age_var = tk.BooleanVar(value=False)
        tk.Checkbutton(f, text="Also check domain age (requires internet, optional)",
                        variable=self.check_age_var, bg=self.colors["card"],
                        fg=self.colors["fg"], selectcolor=self.colors["card"]).pack(pady=5)

        tk.Button(f, text="Check URL", command=self.handle_check, font=("Segoe UI", 11, "bold"),
                  bg="#2980b9", fg="white", width=20).pack(pady=10)

        self.verdict_label = tk.Label(f, text="", font=("Segoe UI", 18, "bold"), bg=self.colors["card"])
        self.verdict_label.pack(pady=(15, 5))

        self.risk_bar = ttk.Progressbar(f, length=400, maximum=100, value=0)
        self.risk_bar.pack(pady=5)
        self.score_label = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d")
        self.score_label.pack()

        tk.Label(f, text="Details:", font=("Segoe UI", 10, "bold"), bg=self.colors["card"],
                 fg=self.colors["fg"]).pack(anchor="w", padx=30, pady=(15, 0))
        self.reasons_text = tk.Text(f, height=10, width=60, font=("Segoe UI", 9),
                                     bg="white", relief="solid", bd=1, wrap="word")
        self.reasons_text.pack(padx=30, pady=10)
        self.reasons_text.config(state="disabled")

    def handle_check(self):
        try:
            self._do_check()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_check(self):
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            return

        result = analyze_url(url, include_domain_age=self.check_age_var.get())

        if "error" in result:
            self.verdict_label.config(text="⚠ Invalid Input", fg="#c0392b")
            self.risk_bar["value"] = 0
            self.score_label.config(text="")
            self._set_reasons([result["error"]])
            return

        self.verdict_label.config(text=result["verdict"], fg=result["color"])
        self.risk_bar["value"] = result["score"]
        self.score_label.config(text=f"Risk score: {result['score']}/100")

        reasons = list(result["reasons"])
        if result["domain_age_note"]:
            reasons.append(result["domain_age_note"])
        self._set_reasons(reasons)

        log_check(result["url"], result["score"], result["verdict"])
        self.refresh_history()

    def _set_reasons(self, reasons):
        self.reasons_text.config(state="normal")
        self.reasons_text.delete("1.0", tk.END)
        self.reasons_text.insert(tk.END, "\n".join(f"• {r}" for r in reasons))
        self.reasons_text.config(state="disabled")

    # ---------- Batch check ----------

    def build_batch_tab(self):
        f = self.batch_tab
        tk.Label(f, text="Batch URL Check", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 10))
        tk.Label(f, text="Paste one URL per line:", font=("Segoe UI", 9),
                 bg=self.colors["card"], fg="#7f8c8d").pack()

        self.batch_input = tk.Text(f, height=8, width=60, font=("Segoe UI", 9))
        self.batch_input.pack(pady=10)

        tk.Button(f, text="Check All", command=self.handle_batch_check,
                  font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=20).pack(pady=5)

        columns = ("url", "score", "verdict")
        self.batch_tree = ttk.Treeview(f, columns=columns, show="headings", height=10)
        for col, width in zip(columns, (320, 70, 100)):
            self.batch_tree.heading(col, text=col.capitalize())
            self.batch_tree.column(col, width=width)
        self.batch_tree.pack(padx=15, pady=15, fill="both", expand=True)

    def handle_batch_check(self):
        try:
            self._do_batch_check()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_batch_check(self):
        raw_text = self.batch_input.get("1.0", tk.END).strip()
        if not raw_text:
            return
        urls = [line.strip() for line in raw_text.splitlines() if line.strip()]

        for row in self.batch_tree.get_children():
            self.batch_tree.delete(row)

        for url in urls:
            result = analyze_url(url)
            if "error" in result:
                self.batch_tree.insert("", "end", values=(url, "-", "Invalid"))
                continue
            self.batch_tree.insert("", "end", values=(result["url"], result["score"], result["verdict"]))
            log_check(result["url"], result["score"], result["verdict"])

        self.refresh_history()

    # ---------- History ----------

    def build_history_tab(self):
        f = self.history_tab
        tk.Label(f, text="Check History", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("url", "score", "verdict", "timestamp")
        self.history_tree = ttk.Treeview(f, columns=columns, show="headings", height=18)
        for col, width in zip(columns, (250, 60, 90, 140)):
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
        cur.execute("SELECT url, score, verdict, timestamp FROM history ORDER BY id DESC LIMIT 50")
        for row in cur.fetchall():
            self.history_tree.insert("", "end", values=row)
        conn.close()


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingApp(root)
    root.mainloop()