import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
import os
import json
import time
import uuid
import re
from datetime import datetime

from vault_core import (
    create_vault_config, unlock_with_password, unlock_with_recovery_key,
    encrypt_bytes, decrypt_bytes
)

APP_NAME = "Adnan's Secure File Locker"
CONFIG_FILE = "vault_config.json"
DB_FILE = "vault_metadata.db"
VAULT_DIR = "vault_files"

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
AUTO_LOCK_IDLE_SECONDS = 180


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_items (
            id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            date_added TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_event(action, detail=""):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO vault_log (timestamp, action, detail) VALUES (?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, detail))
    conn.commit()
    conn.close()


def password_strength_score(password):
    score = 0
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'\d', password): score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=]', password): score += 1
    if score <= 2: return "Weak", "#e74c3c", 25
    if score <= 4: return "Medium", "#f39c12", 60
    if score <= 5: return "Strong", "#27ae60", 85
    return "Very Strong", "#16a085", 100


class VaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("640x680")
        self.root.resizable(False, False)

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.dark_mode = False
        self.colors = self.colors_light

        self.vault_key = None  # None = locked
        self.failed_attempts = 0
        self.lockout_until = 0
        self.last_activity = time.time()

        os.makedirs(VAULT_DIR, exist_ok=True)
        init_db()

        self.root.bind_all("<Any-KeyPress>", self.reset_idle_timer)
        self.root.bind_all("<Any-Button>", self.reset_idle_timer)

        self.build_ui()
        self.check_idle_loop()

    # ---------- Idle / auto-lock ----------

    def reset_idle_timer(self, event=None):
        self.last_activity = time.time()

    def check_idle_loop(self):
        if self.vault_key is not None:
            idle = time.time() - self.last_activity
            if idle >= AUTO_LOCK_IDLE_SECONDS:
                log_event("Auto-lock", f"Idle for {int(idle)}s")
                self.lock_vault()
        self.root.after(2000, self.check_idle_loop)

    def lock_vault(self):
        self.vault_key = None
        self.build_ui()

    # ---------- UI shell ----------

    def build_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.configure(bg=self.colors["bg"])

        top_bar = tk.Frame(self.root, bg=self.colors["bg"])
        top_bar.pack(fill="x", pady=(10, 0), padx=15)
        tk.Label(top_bar, text=APP_NAME, font=("Segoe UI", 13, "bold"),
                 bg=self.colors["bg"], fg=self.colors["fg"]).pack(side="left")
        self.theme_btn = tk.Button(top_bar, text="🌙 Dark Mode", command=self.toggle_theme, font=("Segoe UI", 9))
        self.theme_btn.pack(side="right")

        if not os.path.exists(CONFIG_FILE):
            self.build_setup_screen()
        elif self.vault_key is None:
            self.build_unlock_screen()
        else:
            self.build_vault_screen()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()

    # ---------- First-run setup ----------

    def build_setup_screen(self):
        card = tk.Frame(self.root, bg=self.colors["card"])
        card.pack(expand=True, fill="both", padx=15, pady=15)

        tk.Label(card, text="🔒 Create Your Vault", font=("Segoe UI", 16, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(30, 5))
        tk.Label(card, text="Set a master password to protect this vault.",
                 font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d").pack(pady=(0, 20))

        tk.Label(card, text="Master Password", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=60)
        self.setup_password = tk.Entry(card, font=("Segoe UI", 11), width=32, show="*")
        self.setup_password.pack(pady=(0, 5), padx=60)
        self.setup_password.bind("<KeyRelease>", self.update_setup_strength)

        self.setup_strength_bar = ttk.Progressbar(card, length=300, maximum=100, value=0)
        self.setup_strength_bar.pack(pady=(5, 2), padx=60)
        self.setup_strength_label = tk.Label(card, text="", font=("Segoe UI", 9, "bold"), bg=self.colors["card"])
        self.setup_strength_label.pack(pady=(0, 10))

        tk.Label(card, text="Confirm Password", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=60)
        self.setup_confirm = tk.Entry(card, font=("Segoe UI", 11), width=32, show="*")
        self.setup_confirm.pack(pady=(0, 10), padx=60)

        self.setup_status = tk.Label(card, text="", font=("Segoe UI", 9), bg=self.colors["card"],
                                      fg="#c0392b", wraplength=450)
        self.setup_status.pack(pady=5)

        tk.Button(card, text="Create Vault", command=self.handle_create_vault,
                  font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=20).pack(pady=15)

    def update_setup_strength(self, event=None):
        pwd = self.setup_password.get()
        if not pwd:
            self.setup_strength_bar["value"] = 0
            self.setup_strength_label.config(text="")
            return
        rating, color, percent = password_strength_score(pwd)
        self.setup_strength_bar["value"] = percent
        self.setup_strength_label.config(text=rating, fg=color)

    def handle_create_vault(self):
        pwd = self.setup_password.get()
        confirm = self.setup_confirm.get()

        if len(pwd) < 8:
            self.setup_status.config(text="Password must be at least 8 characters")
            return
        if pwd != confirm:
            self.setup_status.config(text="Passwords do not match")
            return

        config, recovery_key = create_vault_config(pwd)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)

        log_event("Vault created", "")
        self.show_recovery_key_dialog(recovery_key)
        self.build_ui()

    def show_recovery_key_dialog(self, recovery_key):
        win = tk.Toplevel(self.root)
        win.title("Save Your Recovery Key")
        win.geometry("460x300")
        win.grab_set()

        tk.Label(win, text="⚠ Save This Recovery Key Now", font=("Segoe UI", 13, "bold"),
                 fg="#c0392b").pack(pady=(20, 10))
        tk.Label(win, text="If you forget your master password, this is the\nONLY way to recover your files.\nIt will not be shown again.",
                 font=("Segoe UI", 9), justify="center").pack(pady=(0, 15))

        key_entry = tk.Entry(win, font=("Consolas", 14, "bold"), justify="center", width=32)
        key_entry.insert(0, recovery_key)
        key_entry.config(state="readonly")
        key_entry.pack(pady=10)

        confirmed = tk.BooleanVar(value=False)
        tk.Checkbutton(win, text="I have saved this recovery key somewhere safe",
                        variable=confirmed).pack(pady=15)

        def close_if_confirmed():
            if confirmed.get():
                win.destroy()
            else:
                messagebox.showwarning("Not confirmed", "Please confirm you've saved the recovery key.")

        tk.Button(win, text="Continue", command=close_if_confirmed,
                  font=("Segoe UI", 10, "bold"), bg="#27ae60", fg="white", width=15).pack(pady=10)
        win.wait_window()

    # ---------- Unlock screen ----------

    def build_unlock_screen(self):
        card = tk.Frame(self.root, bg=self.colors["card"])
        card.pack(expand=True, fill="both", padx=15, pady=15)

        tk.Label(card, text="🔒 Vault Locked", font=("Segoe UI", 18, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(50, 20))

        self.use_recovery = tk.BooleanVar(value=False)

        self.unlock_label = tk.Label(card, text="Master Password", bg=self.colors["card"], fg=self.colors["fg"])
        self.unlock_label.pack(pady=(10, 0))

        pwd_frame = tk.Frame(card, bg=self.colors["card"])
        pwd_frame.pack(pady=(0, 5))
        self.unlock_entry = tk.Entry(pwd_frame, font=("Segoe UI", 12), width=28, show="*")
        self.unlock_entry.pack(side="left")
        self.unlock_entry.bind("<Return>", lambda e: self.handle_unlock())
        self.unlock_toggle_btn = tk.Button(pwd_frame, text="Show", font=("Segoe UI", 8), width=6,
                                            command=self.toggle_unlock_visibility)
        self.unlock_toggle_btn.pack(side="left", padx=(8, 0))

        self.unlock_status = tk.Label(card, text="", font=("Segoe UI", 9), bg=self.colors["card"],
                                       fg="#c0392b", wraplength=400)
        self.unlock_status.pack(pady=10)

        tk.Button(card, text="Unlock", command=self.handle_unlock,
                  font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=20).pack(pady=5)

        tk.Button(card, text="Use recovery key instead", command=self.toggle_recovery_mode,
                  font=("Segoe UI", 8, "underline"), bg=self.colors["card"], fg="#2980b9",
                  relief="flat", bd=0).pack(pady=15)

    def toggle_unlock_visibility(self):
        if self.unlock_entry.cget("show") == "*":
            self.unlock_entry.config(show="")
            self.unlock_toggle_btn.config(text="Hide")
        else:
            self.unlock_entry.config(show="*")
            self.unlock_toggle_btn.config(text="Show")

    def toggle_recovery_mode(self):
        self.use_recovery.set(not self.use_recovery.get())
        if self.use_recovery.get():
            self.unlock_label.config(text="Recovery Key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)")
            self.unlock_entry.config(show="")
        else:
            self.unlock_label.config(text="Master Password")
            self.unlock_entry.config(show="*")
        self.unlock_entry.delete(0, tk.END)

    def handle_unlock(self):
        try:
            self._do_unlock()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_unlock(self):
        if self.lockout_until and time.time() < self.lockout_until:
            remaining = int(self.lockout_until - time.time())
            self.unlock_status.config(text=f"Too many failed attempts. Try again in {remaining}s.")
            return

        with open(CONFIG_FILE) as f:
            config = json.load(f)

        entered = self.unlock_entry.get()
        if self.use_recovery.get():
            vault_key = unlock_with_recovery_key(config, entered)
        else:
            vault_key = unlock_with_password(config, entered)

        if vault_key:
            self.vault_key = vault_key
            self.failed_attempts = 0
            self.last_activity = time.time()
            log_event("Unlocked", "Recovery key" if self.use_recovery.get() else "Master password")
            self.build_ui()
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
                self.lockout_until = time.time() + LOCKOUT_SECONDS
                log_event("Lockout triggered", f"{self.failed_attempts} failed attempts")
                self.unlock_status.config(text=f"Too many failed attempts. Locked for {LOCKOUT_SECONDS}s.")
            else:
                log_event("Failed unlock attempt", f"Attempt {self.failed_attempts}")
                self.unlock_status.config(text="Incorrect credentials")
            self.unlock_entry.delete(0, tk.END)

    # ---------- Unlocked vault screen ----------

    def build_vault_screen(self):
        status_bar = tk.Frame(self.root, bg="#27ae60")
        status_bar.pack(fill="x", padx=15)
        tk.Label(status_bar, text="🔓 Vault Unlocked", font=("Segoe UI", 10, "bold"),
                 bg="#27ae60", fg="white").pack(side="left", padx=10, pady=4)
        tk.Button(status_bar, text="Lock Now", command=self.lock_vault,
                  font=("Segoe UI", 8, "bold"), bg="#c0392b", fg="white").pack(side="right", padx=10, pady=3)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=10)

        self.vault_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.log_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.notebook.add(self.vault_tab, text="Vault Contents")
        self.notebook.add(self.log_tab, text="Activity Log")

        self.build_vault_tab()
        self.build_log_tab()

    def build_vault_tab(self):
        f = self.vault_tab
        btn_row = tk.Frame(f, bg=self.colors["card"])
        btn_row.pack(pady=10)
        tk.Button(btn_row, text="+ Add Files to Vault", command=self.handle_add_files,
                  font=("Segoe UI", 10, "bold"), bg="#27ae60", fg="white").pack(side="left", padx=5)
        tk.Button(btn_row, text="Extract Selected", command=self.handle_extract,
                  font=("Segoe UI", 10)).pack(side="left", padx=5)
        tk.Button(btn_row, text="Delete Selected", command=self.handle_delete,
                  font=("Segoe UI", 10), fg="white", bg="#c0392b").pack(side="left", padx=5)

        columns = ("name", "size", "date")
        self.vault_tree = ttk.Treeview(f, columns=columns, show="headings", height=15)
        for col, width, label in zip(columns, (220, 100, 160), ("File Name", "Size", "Date Added")):
            self.vault_tree.heading(col, text=label)
            self.vault_tree.column(col, width=width)
        self.vault_tree.pack(padx=15, pady=10, fill="both", expand=True)

        self.vault_status = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"], fg="#c0392b")
        self.vault_status.pack(pady=5)

        self.refresh_vault_list()

    def refresh_vault_list(self):
        for row in self.vault_tree.get_children():
            self.vault_tree.delete(row)
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT id, original_name, size_bytes, date_added FROM vault_items ORDER BY date_added DESC")
        rows = cur.fetchall()
        conn.close()
        self.vault_row_ids = {}
        for item_id, name, size, date_added in rows:
            size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024*1024):.1f} MB"
            tree_id = self.vault_tree.insert("", "end", values=(name, size_str, date_added))
            self.vault_row_ids[tree_id] = item_id

    def handle_add_files(self):
        try:
            self._do_add_files()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_add_files(self):
        files = filedialog.askopenfilenames(title="Select files to add to vault")
        if not files:
            return

        delete_originals = messagebox.askyesno(
            "Delete originals?",
            "Delete the original files from their current location after locking them?\n\n"
            "(They will only exist inside the encrypted vault.)"
        )

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        added = 0
        for path in files:
            with open(path, "rb") as f:
                data = f.read()
            token = encrypt_bytes(self.vault_key, data)
            item_id = str(uuid.uuid4())
            stored_path = os.path.join(VAULT_DIR, item_id + ".vlt")
            with open(stored_path, "wb") as f:
                f.write(token)

            cur.execute(
                "INSERT INTO vault_items (id, original_name, size_bytes, date_added) VALUES (?, ?, ?, ?)",
                (item_id, os.path.basename(path), len(data), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            # Log via the same open connection/cursor — opening a second connection
            # here while this one is mid-transaction causes "database is locked".
            cur.execute(
                "INSERT INTO vault_log (timestamp, action, detail) VALUES (?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "File added", os.path.basename(path))
            )
            added += 1

            if delete_originals:
                os.remove(path)

        conn.commit()
        conn.close()
        self.vault_status.config(text=f"Added {added} file(s) to the vault", fg="#27ae60")
        self.refresh_vault_list()

    def handle_extract(self):
        try:
            self._do_extract()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_extract(self):
        selected = self.vault_tree.selection()
        if not selected:
            self.vault_status.config(text="Select a file to extract first", fg="#c0392b")
            return
        tree_id = selected[0]
        item_id = self.vault_row_ids[tree_id]

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT original_name FROM vault_items WHERE id = ?", (item_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return
        original_name = row[0]

        save_path = filedialog.asksaveasfilename(initialfile=original_name, title="Extract file to...")
        if not save_path:
            return

        stored_path = os.path.join(VAULT_DIR, item_id + ".vlt")
        with open(stored_path, "rb") as f:
            token = f.read()
        data = decrypt_bytes(self.vault_key, token)
        with open(save_path, "wb") as f:
            f.write(data)

        log_event("File extracted", original_name)
        self.vault_status.config(text=f"Extracted '{original_name}'", fg="#27ae60")

    def handle_delete(self):
        selected = self.vault_tree.selection()
        if not selected:
            self.vault_status.config(text="Select a file to delete first", fg="#c0392b")
            return
        tree_id = selected[0]
        item_id = self.vault_row_ids[tree_id]

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT original_name FROM vault_items WHERE id = ?", (item_id,))
        row = cur.fetchone()
        original_name = row[0] if row else "file"

        confirm = messagebox.askyesno("Confirm Permanent Delete",
                                       f"Permanently delete '{original_name}' from the vault?\nThis cannot be undone.")
        if not confirm:
            conn.close()
            return

        cur.execute("DELETE FROM vault_items WHERE id = ?", (item_id,))
        conn.commit()
        conn.close()

        stored_path = os.path.join(VAULT_DIR, item_id + ".vlt")
        if os.path.exists(stored_path):
            os.remove(stored_path)

        log_event("File deleted", original_name)
        self.vault_status.config(text=f"Deleted '{original_name}'", fg="#27ae60")
        self.refresh_vault_list()

    def build_log_tab(self):
        f = self.log_tab
        tk.Label(f, text="Vault Activity Log", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("timestamp", "action", "detail")
        tree = ttk.Treeview(f, columns=columns, show="headings", height=15)
        for col, width in zip(columns, (140, 120, 220)):
            tree.heading(col, text=col.capitalize())
            tree.column(col, width=width)
        tree.pack(padx=15, pady=5, fill="both", expand=True)

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT timestamp, action, detail FROM vault_log ORDER BY id DESC LIMIT 40")
        for row in cur.fetchall():
            tree.insert("", "end", values=row)
        conn.close()


if __name__ == "__main__":
    root = tk.Tk()
    app = VaultApp(root)
    root.mainloop()