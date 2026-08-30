import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
import os
import hashlib
import struct
import secrets
import re
import base64
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

APP_NAME = "Adnan's File Encryption & Decryption Tool"
DB_FILE = "file_crypto_log.db"
ENCRYPTED_EXTENSION = ".dlock"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16

# ---------------- Database (activity log) ----------------

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            success INTEGER NOT NULL,
            detail TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_action(filename, action, success, detail=""):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO file_log (filename, action, timestamp, success, detail) VALUES (?, ?, ?, ?, ?)",
        (os.path.basename(filename), action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), int(success), detail)
    )
    conn.commit()
    conn.close()


# ---------------- Cryptography core ----------------

def derive_key(password, salt):
    """PBKDF2-HMAC-SHA256 -> 32-byte key, base64-encoded for Fernet."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_file(input_path, password, delete_original=False):
    """
    Encrypted file layout on disk:
    [16 bytes salt][Fernet token containing: 4-byte filename length,
     filename bytes, 32-byte SHA-256 of original content, original content]
    """
    with open(input_path, "rb") as f:
        original_data = f.read()

    original_filename = os.path.basename(input_path)
    filename_bytes = original_filename.encode("utf-8")
    file_hash = hashlib.sha256(original_data).digest()

    payload = struct.pack(">I", len(filename_bytes)) + filename_bytes + file_hash + original_data

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(payload)

    output_path = input_path + ENCRYPTED_EXTENSION
    with open(output_path, "wb") as f:
        f.write(salt + token)

    if delete_original:
        _secure_delete(input_path, len(original_data))

    return output_path


def decrypt_file(input_path, password, output_dir):
    with open(input_path, "rb") as f:
        raw = f.read()

    salt = raw[:SALT_SIZE]
    token = raw[SALT_SIZE:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        payload = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError("Incorrect password or corrupted/tampered file")

    filename_len = struct.unpack(">I", payload[:4])[0]
    offset = 4
    original_filename = payload[offset:offset + filename_len].decode("utf-8")
    offset += filename_len
    stored_hash = payload[offset:offset + 32]
    offset += 32
    original_data = payload[offset:]

    # Integrity check
    actual_hash = hashlib.sha256(original_data).digest()
    integrity_ok = secrets.compare_digest(stored_hash, actual_hash)

    output_path = os.path.join(output_dir, original_filename)
    # Avoid overwriting existing files silently
    base, ext = os.path.splitext(output_path)
    counter = 1
    while os.path.exists(output_path):
        output_path = f"{base} ({counter}){ext}"
        counter += 1

    with open(output_path, "wb") as f:
        f.write(original_data)

    return output_path, integrity_ok


def _secure_delete(path, filesize):
    """Best-effort overwrite before deletion (not guaranteed on SSDs/journaled filesystems,
    but demonstrates awareness of data remanence beyond a simple os.remove())."""
    try:
        with open(path, "r+b") as f:
            f.write(secrets.token_bytes(filesize))
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    os.remove(path)


# ---------------- Password policy (reused pattern) ----------------

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


# ---------------- GUI ----------------

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("620x680")
        self.root.resizable(False, False)

        self.dark_mode = False
        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.colors = self.colors_light

        self.encrypt_files = []
        self.decrypt_files = []

        self.build_ui()

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

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=15)

        self.encrypt_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.decrypt_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.log_tab = tk.Frame(self.notebook, bg=self.colors["card"])

        self.notebook.add(self.encrypt_tab, text="Encrypt")
        self.notebook.add(self.decrypt_tab, text="Decrypt")
        self.notebook.add(self.log_tab, text="Activity Log")

        self.build_encrypt_tab()
        self.build_decrypt_tab()
        self.build_log_tab()

    # ---------- Encrypt tab ----------

    def build_encrypt_tab(self):
        f = self.encrypt_tab
        tk.Label(f, text="Encrypt Files", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 10))

        tk.Button(f, text="Select Files...", command=self.pick_encrypt_files,
                  font=("Segoe UI", 10)).pack(pady=5)

        self.encrypt_listbox = tk.Listbox(f, width=60, height=6, font=("Segoe UI", 9))
        self.encrypt_listbox.pack(pady=10, padx=30)

        tk.Label(f, text="Passphrase", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=30)
        pwd_frame = tk.Frame(f, bg=self.colors["card"])
        pwd_frame.pack(pady=(0, 5), padx=30, fill="x")
        self.encrypt_password = tk.Entry(pwd_frame, font=("Segoe UI", 11), width=28, show="*")
        self.encrypt_password.pack(side="left")
        self.encrypt_password.bind("<KeyRelease>", self.update_strength_meter)
        toggle_btn = tk.Button(pwd_frame, text="Show", font=("Segoe UI", 8), width=6)
        toggle_btn.config(command=lambda: self.toggle_visibility(self.encrypt_password, toggle_btn))
        toggle_btn.pack(side="left", padx=(8, 0))

        self.strength_bar = ttk.Progressbar(f, length=300, maximum=100, value=0)
        self.strength_bar.pack(pady=(5, 2), padx=30)
        self.strength_label = tk.Label(f, text="", font=("Segoe UI", 9, "bold"), bg=self.colors["card"])
        self.strength_label.pack(pady=(0, 10))

        self.delete_original_var = tk.BooleanVar(value=False)
        tk.Checkbutton(f, text="Securely delete original files after encrypting",
                        variable=self.delete_original_var, bg=self.colors["card"],
                        fg=self.colors["fg"], selectcolor=self.colors["card"]).pack(pady=5)

        self.encrypt_progress = ttk.Progressbar(f, length=400, mode="determinate")
        self.encrypt_progress.pack(pady=10, padx=30)

        self.encrypt_status = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"],
                                        fg="#c0392b", wraplength=450, justify="left")
        self.encrypt_status.pack(pady=5, padx=30)

        tk.Button(f, text="Encrypt Selected Files", command=self.handle_encrypt,
                  font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=25).pack(pady=10)

    def pick_encrypt_files(self):
        files = filedialog.askopenfilenames(title="Select files to encrypt")
        if files:
            self.encrypt_files = list(files)
            self.encrypt_listbox.delete(0, tk.END)
            for f in self.encrypt_files:
                self.encrypt_listbox.insert(tk.END, os.path.basename(f))

    def update_strength_meter(self, event=None):
        pwd = self.encrypt_password.get()
        if not pwd:
            self.strength_bar["value"] = 0
            self.strength_label.config(text="")
            return
        rating, color, percent = password_strength_score(pwd)
        self.strength_bar["value"] = percent
        self.strength_label.config(text=rating, fg=color)

    def toggle_visibility(self, entry, button):
        if entry.cget("show") == "*":
            entry.config(show="")
            button.config(text="Hide")
        else:
            entry.config(show="*")
            button.config(text="Show")

    def handle_encrypt(self):
        try:
            self._do_encrypt()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_encrypt(self):
        if not self.encrypt_files:
            self.encrypt_status.config(text="Select at least one file first", fg="#c0392b")
            return
        password = self.encrypt_password.get()
        if len(password) < 8:
            self.encrypt_status.config(text="Passphrase must be at least 8 characters", fg="#c0392b")
            return

        self.encrypt_progress["maximum"] = len(self.encrypt_files)
        self.encrypt_progress["value"] = 0
        results = []

        for path in self.encrypt_files:
            try:
                output_path = encrypt_file(path, password, delete_original=self.delete_original_var.get())
                log_action(path, "Encrypt", True, f"-> {os.path.basename(output_path)}")
                results.append(f"✓ {os.path.basename(path)}")
            except Exception as e:
                log_action(path, "Encrypt", False, str(e))
                results.append(f"✗ {os.path.basename(path)} — {e}")
            self.encrypt_progress["value"] += 1
            self.root.update_idletasks()

        self.encrypt_status.config(text="\n".join(results), fg=self.colors["fg"])
        self.encrypt_files = []
        self.encrypt_listbox.delete(0, tk.END)
        self.refresh_log()

    # ---------- Decrypt tab ----------

    def build_decrypt_tab(self):
        f = self.decrypt_tab
        tk.Label(f, text="Decrypt Files", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 10))

        tk.Button(f, text=f"Select {ENCRYPTED_EXTENSION} Files...", command=self.pick_decrypt_files,
                  font=("Segoe UI", 10)).pack(pady=5)

        self.decrypt_listbox = tk.Listbox(f, width=60, height=6, font=("Segoe UI", 9))
        self.decrypt_listbox.pack(pady=10, padx=30)

        tk.Label(f, text="Passphrase", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=30)
        pwd_frame = tk.Frame(f, bg=self.colors["card"])
        pwd_frame.pack(pady=(0, 10), padx=30, fill="x")
        self.decrypt_password = tk.Entry(pwd_frame, font=("Segoe UI", 11), width=28, show="*")
        self.decrypt_password.pack(side="left")
        toggle_btn = tk.Button(pwd_frame, text="Show", font=("Segoe UI", 8), width=6)
        toggle_btn.config(command=lambda: self.toggle_visibility(self.decrypt_password, toggle_btn))
        toggle_btn.pack(side="left", padx=(8, 0))

        self.decrypt_progress = ttk.Progressbar(f, length=400, mode="determinate")
        self.decrypt_progress.pack(pady=10, padx=30)

        self.decrypt_status = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"],
                                        fg="#c0392b", wraplength=450, justify="left")
        self.decrypt_status.pack(pady=5, padx=30)

        tk.Button(f, text="Decrypt Selected Files", command=self.handle_decrypt,
                  font=("Segoe UI", 11, "bold"), bg="#27ae60", fg="white", width=25).pack(pady=10)

    def pick_decrypt_files(self):
        files = filedialog.askopenfilenames(
            title="Select encrypted files",
            filetypes=[(f"{ENCRYPTED_EXTENSION} files", f"*{ENCRYPTED_EXTENSION}"), ("All files", "*.*")]
        )
        if files:
            self.decrypt_files = list(files)
            self.decrypt_listbox.delete(0, tk.END)
            for f in self.decrypt_files:
                self.decrypt_listbox.insert(tk.END, os.path.basename(f))

    def handle_decrypt(self):
        try:
            self._do_decrypt()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_decrypt(self):
        if not self.decrypt_files:
            self.decrypt_status.config(text="Select at least one encrypted file first", fg="#c0392b")
            return
        password = self.decrypt_password.get()
        if not password:
            self.decrypt_status.config(text="Enter the passphrase", fg="#c0392b")
            return

        output_dir = filedialog.askdirectory(title="Choose where to save decrypted files")
        if not output_dir:
            return

        self.decrypt_progress["maximum"] = len(self.decrypt_files)
        self.decrypt_progress["value"] = 0
        results = []

        for path in self.decrypt_files:
            try:
                output_path, integrity_ok = decrypt_file(path, password, output_dir)
                tag = "✓ integrity verified" if integrity_ok else "⚠ integrity check FAILED"
                log_action(path, "Decrypt", True, f"-> {os.path.basename(output_path)} ({tag})")
                results.append(f"✓ {os.path.basename(path)} — {tag}")
            except ValueError as e:
                log_action(path, "Decrypt", False, str(e))
                results.append(f"✗ {os.path.basename(path)} — {e}")
            except Exception as e:
                log_action(path, "Decrypt", False, str(e))
                results.append(f"✗ {os.path.basename(path)} — {e}")
            self.decrypt_progress["value"] += 1
            self.root.update_idletasks()

        self.decrypt_status.config(text="\n".join(results), fg=self.colors["fg"])
        self.decrypt_files = []
        self.decrypt_listbox.delete(0, tk.END)
        self.refresh_log()

    # ---------- Log tab ----------

    def build_log_tab(self):
        f = self.log_tab
        tk.Label(f, text="File Activity Log", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("filename", "action", "timestamp", "result", "detail")
        self.log_tree = ttk.Treeview(f, columns=columns, show="headings", height=15)
        widths = (110, 70, 130, 60, 180)
        for col, width in zip(columns, widths):
            self.log_tree.heading(col, text=col.capitalize())
            self.log_tree.column(col, width=width)
        self.log_tree.pack(padx=15, pady=5, fill="both", expand=True)

        tk.Button(f, text="Refresh", command=self.refresh_log, font=("Segoe UI", 9)).pack(pady=5)
        self.refresh_log()

    def refresh_log(self):
        for row in self.log_tree.get_children():
            self.log_tree.delete(row)
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT filename, action, timestamp, success, detail FROM file_log ORDER BY id DESC LIMIT 30")
        rows = cur.fetchall()
        conn.close()
        for filename, action, timestamp, success, detail in rows:
            result = "Success" if success else "Failed"
            self.log_tree.insert("", "end", values=(filename, action, timestamp, result, detail))

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()


if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()