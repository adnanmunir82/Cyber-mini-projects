import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import secrets
import re
import time
from datetime import datetime, timedelta

APP_NAME = "Adnan's Login Authentication System"
DB_FILE = "auth_system.db"

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
PBKDF2_ITERATIONS = 100_000

# In-memory tracking of failed attempts per username (resets on app restart —
# acceptable for a portfolio demo; a production system would persist this)
failed_attempts = {}   # {username: [count, lockout_until_timestamp]}

# ---------------- Database setup ----------------

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            success INTEGER NOT NULL,
            detail TEXT
        )
    """)
    conn.commit()
    conn.close()


def get_connection():
    return sqlite3.connect(DB_FILE)


# ---------------- Security core ----------------

def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256 with a unique random salt per user."""
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    )
    return salt, pwd_hash.hex()


def verify_password(password, salt, stored_hash):
    _, computed_hash = hash_password(password, salt)
    # Constant-time comparison prevents timing attacks
    return secrets.compare_digest(computed_hash, stored_hash)


def check_password_policy(password):
    """Reused/extended from Project 1's strength logic — enforced at signup."""
    issues = []
    if len(password) < 8:
        issues.append("At least 8 characters")
    if not re.search(r'[a-z]', password):
        issues.append("At least one lowercase letter")
    if not re.search(r'[A-Z]', password):
        issues.append("At least one uppercase letter")
    if not re.search(r'\d', password):
        issues.append("At least one number")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=]', password):
        issues.append("At least one symbol")
    return issues


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


def log_attempt(username, success, detail=""):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO login_log (username, timestamp, success, detail) VALUES (?, ?, ?, ?)",
        (username, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), int(success), detail)
    )
    conn.commit()
    conn.close()


# ---------------- Auth logic ----------------

def signup_user(username, password, confirm_password):
    username = username.strip()

    if not username or not password:
        return False, "Username and password cannot be empty"
    if password != confirm_password:
        return False, "Passwords do not match"

    policy_issues = check_password_policy(password)
    if policy_issues:
        return False, "Password requirements not met:\n- " + "\n- ".join(policy_issues)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return False, "That username is already taken"

    salt, pwd_hash = hash_password(password)
    cur.execute(
        "INSERT INTO users (username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, salt, pwd_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    return True, "Account created successfully. You can now log in."


def is_locked_out(username):
    record = failed_attempts.get(username)
    if not record:
        return False, 0
    count, lockout_until = record
    if lockout_until and time.time() < lockout_until:
        remaining = int(lockout_until - time.time())
        return True, remaining
    return False, 0


def login_user(username, password):
    username = username.strip()

    locked, remaining = is_locked_out(username)
    if locked:
        log_attempt(username, False, f"Blocked — locked out ({remaining}s remaining)")
        return False, f"Too many failed attempts. Try again in {remaining} seconds."

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT salt, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    # Deliberately generic message — never reveal whether the username exists
    generic_error = "Invalid username or password"

    if not row:
        _register_failed_attempt(username)
        log_attempt(username, False, "Unknown username")
        return False, generic_error

    salt, stored_hash = row
    if verify_password(password, salt, stored_hash):
        failed_attempts.pop(username, None)  # reset on success
        log_attempt(username, True, "Login successful")
        return True, "Login successful"
    else:
        _register_failed_attempt(username)
        log_attempt(username, False, "Wrong password")
        return False, generic_error


def _register_failed_attempt(username):
    count, _ = failed_attempts.get(username, [0, 0])
    count += 1
    lockout_until = 0
    if count >= MAX_FAILED_ATTEMPTS:
        lockout_until = time.time() + LOCKOUT_SECONDS
    failed_attempts[username] = [count, lockout_until]


# ---------------- GUI ----------------

class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("520x600")
        self.root.resizable(False, False)

        self.dark_mode = False
        self.session_user = None
        self.session_start = None

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.colors = self.colors_light

        self.build_ui()

    # ---------- UI construction ----------

    def build_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.configure(bg=self.colors["bg"])

        top_bar = tk.Frame(self.root, bg=self.colors["bg"])
        top_bar.pack(fill="x", pady=(10, 0), padx=15)

        tk.Label(top_bar, text=APP_NAME, font=("Segoe UI", 14, "bold"),
                 bg=self.colors["bg"], fg=self.colors["fg"]).pack(side="left")

        self.theme_btn = tk.Button(top_bar, text="🌙 Dark Mode", command=self.toggle_theme,
                                    font=("Segoe UI", 9))
        self.theme_btn.pack(side="right")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=15)

        self.login_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.signup_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.log_tab = tk.Frame(self.notebook, bg=self.colors["card"])

        self.notebook.add(self.login_tab, text="Login")
        self.notebook.add(self.signup_tab, text="Sign Up")
        self.notebook.add(self.log_tab, text="Activity Log")

        self.build_login_tab()
        self.build_signup_tab()
        self.build_log_tab()

    def build_login_tab(self):
        f = self.login_tab
        for widget in f.winfo_children():
            widget.destroy()

        if self.session_user:
            tk.Label(f, text="✅ Session Active", font=("Segoe UI", 13, "bold"),
                     bg=self.colors["card"], fg="#27ae60").pack(pady=(30, 10))
            tk.Label(f, text=f"Logged in as: {self.session_user}", font=("Segoe UI", 11),
                     bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=5)
            tk.Label(f, text=f"Session started: {self.session_start}", font=("Segoe UI", 9),
                     bg=self.colors["card"], fg="#7f8c8d").pack(pady=5)
            tk.Button(f, text="Logout", command=self.logout, font=("Segoe UI", 10, "bold"),
                      bg="#c0392b", fg="white", width=15).pack(pady=20)
            return

        tk.Label(f, text="Log In", font=("Segoe UI", 16, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(25, 15))

        tk.Label(f, text="Username", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=40)
        self.login_username = tk.Entry(f, font=("Segoe UI", 11), width=30)
        self.login_username.pack(pady=(0, 10), padx=40)

        tk.Label(f, text="Password", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=40)
        login_pwd_frame = tk.Frame(f, bg=self.colors["card"])
        login_pwd_frame.pack(pady=(0, 5), padx=40, fill="x")
        self.login_password = tk.Entry(login_pwd_frame, font=("Segoe UI", 11), width=24, show="*")
        self.login_password.pack(side="left")
        self.login_password.bind("<Return>", lambda e: self.handle_login())
        login_toggle_btn = tk.Button(login_pwd_frame, text="Show", font=("Segoe UI", 8), width=6)
        login_toggle_btn.config(command=lambda: self.toggle_password_visibility(self.login_password, login_toggle_btn))
        login_toggle_btn.pack(side="left", padx=(8, 0))

        self.login_status = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"],
                                      fg="#c0392b", wraplength=380, justify="left")
        self.login_status.pack(pady=10, padx=40)

        tk.Button(f, text="Log In", command=self.handle_login, font=("Segoe UI", 11, "bold"),
                  bg="#2980b9", fg="white", width=20).pack(pady=10)

    def build_signup_tab(self):
        f = self.signup_tab

        tk.Label(f, text="Create Account", font=("Segoe UI", 16, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(25, 15))

        tk.Label(f, text="Username", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=40)
        self.signup_username = tk.Entry(f, font=("Segoe UI", 11), width=30)
        self.signup_username.pack(pady=(0, 10), padx=40)

        tk.Label(f, text="Password", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=40)
        signup_pwd_frame = tk.Frame(f, bg=self.colors["card"])
        signup_pwd_frame.pack(pady=(0, 5), padx=40, fill="x")
        self.signup_password = tk.Entry(signup_pwd_frame, font=("Segoe UI", 11), width=24, show="*")
        self.signup_password.pack(side="left")
        self.signup_password.bind("<KeyRelease>", self.update_strength_meter)
        signup_toggle_btn = tk.Button(signup_pwd_frame, text="Show", font=("Segoe UI", 8), width=6)
        signup_toggle_btn.config(command=lambda: self.toggle_password_visibility(self.signup_password, signup_toggle_btn))
        signup_toggle_btn.pack(side="left", padx=(8, 0))

        self.strength_bar = ttk.Progressbar(f, length=300, maximum=100, value=0)
        self.strength_bar.pack(pady=(5, 2), padx=40)
        self.strength_label = tk.Label(f, text="", font=("Segoe UI", 9, "bold"), bg=self.colors["card"])
        self.strength_label.pack(pady=(0, 10))

        tk.Label(f, text="Confirm Password", bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=40)
        confirm_pwd_frame = tk.Frame(f, bg=self.colors["card"])
        confirm_pwd_frame.pack(pady=(0, 10), padx=40, fill="x")
        self.signup_confirm = tk.Entry(confirm_pwd_frame, font=("Segoe UI", 11), width=24, show="*")
        self.signup_confirm.pack(side="left")
        confirm_toggle_btn = tk.Button(confirm_pwd_frame, text="Show", font=("Segoe UI", 8), width=6)
        confirm_toggle_btn.config(command=lambda: self.toggle_password_visibility(self.signup_confirm, confirm_toggle_btn))
        confirm_toggle_btn.pack(side="left", padx=(8, 0))

        self.signup_status = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"],
                                       fg="#c0392b", wraplength=380, justify="left")
        self.signup_status.pack(pady=5, padx=40)

        tk.Button(f, text="Sign Up", command=self.handle_signup, font=("Segoe UI", 11, "bold"),
                  bg="#27ae60", fg="white", width=20).pack(pady=10)

    def build_log_tab(self):
        f = self.log_tab
        tk.Label(f, text="Recent Login Activity", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("username", "timestamp", "result", "detail")
        self.log_tree = ttk.Treeview(f, columns=columns, show="headings", height=15)
        for col, width in zip(columns, (110, 140, 70, 160)):
            self.log_tree.heading(col, text=col.capitalize())
            self.log_tree.column(col, width=width)
        self.log_tree.pack(padx=15, pady=5, fill="both", expand=True)

        tk.Button(f, text="Refresh", command=self.refresh_log, font=("Segoe UI", 9)).pack(pady=5)
        self.refresh_log()

    # ---------- Event handlers ----------

    def toggle_password_visibility(self, entry, button):
        if entry.cget("show") == "*":
            entry.config(show="")
            button.config(text="Hide")
        else:
            entry.config(show="*")
            button.config(text="Show")

    def update_strength_meter(self, event=None):
        pwd = self.signup_password.get()
        if not pwd:
            self.strength_bar["value"] = 0
            self.strength_label.config(text="")
            return
        rating, color, percent = password_strength_score(pwd)
        self.strength_bar["value"] = percent
        self.strength_label.config(text=rating, fg=color)

    def handle_signup(self):
        try:
            self._do_signup()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_signup(self):
        username = self.signup_username.get()
        password = self.signup_password.get()
        confirm = self.signup_confirm.get()

        success, message = signup_user(username, password, confirm)
        self.signup_status.config(text=message, fg="#27ae60" if success else "#c0392b")

        if success:
            self.signup_username.delete(0, tk.END)
            self.signup_password.delete(0, tk.END)
            self.signup_confirm.delete(0, tk.END)
            self.strength_bar["value"] = 0
            self.strength_label.config(text="")
            self.notebook.select(self.login_tab)

    def handle_login(self):
        try:
            self._do_login()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_login(self):
        username = self.login_username.get()
        password = self.login_password.get()

        if not username or not password:
            self.login_status.config(text="Enter both username and password")
            return

        success, message = login_user(username, password)

        if success:
            self.session_user = username
            self.session_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.login_status.config(text="")
            self.build_login_tab()
        else:
            self.login_status.config(text=message)
            self.login_password.delete(0, tk.END)

        self.refresh_log()

    def logout(self):
        log_attempt(self.session_user, True, "Logged out")
        self.session_user = None
        self.session_start = None
        self.build_login_tab()
        self.refresh_log()

    def refresh_log(self):
        for row in self.log_tree.get_children():
            self.log_tree.delete(row)
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, timestamp, success, detail FROM login_log ORDER BY id DESC LIMIT 30")
        rows = cur.fetchall()
        conn.close()
        for username, timestamp, success, detail in rows:
            result = "Success" if success else "Failed"
            self.log_tree.insert("", "end", values=(username, timestamp, result, detail))

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.theme_btn.config(text="☀ Light Mode" if self.dark_mode else "🌙 Dark Mode")
        self.build_ui()


# ---------------- Run ----------------

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()