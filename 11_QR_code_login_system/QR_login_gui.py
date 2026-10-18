import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime
from PIL import ImageTk

from qr_login_core import (
    init_db, register_user, get_registered_user, create_session, get_session_status,
    approve_session, consume_session, generate_qr_image
)
from web_server import run_server, get_local_ip

APP_NAME = "Adnan's QR Code Login System"
SERVER_PORT = 5000


class QRLoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("520x680")
        self.root.resizable(False, False)

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.dark_mode = False
        self.colors = self.colors_light

        self.current_token = None
        self.current_expiry = None
        self.qr_photo = None
        self.logged_in_user = None
        self.local_ip = get_local_ip()

        init_db()
        self._start_server_once()
        self.build_ui()
        self.tick()

    def _start_server_once(self):
        server_thread = threading.Thread(
            target=run_server, kwargs={"host": "0.0.0.0", "port": SERVER_PORT}, daemon=True
        )
        server_thread.start()
        time.sleep(0.5)  # brief pause so the server is ready before the first QR is shown

    def build_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.configure(bg=self.colors["bg"])

        top_bar = tk.Frame(self.root, bg=self.colors["bg"])
        top_bar.pack(fill="x", pady=(10, 0), padx=15)
        tk.Label(top_bar, text=APP_NAME, font=("Segoe UI", 13, "bold"),
                 bg=self.colors["bg"], fg=self.colors["fg"]).pack(side="left")
        tk.Button(top_bar, text="🌙 Dark Mode", command=self.toggle_theme, font=("Segoe UI", 9)).pack(side="right")

        registered = get_registered_user()
        if not registered:
            self._build_registration_screen()
        else:
            self.registered_user = registered
            self._build_login_screen()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()

    # ---------- First-run registration ----------

    def _build_registration_screen(self):
        card = tk.Frame(self.root, bg=self.colors["card"])
        card.pack(expand=True, fill="both", padx=15, pady=15)

        tk.Label(card, text="Set up this account", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(40, 10))
        tk.Label(card, text="This name will appear on the approval page your phone shows.",
                 font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d", wraplength=350).pack(pady=(0, 15))

        self.reg_entry = tk.Entry(card, font=("Segoe UI", 11), width=25)
        self.reg_entry.pack(pady=5)
        tk.Button(card, text="Continue", command=self.handle_register,
                  font=("Segoe UI", 10, "bold"), bg="#27ae60", fg="white").pack(pady=15)

    def handle_register(self):
        username = self.reg_entry.get().strip()
        ok, msg = register_user(username)
        if ok:
            self.build_ui()
        else:
            messagebox.showerror("Could not register", msg)

    # ---------- Main QR login screen ----------

    def _build_login_screen(self):
        card = tk.Frame(self.root, bg=self.colors["card"])
        card.pack(expand=True, fill="both", padx=15, pady=10)

        tk.Label(card, text=f"Scan to log in as {self.registered_user}", font=("Segoe UI", 13, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(15, 5))

        tk.Label(card, text="Open your phone's camera and point it at the code below.\n"
                             "Your phone and this computer must be on the same Wi-Fi network.",
                 font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d", justify="center").pack(pady=(0, 10))

        self.qr_label = tk.Label(card, bg=self.colors["card"])
        self.qr_label.pack(pady=10)

        self.url_label = tk.Label(card, text="", font=("Consolas", 8), bg=self.colors["card"], fg="#7f8c8d")
        self.url_label.pack()

        self.status_label = tk.Label(card, text="", font=("Segoe UI", 12, "bold"), bg=self.colors["card"])
        self.status_label.pack(pady=(15, 5))

        self.countdown_label = tk.Label(card, text="", font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d")
        self.countdown_label.pack()

        tk.Button(card, text="Generate New QR Code", command=self.start_new_session,
                  font=("Segoe UI", 10, "bold"), bg="#2980b9", fg="white").pack(pady=15)

        self.logged_in_label = tk.Label(card, text="", font=("Segoe UI", 13, "bold"),
                                         bg=self.colors["card"], fg="#27ae60")
        self.logged_in_label.pack(pady=10)

        tk.Label(card, text="No phone handy? Use this to test the flow yourself:",
                 font=("Segoe UI", 8), bg=self.colors["card"], fg="#bbb").pack(pady=(20, 2))
        tk.Button(card, text="Simulate Approval (testing only)", command=self.handle_simulate_approval,
                  font=("Segoe UI", 8), fg="#7f8c8d").pack()

        self.start_new_session()

    def start_new_session(self):
        self.logged_in_user = None
        self.logged_in_label.config(text="")
        token, expiry = create_session(expiry_seconds=120)
        self.current_token = token
        self.current_expiry = expiry

        url = f"http://{self.local_ip}:{SERVER_PORT}/approve/{token}"
        img = generate_qr_image(url)
        self.qr_photo = ImageTk.PhotoImage(img)
        self.qr_label.config(image=self.qr_photo)
        self.url_label.config(text=url)
        self.status_label.config(text="Waiting for approval...", fg="#f39c12")

    def handle_simulate_approval(self):
        """Dev/testing convenience — approves the current session directly, standing in for a real phone tap."""
        if not self.current_token:
            return
        approve_session(self.current_token, self.registered_user)

    # ---------- Polling loop (local DB reads only — safe on the main thread) ----------

    def tick(self):
        if self.current_token and self.logged_in_user is None and hasattr(self, "status_label"):
            status = get_session_status(self.current_token)
            if status is None:
                pass
            elif status["status"] == "approved":
                ok, username = consume_session(self.current_token)
                if ok:
                    self.logged_in_user = username
                    self.status_label.config(text="Approved!", fg="#27ae60")
                    self.logged_in_label.config(text=f"✅ Logged in as {username}")
                    self.countdown_label.config(text="")
            elif status["status"] == "denied":
                self.status_label.config(text="Login denied on phone", fg="#c0392b")
                self.countdown_label.config(text="")
            elif status["status"] == "expired":
                self.status_label.config(text="QR code expired — generating a new one...", fg="#c0392b")
                self.root.after(1000, self.start_new_session)
            elif status["status"] == "pending":
                remaining = (self.current_expiry - datetime.now()).total_seconds()
                if remaining > 0:
                    mins, secs = divmod(int(remaining), 60)
                    self.countdown_label.config(text=f"Expires in {mins}:{secs:02d}")

        self.root.after(1000, self.tick)


if __name__ == "__main__":
    root = tk.Tk()
    app = QRLoginApp(root)
    root.mainloop()