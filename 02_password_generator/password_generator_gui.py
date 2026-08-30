import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string
import json
import os
import math
from datetime import datetime

APP_NAME = "Adnan's Password Generator"
VAULT_FILE = "password_vault.json"

# ---------------- Core generation logic ----------------

def generate_password(length, use_lower, use_upper, use_digits, use_symbols):
    pools = []
    guaranteed = []

    if use_lower:
        pools.append(string.ascii_lowercase)
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        pools.append(string.ascii_uppercase)
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pools.append(string.digits)
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pools.append(symbols)
        guaranteed.append(secrets.choice(symbols))

    if not pools:
        return None, "Select at least one character type"

    if length < len(guaranteed):
        return None, f"Length must be at least {len(guaranteed)} for selected options"

    all_chars = "".join(pools)
    remaining_length = length - len(guaranteed)
    password_chars = guaranteed + [secrets.choice(all_chars) for _ in range(remaining_length)]

    # Shuffle securely so guaranteed chars aren't always at the start
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars), None


def calculate_strength(password, use_lower, use_upper, use_digits, use_symbols):
    pool_size = 0
    if use_lower: pool_size += 26
    if use_upper: pool_size += 26
    if use_digits: pool_size += 10
    if use_symbols: pool_size += 27
    entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0

    if entropy < 40:
        return "Weak", "#e74c3c", entropy
    elif entropy < 60:
        return "Medium", "#f39c12", entropy
    elif entropy < 80:
        return "Strong", "#27ae60", entropy
    else:
        return "Very Strong", "#16a085", entropy


# ---------------- Vault (save/load) logic ----------------

def load_vault():
    if not os.path.exists(VAULT_FILE):
        return []
    try:
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def save_vault(entries):
    with open(VAULT_FILE, "w") as f:
        json.dump(entries, f, indent=2)


# ---------------- GUI logic ----------------

def on_generate():
    try:
        length = int(length_var.get())
    except ValueError:
        messagebox.showerror("Invalid length", "Length must be a number")
        return

    pwd, error = generate_password(
        length,
        lower_var.get(), upper_var.get(), digit_var.get(), symbol_var.get()
    )

    if error:
        messagebox.showerror("Cannot generate", error)
        return

    password_var.set(pwd)
    rating, color, entropy = calculate_strength(
        pwd, lower_var.get(), upper_var.get(), digit_var.get(), symbol_var.get()
    )
    strength_label.config(text=f"{rating}  ({entropy:.0f} bits entropy)", fg=color)


def on_copy():
    pwd = password_var.get()
    if not pwd:
        messagebox.showwarning("Nothing to copy", "Generate a password first")
        return
    window.clipboard_clear()
    window.clipboard_append(pwd)
    messagebox.showinfo("Copied", "Password copied to clipboard")


def on_save():
    pwd = password_var.get()
    label = label_var.get().strip()

    if not pwd:
        messagebox.showwarning("Nothing to save", "Generate a password first")
        return
    if not label:
        messagebox.showwarning("Label required", "Enter what this password is for (e.g. Gmail)")
        return

    entries = load_vault()
    entries.append({
        "label": label,
        "password": pwd,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M")
    })
    save_vault(entries)
    label_var.set("")
    messagebox.showinfo("Saved", f"Password saved for '{label}'")
    refresh_vault_list()


def refresh_vault_list():
    vault_list.delete(0, tk.END)
    entries = load_vault()
    for e in entries:
        vault_list.insert(tk.END, f"{e['label']}   —   {e['created']}")


def on_view_selected(event):
    selection = vault_list.curselection()
    if not selection:
        return
    entries = load_vault()
    entry = entries[selection[0]]
    reveal_win = tk.Toplevel(window)
    reveal_win.title(entry["label"])
    reveal_win.geometry("360x120")
    tk.Label(reveal_win, text=f"For: {entry['label']}", font=("Segoe UI", 11, "bold")).pack(pady=(15, 5))
    pwd_display = tk.Entry(reveal_win, font=("Consolas", 12), justify="center", width=30)
    pwd_display.insert(0, entry["password"])
    pwd_display.config(state="readonly")
    pwd_display.pack(pady=5)

    def copy_this():
        window.clipboard_clear()
        window.clipboard_append(entry["password"])

    tk.Button(reveal_win, text="Copy", command=copy_this).pack(pady=5)


def on_delete_selected():
    selection = vault_list.curselection()
    if not selection:
        messagebox.showwarning("Nothing selected", "Select a saved password to delete")
        return
    entries = load_vault()
    confirm = messagebox.askyesno("Confirm delete", f"Delete password for '{entries[selection[0]]['label']}'?")
    if confirm:
        del entries[selection[0]]
        save_vault(entries)
        refresh_vault_list()


# ---------------- Build window ----------------

window = tk.Tk()
window.title(APP_NAME)
window.geometry("480x620")
window.resizable(False, False)
window.configure(bg="#f4f6f7")

tk.Label(window, text=APP_NAME, font=("Segoe UI", 15, "bold"), bg="#f4f6f7").pack(pady=(20, 10))

# --- Generated password display ---
password_var = tk.StringVar()
pwd_display = tk.Entry(window, textvariable=password_var, font=("Consolas", 14),
                        justify="center", width=32, state="readonly")
pwd_display.pack(pady=5)

strength_label = tk.Label(window, text="", font=("Segoe UI", 10, "bold"), bg="#f4f6f7")
strength_label.pack(pady=(0, 10))

btn_frame = tk.Frame(window, bg="#f4f6f7")
btn_frame.pack(pady=5)
tk.Button(btn_frame, text="Generate", command=on_generate, font=("Segoe UI", 10, "bold"),
          bg="#2980b9", fg="white", width=12).pack(side="left", padx=5)
tk.Button(btn_frame, text="Copy", command=on_copy, font=("Segoe UI", 10), width=12).pack(side="left", padx=5)

# --- Options ---
options_frame = tk.LabelFrame(window, text="Options", bg="#f4f6f7", font=("Segoe UI", 10, "bold"), padx=15, pady=10)
options_frame.pack(pady=15, padx=20, fill="x")

length_frame = tk.Frame(options_frame, bg="#f4f6f7")
length_frame.pack(fill="x", pady=5)
tk.Label(length_frame, text="Length:", bg="#f4f6f7").pack(side="left")
length_var = tk.IntVar(value=16)
length_scale = tk.Scale(length_frame, from_=8, to=64, orient="horizontal", variable=length_var,
                         bg="#f4f6f7", length=250)
length_scale.pack(side="left", padx=10)

lower_var = tk.BooleanVar(value=True)
upper_var = tk.BooleanVar(value=True)
digit_var = tk.BooleanVar(value=True)
symbol_var = tk.BooleanVar(value=True)

tk.Checkbutton(options_frame, text="Lowercase (a-z)", variable=lower_var, bg="#f4f6f7").pack(anchor="w")
tk.Checkbutton(options_frame, text="Uppercase (A-Z)", variable=upper_var, bg="#f4f6f7").pack(anchor="w")
tk.Checkbutton(options_frame, text="Digits (0-9)", variable=digit_var, bg="#f4f6f7").pack(anchor="w")
tk.Checkbutton(options_frame, text="Symbols (!@#$%)", variable=symbol_var, bg="#f4f6f7").pack(anchor="w")

# --- Save section ---
save_frame = tk.LabelFrame(window, text="Save this password", bg="#f4f6f7", font=("Segoe UI", 10, "bold"),
                            padx=15, pady=10)
save_frame.pack(pady=10, padx=20, fill="x")

label_var = tk.StringVar()
tk.Label(save_frame, text="What is this for? (e.g. Gmail, Instagram)", bg="#f4f6f7", font=("Segoe UI", 9)).pack(anchor="w")
tk.Entry(save_frame, textvariable=label_var, font=("Segoe UI", 10), width=35).pack(pady=5)
tk.Button(save_frame, text="Save to Vault", command=on_save, font=("Segoe UI", 10),
          bg="#27ae60", fg="white").pack(pady=5)

# --- Vault list ---
vault_frame = tk.LabelFrame(window, text="Saved Passwords", bg="#f4f6f7", font=("Segoe UI", 10, "bold"),
                             padx=10, pady=10)
vault_frame.pack(pady=10, padx=20, fill="both", expand=True)

vault_list = tk.Listbox(vault_frame, font=("Segoe UI", 10), height=6)
vault_list.pack(fill="both", expand=True, pady=(0, 5))
vault_list.bind("<Double-Button-1>", on_view_selected)

tk.Button(vault_frame, text="Delete Selected", command=on_delete_selected,
          font=("Segoe UI", 9), fg="white", bg="#c0392b").pack()

refresh_vault_list()
on_generate()  # Generate one password on startup

window.mainloop()