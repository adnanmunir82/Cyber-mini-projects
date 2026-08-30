import tkinter as tk
from tkinter import ttk
import re
import math

APP_NAME = "Adnan's Password Strength Checker"

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "123123", "letmein", "iloveyou",
    "admin", "welcome", "monkey", "dragon", "football"
}

def has_sequential_chars(password, length=3):
    """Detects sequences like 'abc', '123', 'xyz'."""
    pwd = password.lower()
    for i in range(len(pwd) - length + 1):
        chunk = pwd[i:i + length]
        if all(ord(chunk[j]) + 1 == ord(chunk[j + 1]) for j in range(len(chunk) - 1)):
            return True
    return False

def has_repeated_chars(password, repeat_count=3):
    """Detects repeats like 'aaa', '111'."""
    for i in range(len(password) - repeat_count + 1):
        if len(set(password[i:i + repeat_count])) == 1:
            return True
    return False

def check_password_strength(password):
    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=~`]', password))
    is_common = password.lower() in COMMON_PASSWORDS
    is_sequential = has_sequential_chars(password)
    is_repeated = has_repeated_chars(password)

    score = 0
    feedback = []

    if length == 0:
        return 0, "None", 0, ["Start typing a password..."], "#7f8c8d"

    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters (12+ recommended)")

    if has_lower:
        score += 1
    else:
        feedback.append("Add lowercase letters (a-z)")

    if has_upper:
        score += 1
    else:
        feedback.append("Add uppercase letters (A-Z)")

    if has_digit:
        score += 1
    else:
        feedback.append("Add numbers (0-9)")

    if has_symbol:
        score += 1
    else:
        feedback.append("Add symbols (!@#$%^&* etc.)")

    if is_common:
        score = 0
        feedback.insert(0, "This is a commonly used password — avoid it entirely")

    if is_sequential:
        score = max(0, score - 2)
        feedback.append("Avoid sequential characters (abc, 123)")

    if is_repeated:
        score = max(0, score - 1)
        feedback.append("Avoid repeated characters (aaa, 111)")

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32
    entropy = length * math.log2(pool_size) if pool_size > 0 else 0

    max_score = 7
    percent = min(100, int((score / max_score) * 100))

    if is_common:
        rating, color = "Unsafe", "#c0392b"
    elif score <= 2:
        rating, color = "Weak", "#e74c3c"
    elif score <= 4:
        rating, color = "Medium", "#f39c12"
    elif score <= 5:
        rating, color = "Strong", "#27ae60"
    else:
        rating, color = "Very Strong", "#16a085"

    if not feedback:
        feedback = ["Excellent! This password follows all best practices."]

    return score, rating, entropy, feedback, color, percent


def on_check(*args):
    pwd = entry.get()
    result = check_password_strength(pwd)

    if len(result) == 5:  # empty password case
        _, rating, entropy, feedback, color = result
        percent = 0
    else:
        _, rating, entropy, feedback, color, percent = result

    result_label.config(text=f"{rating}", fg=color)
    entropy_label.config(text=f"Entropy: {entropy:.1f} bits")
    feedback_text.config(state="normal")
    feedback_text.delete("1.0", tk.END)
    feedback_text.insert(tk.END, "\n".join(f"• {tip}" for tip in feedback))
    feedback_text.config(state="disabled")

    progress_bar["value"] = percent
    style.configure("Colored.Horizontal.TProgressbar", background=color)


def toggle_visibility():
    if entry.cget("show") == "*":
        entry.config(show="")
        toggle_btn.config(text="Hide")
    else:
        entry.config(show="*")
        toggle_btn.config(text="Show")


# --- Build the window ---
window = tk.Tk()
window.title(APP_NAME)
window.geometry("460x420")
window.resizable(False, False)
window.configure(bg="#f4f6f7")

title_label = tk.Label(window, text=APP_NAME, font=("Segoe UI", 15, "bold"), bg="#f4f6f7")
title_label.pack(pady=(20, 15))

input_frame = tk.Frame(window, bg="#f4f6f7")
input_frame.pack(pady=5)

entry = tk.Entry(input_frame, show="*", width=28, font=("Segoe UI", 12))
entry.pack(side="left", padx=(0, 8))
entry.bind("<KeyRelease>", on_check)

toggle_btn = tk.Button(input_frame, text="Show", command=toggle_visibility, font=("Segoe UI", 9))
toggle_btn.pack(side="left")

style = ttk.Style()
style.theme_use("default")
style.configure("Colored.Horizontal.TProgressbar", thickness=18)

progress_bar = ttk.Progressbar(window, style="Colored.Horizontal.TProgressbar",
                                length=380, maximum=100, value=0)
progress_bar.pack(pady=15)

result_label = tk.Label(window, text="", font=("Segoe UI", 16, "bold"), bg="#f4f6f7")
result_label.pack()

entropy_label = tk.Label(window, text="Entropy: -- bits", font=("Segoe UI", 9), bg="#f4f6f7", fg="#555")
entropy_label.pack(pady=(2, 15))

feedback_text = tk.Text(window, height=8, width=48, font=("Segoe UI", 10),
                         bg="white", relief="solid", bd=1, wrap="word")
feedback_text.pack(padx=20)
feedback_text.config(state="disabled")

window.mainloop()