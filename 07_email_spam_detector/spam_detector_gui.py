import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
import json
import numpy as np
import joblib
from datetime import datetime

APP_NAME = "Adnan's Email Spam Detector"
DB_FILE = "spam_history.db"
MODEL_PATH = "spam_model.joblib"
VECTORIZER_PATH = "vectorizer.joblib"
METRICS_PATH = "model_metrics.json"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_check(message, prediction, confidence):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    truncated = message[:200]
    cur.execute("INSERT INTO history (message, prediction, confidence, timestamp) VALUES (?, ?, ?, ?)",
                (truncated, prediction, confidence, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


class SpamClassifier:
    """Wraps the trained model + vectorizer and provides prediction + explanation."""

    def __init__(self):
        if not (os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH)):
            raise FileNotFoundError(
                "Trained model files not found. Run 'python train_spam_model.py' first "
                "to train the model before launching the app."
            )
        self.model = joblib.load(MODEL_PATH)
        self.vectorizer = joblib.load(VECTORIZER_PATH)
        self.feature_names = self.vectorizer.get_feature_names_out()
        self.spam_indicativeness = self.model.feature_log_prob_[1] - self.model.feature_log_prob_[0]

        self.metrics = {}
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH) as f:
                self.metrics = json.load(f)

    def predict(self, text):
        vec = self.vectorizer.transform([text])
        prediction = self.model.predict(vec)[0]
        proba = self.model.predict_proba(vec)[0]
        confidence = float(max(proba)) * 100
        label = "Spam" if prediction == 1 else "Not Spam"
        return label, confidence

    def explain(self, text, top_n=5):
        vec = self.vectorizer.transform([text])
        present_indices = vec.nonzero()[1]
        contributions = [(self.feature_names[i], self.spam_indicativeness[i]) for i in present_indices]
        contributions.sort(key=lambda x: -x[1])
        return contributions[:top_n]


class SpamApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("640x700")
        self.root.resizable(False, False)

        self.colors_light = {"bg": "#f4f6f7", "fg": "#2c3e50", "card": "#ffffff"}
        self.colors_dark = {"bg": "#1e272e", "fg": "#ecf0f1", "card": "#2f3640"}
        self.dark_mode = False
        self.colors = self.colors_light

        try:
            self.classifier = SpamClassifier()
        except FileNotFoundError as e:
            messagebox.showerror("Model Not Found", str(e))
            self.classifier = None

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

        if self.classifier is None:
            tk.Label(self.root, text="⚠ Model not found.\nRun train_spam_model.py first.",
                     font=("Segoe UI", 12), fg="#c0392b", bg=self.colors["bg"]).pack(pady=50)
            return

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=15)

        self.single_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.batch_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.history_tab = tk.Frame(self.notebook, bg=self.colors["card"])
        self.performance_tab = tk.Frame(self.notebook, bg=self.colors["card"])

        self.notebook.add(self.single_tab, text="Check Message")
        self.notebook.add(self.batch_tab, text="Batch Check")
        self.notebook.add(self.history_tab, text="History")
        self.notebook.add(self.performance_tab, text="Model Performance")

        self.build_single_tab()
        self.build_batch_tab()
        self.build_history_tab()
        self.build_performance_tab()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.colors = self.colors_dark if self.dark_mode else self.colors_light
        self.build_ui()

    # ---------- Single message check ----------

    def build_single_tab(self):
        f = self.single_tab
        tk.Label(f, text="Check a Message", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(15, 10))

        self.message_input = tk.Text(f, height=6, width=60, font=("Segoe UI", 10))
        self.message_input.pack(pady=5, padx=20)

        tk.Button(f, text="Check Message", command=self.handle_check,
                  font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=20).pack(pady=10)

        self.verdict_label = tk.Label(f, text="", font=("Segoe UI", 18, "bold"), bg=self.colors["card"])
        self.verdict_label.pack(pady=(10, 5))

        self.confidence_bar = ttk.Progressbar(f, length=400, maximum=100, value=0)
        self.confidence_bar.pack(pady=5)
        self.confidence_label = tk.Label(f, text="", font=("Segoe UI", 9), bg=self.colors["card"], fg="#7f8c8d")
        self.confidence_label.pack()

        tk.Label(f, text="Top contributing words:", font=("Segoe UI", 10, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(anchor="w", padx=25, pady=(15, 0))
        self.explain_text = tk.Text(f, height=6, width=60, font=("Segoe UI", 9),
                                     bg="white", relief="solid", bd=1)
        self.explain_text.pack(padx=20, pady=10)
        self.explain_text.config(state="disabled")

    def handle_check(self):
        try:
            self._do_check()
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")

    def _do_check(self):
        text = self.message_input.get("1.0", tk.END).strip()
        if not text:
            return

        label, confidence = self.classifier.predict(text)
        color = "#c0392b" if label == "Spam" else "#27ae60"

        self.verdict_label.config(text=label, fg=color)
        self.confidence_bar["value"] = confidence
        self.confidence_label.config(text=f"Confidence: {confidence:.1f}%")

        contributions = self.classifier.explain(text)
        self.explain_text.config(state="normal")
        self.explain_text.delete("1.0", tk.END)
        if contributions:
            for word, score in contributions:
                direction = "→ spam" if score > 0 else "→ not spam"
                self.explain_text.insert(tk.END, f"'{word}'  ({direction}, weight {score:.2f})\n")
        else:
            self.explain_text.insert(tk.END, "No strongly distinctive words found in this message.")
        self.explain_text.config(state="disabled")

        log_check(text, label, confidence)
        self.refresh_history()

    # ---------- Batch check ----------

    def build_batch_tab(self):
        f = self.batch_tab
        tk.Label(f, text="Batch Message Check", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 10))
        tk.Label(f, text="Paste one message per line:", font=("Segoe UI", 9),
                 bg=self.colors["card"], fg="#7f8c8d").pack()

        self.batch_input = tk.Text(f, height=8, width=60, font=("Segoe UI", 9))
        self.batch_input.pack(pady=10)

        tk.Button(f, text="Check All", command=self.handle_batch_check,
                  font=("Segoe UI", 11, "bold"), bg="#2980b9", fg="white", width=20).pack(pady=5)

        columns = ("message", "prediction", "confidence")
        self.batch_tree = ttk.Treeview(f, columns=columns, show="headings", height=10)
        for col, width in zip(columns, (300, 90, 90)):
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
        messages = [line.strip() for line in raw_text.splitlines() if line.strip()]

        for row in self.batch_tree.get_children():
            self.batch_tree.delete(row)

        for msg in messages:
            label, confidence = self.classifier.predict(msg)
            display_msg = msg if len(msg) <= 50 else msg[:47] + "..."
            self.batch_tree.insert("", "end", values=(display_msg, label, f"{confidence:.1f}%"))
            log_check(msg, label, confidence)

        self.refresh_history()

    # ---------- History ----------

    def build_history_tab(self):
        f = self.history_tab
        tk.Label(f, text="Check History", font=("Segoe UI", 14, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=15)

        columns = ("message", "prediction", "confidence", "timestamp")
        self.history_tree = ttk.Treeview(f, columns=columns, show="headings", height=16)
        for col, width in zip(columns, (220, 80, 80, 140)):
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
        cur.execute("SELECT message, prediction, confidence, timestamp FROM history ORDER BY id DESC LIMIT 50")
        for msg, pred, conf, ts in cur.fetchall():
            display_msg = msg if len(msg) <= 40 else msg[:37] + "..."
            self.history_tree.insert("", "end", values=(display_msg, pred, f"{conf:.1f}%", ts))
        conn.close()

    # ---------- Model performance ----------

    def build_performance_tab(self):
        f = self.performance_tab
        tk.Label(f, text="Model Performance", font=("Segoe UI", 15, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(20, 15))

        m = self.classifier.metrics
        if not m:
            tk.Label(f, text="No metrics available.", bg=self.colors["card"]).pack()
            return

        stats = [
            ("Accuracy", f"{m['accuracy']*100:.1f}%"),
            ("Precision", f"{m['precision']*100:.1f}%"),
            ("Recall", f"{m['recall']*100:.1f}%"),
            ("F1 Score", f"{m['f1_score']*100:.1f}%"),
            ("Training examples", str(m['train_size'])),
            ("Test examples", str(m['test_size'])),
        ]
        for label, value in stats:
            row = tk.Frame(f, bg=self.colors["card"])
            row.pack(fill="x", padx=60, pady=4)
            tk.Label(row, text=label, font=("Segoe UI", 10), bg=self.colors["card"],
                     fg=self.colors["fg"], anchor="w").pack(side="left")
            tk.Label(row, text=value, font=("Segoe UI", 10, "bold"), bg=self.colors["card"],
                     fg="#2980b9", anchor="e").pack(side="right")

        tk.Label(f, text="Confusion Matrix (Test Set)", font=("Segoe UI", 11, "bold"),
                 bg=self.colors["card"], fg=self.colors["fg"]).pack(pady=(25, 10))

        cm = m.get("confusion_matrix", [[0, 0], [0, 0]])
        grid = tk.Frame(f, bg=self.colors["card"])
        grid.pack()
        headers = ["", "Predicted: Ham", "Predicted: Spam"]
        rows = [["Actual: Ham", str(cm[0][0]), str(cm[0][1])],
                ["Actual: Spam", str(cm[1][0]), str(cm[1][1])]]
        for c, h in enumerate(headers):
            tk.Label(grid, text=h, font=("Segoe UI", 9, "bold"), bg=self.colors["card"],
                     fg=self.colors["fg"], width=16).grid(row=0, column=c, padx=2, pady=2)
        for r, row_data in enumerate(rows, start=1):
            for c, val in enumerate(row_data):
                bg = "#eafaf1" if (r == c) else ("#fdecea" if c != 0 else self.colors["card"])
                tk.Label(grid, text=val, font=("Segoe UI", 9), bg=bg, width=16,
                         relief="solid", bd=1).grid(row=r, column=c, padx=2, pady=2)

        tk.Label(f, text="Model: Multinomial Naive Bayes on TF-IDF features (unigrams + bigrams)",
                 font=("Segoe UI", 8), bg=self.colors["card"], fg="#7f8c8d").pack(pady=(20, 5))


if __name__ == "__main__":
    root = tk.Tk()
    app = SpamApp(root)
    root.mainloop()