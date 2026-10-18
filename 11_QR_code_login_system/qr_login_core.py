import sqlite3
import secrets
import qrcode
from datetime import datetime, timedelta

DB_FILE = "qr_login.db"
DEFAULT_EXPIRY_SECONDS = 120


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            registered_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            approved_by TEXT,
            approved_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            event TEXT NOT NULL,
            detail TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_event(token, event, detail=""):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO login_log (token, event, detail, timestamp) VALUES (?, ?, ?, ?)",
                (token[:12] + "...", event, detail, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


# ---------------- User registration (the "phone" is tied to a registered user) ----------------

def register_user(username):
    username = username.strip()
    if not username:
        return False, "Username cannot be empty"
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return True, "Already registered"
    cur.execute("INSERT INTO users (username, registered_at) VALUES (?, ?)",
                (username, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return True, "Registered"


def get_registered_user():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT username FROM users ORDER BY registered_at DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


# ---------------- Session (token) lifecycle ----------------

def create_session(expiry_seconds=DEFAULT_EXPIRY_SECONDS):
    token = secrets.token_urlsafe(24)
    now = datetime.now()
    expires_at = now + timedelta(seconds=expiry_seconds)

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sessions (token, status, created_at, expires_at, approved_by, approved_at) "
        "VALUES (?, 'pending', ?, ?, NULL, NULL)",
        (token, now.strftime("%Y-%m-%d %H:%M:%S"), expires_at.strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    log_event(token, "created", f"expires in {expiry_seconds}s")
    return token, expires_at


def _row_to_dict(row):
    token, status, created_at, expires_at, approved_by, approved_at = row
    return {
        "token": token, "status": status, "created_at": created_at,
        "expires_at": expires_at, "approved_by": approved_by, "approved_at": approved_at
    }


def _auto_expire_if_needed(cur, session):
    if session["status"] == "pending":
        expires_at = datetime.strptime(session["expires_at"], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expires_at:
            cur.execute("UPDATE sessions SET status = 'expired' WHERE token = ?", (session["token"],))
            session["status"] = "expired"
    return session


def get_session_status(token):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT token, status, created_at, expires_at, approved_by, approved_at FROM sessions WHERE token = ?",
                (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    session = _row_to_dict(row)
    session = _auto_expire_if_needed(cur, session)
    conn.commit()
    conn.close()
    return session


def list_pending_sessions():
    """For the 'phone' panel — all sessions still waiting for approval and not expired."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT token, status, created_at, expires_at, approved_by, approved_at FROM sessions WHERE status = 'pending'")
    rows = cur.fetchall()
    results = []
    for row in rows:
        session = _row_to_dict(row)
        session = _auto_expire_if_needed(cur, session)
        if session["status"] == "pending":
            results.append(session)
    conn.commit()
    conn.close()
    return results


def approve_session(token, username):
    session = get_session_status(token)
    if session is None:
        return False, "Session not found"
    if session["status"] != "pending":
        return False, f"Session is '{session['status']}', cannot approve"

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "UPDATE sessions SET status = 'approved', approved_by = ?, approved_at = ? WHERE token = ?",
        (username, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), token)
    )
    conn.commit()
    conn.close()
    log_event(token, "approved", f"by {username}")
    return True, "Approved"


def deny_session(token):
    session = get_session_status(token)
    if session is None:
        return False, "Session not found"
    if session["status"] != "pending":
        return False, f"Session is '{session['status']}', cannot deny"

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("UPDATE sessions SET status = 'denied' WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    log_event(token, "denied")
    return True, "Denied"


def consume_session(token):
    """
    Marks an approved session as consumed (fully logged in), preventing replay.
    Returns (success, username_or_None).
    """
    session = get_session_status(token)
    if session is None or session["status"] != "approved":
        return False, None

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("UPDATE sessions SET status = 'consumed' WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    log_event(token, "consumed", f"login completed for {session['approved_by']}")
    return True, session["approved_by"]


def generate_qr_image(data):
    """Returns a PIL Image of the QR code encoding the given data."""
    qr = qrcode.QRCode(version=1, box_size=8, border=3, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")