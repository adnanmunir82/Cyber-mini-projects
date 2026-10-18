import socket
from flask import Flask, render_template_string, redirect, url_for

from qr_login_core import get_session_status, approve_session, deny_session, get_registered_user

app = Flask(__name__)

HEALTH_TIPS = [
    ("💧", "Stay Hydrated", "Aim for 6-8 glasses of water a day — even mild dehydration affects focus and energy."),
    ("😴", "Protect Your Sleep", "7-9 hours a night isn't a luxury — it's when your brain and body actually repair."),
    ("🧘", "Take Screen Breaks", "Every 20 minutes, look at something 20 feet away for 20 seconds — easy on tired eyes."),
    ("🥦", "Eat the Rainbow", "Different colored fruits and vegetables bring different nutrients — variety matters more than any single 'superfood'."),
]

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dani Health Tips</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f4f6f7;
            color: #2c3e50;
            padding: 20px;
            max-width: 480px;
            margin: 0 auto;
        }
        header { text-align: center; padding: 20px 0; }
        header h1 { font-size: 24px; color: #16a085; }
        header p { color: #7f8c8d; font-size: 13px; margin-top: 4px; }

        .login-card {
            background: white;
            border: 2px solid #2980b9;
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .login-card h2 { font-size: 16px; color: #2980b9; margin-bottom: 8px; }
        .login-card p { font-size: 13px; color: #555; margin-bottom: 14px; }
        .btn-row { display: flex; gap: 10px; }
        .btn {
            flex: 1; padding: 12px; border: none; border-radius: 8px;
            font-size: 14px; font-weight: bold; color: white; cursor: pointer;
        }
        .btn-approve { background: #27ae60; }
        .btn-deny { background: #c0392b; }

        .status-card {
            background: white; border-radius: 12px; padding: 20px;
            text-align: center; margin-bottom: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .status-card.success { border-left: 5px solid #27ae60; }
        .status-card.error { border-left: 5px solid #c0392b; }

        .tip-card {
            background: white; border-radius: 10px; padding: 14px;
            margin-bottom: 12px; display: flex; gap: 12px; align-items: flex-start;
            box-shadow: 0 1px 4px rgba(0,0,0,0.06);
        }
        .tip-emoji { font-size: 24px; }
        .tip-title { font-size: 14px; font-weight: bold; margin-bottom: 3px; }
        .tip-text { font-size: 12px; color: #7f8c8d; }
        footer { text-align: center; color: #bbb; font-size: 11px; margin-top: 20px; }
    </style>
</head>
<body>
    <header>
        <h1>🌿 Dani Health Tips</h1>
        <p>Small daily habits, real results</p>
    </header>

    {% if login_card %}
        {{ login_card | safe }}
    {% endif %}

    {% for emoji, title, text in tips %}
    <div class="tip-card">
        <div class="tip-emoji">{{ emoji }}</div>
        <div>
            <div class="tip-title">{{ title }}</div>
            <div class="tip-text">{{ text }}</div>
        </div>
    </div>
    {% endfor %}

    <footer>Dani Health Tips — part of a cybersecurity demo project</footer>
</body>
</html>
"""


def render_page(login_card_html=""):
    return render_template_string(PAGE_TEMPLATE, login_card=login_card_html, tips=HEALTH_TIPS)


@app.route("/")
def home():
    return render_page()


@app.route("/approve/<token>", methods=["GET"])
def approval_page(token):
    session = get_session_status(token)
    username = get_registered_user() or "this device"

    if session is None:
        card = '<div class="status-card error"><h2>⚠ Invalid Link</h2><p>This sign-in link is not recognized.</p></div>'
    elif session["status"] == "pending":
        card = f"""
        <div class="login-card">
            <h2>🔐 Sign-in Request</h2>
            <p>A desktop device wants to log in as <b>{username}</b>. Approve this sign-in?</p>
            <div class="btn-row">
                <form method="POST" action="/approve/{token}" style="flex:1">
                    <button class="btn btn-approve" type="submit">✓ Approve</button>
                </form>
                <form method="POST" action="/deny/{token}" style="flex:1">
                    <button class="btn btn-deny" type="submit">✗ Deny</button>
                </form>
            </div>
        </div>
        """
    elif session["status"] == "approved" or session["status"] == "consumed":
        card = '<div class="status-card success"><h2>✅ Already Approved</h2><p>This sign-in was already approved. You can return to your desktop.</p></div>'
    elif session["status"] == "denied":
        card = '<div class="status-card error"><h2>Sign-in Denied</h2><p>You already denied this sign-in request.</p></div>'
    elif session["status"] == "expired":
        card = '<div class="status-card error"><h2>⌛ Link Expired</h2><p>This sign-in request has expired. Refresh the QR code on your desktop and scan again.</p></div>'
    else:
        card = '<div class="status-card error"><h2>⚠ Something went wrong</h2></div>'

    return render_page(card)


@app.route("/approve/<token>", methods=["POST"])
def do_approve(token):
    username = get_registered_user() or "unknown"
    approve_session(token, username)
    return redirect(url_for("approval_page", token=token))


@app.route("/deny/<token>", methods=["POST"])
def do_deny(token):
    deny_session(token)
    return redirect(url_for("approval_page", token=token))


def get_local_ip():
    """Best-effort detection of this machine's LAN IP (the address a phone on the same Wi-Fi can reach)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def run_server(host="0.0.0.0", port=5000):
    """Blocking call — intended to run on a background daemon thread."""
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)