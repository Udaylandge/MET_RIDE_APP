"""OTP email delivery: Brevo HTTP API (recommended) or SMTP via Flask-Mail.

.env:  EMAIL_PROVIDER=brevo|smtp   BREVO_API_KEY=...   MAIL_FROM_EMAIL=<verified sender>
"""
import os

import requests
from flask import current_app
from flask_mail import Message

from extensions import mail


def _html(otp):
    return ("<div style='font-family:Arial,sans-serif;max-width:420px;margin:auto'>"
            "<h2 style='color:#9E1B32'>MET RIDE</h2><p>Your verification code is:</p>"
            f"<p style='font-size:32px;letter-spacing:6px;font-weight:bold'>{otp}</p>"
            "<p>It expires in 10 minutes. Never share this code with anyone.</p></div>")


def explain_brevo_error(status, text):
    """Turn Brevo's error into a one-line fix the developer can act on (shown in the server log)."""
    t = (text or "").lower()
    if status == 401 and ("ip" in t and ("unrecognised" in t or "unrecognized" in t or "authorised" in t or "authorized" in t)):
        return ("Brevo blocked this computer's IP address. In Brevo go to Security -> Authorised IPs "
                "and add this PC's public IP (or deactivate IP blocking), then retry.")
    if status == 401:
        return "Brevo rejected the API key. Create a new key (SMTP & API -> API Keys) and paste it as BREVO_API_KEY."
    if status == 400 and "sender" in t:
        return "The sender address is not verified in Brevo. Add it under Senders & IP and click the link Brevo emails you."
    if status == 400:
        return f"Brevo rejected the request: {text[:160]}"
    if status == 403:
        return "Your Brevo account is not activated for sending yet. Check Brevo's account status / support email."
    if status == 429:
        return "Brevo daily sending limit reached."
    return f"Brevo error {status}: {text[:160]}"


def send_otp_email(to_email, otp):
    """Returns (ok, error_text)."""
    provider = os.getenv("EMAIL_PROVIDER", "smtp").lower()
    subject = "MET RIDE - Your verification code"
    try:
        if provider == "brevo":
            if not os.getenv("BREVO_API_KEY", "").strip():
                return False, "BREVO_API_KEY is empty. Add it to .env and restart the server."
            if not (os.getenv("MAIL_FROM_EMAIL") or os.getenv("MAIL_DEFAULT_SENDER")):
                return False, "MAIL_FROM_EMAIL is empty. Use a sender you verified in Brevo."
            sender = os.getenv("MAIL_FROM_EMAIL") or os.getenv("MAIL_DEFAULT_SENDER")
            r = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={"api-key": os.getenv("BREVO_API_KEY", "").strip(), "accept": "application/json"},
                json={"sender": {"name": "MET RIDE", "email": sender}, "to": [{"email": to_email}],
                      "subject": subject, "htmlContent": _html(otp)},
                timeout=15)
            if r.status_code >= 300:
                return False, explain_brevo_error(r.status_code, r.text)
            return True, None
        mail.send(Message(subject=subject, recipients=[to_email], html=_html(otp)))
        return True, None
    except Exception as e:  # noqa: BLE001
        current_app.logger.warning(f"OTP email failed: {e}")
        return False, str(e)
