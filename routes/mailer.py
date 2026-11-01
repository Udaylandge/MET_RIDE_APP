
import os
import requests
from flask import current_app


def _html(otp):
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:420px;margin:auto">
        <h2 style="color:#9E1B32">MET RIDE</h2>
        <p>Your verification code is:</p>
        <h1 style="letter-spacing:6px">{otp}</h1>
        <p>It expires in 10 minutes.</p>
        <p>Never share this code with anyone.</p>
    </div>
    """


def send_otp_email(to_email, otp):
    """Send OTP using Mailjet HTTPS API."""

    api_key = os.getenv("MAILJET_API_KEY", "").strip()
    secret_key = os.getenv("MAILJET_SECRET_KEY", "").strip()
    sender = os.getenv("MAILJET_FROM_EMAIL", "").strip()

    if not api_key or not secret_key or not sender:
        return False, "Mailjet configuration is missing."

    payload = {
        "Messages": [
            {
                "From": {
                    "Email": sender,
                    "Name": "MET RIDE"
                },
                "To": [
                    {"Email": to_email}
                ],
                "Subject": "MET RIDE - Your verification code",
                "TextPart": (
                    f"Your MET RIDE OTP is {otp}. "
                    "It expires in 10 minutes."
                ),
                "HTMLPart": _html(otp)
            }
        ]
    }

    try:
        response = requests.post(
            "https://api.mailjet.com/v3.1/send",
            auth=(api_key, secret_key),
            json=payload,
            timeout=20
        )

        if response.status_code >= 300:
            current_app.logger.error(
                f"Mailjet API error: {response.status_code} "
                f"{response.text[:200]}"
            )
            return False, "Mailjet could not send the email."

        result = response.json()
        messages = result.get("Messages", [])

        if not messages or messages[0].get("Status") != "success":
            return False, "Mailjet did not accept the email."

        current_app.logger.info(
            f"OTP email accepted by Mailjet for {to_email}"
        )

        return True, None

    except requests.RequestException:
        current_app.logger.exception("Mailjet connection failed")
        return False, "Unable to connect to Mailjet."
