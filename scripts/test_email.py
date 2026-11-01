"""Send a real test OTP email with the settings in .env, to check Brevo/SMTP before the demo.

Usage:   python scripts/test_email.py your.name@bkc.met.edu
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv

load_dotenv()
from flask import Flask  # noqa: E402

from extensions import mail  # noqa: E402
from routes.mailer import send_otp_email  # noqa: E402

if len(sys.argv) != 2 or "@" not in sys.argv[1]:
    sys.exit("Usage: python scripts/test_email.py <recipient email>")

app = Flask(__name__)
for k in ("MAIL_SERVER", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_DEFAULT_SENDER"):
    app.config[k] = os.getenv(k, "")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "False").lower() == "true"
mail.init_app(app)

provider = os.getenv("EMAIL_PROVIDER", "smtp")
print(f"Provider: {provider}")
with app.app_context():
    ok, err = send_otp_email(sys.argv[1], "123456")
if ok:
    print(f"SENT. Check the inbox (and spam) of {sys.argv[1]} for a MET RIDE code 123456.")
else:
    print("FAILED:", err)
    sys.exit(1)
