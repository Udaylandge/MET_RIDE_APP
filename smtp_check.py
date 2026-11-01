
import smtplib
import ssl
import getpass


def test_587(email, password):
    print("\nTesting Gmail SMTP port 587 (STARTTLS)...")

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.ehlo()
            print("SMTP greeting: SUCCESS")

            server.starttls(context=ssl.create_default_context())
            print("TLS handshake: SUCCESS")

            server.ehlo()
            server.login(email, password)
            print("Gmail authentication: SUCCESS")

    except smtplib.SMTPAuthenticationError as e:
        print("Gmail authentication: FAILED")
        print("SMTP error code:", e.smtp_code)

    except Exception as e:
        print("Port 587 failed:", type(e).__name__, str(e))


def test_465(email, password):
    print("\nTesting Gmail SMTP port 465 (SSL)...")

    try:
        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            timeout=20,
            context=ssl.create_default_context()
        ) as server:

            server.ehlo()
            print("SSL connection: SUCCESS")

            server.login(email, password)
            print("Gmail authentication: SUCCESS")

    except smtplib.SMTPAuthenticationError as e:
        print("Gmail authentication: FAILED")
        print("SMTP error code:", e.smtp_code)

    except Exception as e:
        print("Port 465 failed:", type(e).__name__, str(e))


if __name__ == "__main__":
    print("GMAIL SMTP CONNECTION TEST")

    email = input("Enter sender Gmail address: ").strip()
    password = getpass.getpass("Enter Gmail App Password: ").replace(" ", "")

    test_587(email, password)
    test_465(email, password)

    print("\nTest completed.")
