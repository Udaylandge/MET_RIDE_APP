# MET RIDE backend

Flask + MongoDB + Socket.IO API for the MET RIDE campus carpooling Android app.

## Setup
    python -m venv .venv && .venv\Scripts\activate      # Windows
    pip install -r requirements.txt
    copy .env.example .env                               # then fill it in (see below)
    python reset_admin_password.py                       # creates/updates the admin from ADMIN_EMAIL / NEW_ADMIN_PASSWORD
    python app.py

`.env` essentials: `MONGO_URI`, `SECRET_KEY` (64 hex chars; the server refuses to start without a strong one),
`EMAIL_PROVIDER=brevo` + `BREVO_API_KEY` + `MAIL_FROM_EMAIL` (a sender verified in Brevo).
Check email delivery with `python scripts/test_email.py you@bkc.met.edu`. Health check: `GET /api/health`.

## Structure
    app.py                 app factory, security headers, error handlers, private file serving
    extensions.py          Mongo, Mail, Socket.IO instances
    routes/auth_routes.py  OTP (hashed, expiring), register, login, refresh
    routes/profile_routes.py  profile, ID card / fee receipt upload, dashboard, ride history
    routes/ride_routes.py  post ride, nearby search, ride details
    routes/lifecycle_routes.py  request, accept/reject, OTP start, location, complete, cancel, rate, notifications, SOS
    routes/admin_routes.py admin login, verification queue, block/unblock, SOS, ride audit
    routes/socket_handlers.py  live ride events
    routes/security.py     rate limits, lockout, password policy, signed file links
    routes/mailer.py       Brevo API / SMTP email with readable error hints
    routes/ride_utils.py   shared helpers and ride serializer
    tests/                 test_e2e.py (85 checks) and test_security.py (39 checks)

## Security summary
Rate limits per IP, 5-strike account lockout, 8+ char passwords with letter and number, hashed OTPs that expire
after 10 minutes, JWT with database re-checks, private ID documents served only through 1-hour signed links,
security headers, JSON-only errors, 6 MB request limit, debug off by default.

## Tests
    pip install -r requirements-dev.txt
    python tests/test_e2e.py
    python tests/test_security.py
