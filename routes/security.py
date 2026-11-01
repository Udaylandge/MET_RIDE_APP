"""Security helpers: rate limiting, login lockout, password policy, signed file links."""
import datetime
import os
import re
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import current_app, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from extensions import mongo

# ── Rate limiting (in-memory, per client IP + route). Good for a single server process. ────────
_hits = defaultdict(deque)
_lock = threading.Lock()


def _enabled():
    return os.getenv("RATE_LIMIT_ENABLED", "true").lower() not in ("false", "0", "no")


def client_ip():
    return request.remote_addr or "unknown"


def rate_limit(name, limit, window_seconds):
    """Allow `limit` calls per `window_seconds` per IP for this route name; else 429."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if _enabled():
                key = f"{name}:{client_ip()}"
                now = time.time()
                with _lock:
                    q = _hits[key]
                    while q and now - q[0] > window_seconds:
                        q.popleft()
                    if len(q) >= limit:
                        retry = int(window_seconds - (now - q[0])) + 1
                        resp = jsonify({"success": False,
                                        "message": f"Too many attempts. Try again in {retry} seconds."})
                        resp.status_code = 429
                        resp.headers["Retry-After"] = str(retry)
                        return resp
                    q.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def reset_rate_limits():
    with _lock:
        _hits.clear()


# ── Per-account lockout after repeated wrong passwords ─────────────────────────────────────────
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 15


def _utc(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def lockout_message(user):
    """Returns a message if the account is currently locked, else None."""
    until = _utc(user.get("lock_until"))
    if until and datetime.datetime.now(datetime.timezone.utc) < until:
        mins = int((until - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 60) + 1
        return f"Too many wrong passwords. Account locked for {mins} more minute(s)."
    return None


def record_failed_login(user):
    fails = int(user.get("failed_logins", 0)) + 1
    update = {"failed_logins": fails}
    if fails >= MAX_FAILED_LOGINS:
        update["lock_until"] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=LOCK_MINUTES)
        update["failed_logins"] = 0
    mongo.db.users.update_one({"_id": user["_id"]}, {"$set": update})


def clear_failed_logins(user):
    if user.get("failed_logins") or user.get("lock_until"):
        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"failed_logins": 0}, "$unset": {"lock_until": ""}})


# ── Password policy ────────────────────────────────────────────────────────────────────────────
def password_problem(pw):
    if len(pw) < 8:
        return "Password must be at least 8 characters"
    if len(pw) > 128:
        return "Password is too long"
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return "Password must contain at least one letter and one number"
    return None


# ── Signed, expiring links for private documents (ID cards, fee receipts) ──────────────────────
FILE_URL_TTL = 3600


def _ser():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="private-uploads")


def signed_upload_url(stored):
    """Turn whatever is stored in the DB (absolute URL, /uploads/x or x) into a signed, expiring URL."""
    if not stored:
        return None
    name = os.path.basename(str(stored).split("?")[0].strip())
    if not name:
        return None
    base = request.host_url.rstrip("/")
    return f"{base}/uploads/{name}?t={_ser().dumps(name)}"


def file_token_ok(filename, token):
    if not token:
        return False
    try:
        return _ser().loads(token, max_age=FILE_URL_TTL) == filename
    except (BadSignature, SignatureExpired):
        return False
