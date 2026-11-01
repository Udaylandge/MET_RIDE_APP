"""Shared helpers for the ride lifecycle: auth, serialization, notifications, sockets."""
import datetime
from functools import wraps

import jwt
from bson import ObjectId
from flask import current_app, g, jsonify, request

from extensions import mongo, socketio

# Ride statuses stored in Mongo (uppercase, matching the existing offer/book code)
PENDING, FULL, IN_PROGRESS, COMPLETED, CANCELLED = (
    "PENDING", "FULL", "IN_PROGRESS", "COMPLETED", "CANCELLED")

# What the Android app expects in the JSON
_API_STATUS = {
    "PENDING": "scheduled", "FULL": "scheduled", "ACTIVE": "scheduled",
    "IN_PROGRESS": "in_progress", "COMPLETED": "completed", "CANCELLED": "cancelled",
}


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def when_text(ride):
    """Human friendly departure time, e.g. '25 Oct, 08:00 AM' (falls back to the raw text)."""
    raw = str(ride.get("departure_time") or "").strip()
    if not raw:
        return "the scheduled time"
    try:
        dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%d %b, %I:%M %p")
    except ValueError:
        return raw


def api_status(raw):
    return _API_STATUS.get(str(raw or "PENDING").upper(), "scheduled")


def iso(v):
    return v.isoformat() if isinstance(v, datetime.datetime) else v


def oid(value):
    try:
        return ObjectId(str(value))
    except Exception:
        return None


# ── Auth ────────────────────────────────────────────────────────────────────
def user_from_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    try:
        payload = jwt.decode(header.split(" ", 1)[1].strip(),
                             current_app.config["SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return None
    uid = oid(payload.get("sub") or payload.get("id") or payload.get("user_id"))
    return mongo.db.users.find_one({"_id": uid}) if uid else None


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = user_from_token()
        if not user:
            return jsonify({"success": False, "message": "Authentication required"}), 401
        if user.get("is_blocked") or user.get("isBlocked"):
            return jsonify({"success": False, "error": "account_blocked",
                            "message": "Account is blocked. Contact administrator."}), 403
        g.current_user = user
        g.user_id = str(user["_id"])
        return fn(*args, **kwargs)
    return wrapper


# ── Notifications + realtime ────────────────────────────────────────────────
def notify(user_id, ntype, title, body, ride_id=None):
    try:
        mongo.db.notifications.insert_one({
            "recipient_id": str(user_id), "user_id": str(user_id), "type": ntype,
            "title": title, "message": body, "body": body, "is_read": False,
            "related_ride_id": str(ride_id) if ride_id else None, "created_at": now_utc(),
        })
    except Exception as e:  # never break a ride action because of a notification
        current_app.logger.warning(f"notify failed: {e}")


def emit(event, payload, room):
    try:
        socketio.emit(event, payload, to=room)
    except Exception as e:
        current_app.logger.warning(f"socket emit failed: {e}")


# ── Serialization (matches Android RideDto.RideData) ────────────────────────
def booking_status(b):
    return b.get("status") or "accepted"   # legacy instant bookings count as accepted


def serialize_ride(ride, viewer_id=None):
    bookings = ride.get("bookings") or []
    passengers, my_status, my_otp = [], None, None
    is_driver = viewer_id is not None and str(ride.get("driver_id")) == str(viewer_id)
    for b in bookings:
        st = booking_status(b)
        passengers.append({"id": b.get("passenger_id"), "name": b.get("name", ""),
                           "avatar": None, "seats": b.get("seats", 1), "request_status": st})
        if viewer_id is not None and b.get("passenger_id") == str(viewer_id):
            my_status = st
            if st == "accepted":
                my_otp = b.get("otp_plain")
    cur = ride.get("current_location") or {}
    seats_avail = int(ride.get("seats_available", 0))
    seats_total = int(ride.get("seats_total", seats_avail))
    return {
        "id": str(ride["_id"]),
        "driver_id": str(ride.get("driver_id", "")),
        "driver_name": ride.get("driver_name", "Driver"),
        "driver_avatar": None,
        "driver_rating": float(ride.get("driver_rating", 5.0) or 5.0),
        "origin": ride.get("origin", ""),
        "destination": ride.get("destination", ""),
        "origin_lat": ride.get("origin_lat"),
        "origin_lng": ride.get("origin_lng"),
        "destination_lat": ride.get("destination_lat"),
        "destination_lng": ride.get("destination_lng"),
        "departure_time": str(ride.get("departure_time", "")),
        "seats_available": seats_avail,
        "seats_taken": int(ride.get("seats_taken", max(0, seats_total - seats_avail))),
        "fare": float(ride.get("fare", 0) or 0),
        "upi_id": ride.get("upi_id"),
        "status": api_status(ride.get("status")),
        "request_status": my_status,
        "otp": my_otp,
        "current_lat": cur.get("lat"),
        "current_lng": cur.get("lng"),
        "created_at": iso(ride.get("created_at")),
        # Passenger list is for the driver; a passenger only sees their own row.
        "passengers": passengers if is_driver else [p for p in passengers if p["id"] == str(viewer_id)],
    }
