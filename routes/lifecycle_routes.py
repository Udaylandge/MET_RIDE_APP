"""Ride lifecycle used by the Android app: request → accept/reject → OTP start →
live location → complete / cancel → rate, plus notifications and SOS."""
import random

from flask import Blueprint, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import mongo
from routes.ride_routes import verify_user_ride_access
from routes.ride_utils import (
    CANCELLED, COMPLETED, FULL, IN_PROGRESS, PENDING, auth_required, booking_status,
    emit, iso, notify, now_utc, oid, serialize_ride, when_text,
)

lifecycle_bp = Blueprint("lifecycle", __name__)

MAX_OTP_ATTEMPTS = 5
OPEN_STATUSES = [PENDING, "pending", "ACTIVE", "active"]


def _err(msg, code=400, **extra):
    return jsonify({"success": False, "message": msg, **extra}), code


def _load_ride(ride_id):
    rid = oid(ride_id)
    if not rid:
        return None, _err("Invalid ride id", 400)
    ride = mongo.db.rides.find_one({"_id": rid})
    if not ride:
        return None, _err("Ride not found", 404)
    return ride, None


def _find_booking(ride, passenger_id):
    return next((b for b in ride.get("bookings", []) if b.get("passenger_id") == str(passenger_id)), None)


# ── My rides ────────────────────────────────────────────────────────────────
@lifecycle_bp.route("/rides/my", methods=["GET"])
@auth_required
def my_rides():
    uid = g.user_id
    docs = mongo.db.rides.find({"$or": [{"driver_id": uid}, {"bookings.passenger_id": uid}]}) \
        .sort("created_at", -1).limit(100)
    rides = [serialize_ride(r, uid) for r in docs]
    return jsonify({"success": True, "count": len(rides), "rides": rides}), 200


# ── Passenger requests a seat ───────────────────────────────────────────────
@lifecycle_bp.route("/rides/<ride_id>/request", methods=["POST"])
@auth_required
def request_seat(ride_id):
    ok, resp = verify_user_ride_access(g.current_user, "request rides")
    if not ok:
        return resp
    ride, err = _load_ride(ride_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        seats = int(data.get("seats_requested", 1))
    except (TypeError, ValueError):
        return _err("seats_requested must be a number")
    if seats < 1:
        return _err("seats_requested must be at least 1")
    if str(ride.get("driver_id")) == g.user_id:
        return _err("You cannot request a seat on your own ride", 400)
    if ride.get("status") not in OPEN_STATUSES:
        return _err("This ride is no longer available", 409)
    if seats > int(ride.get("seats_available", 0)):
        return _err("Not enough seats available", 409)
    existing = _find_booking(ride, g.user_id)
    if existing and booking_status(existing) in ("pending", "accepted"):
        return _err("You already have a request on this ride", 409)

    entry = {"passenger_id": g.user_id, "name": g.current_user.get("name", "Student"),
             "seats": seats, "status": "pending", "requested_at": now_utc().isoformat()}
    mongo.db.rides.update_one({"_id": ride["_id"]}, {"$pull": {"bookings": {"passenger_id": g.user_id}}})
    mongo.db.rides.update_one({"_id": ride["_id"]}, {"$push": {"bookings": entry}})

    name = entry["name"]
    notify(ride["driver_id"], "ride_request", "New seat request",
           f"{name} wants {seats} seat(s) on your ride {ride.get('origin')} → {ride.get('destination')} "
           f"({when_text(ride)}). Open the Requests tab to accept or decline.", ride["_id"])
    emit("new_ride_request", {"ride_id": str(ride["_id"]), "passenger_id": g.user_id,
                              "passenger_name": name, "seats": seats}, f"user_{ride['driver_id']}")
    return jsonify({"success": True, "message": "Request sent to the driver"}), 200


# ── Driver accepts / rejects ────────────────────────────────────────────────
def _driver_ride(ride_id):
    ride, err = _load_ride(ride_id)
    if err:
        return None, err
    if str(ride.get("driver_id")) != g.user_id:
        return None, _err("Only the driver of this ride can do that", 403)
    return ride, None


@lifecycle_bp.route("/rides/<ride_id>/accept/<passenger_id>", methods=["POST"])
@auth_required
def accept_passenger(ride_id, passenger_id):
    ride, err = _driver_ride(ride_id)
    if err:
        return err
    booking = _find_booking(ride, passenger_id)
    if not booking or booking_status(booking) != "pending":
        return _err("No pending request from this passenger", 404)
    seats = int(booking.get("seats", 1))
    otp = f"{random.SystemRandom().randint(0, 9999):04d}"

    # Atomic: only take the seats if they are still free (prevents overbooking).
    updated = mongo.db.rides.find_one_and_update(
        {"_id": ride["_id"], "status": {"$in": OPEN_STATUSES}, "seats_available": {"$gte": seats},
         "bookings": {"$elemMatch": {"passenger_id": str(passenger_id), "status": "pending"}}},
        {"$inc": {"seats_available": -seats, "seats_taken": seats},
         "$set": {"bookings.$.status": "accepted", "bookings.$.otp_hash": generate_password_hash(otp),
                  "bookings.$.otp_plain": otp, "bookings.$.otp_attempts": 0,
                  "bookings.$.accepted_at": now_utc().isoformat()}},
        return_document=True)
    if not updated:
        return _err("Not enough seats left to accept this request", 409)
    if updated.get("seats_available") == 0:
        mongo.db.rides.update_one({"_id": ride["_id"], "status": PENDING}, {"$set": {"status": FULL}})

    notify(passenger_id, "ride_accepted", "Request accepted ✅",
           f"{ride.get('driver_name', 'Your driver')} accepted your request. They will pick you up at "
           f"{ride.get('origin')} around {when_text(ride)} and drop you at {ride.get('destination')}. "
           f"Your boarding OTP is {otp}. Share it with the driver only when you board.", ride["_id"])
    payload = {"ride_id": str(ride["_id"]), "status": "accepted", "driver_name": ride.get("driver_name"),
               "departure": when_text(ride), "origin": ride.get("origin"), "destination": ride.get("destination")}
    emit("request_response", payload, f"user_{passenger_id}")
    return jsonify({"success": True, "message": "Passenger accepted"}), 200


@lifecycle_bp.route("/rides/<ride_id>/reject/<passenger_id>", methods=["POST"])
@auth_required
def reject_passenger(ride_id, passenger_id):
    ride, err = _driver_ride(ride_id)
    if err:
        return err
    booking = _find_booking(ride, passenger_id)
    if not booking or booking_status(booking) != "pending":
        return _err("No pending request from this passenger", 404)
    mongo.db.rides.update_one(
        {"_id": ride["_id"], "bookings.passenger_id": str(passenger_id)},
        {"$set": {"bookings.$.status": "rejected"}})
    notify(passenger_id, "ride_rejected", "Request declined",
           f"{ride.get('driver_name', 'The driver')} could not take you on {ride.get('origin')} → "
           f"{ride.get('destination')} ({when_text(ride)}). Try another ride.", ride["_id"])
    emit("request_response", {"ride_id": str(ride["_id"]), "status": "rejected",
                              "driver_name": ride.get("driver_name")}, f"user_{passenger_id}")
    return jsonify({"success": True, "message": "Request rejected"}), 200


# ── Start ride with the passenger's OTP ─────────────────────────────────────
@lifecycle_bp.route("/rides/<ride_id>/verify-otp", methods=["POST"])
@auth_required
def verify_ride_otp(ride_id):
    ride, err = _driver_ride(ride_id)
    if err:
        return err
    if ride.get("status") == IN_PROGRESS:
        return jsonify({"success": True, "message": "Ride already in progress"}), 200
    if ride.get("status") in (COMPLETED, CANCELLED):
        return _err(f"Ride is {ride.get('status').lower()}", 409)

    otp = str((request.get_json(silent=True) or {}).get("otp", "")).strip()
    if not otp:
        return _err("otp is required")
    attempts = int(ride.get("otp_attempts", 0))
    if attempts >= MAX_OTP_ATTEMPTS:
        return _err("Too many wrong attempts. Ask the passenger to confirm the code and contact support.", 429)

    accepted = [b for b in ride.get("bookings", []) if booking_status(b) == "accepted"]
    if not accepted:
        return _err("No accepted passengers on this ride yet", 409)

    match = next((b for b in accepted if b.get("otp_hash") and check_password_hash(b["otp_hash"], otp)), None)
    if not match:
        mongo.db.rides.update_one({"_id": ride["_id"]}, {"$inc": {"otp_attempts": 1}})
        left = MAX_OTP_ATTEMPTS - attempts - 1
        return _err(f"Incorrect OTP. {max(left, 0)} attempt(s) left.", 400)

    mongo.db.rides.update_one(
        {"_id": ride["_id"], "bookings.passenger_id": match["passenger_id"]},
        {"$set": {"status": IN_PROGRESS, "started_at": now_utc(), "otp_attempts": 0,
                  "bookings.$.boarded": True}})
    started = {"ride_id": str(ride["_id"]), "status": "in_progress"}
    emit("ride_status_update", started, f"ride_{ride['_id']}")
    for b in accepted:
        notify(b["passenger_id"], "system", "Ride started", "Your ride is now in progress. Stay safe!", ride["_id"])
    return jsonify({"success": True, "message": "OTP verified. Ride started."}), 200


# ── Live location (REST fallback; sockets use update_location) ──────────────
@lifecycle_bp.route("/rides/<ride_id>/location", methods=["POST"])
@auth_required
def update_location(ride_id):
    ride, err = _driver_ride(ride_id)
    if err:
        return err
    if ride.get("status") != IN_PROGRESS:
        return _err("Ride is not in progress", 409)
    data = request.get_json(silent=True) or {}
    try:
        lat, lng = float(data["latitude"]), float(data["longitude"])
    except (KeyError, TypeError, ValueError):
        return _err("latitude and longitude are required numbers")
    mongo.db.rides.update_one({"_id": ride["_id"]},
                              {"$set": {"current_location": {"lat": lat, "lng": lng, "at": now_utc()}}})
    emit("location_update", {"ride_id": str(ride["_id"]), "latitude": lat, "longitude": lng},
         f"ride_{ride['_id']}")
    return jsonify({"success": True, "message": "Location updated"}), 200


# ── Complete / cancel / rate ────────────────────────────────────────────────
@lifecycle_bp.route("/rides/<ride_id>/complete", methods=["POST"])
@auth_required
def complete_ride(ride_id):
    ride, err = _driver_ride(ride_id)
    if err:
        return err
    if ride.get("status") == COMPLETED:
        return jsonify({"success": True, "message": "Ride already completed"}), 200
    if ride.get("status") != IN_PROGRESS:
        return _err("Only a ride in progress can be completed (start it with the passenger OTP first)", 409)
    mongo.db.rides.update_one({"_id": ride["_id"]}, {"$set": {"status": COMPLETED, "completed_at": now_utc()}})
    riders = [b["passenger_id"] for b in ride.get("bookings", []) if b.get("boarded") or booking_status(b) == "accepted"]
    mongo.db.users.update_one({"_id": oid(g.user_id)}, {"$inc": {"rides_given": 1}})
    for pid in riders:
        mongo.db.users.update_one({"_id": oid(pid)}, {"$inc": {"rides_taken": 1}})
        notify(pid, "system", "Ride completed", "Please rate your driver.", ride["_id"])
    emit("ride_status_update", {"ride_id": str(ride["_id"]), "status": "completed"}, f"ride_{ride['_id']}")
    return jsonify({"success": True, "message": "Ride completed"}), 200


@lifecycle_bp.route("/rides/<ride_id>/cancel", methods=["POST"])
@auth_required
def cancel_ride_by_id(ride_id):
    ride, err = _load_ride(ride_id)
    if err:
        return err
    reason = str((request.get_json(silent=True) or {}).get("reason") or "").strip()
    if ride.get("status") in (COMPLETED, CANCELLED):
        return _err(f"Ride is already {ride.get('status').lower()}", 409)

    if str(ride.get("driver_id")) == g.user_id:
        mongo.db.rides.update_one({"_id": ride["_id"]}, {"$set": {
            "status": CANCELLED, "cancelled_at": now_utc(), "cancel_reason": reason, "cancelled_by": "driver"}})
        for b in ride.get("bookings", []):
            if booking_status(b) in ("pending", "accepted"):
                notify(b["passenger_id"], "system", "Ride cancelled",
                       f"The driver cancelled {ride.get('origin')} → {ride.get('destination')}.", ride["_id"])
        emit("ride_status_update", {"ride_id": str(ride["_id"]), "status": "cancelled"}, f"ride_{ride['_id']}")
        return jsonify({"success": True, "message": "Ride cancelled"}), 200

    booking = _find_booking(ride, g.user_id)
    if not booking or booking_status(booking) not in ("pending", "accepted"):
        return _err("You have no active booking on this ride", 404)
    if ride.get("status") == IN_PROGRESS:
        return _err("The ride has already started and cannot be cancelled", 409)
    update = {"$set": {"bookings.$.status": "cancelled"}}
    if booking_status(booking) == "accepted":
        seats = int(booking.get("seats", 1))
        update["$inc"] = {"seats_available": seats, "seats_taken": -seats}
    mongo.db.rides.update_one({"_id": ride["_id"], "bookings.passenger_id": g.user_id}, update)
    mongo.db.rides.update_one({"_id": ride["_id"], "status": FULL}, {"$set": {"status": PENDING}})
    notify(ride["driver_id"], "system", "Passenger cancelled",
           f"{booking.get('name', 'A passenger')} cancelled their seat.", ride["_id"])
    return jsonify({"success": True, "message": "Your booking was cancelled"}), 200


@lifecycle_bp.route("/rides/<ride_id>/rate", methods=["POST"])
@auth_required
def rate_ride(ride_id):
    ride, err = _load_ride(ride_id)
    if err:
        return err
    if ride.get("status") != COMPLETED:
        return _err("You can rate a ride only after it is completed", 409)
    data = request.get_json(silent=True) or {}
    try:
        rating = int(data.get("rating"))
    except (TypeError, ValueError):
        return _err("rating must be 1 to 5")
    if not 1 <= rating <= 5:
        return _err("rating must be 1 to 5")

    if str(ride.get("driver_id")) == g.user_id:
        return _err("Drivers cannot rate their own ride", 400)
    booking = _find_booking(ride, g.user_id)
    if not booking or booking_status(booking) != "accepted":
        return _err("Only passengers of this ride can rate it", 403)
    if booking.get("rated"):
        return _err("You already rated this ride", 409)

    mongo.db.rides.update_one({"_id": ride["_id"], "bookings.passenger_id": g.user_id},
                              {"$set": {"bookings.$.rated": True, "bookings.$.rating": rating,
                                        "bookings.$.review": str(data.get("review") or "")[:500]}})
    driver = mongo.db.users.find_one({"_id": oid(ride["driver_id"])}) or {}
    count = int(driver.get("rating_count", 0))
    avg = float(driver.get("avg_rating", 0) or 0)
    new_avg = round((avg * count + rating) / (count + 1), 2)
    mongo.db.users.update_one({"_id": oid(ride["driver_id"])},
                              {"$set": {"avg_rating": new_avg, "rating": new_avg, "rating_count": count + 1}})
    return jsonify({"success": True, "message": "Thanks for rating!"}), 200


# ── Notifications ───────────────────────────────────────────────────────────
@lifecycle_bp.route("/notifications", methods=["GET"])
@auth_required
def get_notifications():
    docs = list(mongo.db.notifications.find({"user_id": g.user_id}).sort("created_at", -1).limit(100))
    items = [{"id": str(n["_id"]), "type": n.get("type", "system"), "title": n.get("title", ""),
              "body": n.get("body") or n.get("message", ""), "read": bool(n.get("is_read", False)),
              "related_ride_id": n.get("related_ride_id"), "created_at": iso(n.get("created_at"))}
             for n in docs]
    return jsonify({"success": True, "count": len(items),
                    "unread_count": sum(1 for i in items if not i["read"]), "notifications": items}), 200


@lifecycle_bp.route("/notifications/mark-all-read", methods=["POST"])
@auth_required
def mark_all_read():
    mongo.db.notifications.update_many({"user_id": g.user_id, "is_read": False}, {"$set": {"is_read": True}})
    return jsonify({"success": True, "message": "All notifications marked as read"}), 200


@lifecycle_bp.route("/notifications/<nid>/read", methods=["POST"])
@auth_required
def mark_read(nid):
    n = oid(nid)
    if not n:
        return _err("Invalid notification id")
    mongo.db.notifications.update_one({"_id": n, "user_id": g.user_id}, {"$set": {"is_read": True}})
    return jsonify({"success": True, "message": "Marked as read"}), 200


# ── SOS ─────────────────────────────────────────────────────────────────────
@lifecycle_bp.route("/sos", methods=["POST"])
@auth_required
def send_sos():
    data = request.get_json(silent=True) or {}
    try:
        lat, lng = float(data.get("latitude", 0)), float(data.get("longitude", 0))
    except (TypeError, ValueError):
        return _err("latitude and longitude must be numbers")
    alert = {"user_id": g.user_id, "user_name": g.current_user.get("name", "Student"),
             "email": g.current_user.get("email"), "latitude": lat, "longitude": lng,
             "message": str(data.get("message") or "Emergency SOS")[:300],
             "status": "active", "created_at": now_utc()}
    res = mongo.db.alerts.insert_one(alert)
    emit("sos_alert", {"id": str(res.inserted_id), "user_name": alert["user_name"],
                       "latitude": lat, "longitude": lng, "message": alert["message"]}, "admins")
    return jsonify({"success": True, "message": "SOS alert sent to campus security"}), 200
