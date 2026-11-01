"""Socket.IO events used by the Android SocketIOManager.

Client → server:  join_ride {ride_id}, leave_ride {ride_id}, update_location {ride_id, latitude, longitude}
Server → client:  location_update, ride_status_update, new_ride_request, request_response, sos_alert
Rooms: user_<id> (personal), ride_<id> (live tracking), admins.
"""
import jwt
from flask import current_app, request
from flask_socketio import ConnectionRefusedError, emit, join_room, leave_room

from extensions import mongo, socketio
from routes.ride_utils import IN_PROGRESS, now_utc, oid

_sessions = {}   # sid -> user doc id (str)


def _authenticate(auth):
    token = (auth or {}).get("token") if isinstance(auth, dict) else None
    if not token:
        header = request.headers.get("Authorization", "")
        token = header.split(" ", 1)[1].strip() if header.startswith("Bearer ") else None
    if not token:
        return None
    try:
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return None
    uid = oid(payload.get("sub") or payload.get("id") or payload.get("user_id"))
    return mongo.db.users.find_one({"_id": uid}) if uid else None


@socketio.on("connect")
def on_connect(auth=None):
    user = _authenticate(auth)
    if not user or user.get("is_blocked") or user.get("isBlocked"):
        raise ConnectionRefusedError("unauthorized")
    uid = str(user["_id"])
    _sessions[request.sid] = uid
    join_room(f"user_{uid}")
    if user.get("role") in ("admin", "super_admin") or user.get("is_admin"):
        join_room("admins")


@socketio.on("disconnect")
def on_disconnect(*_):
    _sessions.pop(request.sid, None)


def _ride_for_member(ride_id, uid):
    rid = oid(ride_id)
    if not rid:
        return None
    return mongo.db.rides.find_one({
        "_id": rid,
        "$or": [{"driver_id": uid}, {"bookings.passenger_id": uid}]})


@socketio.on("join_ride")
def on_join_ride(data):
    uid = _sessions.get(request.sid)
    ride_id = (data or {}).get("ride_id")
    if uid and _ride_for_member(ride_id, uid):          # only people on the ride may listen
        join_room(f"ride_{ride_id}")


@socketio.on("leave_ride")
def on_leave_ride(data):
    ride_id = (data or {}).get("ride_id")
    if ride_id:
        leave_room(f"ride_{ride_id}")


@socketio.on("update_location")
def on_update_location(data):
    uid = _sessions.get(request.sid)
    data = data or {}
    rid = oid(data.get("ride_id"))
    if not uid or not rid:
        return
    try:
        lat, lng = float(data["latitude"]), float(data["longitude"])
    except (KeyError, TypeError, ValueError):
        return
    ride = mongo.db.rides.find_one({"_id": rid, "driver_id": uid, "status": IN_PROGRESS})
    if not ride:                                          # only the driver, only while in progress
        return
    mongo.db.rides.update_one({"_id": rid}, {"$set": {"current_location": {"lat": lat, "lng": lng, "at": now_utc()}}})
    emit("location_update", {"ride_id": str(rid), "latitude": lat, "longitude": lng,
                             "speed": data.get("speed"), "heading": data.get("heading")},
         to=f"ride_{rid}", include_self=False)
