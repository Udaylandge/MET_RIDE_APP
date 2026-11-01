import re
import datetime
from bson import ObjectId
from flask import Blueprint, request, jsonify, current_app
import jwt
from extensions import mongo

ride_bp = Blueprint('rides', __name__)


def init_ride_indexes():
    """
    Ensure 2dsphere index exists on start_location field in rides collection.
    """
    try:
        mongo.db.rides.create_index([("start_location", "2dsphere")])
    except Exception as e:
        current_app.logger.error(f"Failed to create 2dsphere index: {e}")


def get_current_user_from_request(user_id_param=None):
    user = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        secret_key = current_app.config.get("SECRET_KEY", "secret_key")
        try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            uid = payload.get("sub") or payload.get("id") or payload.get("user_id")
            if uid:
                try:
                    user = mongo.db.users.find_one({"_id": ObjectId(uid)})
                except Exception:
                    pass
        except Exception:
            pass

    if not user and user_id_param:
        try:
            user = mongo.db.users.find_one({"_id": ObjectId(user_id_param)})
        except Exception:
            pass

    return user


def verify_user_ride_access(user, action_name="post or request rides"):
    """
    verification_status == 'verified' is required to post or request rides.
    Admin and super_admin accounts are exempt from the ride gating.
    Verified users must pass.
    """
    if not user:
        return False, (jsonify({
            "success": False,
            "error": "authentication_required",
            "message": "Authentication required. Bearer token or valid user ID missing."
        }), 401)

    if user.get("is_blocked") or user.get("isBlocked"):
        return False, (jsonify({
            "success": False,
            "error": "account_blocked",
            "message": "Account is blocked. Contact administrator."
        }), 403)

    is_exempt = user.get("is_admin", False) or user.get("role") in ["admin", "super_admin"]
    if is_exempt:
        return True, None

    ver_status = user.get("verification_status", "unverified")
    is_verified = (ver_status == "verified") or (user.get("is_verified") is True) or (user.get("isVerified") is True)
    if not is_verified:
        return False, (jsonify({
            "success": False,
            "error": "verification_required",
            "message": f"Account must be verified before you can {action_name}. Please verify your account first."
        }), 403)

    return True, None


@ride_bp.route('', methods=['POST'])
@ride_bp.route('/', methods=['POST'])
def offer_ride():
    """
    POST /api/rides or /api/rides/offer
    Accepts: origin, destination, origin_lat, origin_lng, destination_lat, destination_lng,
             departure_time, seats_available, fare, upi_id (and legacy start_location).
    Required: origin, destination, coordinates, seats_available >= 1.
    Optional: fare (default 0), upi_id.
    """
    data = request.get_json(silent=True) or {}
    keys_received = list(data.keys())

    def bad_request(msg):
        current_app.logger.warning(f"400 Bad Request on {request.path}: received keys={keys_received}, reason={msg}")
        return jsonify({"success": False, "message": msg}), 400

    driver_id = data.get('driver_id')
    user = get_current_user_from_request(driver_id)
    allowed, err_resp = verify_user_ride_access(user, "post rides")
    if not allowed:
        return err_resp

    if not driver_id:
        driver_id = str(user['_id']) if user else None

    # Origin extraction
    origin = data.get('origin') or data.get('start_address') or data.get('from')
    raw_location = data.get('start_location')
    if not origin and isinstance(raw_location, str):
        origin = raw_location

    # Destination extraction
    destination = data.get('destination') or data.get('to')
    if not destination or str(destination).strip() == '':
        return bad_request("destination is required")
    destination = str(destination).strip()

    # Origin coordinates extraction
    origin_lat = data.get('origin_lat') if data.get('origin_lat') is not None else data.get('start_lat')
    if origin_lat is None:
        origin_lat = data.get('lat')
    origin_lng = data.get('origin_lng') if data.get('origin_lng') is not None else data.get('start_lng')
    if origin_lng is None:
        origin_lng = data.get('lng')

    if isinstance(raw_location, dict):
        if origin_lat is None:
            origin_lat = raw_location.get('lat') if 'lat' in raw_location else raw_location.get('latitude')
        if origin_lng is None:
            origin_lng = raw_location.get('lng') if 'lng' in raw_location else raw_location.get('longitude')
        if origin_lat is None and origin_lng is None and 'coordinates' in raw_location:
            coords = raw_location['coordinates']
            origin_lng, origin_lat = coords[0], coords[1]
    elif isinstance(raw_location, (list, tuple)) and len(raw_location) >= 2:
        if origin_lng is None and origin_lat is None:
            origin_lng, origin_lat = raw_location[0], raw_location[1]

    if not origin:
        if raw_location and (origin_lat is not None and origin_lng is not None):
            origin = "Pickup Location"
        else:
            return bad_request("origin is required")
    origin = str(origin).strip()

    if origin_lat is None or origin_lng is None:
        return bad_request("origin_lat and origin_lng coordinates are required")

    try:
        lat = float(origin_lat)
        lng = float(origin_lng)
    except (ValueError, TypeError):
        return bad_request("origin_lat and origin_lng coordinates must be valid numbers")

    # Seats available
    seats_raw = data.get('seats_available') if data.get('seats_available') is not None else data.get('seats')
    if seats_raw is None:
        return bad_request("seats_available is required")
    try:
        seats_available = int(seats_raw)
    except (ValueError, TypeError):
        return bad_request("seats_available must be an integer")
    if seats_available < 1:
        return bad_request("seats_available must be at least 1")

    # Destination coordinates (optional)
    dest_lat_raw = data.get('destination_lat') if data.get('destination_lat') is not None else data.get('dest_lat')
    dest_lng_raw = data.get('destination_lng') if data.get('destination_lng') is not None else data.get('dest_lng')
    if isinstance(data.get('destination_location'), dict):
        dest_lat_raw = dest_lat_raw or data['destination_location'].get('lat')
        dest_lng_raw = dest_lng_raw or data['destination_location'].get('lng')
    dest_lat = None
    dest_lng = None
    if dest_lat_raw is not None and dest_lng_raw is not None:
        try:
            dest_lat = float(dest_lat_raw)
            dest_lng = float(dest_lng_raw)
        except (ValueError, TypeError):
            pass

    # Departure time (optional, ISO string or epoch)
    dep_time_raw = data.get('departure_time') or data.get('time') or data.get('departureTime')
    if isinstance(dep_time_raw, (int, float)):
        try:
            ts = float(dep_time_raw)
            if ts > 1e11:  # ms
                ts /= 1000.0
            departure_time = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
        except Exception:
            departure_time = str(dep_time_raw)
    elif dep_time_raw:
        departure_time = str(dep_time_raw)
    else:
        departure_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Fare (optional, default 0)
    try:
        fare = float(data.get('fare', 0))
    except (ValueError, TypeError):
        fare = 0.0

    # upi_id (optional)
    upi_id = data.get('upi_id') or (user.get('upi_id') if user else '') or ''

    # Driver info
    driver_name = user.get('name', 'Driver') if user else 'Driver'
    driver_rating = float(user.get('avg_rating', user.get('rating', 5.0))) if user else 5.0

    geojson_start_location = {
        "type": "Point",
        "coordinates": [lng, lat]
    }

    now = datetime.datetime.now(datetime.timezone.utc)
    ride_doc = {
        "driver_id": str(driver_id or (user['_id'] if user else '')),
        "driver_name": driver_name,
        "driver_rating": driver_rating,
        "origin": origin,
        "destination": destination,
        "origin_lat": lat,
        "origin_lng": lng,
        "destination_lat": dest_lat,
        "destination_lng": dest_lng,
        "start_location": geojson_start_location,
        "departure_time": departure_time,
        "seats_available": seats_available,
        "seats_total": seats_available,
        "seats_taken": 0,
        "fare": fare,
        "upi_id": str(upi_id).strip(),
        "status": "PENDING",
        "bookings": [],
        "created_at": now
    }

    init_ride_indexes()
    result = mongo.db.rides.insert_one(ride_doc)

    ride_doc['id'] = str(result.inserted_id)
    ride_doc['_id'] = str(result.inserted_id)
    ride_doc['created_at'] = now.isoformat()

    return jsonify({
        'success': True,
        'message': 'Ride offered successfully',
        'ride': ride_doc
    }), 201


@ride_bp.route('/nearby', methods=['GET'])
def search_or_nearby_rides():
    """
    GET /api/rides/nearby or /api/rides/search
    Accepts: latitude/longitude (or lat/lng), radius in km (default 5),
             and optional destination (empty string means no filter).
    Returns {success:true, rides:[...]} with each ride as id, driver_id, driver_name,
    driver_rating, origin, destination, origin_lat, origin_lng, destination_lat,
    destination_lng, departure_time, seats_available, seats_taken, fare, status.
    """
    keys_received = list(request.args.keys())

    def bad_request(msg):
        current_app.logger.warning(f"400 Bad Request on {request.path}: received args={keys_received}, reason={msg}")
        return jsonify({"success": False, "message": msg}), 400

    # If caller is authenticated, check verification status
    auth_user = get_current_user_from_request(request.args.get('passenger_id') or request.args.get('user_id'))
    if auth_user:
        allowed, err_resp = verify_user_ride_access(auth_user, "find rides")
        if not allowed:
            return err_resp

    lat_raw = request.args.get('latitude') if request.args.get('latitude') is not None else (
        request.args.get('lat') if request.args.get('lat') is not None else request.args.get('passenger_lat')
    )
    lng_raw = request.args.get('longitude') if request.args.get('longitude') is not None else (
        request.args.get('lng') if request.args.get('lng') is not None else request.args.get('passenger_lng')
    )

    if lat_raw is None or str(lat_raw).strip() == '':
        return bad_request("latitude is required")
    if lng_raw is None or str(lng_raw).strip() == '':
        return bad_request("longitude is required")

    try:
        lat = float(lat_raw)
        lng = float(lng_raw)
    except (ValueError, TypeError):
        return bad_request("latitude and longitude must be valid numbers")

    # Radius in km (default 5)
    radius_km = 5.0
    if request.args.get('radius') is not None and str(request.args.get('radius')).strip() != '':
        try:
            radius_km = float(request.args.get('radius'))
        except (ValueError, TypeError):
            radius_km = 5.0
    elif request.args.get('max_distance') is not None and str(request.args.get('max_distance')).strip() != '':
        try:
            md = float(request.args.get('max_distance'))
            radius_km = (md / 1000.0) if md > 100 else md
        except (ValueError, TypeError):
            radius_km = 5.0

    max_dist_meters = radius_km * 1000.0

    # Optional destination (empty string means no filter)
    dest_filter = str(request.args.get('destination', '')).strip()

    init_ride_indexes()

    query = {
        "status": {"$in": ["PENDING", "pending", "ACTIVE", "active"]},
        "seats_available": {"$gt": 0},
        "start_location": {
            "$near": {
                "$geometry": {
                    "type": "Point",
                    "coordinates": [lng, lat]
                },
                "$maxDistance": max_dist_meters
            }
        }
    }

    if dest_filter:
        query["destination"] = {"$regex": re.escape(dest_filter), "$options": "i"}

    rides_cursor = mongo.db.rides.find(query)

    matching_rides = []
    user_cache = {}

    for ride in rides_cursor:
        r_id = str(ride.get('_id', ride.get('id', '')))
        driver_id = str(ride.get('driver_id', ''))

        # Driver details
        driver_name = ride.get('driver_name')
        driver_rating = ride.get('driver_rating')
        if (not driver_name or driver_rating is None) and driver_id:
            if driver_id not in user_cache:
                try:
                    d_user = mongo.db.users.find_one({'_id': ObjectId(driver_id)})
                    user_cache[driver_id] = d_user
                except Exception:
                    user_cache[driver_id] = None
            d_user = user_cache.get(driver_id)
            if d_user:
                if not driver_name:
                    driver_name = d_user.get('name', 'Driver')
                if driver_rating is None:
                    driver_rating = float(d_user.get('avg_rating', d_user.get('rating', 5.0)))

        if not driver_name:
            driver_name = 'Driver'
        if driver_rating is None:
            driver_rating = 5.0

        # Coordinates
        o_lat = ride.get('origin_lat')
        o_lng = ride.get('origin_lng')
        sl = ride.get('start_location')
        if isinstance(sl, dict) and 'coordinates' in sl:
            coords = sl['coordinates']
            if len(coords) >= 2:
                if o_lng is None:
                    o_lng = coords[0]
                if o_lat is None:
                    o_lat = coords[1]
        elif isinstance(sl, (list, tuple)) and len(sl) >= 2:
            if o_lng is None:
                o_lng = sl[0]
            if o_lat is None:
                o_lat = sl[1]

        seats_avail = int(ride.get('seats_available', 0))
        seats_tot = int(ride.get('seats_total', seats_avail))
        seats_taken = int(ride.get('seats_taken', max(0, seats_tot - seats_avail)))

        dep_time = ride.get('departure_time')
        if not dep_time:
            c_at = ride.get('created_at')
            dep_time = c_at.isoformat() if isinstance(c_at, datetime.datetime) else str(c_at or '')

        origin_str = ride.get('origin') or ride.get('start_location_name')
        if not origin_str and isinstance(sl, str):
            origin_str = sl
        if not origin_str:
            origin_str = 'Pickup Location'

        matching_rides.append({
            "id": r_id,
            "driver_id": driver_id,
            "driver_name": driver_name,
            "driver_rating": float(driver_rating),
            "origin": str(origin_str),
            "destination": str(ride.get('destination', '')),
            "origin_lat": float(o_lat) if o_lat is not None else None,
            "origin_lng": float(o_lng) if o_lng is not None else None,
            "destination_lat": float(ride['destination_lat']) if ride.get('destination_lat') is not None else None,
            "destination_lng": float(ride['destination_lng']) if ride.get('destination_lng') is not None else None,
            "departure_time": str(dep_time),
            "seats_available": seats_avail,
            "seats_taken": seats_taken,
            "fare": float(ride.get('fare', 0.0)),
            "status": str(ride.get('status', 'PENDING')),
        })

    return jsonify({
        'success': True,
        'rides': matching_rides,
        'count': len(matching_rides),
        'radius_km': radius_km
    }), 200


@ride_bp.route('/<ride_id>', methods=['GET'])
def get_ride(ride_id):
    """
    GET /api/rides/<ride_id>
    Returns full details of a single ride by its MongoDB ObjectId.
    """
    try:
        oid = ObjectId(ride_id)
    except Exception:
        current_app.logger.warning(f"400 Bad Request on {request.path}: Invalid ride_id format '{ride_id}'")
        return jsonify({'success': False, 'message': 'Invalid ride_id format'}), 400

    ride = mongo.db.rides.find_one({'_id': oid})
    if not ride:
        return jsonify({'success': False, 'message': 'Ride not found'}), 404

    from routes.ride_utils import serialize_ride, user_from_token
    viewer = user_from_token()
    return jsonify({'success': True, 'ride': serialize_ride(ride, str(viewer['_id']) if viewer else None)}), 200
