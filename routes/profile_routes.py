import os
import uuid
import datetime
import re
from functools import wraps
from bson import ObjectId
from flask import Blueprint, request, jsonify, current_app, g
import jwt
from routes.security import signed_upload_url
from extensions import mongo

profile_bp = Blueprint('profile', __name__)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "message": "Authentication required. Bearer token missing."}), 401

        token = auth_header.split(" ", 1)[1].strip()
        secret_key = current_app.config.get("SECRET_KEY", "secret_key")
        try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token has expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Invalid token."}), 401

        user_id = payload.get("sub") or payload.get("id") or payload.get("user_id")
        if not user_id:
            return jsonify({"success": False, "message": "Invalid token payload."}), 401

        try:
            user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        except Exception:
            user = None

        if not user:
            return jsonify({"success": False, "message": "User not found."}), 401

        if user.get("is_blocked") or user.get("isBlocked"):
            return jsonify({"success": False, "message": "Account is blocked. Contact administrator."}), 403

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


def detect_file_type(data: bytes):
    """
    Detect file extension from file magic bytes (JPG, PNG, WEBP, PDF).
    Returns 'jpg', 'png', 'webp', 'pdf', or None.
    """
    if not data or len(data) < 4:
        return None
    # JPEG starts with FF D8 FF
    if data.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    # PNG starts with 89 50 4E 47 0D 0A 1A 0A
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    # WEBP starts with RIFF and has WEBP at offset 8
    if data.startswith(b'RIFF') and len(data) >= 12 and data[8:12] == b'WEBP':
        return 'webp'
    # PDF header in the first 1024 bytes
    if data[:1024].find(b'%PDF') != -1:
        return 'pdf'
    return None


def serialize_profile(user):
    ver_status = user.get("verification_status")
    id_card = user.get("id_card_url")
    receipt = user.get("fee_receipt_url")

    if not ver_status:
        if id_card and receipt:
            ver_status = "pending"
        elif user.get("is_verified") is True:
            ver_status = "verified"
        else:
            ver_status = "unverified"

    # One source of truth: is_verified is ONLY True when verification_status == 'verified'
    is_ver = (ver_status == "verified")

    id_card_url = signed_upload_url(id_card)
    fee_receipt_url = signed_upload_url(receipt)

    created_at = user.get("created_at") or user.get("createdAt") or ""
    if isinstance(created_at, datetime.datetime):
        created_at = created_at.isoformat()

    driver_profile = user.get("driverProfile", {})
    is_driver_enabled = driver_profile.get("isDriverEnabled", False) if isinstance(driver_profile, dict) else False

    return {
        "id": str(user["_id"]),
        "_id": str(user["_id"]),
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "role": user.get("role", "student"),
        "department": user.get("department", "Student"),
        "institute": user.get("institute", "MET BKC"),
        "is_verified": is_ver,
        "isVerified": is_ver,
        "verification_status": ver_status,
        "id_card_url": id_card_url,
        "fee_receipt_url": fee_receipt_url,
        "rejection_reason": user.get("rejection_reason"),
        "upi_id": user.get("upi_id"),
        "avg_rating": float(user.get("avg_rating", user.get("rating", 0)) or 0),
        "rides_given": int(user.get("rides_given", 0) or 0),
        "rides_taken": int(user.get("rides_taken", 0) or 0),
        "is_blocked": bool(user.get("is_blocked", False)),
        "isDriverEnabled": is_driver_enabled,
        "driverProfile": driver_profile,
        "created_at": str(created_at),
    }


def process_document_upload(doc_type):
    """
    Handles multipart upload for 'id_card' or 'fee_receipt'.
    Accepts multipart under any part name (app uses image).
    Detects JPG/PNG/WEBP/PDF from file content.
    Limits to 5 MB. Creates upload folder if missing.
    Returns JSON {success, message, ...}
    """
    try:
        user = g.current_user
        user_id = str(user['_id'])

        if not request.files:
            return jsonify({
                'success': False,
                'message': 'No file part found in request. Please upload a document.'
            }), 400

        # Find the uploaded file object (the app uses 'image', but accept any part name)
        file_obj = request.files.get('image')
        if not file_obj:
            for candidate_key in ['file', 'doc', 'document', doc_type, 'receipt', 'id_card']:
                if candidate_key in request.files:
                    file_obj = request.files[candidate_key]
                    break
        if not file_obj:
            file_obj = next(iter(request.files.values()), None)

        if not file_obj:
            return jsonify({
                'success': False,
                'message': 'No file selected for upload.'
            }), 400

        # Read the file content
        data = file_obj.read()
        if not data or len(data) == 0:
            return jsonify({
                'success': False,
                'message': 'Uploaded file is empty.'
            }), 400

        # Limit: 5 MB
        max_size = 5 * 1024 * 1024
        if len(data) > max_size:
            return jsonify({
                'success': False,
                'message': 'File size exceeds the 5 MB limit.'
            }), 400

        # Detect format from content
        ext = detect_file_type(data)
        if not ext:
            return jsonify({
                'success': False,
                'message': 'Invalid file format. Only JPG, PNG, WEBP, and PDF files are accepted.'
            }), 400

        # Create upload folder if missing
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        if not upload_folder:
            upload_folder = os.path.join(current_app.root_path, 'uploads')
        os.makedirs(upload_folder, exist_ok=True)

        filename = f"{doc_type}_{user_id}_{int(datetime.datetime.now().timestamp())}_{uuid.uuid4().hex[:6]}.{ext}"
        filepath = os.path.join(upload_folder, filename)

        with open(filepath, 'wb') as f:
            f.write(data)

        base_url = request.host_url.rstrip('/')
        absolute_file_url = f"{base_url}/uploads/{filename}"      # stored form (unsigned, never sent to clients as-is)

        field_to_set = 'id_card_url' if doc_type == 'id_card' else 'fee_receipt_url'
        now = datetime.datetime.now(datetime.timezone.utc)

        # Check latest user document
        latest_user = mongo.db.users.find_one({'_id': user['_id']})
        id_card = absolute_file_url if doc_type == 'id_card' else latest_user.get('id_card_url')
        fee_receipt = absolute_file_url if doc_type == 'fee_receipt' else latest_user.get('fee_receipt_url')

        update_fields = {
            field_to_set: absolute_file_url,
            'updatedAt': now
        }

        # When both an ID card and a fee receipt are on file and the user is unverified, set the status to pending.
        current_status = latest_user.get('verification_status', 'unverified')
        if id_card and fee_receipt and current_status in ['unverified', 'rejected', None, '']:
            update_fields['verification_status'] = 'pending'
            update_fields['is_verified'] = False
            update_fields['isVerified'] = False
            new_status = 'pending'
        else:
            new_status = current_status

        mongo.db.users.update_one({'_id': user['_id']}, {'$set': update_fields})

        readable_name = "ID card" if doc_type == 'id_card' else "Fee receipt"
        return jsonify({
            'success': True,
            'message': f'{readable_name} uploaded successfully',
            'url': signed_upload_url(absolute_file_url),
            'id_card_url': signed_upload_url(id_card),
            'fee_receipt_url': signed_upload_url(fee_receipt),
            'verification_status': new_status,
            'is_verified': (new_status == 'verified'),
        }), 200

    except Exception as e:
        current_app.logger.exception(f"Exception during {doc_type} upload: {e}")
        return jsonify({
            'success': False,
            'message': f'Server error during upload: {str(e)}'
        }), 500


@profile_bp.route('/upload-id', methods=['POST'])
@token_required
def upload_id_card():
    """POST /api/profile/upload-id"""
    return process_document_upload('id_card')


@profile_bp.route('/upload-receipt', methods=['POST'])
@token_required
def upload_fee_receipt():
    """POST /api/profile/upload-receipt"""
    return process_document_upload('fee_receipt')


@profile_bp.route('', methods=['GET'])
@token_required
def get_user_profile():
    """GET /api/profile or /api/profile/me"""
    user = g.current_user
    # Refresh user from database to ensure fresh state
    fresh_user = mongo.db.users.find_one({'_id': user['_id']}) or user
    profile_data = serialize_profile(fresh_user)
    return jsonify({
        'success': True,
        'user': profile_data,
        'profile': profile_data,
        'is_verified': profile_data['is_verified'],
        'verification_status': profile_data['verification_status'],
        'id_card_url': profile_data['id_card_url'],
        'fee_receipt_url': profile_data['fee_receipt_url'],
    }), 200


_UPI_RE = re.compile(r"^[\w.\-]{2,64}@[A-Za-z]{2,32}$")


@profile_bp.route('', methods=['PUT'])
@token_required
def update_profile():
    """PUT /api/profile  {name, department, institute, upi_id}: only these fields can be changed."""
    data = request.get_json(silent=True) or {}
    updates = {}
    for field, label, max_len in (('name', 'Name', 60), ('department', 'Department', 60), ('institute', 'Institute', 80)):
        if field in data and data[field] is not None:
            value = str(data[field]).strip()
            if field == 'name' and not value:
                return jsonify({'success': False, 'message': 'Name cannot be empty'}), 400
            if len(value) > max_len:
                return jsonify({'success': False, 'message': f'{label} is too long (max {max_len} characters)'}), 400
            updates[field] = value
    if 'upi_id' in data and data['upi_id'] is not None:
        upi = str(data['upi_id']).strip()
        if upi and not _UPI_RE.match(upi):
            return jsonify({'success': False, 'message': 'Enter a valid UPI ID, for example name@okaxis'}), 400
        updates['upi_id'] = upi or None
    if not updates:
        return jsonify({'success': False, 'message': 'Nothing to update'}), 400

    updates['updatedAt'] = datetime.datetime.now(datetime.timezone.utc)
    mongo.db.users.update_one({'_id': g.current_user['_id']}, {'$set': updates})
    fresh = mongo.db.users.find_one({'_id': g.current_user['_id']})
    profile_data = serialize_profile(fresh)
    return jsonify({'success': True, 'message': 'Profile updated', 'user': profile_data, 'profile': profile_data}), 200


def serialize_ride(ride):
    if not ride:
        return None
    r_id = str(ride.get('_id', ride.get('id', '')))
    driver_id = str(ride.get('driver_id', ''))

    # Extract coordinates
    origin_lat = ride.get('origin_lat')
    origin_lng = ride.get('origin_lng')
    start_loc = ride.get('start_location')
    if isinstance(start_loc, dict) and 'coordinates' in start_loc:
        coords = start_loc['coordinates']
        if len(coords) >= 2:
            if origin_lng is None:
                origin_lng = coords[0]
            if origin_lat is None:
                origin_lat = coords[1]
    elif isinstance(start_loc, (list, tuple)) and len(start_loc) >= 2:
        if origin_lng is None:
            origin_lng = start_loc[0]
        if origin_lat is None:
            origin_lat = start_loc[1]

    driver_name = ride.get('driver_name')
    driver_rating = ride.get('driver_rating')
    if (not driver_name or driver_rating is None) and driver_id:
        try:
            d_user = mongo.db.users.find_one({'_id': ObjectId(driver_id)})
            if d_user:
                if not driver_name:
                    driver_name = d_user.get('name', 'Driver')
                if driver_rating is None:
                    driver_rating = float(d_user.get('avg_rating', d_user.get('rating', 5.0)))
        except Exception:
            pass

    if not driver_name:
        driver_name = 'Driver'
    if driver_rating is None:
        driver_rating = 5.0

    seats_avail = int(ride.get('seats_available', 0))
    seats_tot = int(ride.get('seats_total', seats_avail))
    seats_taken = int(ride.get('seats_taken', max(0, seats_tot - seats_avail)))

    dep_time = ride.get('departure_time')
    if not dep_time:
        created = ride.get('created_at')
        if isinstance(created, datetime.datetime):
            dep_time = created.isoformat()
        else:
            dep_time = str(created or '')

    origin_str = ride.get('origin') or ride.get('start_location_name')
    if not origin_str and isinstance(start_loc, str):
        origin_str = start_loc
    if not origin_str:
        origin_str = 'Pickup Location'

    return {
        'id': r_id,
        '_id': r_id,
        'driver_id': driver_id,
        'driver_name': driver_name,
        'driver_rating': float(driver_rating),
        'origin': str(origin_str),
        'destination': str(ride.get('destination', '')),
        'origin_lat': float(origin_lat) if origin_lat is not None else None,
        'origin_lng': float(origin_lng) if origin_lng is not None else None,
        'destination_lat': float(ride['destination_lat']) if ride.get('destination_lat') is not None else None,
        'destination_lng': float(ride['destination_lng']) if ride.get('destination_lng') is not None else None,
        'departure_time': str(dep_time),
        'seats_available': seats_avail,
        'seats_taken': seats_taken,
        'fare': float(ride.get('fare', 0.0)),
        'status': str(ride.get('status', 'PENDING')),
    }


@token_required
def get_dashboard():
    """
    GET /api/dashboard
    Returns {success:true, data:{active_rides, fuel_saved_today, riders_online, your_rating, upcoming_rides:[ride], active_ride:ride|null, unread_notifications}}
    using existing collections; zeros and empty lists when there is no data, never an error.
    """
    try:
        user = g.current_user
        user_id = str(user['_id'])

        # active_rides
        try:
            active_rides = mongo.db.rides.count_documents({
                'status': {'$in': ['PENDING', 'pending', 'ACTIVE', 'active', 'IN_PROGRESS', 'in_progress']}
            })
        except Exception:
            active_rides = 0

        # fuel_saved_today
        try:
            today_start = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            completed_today = mongo.db.rides.count_documents({
                'status': {'$in': ['COMPLETED', 'completed']},
                'created_at': {'$gte': today_start}
            })
            fuel_saved_today = round(completed_today * 2.5, 1)
        except Exception:
            fuel_saved_today = 0.0

        # riders_online
        try:
            riders_online = mongo.db.users.count_documents({
                'role': {'$nin': ['admin', 'super_admin']},
                'is_blocked': {'$ne': True}
            })
        except Exception:
            riders_online = 0

        # your_rating
        try:
            your_rating = float(user.get('avg_rating', user.get('rating', 5.0)))
        except Exception:
            your_rating = 5.0

        # upcoming_rides
        upcoming_rides = []
        try:
            upcoming_cursor = mongo.db.rides.find({
                '$or': [
                    {'driver_id': user_id},
                    {'bookings.passenger_id': user_id}
                ],
                'status': {'$in': ['PENDING', 'pending', 'SCHEDULED', 'scheduled', 'CONFIRMED', 'confirmed']}
            }).sort('created_at', -1).limit(10)
            for r in upcoming_cursor:
                upcoming_rides.append(serialize_ride(r))
        except Exception:
            upcoming_rides = []

        # active_ride
        active_ride = None
        try:
            active_doc = mongo.db.rides.find_one({
                '$or': [
                    {'driver_id': user_id},
                    {'bookings.passenger_id': user_id}
                ],
                'status': {'$in': ['IN_PROGRESS', 'in_progress', 'active', 'ACTIVE']}
            })
            if active_doc:
                active_ride = serialize_ride(active_doc)
        except Exception:
            active_ride = None

        # unread_notifications
        try:
            unread_notifications = mongo.db.notifications.count_documents({
                '$or': [
                    {'recipient_id': user_id},
                    {'user_id': user_id}
                ],
                'is_read': False
            })
        except Exception:
            unread_notifications = 0

        return jsonify({
            'success': True,
            'data': {
                'active_rides': int(active_rides),
                'fuel_saved_today': float(fuel_saved_today),
                'riders_online': int(riders_online),
                'your_rating': float(your_rating),
                'upcoming_rides': upcoming_rides,
                'active_ride': active_ride,
                'unread_notifications': int(unread_notifications)
            }
        }), 200

    except Exception as e:
        current_app.logger.exception(f"Unexpected error in get_dashboard: {e}")
        return jsonify({
            'success': True,
            'data': {
                'active_rides': 0,
                'fuel_saved_today': 0.0,
                'riders_online': 0,
                'your_rating': 5.0,
                'upcoming_rides': [],
                'active_ride': None,
                'unread_notifications': 0
            }
        }), 200


@profile_bp.route('/ride-history', methods=['GET'])
@token_required
def get_ride_history():
    """
    GET /api/profile/ride-history?page=&limit=
    Returns {success:true, rides:[...], page, total} of the user's completed/cancelled rides as driver or passenger, newest first; empty list when none.
    """
    user = g.current_user
    user_id = str(user['_id'])

    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except (ValueError, TypeError):
        page = 1

    try:
        limit = int(request.args.get('limit', 10))
        if limit < 1:
            limit = 10
    except (ValueError, TypeError):
        limit = 10

    rides_list = []
    total = 0
    try:
        query = {
            '$and': [
                {
                    '$or': [
                        {'driver_id': user_id},
                        {'bookings.passenger_id': user_id}
                    ]
                },
                {
                    'status': {'$in': ['COMPLETED', 'completed', 'CANCELLED', 'cancelled', 'FINISHED', 'finished']}
                }
            ]
        }
        total = mongo.db.rides.count_documents(query)
        cursor = mongo.db.rides.find(query).sort([('created_at', -1), ('_id', -1)]).skip((page - 1) * limit).limit(limit)
        for r in cursor:
            rides_list.append(serialize_ride(r))
    except Exception as e:
        current_app.logger.warning(f"Error fetching ride history: {e}")
        rides_list = []
        total = 0

    return jsonify({
        'success': True,
        'rides': rides_list,
        'page': page,
        'total': total
    }), 200
