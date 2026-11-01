import datetime
from functools import wraps
import re
from bson import ObjectId
from flask import Blueprint, request, jsonify, current_app, g
import jwt
from werkzeug.security import check_password_hash
from routes.security import rate_limit, lockout_message, record_failed_login, clear_failed_logins, signed_upload_url
from extensions import mongo

admin_bp = Blueprint('admin', __name__)


def admin_required(f):
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

        user_id = payload.get("sub")
        if not user_id:
            return jsonify({"success": False, "message": "Invalid token payload."}), 401

        try:
            user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        except Exception:
            user = None

        if not user:
            return jsonify({"success": False, "message": "User not found."}), 401

        role = user.get("role", "")
        is_admin = user.get("is_admin", False)
        if not is_admin and role not in ["admin", "super_admin"]:
            return jsonify({"success": False, "message": "Admin or Super Admin access required."}), 403

        g.admin_user = user
        return f(*args, **kwargs)

    return decorated


def serialize_admin_user(u):
    ver_status = u.get("verification_status")
    id_card = u.get("id_card_url")
    receipt = u.get("fee_receipt_url")

    # verification_status (unverified|pending|verified|rejected) is the only truth
    if not ver_status:
        if id_card and receipt:
            ver_status = "pending"
        elif u.get("is_verified") is True or u.get("isVerified") is True:
            ver_status = "verified"
        else:
            ver_status = "unverified"

    # One source of truth: is_verified must equal verification_status == "verified"
    is_ver = (ver_status == "verified")

    id_card_url = signed_upload_url(id_card)
    fee_receipt_url = signed_upload_url(receipt)

    created_at = u.get("created_at") or u.get("createdAt") or ""
    if isinstance(created_at, datetime.datetime):
        created_at = created_at.isoformat()

    return {
        "id": str(u["_id"]),
        "name": u.get("name", ""),
        "email": u.get("email", ""),
        "role": u.get("role", "student"),
        "department": u.get("department", "Student"),
        "institute": u.get("institute", "MET BKC"),
        "is_verified": is_ver,
        "isVerified": is_ver,
        "verification_status": ver_status,
        "id_card_url": id_card_url,
        "fee_receipt_url": fee_receipt_url,
        "rejection_reason": u.get("rejection_reason"),
        "verification_deadline": u.get("verification_deadline"),
        "block_deadline": u.get("block_deadline"),
        "is_blocked": bool(u.get("is_blocked", False)),
        "avg_rating": float(u.get("avg_rating", 5.0)),
        "rides_given": int(u.get("rides_given", 0)),
        "rides_taken": int(u.get("rides_taken", 0)),
        "created_at": str(created_at),
    }


def get_pending_filter():
    """pending = both documents uploaded and awaiting review"""
    return {
        "$and": [
            {"verification_status": {"$ne": "verified"}},
            {"is_verified": {"$ne": True}},
            {
                "$or": [
                    {"verification_status": "pending"},
                    {
                        "id_card_url": {"$nin": [None, ""]},
                        "fee_receipt_url": {"$nin": [None, ""]},
                    }
                ]
            }
        ]
    }


def get_unverified_filter():
    """unverified = newly registered user who has not uploaded both documents yet"""
    return {
        "$and": [
            {"verification_status": {"$in": ["unverified", None, ""]}},
            {"is_verified": {"$ne": True}},
            {
                "$or": [
                    {"id_card_url": {"$in": [None, ""]}},
                    {"fee_receipt_url": {"$in": [None, ""]}}
                ]
            }
        ]
    }


def get_needs_action_filter():
    """needs_action = unverified + pending together"""
    return {
        "$and": [
            {"verification_status": {"$ne": "verified"}},
            {"is_verified": {"$ne": True}},
            {"verification_status": {"$nin": ["rejected"]}},
            {
                "$or": [
                    {"verification_status": {"$in": ["unverified", "pending", None, ""]}},
                    {"id_card_url": {"$nin": [None, ""]}},
                    {"fee_receipt_url": {"$nin": [None, ""]}}
                ]
            }
        ]
    }


@admin_bp.route('/login', methods=['POST'])
@rate_limit('admin_login', 8, 300)
def admin_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))

    if not email or not password:
        current_app.logger.warning(f"[ADMIN LOGIN FAILED] Missing email or password. Received keys: {list(data.keys())}")
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        current_app.logger.warning(f"[ADMIN LOGIN FAILED] Email '{email}': user not found")
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

    if not user.get('is_admin') and user.get('role') not in ['admin', 'super_admin']:
        current_app.logger.warning(f"[ADMIN LOGIN FAILED] Email '{email}': not an admin")
        return jsonify({'success': False, 'message': 'This account does not have admin access'}), 403

    locked = lockout_message(user)
    if locked:
        return jsonify({'success': False, 'message': locked}), 429

    if not user.get('password') or not check_password_hash(user['password'], password):
        current_app.logger.warning(f"[ADMIN LOGIN FAILED] Email '{email}': wrong password")
        record_failed_login(user)
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    clear_failed_logins(user)

    if user.get('is_blocked') or user.get('isBlocked'):
        current_app.logger.warning(f"[ADMIN LOGIN FAILED] Email '{email}': account is blocked")
        return jsonify({'success': False, 'message': 'Account is blocked. Contact administrator.'}), 403

    secret_key = current_app.config.get('SECRET_KEY', 'secret_key')
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        'sub': str(user['_id']),
        'email': email,
        'role': user.get('role', 'admin'),
        'is_admin': True,
        'iat': now,
        'exp': now + datetime.timedelta(days=7),
    }
    token = jwt.encode(payload, secret_key, algorithm='HS256')

    return jsonify({
        'success': True,
        'message': 'Admin login successful',
        'access_token': token,
        'token': token,
        'refresh_token': token,
        'user': {
            'id': str(user['_id']),
            'email': user['email'],
            'name': user.get('name', 'Admin'),
            'role': user.get('role', 'admin'),
            'is_admin': True,
            'is_verified': user.get('is_verified', user.get('isVerified', True)),
            'department': user.get('department', 'Administration'),
            'institute': user.get('institute', 'MET BKC'),
        },
    }), 200


@admin_bp.route('/stats', methods=['GET'])
@admin_required
def admin_stats():
    # Never include admin or super_admin accounts in student counts
    base_filter = {"role": {"$nin": ["admin", "super_admin"]}, "is_admin": {"$ne": True}}

    total_users = mongo.db.users.count_documents(base_filter)
    total_rides = mongo.db.rides.count_documents({})
    active_rides = mongo.db.rides.count_documents({"$or": [{"status": "active"}, {"active": True}]})

    # pending_review = pending only
    pending_filter = {"$and": [base_filter, get_pending_filter()]}
    pending_count = mongo.db.users.count_documents(pending_filter)

    # needs_action = unverified + pending together
    needs_action_filter = {"$and": [base_filter, get_needs_action_filter()]}
    needs_action_count = mongo.db.users.count_documents(needs_action_filter)

    active_sos = 0
    try:
        active_sos = mongo.db.alerts.count_documents({"status": "active"})
    except Exception:
        pass

    return jsonify({
        'success': True,
        'stats': {
            'total_users': total_users,
            'total_rides': total_rides,
            'active_rides': active_rides,
            'pending_review': pending_count,
            'pending_verifications': pending_count,
            'needs_action': needs_action_count,
            'active_sos_alerts': active_sos,
            'rides_today': total_rides,
        },
    }), 200


@admin_bp.route('/users', methods=['GET'])
@admin_required
def admin_users():
    """
    GET /api/admin/users
    status: 'needs_action' (default: unverified + pending), 'pending', 'unverified', 'verified', 'rejected', 'blocked', 'all'
    """
    status = request.args.get('status', '').strip().lower()
    q = request.args.get('q', '').strip()
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    skip = (page - 1) * limit

    # Must never return admin or super_admin accounts
    query_parts = [{"role": {"$nin": ["admin", "super_admin"]}, "is_admin": {"$ne": True}}]

    # Documented default for review screen is needs_action (unverified + pending)
    if not status or status == 'needs_action':
        query_parts.append(get_needs_action_filter())
    elif status == 'pending':
        query_parts.append(get_pending_filter())
    elif status == 'unverified':
        query_parts.append(get_unverified_filter())
    elif status == 'verified':
        query_parts.append({
            "$or": [
                {"verification_status": "verified"},
                {"is_verified": True},
            ]
        })
    elif status == 'rejected':
        query_parts.append({"verification_status": "rejected"})
    elif status == 'blocked':
        query_parts.append({"is_blocked": True})
    elif status == 'all':
        pass
    else:
        query_parts.append({"verification_status": status})

    if q:
        escaped_q = re.escape(q)
        query_parts.append({
            "$or": [
                {"name": {"$regex": escaped_q, "$options": "i"}},
                {"email": {"$regex": escaped_q, "$options": "i"}},
            ]
        })

    final_query = {"$and": query_parts} if len(query_parts) > 1 else query_parts[0]

    users_cursor = mongo.db.users.find(final_query, {"password": 0, "otp": 0})
    all_users = [serialize_admin_user(u) for u in users_cursor]

    def parse_created_at(val):
        if not val:
            return 0.0
        if isinstance(val, (int, float)):
            return float(val)
        try:
            val_str = str(val).replace('Z', '+00:00')
            return datetime.datetime.fromisoformat(val_str).timestamp()
        except Exception:
            return 0.0

    # Sort with pending first, then newest created first
    def sort_key(u):
        is_pending = 0 if u.get("verification_status") == "pending" else 1
        created_ts = parse_created_at(u.get("created_at"))
        return (is_pending, -created_ts)

    sorted_users = sorted(all_users, key=sort_key)
    paged_users = sorted_users[skip: skip + limit]

    return jsonify({
        'success': True,
        'count': len(paged_users),
        'total': len(sorted_users),
        'users': paged_users,
    }), 200


@admin_bp.route('/users/<user_id>', methods=['GET'])
@admin_required
def admin_get_single_user(user_id):
    """GET /api/admin/users/<id> returning one user for detail screen."""
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        return jsonify({"success": False, "message": "Invalid user ID"}), 400

    u = mongo.db.users.find_one({
        "_id": obj_id,
        "role": {"$nin": ["admin", "super_admin"]},
        "is_admin": {"$ne": True},
    })
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404

    return jsonify({
        "success": True,
        "user": serialize_admin_user(u),
    }), 200


@admin_bp.route('/users/<user_id>/verify', methods=['POST'])
@admin_required
def verify_user(user_id):
    """
    POST /api/admin/users/<id>/verify
    body: { "action": "approve" | "reject", "reason": "optional" }
    """
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

    target_user = mongo.db.users.find_one({'_id': obj_id})
    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    data = request.get_json(silent=True) or {}
    action = str(data.get('action', 'approve')).strip().lower()
    reason = str(data.get('reason', '')).strip()

    now = datetime.datetime.now(datetime.timezone.utc)
    user_name = target_user.get('name', 'User')

    if action == 'approve':
        id_card = target_user.get('id_card_url')
        fee_receipt = target_user.get('fee_receipt_url')

        if not id_card or not str(id_card).strip() or not fee_receipt or not str(fee_receipt).strip():
            return jsonify({
                'success': False,
                'message': 'User has not uploaded ID card and fee receipt yet',
            }), 400

        mongo.db.users.update_one(
            {'_id': obj_id},
            {
                '$set': {
                    'is_verified': True,
                    'isVerified': True,
                    'verification_status': 'verified',
                    'is_blocked': False,
                    'updatedAt': now,
                },
                '$unset': {
                    'rejection_reason': '',
                },
            },
        )

        try:
            mongo.db.notifications.insert_one({
                'recipient_id': str(obj_id),
                'user_id': str(obj_id),
                'title': 'ID Verification Approved',
                'message': 'Your student verification documents have been approved by admin. You now have full access to campus rides.',
                'type': 'verification_approved',
                'is_read': False,
                'created_at': now,
            })
        except Exception as e:
            current_app.logger.warning(f"Failed to create notification: {e}")

        return jsonify({
            'success': True,
            'message': f'{user_name} approved successfully',
        }), 200

    elif action == 'reject':
        mongo.db.users.update_one(
            {'_id': obj_id},
            {
                '$set': {
                    'is_verified': False,
                    'isVerified': False,
                    'verification_status': 'rejected',
                    'rejection_reason': reason,
                    'updatedAt': now,
                },
            },
        )

        try:
            mongo.db.notifications.insert_one({
                'recipient_id': str(obj_id),
                'user_id': str(obj_id),
                'title': 'ID Verification Rejected',
                'message': f"Your verification documents were rejected: {reason or 'Invalid documents provided. Please re-upload.'}",
                'type': 'verification_rejected',
                'is_read': False,
                'created_at': now,
            })
        except Exception as e:
            current_app.logger.warning(f"Failed to create notification: {e}")

        return jsonify({
            'success': True,
            'message': f'{user_name} rejected: {reason or "No reason provided"}',
        }), 200

    else:
        return jsonify({
            'success': False,
            'message': f"Invalid verification action '{action}'. Must be 'approve' or 'reject'",
        }), 400


@admin_bp.route('/users/<user_id>/block', methods=['POST'])
@admin_required
def block_user(user_id):
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

    user = mongo.db.users.find_one({'_id': obj_id})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    now = datetime.datetime.now(datetime.timezone.utc)
    mongo.db.users.update_one(
        {'_id': obj_id},
        {'$set': {'is_blocked': True, 'updatedAt': now}},
    )
    return jsonify({'success': True, 'message': f"{user.get('name', 'User')} blocked successfully"}), 200


@admin_bp.route('/users/<user_id>/unblock', methods=['POST'])
@admin_required
def unblock_user(user_id):
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

    user = mongo.db.users.find_one({'_id': obj_id})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    now = datetime.datetime.now(datetime.timezone.utc)
    mongo.db.users.update_one(
        {'_id': obj_id},
        {'$set': {'is_blocked': False, 'updatedAt': now}},
    )
    return jsonify({'success': True, 'message': f"{user.get('name', 'User')} unblocked successfully"}), 200


@admin_bp.route('/users/<user_id>/role', methods=['POST'])
@admin_required
def update_user_role(user_id):
    try:
        obj_id = ObjectId(user_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

    user = mongo.db.users.find_one({'_id': obj_id})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    data = request.get_json(silent=True) or {}
    role = data.get('role', 'user')
    is_admin = (role in ['admin', 'super_admin'])
    now = datetime.datetime.now(datetime.timezone.utc)

    mongo.db.users.update_one(
        {'_id': obj_id},
        {'$set': {'role': role, 'is_admin': is_admin, 'updatedAt': now}},
    )
    return jsonify({'success': True, 'message': f'Role updated to {role}'}), 200


@admin_bp.route('/sos-alerts', methods=['GET'])
@admin_required
def get_sos_alerts():
    alerts_list = []
    try:
        alerts_cursor = mongo.db.alerts.find().sort('created_at', -1).limit(50)
        for a in alerts_cursor:
            a['id'] = str(a['_id'])
            del a['_id']
            alerts_list.append(a)
    except Exception:
        pass
    return jsonify({'success': True, 'count': len(alerts_list), 'alerts': alerts_list}), 200


@admin_bp.route('/sos-alerts/<alert_id>/resolve', methods=['POST'])
@admin_required
def resolve_sos_alert(alert_id):
    try:
        obj_id = ObjectId(alert_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid alert ID'}), 400

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        mongo.db.alerts.update_one(
            {'_id': obj_id},
            {'$set': {'status': 'resolved', 'resolved_at': now}},
        )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    return jsonify({'success': True, 'message': 'Alert resolved'}), 200


@admin_bp.route('/rides', methods=['GET'])
@admin_required
def get_admin_rides():
    from routes.ride_utils import serialize_ride
    wanted = (request.args.get('status') or '').strip().lower()
    groups = {
        'active': ['IN_PROGRESS'],
        'waiting': ['PENDING', 'FULL', 'ACTIVE', 'pending', 'active'],
        'completed': ['COMPLETED', 'CANCELLED'],
    }
    query = {'status': {'$in': groups[wanted]}} if wanted in groups else {}
    rides_list = []
    try:
        for r in mongo.db.rides.find(query).sort('created_at', -1).limit(100):
            item = serialize_ride(r)
            item['passengers'] = serialize_ride(r, str(r.get('driver_id')))['passengers']
            rides_list.append(item)
    except Exception as e:
        current_app.logger.warning(f"admin rides failed: {e}")
    return jsonify({'success': True, 'count': len(rides_list), 'rides': rides_list}), 200
