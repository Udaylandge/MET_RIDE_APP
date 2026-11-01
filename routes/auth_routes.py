import secrets
import datetime
import jwt
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import mongo

auth_bp = Blueprint('auth', __name__)



from routes.security import (rate_limit, lockout_message, record_failed_login, clear_failed_logins, password_problem)

OTP_TTL_MIN = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 45


def _dev_extra(otp):
    """The OTP is only ever echoed in the API response when DEV_RETURN_OTP=true (local testing)."""
    import os
    if os.getenv('DEV_RETURN_OTP', 'false').lower() in ('true', '1', 'yes'):
        return {'dev_otp': otp}
    return {}


def _otp_fields(otp, now):
    return {
        'otp_hash': generate_password_hash(otp),
        'otp_expires_at': now + datetime.timedelta(minutes=OTP_TTL_MIN),
        'otp_attempts': 0,
        'otpCreatedAt': now,
    }


def _check_otp(user, otp):
    """Validate a hashed, expiring, attempt-limited OTP. Returns (ok, message)."""
    h = user.get('otp_hash')
    if not h:
        return False, 'No active code. Please request a new OTP.'
    if int(user.get('otp_attempts', 0)) >= OTP_MAX_ATTEMPTS:
        return False, 'Too many wrong attempts. Request a new OTP.'
    exp = user.get('otp_expires_at')
    if exp is not None:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            return False, 'This code has expired. Request a new OTP.'
    if not check_password_hash(h, otp):
        mongo.db.users.update_one({'_id': user['_id']}, {'$inc': {'otp_attempts': 1}})
        return False, 'Invalid email or OTP'
    return True, ''


@auth_bp.route('/request-otp', methods=['POST'])
@rate_limit('request_otp', 8, 600)
def request_otp():
    """
    POST /api/auth/request-otp or /api/request-otp
    Accepts: { "email": "student@bkc.met.edu" }
    Verifies @bkc.met.edu domain, generates 6-digit OTP, upserts user document with isVerified: false,
    and sends OTP email via Flask-Mail.
    """
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    if not email.endswith('@bkc.met.edu'):
        return jsonify({'success': False, 'message': 'Email must belong to the @bkc.met.edu domain'}), 400

    now = datetime.datetime.now(datetime.timezone.utc)
    existing = mongo.db.users.find_one({'email': email})
    last = existing.get('otpCreatedAt') if existing else None
    if last is not None:
        if last.tzinfo is None:
            last = last.replace(tzinfo=datetime.timezone.utc)
        if (now - last).total_seconds() < OTP_RESEND_SECONDS:
            return jsonify({'success': False, 'message': 'Please wait a few seconds before requesting another code.'}), 429

    otp = str(secrets.randbelow(900000) + 100000)
    mongo.db.users.update_one(
        {'email': email},
        {
            '$set': {'email': email, 'updatedAt': now, **_otp_fields(otp, now)},
            '$unset': {'otp': ''},
            '$setOnInsert': {
                'isVerified': False, 'is_verified': False, 'verification_status': 'unverified',
                'role': 'student', 'is_blocked': False,
                'created_at': now.isoformat(), 'createdAt': now,
            }
        },
        upsert=True
    )

    import os
    if os.getenv('BYPASS_EMAIL', 'false').lower() in ('true', '1', 'yes'):
        print(f"[MET RIDE OTP] {email} -> {otp}", flush=True)       # local testing only
        return jsonify({'success': True, 'message': 'OTP generated (BYPASS_EMAIL: see server console)',
                        **_dev_extra(otp)}), 200

    from routes.mailer import send_otp_email
    ok, err = send_otp_email(email, otp)
    if not ok:
        current_app.logger.error(f"OTP email to {email} failed: {err}")
        # Let the user retry immediately instead of waiting out the resend throttle.
        mongo.db.users.update_one({'email': email}, {'$unset': {'otpCreatedAt': ''}})
        return jsonify({'success': False,
                        'message': 'Could not send the verification email. Please try again shortly.',
                        **_dev_extra(otp)}), 502
    return jsonify({'success': True, 'message': 'OTP sent to your email', **_dev_extra(otp)}), 200


@auth_bp.route('/verify-otp', methods=['POST'])
@rate_limit('verify_otp', 15, 600)
def verify_otp():
    """
    POST /api/auth/verify-otp or /api/verify-otp
    Accepts: { "email": "student@bkc.met.edu", "otp": "123456" }
    Verifies OTP, marks email as verified, returns JWT token and user info.
    Does NOT mark student identity as verified (identity verification requires admin approval).
    """
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    otp = str(data.get('otp', '')).strip()

    if not email or not otp:
        return jsonify({'success': False, 'message': 'Email and OTP are required'}), 400

    user = mongo.db.users.find_one({'email': email})

    if not user:
        return jsonify({'success': False, 'message': 'Invalid email or OTP'}), 400
    ok, msg = _check_otp(user, otp)
    if not ok:
        return jsonify({'success': False, 'message': msg}), 400

    driver_profile = user.get('driverProfile', {})
    is_driver_enabled = driver_profile.get('isDriverEnabled', False) if isinstance(driver_profile, dict) else False

    now = datetime.datetime.now(datetime.timezone.utc)
    # Verification status is the single source of truth (email verification != ID verification)
    ver_status = user.get('verification_status')
    if not ver_status:
        ver_status = 'unverified'
    is_ver = (ver_status == 'verified')

    mongo.db.users.update_one(
        {'email': email},
        {
            '$set': {
                'email_verified': True,
                'emailVerified': True,
                'isVerified': is_ver,
                'is_verified': is_ver,
                'verification_status': ver_status,
                'updatedAt': now
            },
            '$unset': {
                'otp': '', 'otp_hash': '', 'otp_expires_at': '', 'otp_attempts': ''
            }
        }
    )

    user_id = str(user['_id'])
    role = user.get('role', 'student')
    secret_key = current_app.config.get('SECRET_KEY', 'secret_key')
    payload = {
        'sub': user_id,
        'email': email,
        'role': role,
        'iat': now,
        'exp': now + datetime.timedelta(days=7)
    }

    token = jwt.encode(payload, secret_key, algorithm='HS256')

    user_data = {
        'id': user_id,
        'name': user.get('name', email.split('@')[0]),
        'email': email,
        'role': role,
        'is_verified': is_ver,
        'isVerified': is_ver,
        'verification_status': ver_status,
        'is_blocked': user.get('is_blocked', False)
    }

    return jsonify({
        'success': True,
        'message': 'OTP verified successfully',
        'access_token': token,
        'token': token,
        'refresh_token': token,
        'user': user_data,
        'isDriverEnabled': is_driver_enabled
    }), 200


@auth_bp.route('/register', methods=['POST'])
@rate_limit('register', 10, 3600)
def register():
    """
    POST /api/register or /api/auth/register
    Accepts: { "name": "...", "email": "...", "password": "...", "otp": "..." (optional) }
    New accounts start unverified.
    """
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    otp = str(data.get('otp', '')).strip()

    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    if not email.endswith('@bkc.met.edu'):
        return jsonify({'success': False, 'message': 'Must use @bkc.met.edu institutional email'}), 400

    if not password or len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    problem = password_problem(password)
    if problem:
        return jsonify({'success': False, 'message': problem}), 400

    if not otp:
        return jsonify({'success': False, 'message': 'Enter the OTP sent to your email to finish registration'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'success': False, 'message': 'Request an OTP for this email first'}), 400
    if user.get('password'):
        # Never let a register call overwrite an existing account's password.
        return jsonify({'success': False, 'message': 'An account with this email already exists. Please log in.'}), 409

    ok, msg = _check_otp(user, otp)
    if not ok:
        return jsonify({'success': False, 'message': msg}), 400

    password_hash = generate_password_hash(password)
    now = datetime.datetime.now(datetime.timezone.utc)

    # Email ownership is now proven; ID verification is still a separate admin step.
    mongo.db.users.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'name': name or user.get('name') or email.split('@')[0],
                'password': password_hash,
                'email_verified': True, 'emailVerified': True,
                'updatedAt': now,
            },
            '$unset': {'otp': '', 'otp_hash': '', 'otp_expires_at': '', 'otp_attempts': ''},
        }
    )

    updated_user = mongo.db.users.find_one({'email': email})
    user_id = str(updated_user['_id'])

    secret_key = current_app.config.get('SECRET_KEY', 'secret_key')
    payload = {
        'sub': user_id,
        'email': email,
        'role': updated_user.get('role', 'student'),
        'iat': now,
        'exp': now + datetime.timedelta(days=7)
    }
    token = jwt.encode(payload, secret_key, algorithm='HS256')

    user_data = {
        'id': user_id,
        'name': updated_user.get('name', name),
        'email': email,
        'role': updated_user.get('role', 'student'),
        'is_verified': updated_user.get('verification_status') == 'verified',
        'isVerified': updated_user.get('verification_status') == 'verified',
        'verification_status': updated_user.get('verification_status', 'unverified'),
        'is_blocked': bool(updated_user.get('is_blocked', False))
    }

    return jsonify({
        'success': True,
        'message': 'Registration successful',
        'access_token': token,
        'token': token,
        'refresh_token': token,
        'user': user_data
    }), 200


@auth_bp.route('/login', methods=['POST'])
@rate_limit('login', 12, 300)
def login():
    """
    POST /api/login or /api/auth/login
    Accepts: { "email": "...", "password": "..." }
    is_verified is strictly (verification_status == 'verified').
    """
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', '')).strip()

    if not email or not password:
        current_app.logger.warning(f"[LOGIN FAILED] Missing email or password. Received keys: {list(data.keys())}")
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        current_app.logger.warning(f"[LOGIN FAILED] Email '{email}': user not found")
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

    locked = lockout_message(user)
    if locked:
        return jsonify({'success': False, 'message': locked}), 429

    if not user.get('password') or not check_password_hash(user['password'], password):
        current_app.logger.warning(f"[LOGIN FAILED] Email '{email}': wrong password")
        record_failed_login(user)
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    clear_failed_logins(user)

    if user.get('is_blocked') or user.get('isBlocked'):
        current_app.logger.warning(f"[LOGIN FAILED] Email '{email}': account is blocked")
        return jsonify({'success': False, 'message': 'Account is blocked. Contact administrator.'}), 403

    user_id = str(user['_id'])
    role = user.get('role', 'student')
    now = datetime.datetime.now(datetime.timezone.utc)

    secret_key = current_app.config.get('SECRET_KEY', 'secret_key')
    payload = {
        'sub': user_id,
        'email': email,
        'role': role,
        'iat': now,
        'exp': now + datetime.timedelta(days=7)
    }
    token = jwt.encode(payload, secret_key, algorithm='HS256')

    ver_status = user.get('verification_status', 'unverified')
    is_ver = (ver_status == 'verified')

    user_data = {
        'id': user_id,
        'name': user.get('name', email.split('@')[0]),
        'email': email,
        'role': role,
        'is_verified': is_ver,
        'isVerified': is_ver,
        'verification_status': ver_status,
        'is_blocked': user.get('is_blocked', False)
    }

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'access_token': token,
        'token': token,
        'refresh_token': token,
        'user': user_data
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """
    POST /api/auth/refresh or /api/refresh
    """
    data = request.get_json(silent=True) or {}
    ref_token = str(data.get('refresh_token', ''))
    secret_key = current_app.config.get('SECRET_KEY')
    try:
        payload = jwt.decode(ref_token, secret_key, algorithms=['HS256'])
        from bson import ObjectId
        user = mongo.db.users.find_one({'_id': ObjectId(payload.get('sub'))})
        # Re-check the account every time: deleted/blocked users cannot keep refreshing,
        # and the role always comes from the database (a demoted admin loses admin rights).
        if not user or user.get('is_blocked') or user.get('isBlocked'):
            return jsonify({'success': False, 'message': 'Invalid or expired refresh token'}), 401
        now = datetime.datetime.now(datetime.timezone.utc)
        new_payload = {
            'sub': str(user['_id']),
            'email': user.get('email'),
            'role': user.get('role', 'student'),
            'iat': now,
            'exp': now + datetime.timedelta(days=7)
        }
        new_token = jwt.encode(new_payload, secret_key, algorithm='HS256')
        return jsonify({
            'success': True,
            'access_token': new_token,
            'token': new_token,
            'refresh_token': new_token
        }), 200
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid or expired refresh token'}), 401


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    POST /api/logout or /api/auth/logout
    """
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200
