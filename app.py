import importlib
import os
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from extensions import mongo, mail, socketio

# Load environment variables from .env
load_dotenv()

import datetime
from werkzeug.security import generate_password_hash


def seed_admin_if_missing(app):
    with app.app_context():
        try:
            admin_email = os.getenv('ADMIN_EMAIL')
            admin_password = os.getenv('NEW_ADMIN_PASSWORD') or os.getenv('ADMIN_PASSWORD')
            if not admin_email or not admin_password:
                return

            admin_email = admin_email.strip().lower()
            existing = mongo.db.users.find_one({'email': admin_email})
            if not existing:
                now = datetime.datetime.now(datetime.timezone.utc)
                mongo.db.users.insert_one({
                    'email': admin_email,
                    'name': 'Admin',
                    'password': generate_password_hash(admin_password),
                    'role': 'admin',
                    'is_admin': True,
                    'is_blocked': False,
                    'isBlocked': False,
                    'verification_status': 'verified',
                    'is_verified': True,
                    'isVerified': True,
                    'created_at': now.isoformat(),
                    'createdAt': now,
                    'updatedAt': now
                })
                app.logger.info(f"[SEED] Created initial admin account: {admin_email}")
            else:
                # Idempotent: Never overwrite an existing password!
                pass
        except Exception as e:
            app.logger.warning(f"[SEED] Startup admin seeding skipped: {e}")


def _startup_checks(app):
    log = app.logger
    if os.getenv('BYPASS_EMAIL', 'false').lower() in ('true', '1', 'yes'):
        log.warning("BYPASS_EMAIL=true: OTPs are printed in this console and NOT emailed. Do not use in production.")
    if os.getenv('DEV_RETURN_OTP', 'false').lower() in ('true', '1', 'yes'):
        log.warning("DEV_RETURN_OTP=true: OTPs are returned in API responses. INSECURE. Turn it off.")
    provider = os.getenv('EMAIL_PROVIDER', 'smtp').lower()
    if provider == 'brevo' and not os.getenv('BREVO_API_KEY', '').strip():
        log.error("EMAIL_PROVIDER=brevo but BREVO_API_KEY is empty: OTP emails will fail.")
    if provider == 'brevo' and not (os.getenv('MAIL_FROM_EMAIL') or os.getenv('MAIL_DEFAULT_SENDER')):
        log.error("MAIL_FROM_EMAIL is empty: use a sender address verified in Brevo.")


def create_app():
    app = Flask(__name__)

    # Core Config
    secret = os.getenv('SECRET_KEY', '')
    weak = len(secret) < 24 or secret.lower() in ('change_me_in_production', 'secret', 'secret_key', 'changeme')
    if weak and os.getenv('ALLOW_INSECURE_DEV', 'false').lower() != 'true':
        raise RuntimeError(
            "SECRET_KEY is missing or too weak. Anyone could forge login tokens (including admin). "
            "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\"  "
            "and put it in .env as SECRET_KEY=...")
    app.config['SECRET_KEY'] = secret or 'insecure-dev-key-only'
    app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024   # reject huge uploads early

    # MongoDB Config
    app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/met_ride')

    # Flask-Mail Config
    app.config['MAIL_SERVER']         = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT']           = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS']        = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USE_SSL']        = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
    app.config['MAIL_USERNAME']       = os.getenv('MAIL_USERNAME', '')
    app.config['MAIL_PASSWORD']       = os.getenv('MAIL_PASSWORD', '')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', os.getenv('MAIL_USERNAME', ''))

    # Upload Folder Config
    upload_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_folder

    # Initialize Extensions
    CORS(app, resources={r'/api/*': {'origins': os.getenv('CORS_ORIGINS', '*')}})  # Android needs no CORS; restrict browsers via CORS_ORIGINS
    mongo.init_app(app)
    mail.init_app(app)
    socketio.init_app(app)

    # Idempotent startup admin seeding (creates admin only if missing, never overwrites existing password)
    seed_admin_if_missing(app)

    # Register Blueprints
    from routes.auth_routes import auth_bp, login, register, logout
    from routes.ride_routes import ride_bp
    from routes.admin_routes import admin_bp
    from routes.profile_routes import profile_bp, get_dashboard
    from routes.lifecycle_routes import lifecycle_bp
    importlib.import_module('routes.socket_handlers')   # registers the Socket.IO events

    app.register_blueprint(auth_bp,      url_prefix='/api/auth')
    app.register_blueprint(profile_bp,   url_prefix='/api/profile')
    app.register_blueprint(ride_bp,      url_prefix='/api/rides')
    app.register_blueprint(admin_bp,     url_prefix='/api/admin')
    app.register_blueprint(lifecycle_bp, url_prefix='/api')

    # Top-level endpoints used by the Android app
    app.add_url_rule('/api/login',     'login_root',     login,         methods=['POST'])
    app.add_url_rule('/api/register',  'register_root',  register,      methods=['POST'])
    app.add_url_rule('/api/logout',    'logout_root',    logout,        methods=['POST'])
    app.add_url_rule('/api/dashboard', 'dashboard_root', get_dashboard, methods=['GET'])

    # Serve uploaded documents
    from flask import send_from_directory, jsonify
    @app.route('/uploads/<path:filename>')
    @app.route('/api/uploads/<path:filename>')
    def serve_uploaded_file(filename):
        # ID cards / receipts are private: only links signed by the server (valid for 1 hour) work.
        from flask import request, abort
        from routes.security import file_token_ok
        if '/' in filename or '\\' in filename or not file_token_ok(filename, request.args.get('t')):
            abort(403)
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('X-Frame-Options', 'DENY')
        resp.headers.setdefault('Referrer-Policy', 'no-referrer')
        resp.headers.setdefault('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
        from flask import request
        if request.path.startswith('/api/'):
            resp.headers['Cache-Control'] = 'no-store'
        return resp

    @app.route('/api/health')
    def health():
        return jsonify({'success': True, 'status': 'ok'})

    @app.errorhandler(403)
    def handle_forbidden(e):
        return jsonify({'success': False, 'message': 'Forbidden'}), 403

    @app.errorhandler(429)
    def handle_too_many(e):
        return jsonify({'success': False, 'message': 'Too many requests'}), 429

    _startup_checks(app)

    # Global JSON error handlers (never return raw HTML errors)
    @app.errorhandler(400)
    def handle_bad_request(e):
        msg = getattr(e, 'description', str(e))
        return jsonify({'success': False, 'message': str(msg)}), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({'success': False, 'message': 'Resource not found'}), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(e):
        return jsonify({'success': False, 'message': 'Method not allowed'}), 405

    @app.errorhandler(413)
    def handle_payload_too_large(e):
        return jsonify({'success': False, 'message': 'File size exceeds 5 MB limit'}), 413

    @app.errorhandler(500)
    def handle_server_error(e):
        app.logger.exception(f"Internal server error: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

    return app


if __name__ == '__main__':
    app = create_app()

    port = int(os.getenv('PORT', 5001))

    print(f"\nMET RIDE server running on http://0.0.0.0:{port}  (health: /api/health)\n")

    debug = os.getenv('FLASK_DEBUG', 'false').lower() in ('true', '1', 'yes')
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, use_reloader=debug,
                 allow_unsafe_werkzeug=True)
