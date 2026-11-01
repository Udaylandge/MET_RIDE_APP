import os
import sys
import datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash

def main():
    # Load .env file
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    load_dotenv(dotenv_path=env_path, override=True)

    admin_email = os.getenv('ADMIN_EMAIL')
    new_password = os.getenv('NEW_ADMIN_PASSWORD') or os.getenv('ADMIN_PASSWORD')

    if not admin_email:
        sys.stderr.write("Error: ADMIN_EMAIL not found in .env\n")
        sys.exit(1)

    if not new_password:
        sys.stderr.write("Error: NEW_ADMIN_PASSWORD not found in .env\n")
        sys.exit(1)

    admin_email = admin_email.strip().lower()
    mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/met_ride')

    client = MongoClient(mongo_uri)
    db = client.get_default_database()
    if db is None or db.name == 'admin':
        db = client['met_ride']

    # Use the same hashing method that login verifies (werkzeug generate_password_hash)
    password_hash = generate_password_hash(new_password)
    now = datetime.datetime.now(datetime.timezone.utc)

    user = db.users.find_one({'email': admin_email})

    if user:
        # Preserve super_admin if defined, else admin
        existing_role = user.get('role')
        role = existing_role if existing_role in ['admin', 'super_admin'] else 'admin'

        db.users.update_one(
            {'_id': user['_id']},
            {
                '$set': {
                    'password': password_hash,
                    'role': role,
                    'is_admin': True,
                    'is_blocked': False,
                    'isBlocked': False,
                    'verification_status': 'verified',
                    'is_verified': True,
                    'isVerified': True,
                    'updatedAt': now
                }
            }
        )
    else:
        # Create new admin user
        db.users.insert_one({
            'email': admin_email,
            'name': 'Admin',
            'password': password_hash,
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

    # Print "done", never print the password
    print("done")


if __name__ == '__main__':
    main()
