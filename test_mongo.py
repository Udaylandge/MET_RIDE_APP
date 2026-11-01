
import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

uri = os.getenv("MONGO_URI")

if not uri:
    raise ValueError("MONGO_URI is missing from .env")

try:
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=10000
    )

    client.admin.command("ping")

    db = client["MET_RIDE_DB"]

    print("SUCCESS: Connected to MongoDB Atlas!")
    print("Database:", db.name)
    print("Connection:", "Active")

except Exception as e:
    print("MongoDB connection failed:")
    print(type(e).__name__, str(e))

finally:
    if "client" in globals():
        client.close()
