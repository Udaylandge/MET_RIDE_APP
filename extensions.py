from flask_pymongo import PyMongo
from flask_mail import Mail

mongo = PyMongo()
mail = Mail()
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")
