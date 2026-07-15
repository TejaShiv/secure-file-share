"""Flask extension instances.

These are created once here and initialised against the app inside the
factory. Keeping a single ``db`` instance in one place avoids the original
bug where two separate SQLAlchemy() objects existed (one in app.py, one in
models.py) and only worked by accident of import order.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO

db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO()
