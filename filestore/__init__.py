"""Application factory for FileStorageApp.

Usage:
    from filestore import create_app
    app = create_app()
"""
import os

from flask import Flask

from .config import get_config
from .extensions import db, migrate, socketio
from .security import Encryptor, generate_key


def _load_encryption_key(app):
    """Resolve the Fernet key from config, or bootstrap one in development.

    In production the key must be supplied via ENCRYPTION_KEY. In development
    we persist a generated key to a local file so restarts can still decrypt
    previously uploaded files.
    """
    key = app.config.get("ENCRYPTION_KEY")
    if key:
        return key.encode() if isinstance(key, str) else key

    if not app.config.get("DEBUG") and not app.config.get("TESTING"):
        raise RuntimeError("ENCRYPTION_KEY environment variable is required in production")

    key_path = os.path.join(app.config["UPLOAD_FOLDER"], "..", "dev_secret.key")
    key_path = os.path.abspath(key_path)
    if os.path.exists(key_path):
        with open(key_path, "rb") as fh:
            return fh.read()
    new_key = generate_key()
    with open(key_path, "wb") as fh:
        fh.write(new_key)
    return new_key


def create_app(config_name=None):
    app = Flask(__name__)
    app.config.from_object(get_config(config_name))

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    # Use the dependency-free threading mode under tests so the async server
    # backend (eventlet) is never imported; it is only needed for the live
    # production server.
    socketio.init_app(app, async_mode="threading" if app.config.get("TESTING") else None)

    # Attach a ready-to-use encryptor to the app for the file routes.
    app.extensions["encryptor"] = Encryptor(_load_encryption_key(app))

    # Track connected usernames for the "online users" widget.
    app.extensions["online_users"] = set()

    from .auth.routes import auth_bp
    from .files.routes import files_bp
    from .main.routes import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)

    from . import sockets  # noqa: F401  (registers socket handlers)

    return app
