"""Application configuration.

Configuration is environment-driven. Nothing secret is hardcoded: the
session secret and encryption key are read from the environment, so the
same code runs safely in development and production with different values.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class BaseConfig:
    # SECRET_KEY signs session cookies. If it is guessable, anyone can forge
    # a session for any user, so it must come from the environment.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB upload ceiling

    # Where encrypted file blobs are written.
    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads")
    )

    # Fernet key used to encrypt file contents at rest (base64, 32 bytes).
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

    # Account lockout policy.
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_SECONDS = 30

    @staticmethod
    def _db_uri(name):
        return "sqlite:///" + os.path.join(BASE_DIR, name)


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    # A default key is acceptable ONLY in development so `flask run` works
    # out of the box. Production must supply its own via the environment.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-not-for-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", BaseConfig._db_uri("file_storage_dev.db")
    )


class ProductionConfig(BaseConfig):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or BaseConfig._db_uri(
        "file_storage.db"
    )

    def __init__(self):
        # Fail loudly at startup if production secrets are missing, rather
        # than silently running with an insecure default.
        if not self.SECRET_KEY:
            raise RuntimeError("SECRET_KEY environment variable is required in production")


class TestingConfig(BaseConfig):
    TESTING = True
    SECRET_KEY = "testing-key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False


_CONFIGS = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name=None):
    """Resolve a config class from a name or the FLASK_CONFIG env var."""
    name = name or os.environ.get("FLASK_CONFIG", "development")
    config_class = _CONFIGS.get(name, DevelopmentConfig)
    # ProductionConfig validates required env vars in __init__.
    return config_class() if isinstance(config_class, type) and name == "production" else config_class
