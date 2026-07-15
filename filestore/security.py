"""Security helpers: encryption at rest, safe file storage, ledger hashing.

This module centralises the security-sensitive logic so it can be reviewed
and unit-tested in one place rather than scattered through the routes.
"""
import hashlib
import os
import uuid

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename


class Encryptor:
    """Thin wrapper around Fernet for encrypting file contents at rest."""

    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt data. Raises InvalidToken if the data is corrupt or the
        key is wrong -- callers should handle that specific exception rather
        than swallowing everything with a bare except."""
        return self._fernet.decrypt(token)


def generate_key() -> bytes:
    """Generate a new Fernet key (used by the key-bootstrap CLI/helper)."""
    return Fernet.generate_key()


def safe_storage_name(original_filename: str) -> str:
    """Return a collision-free, traversal-safe name to store a file under.

    The original name is sanitised with secure_filename (which strips path
    separators and traversal sequences like ``../``) purely to preserve a
    readable extension, then prefixed with a random UUID so that:

      * two users uploading "report.pdf" never overwrite each other, and
      * the on-disk name cannot be used to guess or reach another file.

    The human-friendly original name is stored separately in the database.
    """
    cleaned = secure_filename(original_filename) or "file"
    return f"{uuid.uuid4().hex}_{cleaned}"


def file_extension(original_filename: str) -> str:
    """Extract a lowercase extension without a leading dot, or '' if none."""
    _, ext = os.path.splitext(original_filename)
    return ext.lstrip(".").lower()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Sentinel value used as the "previous hash" of the very first ledger entry.
GENESIS_PREV_HASH = "0" * 64


def compute_ledger_hash(prev_hash: str, sent_by: str, sent_to: str,
                        stored_name: str, content_hash: str,
                        timestamp_iso: str) -> str:
    """Compute the integrity hash for an append-only ledger entry.

    Each entry hashes its own contents together with the previous entry's
    hash. That linkage is what makes the ledger tamper-evident: altering any
    past entry changes its hash, which breaks every hash after it. This is a
    hash-chained audit log -- deliberately not called a "blockchain", since
    there is no distributed consensus, just integrity linkage.
    """
    payload = "|".join([
        prev_hash, sent_by, sent_to, stored_name, content_hash, timestamp_iso,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = [
    "Encryptor", "InvalidToken", "generate_key", "safe_storage_name",
    "file_extension", "sha256_hex", "compute_ledger_hash", "GENESIS_PREV_HASH",
]
