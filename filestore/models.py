"""Database models."""
import datetime

from .extensions import db


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    lock_time = db.Column(db.DateTime)

    def is_locked(self) -> bool:
        return self.lock_time is not None and _utcnow() < self._aware(self.lock_time)

    def lock_seconds_remaining(self) -> int:
        if not self.is_locked():
            return 0
        return int((self._aware(self.lock_time) - _utcnow()).total_seconds())

    @staticmethod
    def _aware(dt):
        # SQLite returns naive datetimes; treat stored times as UTC.
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)

    def __repr__(self):
        return f"<User {self.username}>"


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    # Human-readable name shown in the UI and used for downloads.
    original_name = db.Column(db.String(255), nullable=False)
    # Randomised, traversal-safe name the encrypted blob is stored under.
    stored_name = db.Column(db.String(300), unique=True, nullable=False)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    upload_time = db.Column(db.DateTime, default=_utcnow, nullable=False)

    owner = db.relationship("User", foreign_keys=[owner_id])
    shared_with = db.relationship("User", foreign_keys=[shared_with_id])

    def __repr__(self):
        return f"<File {self.original_name} owner={self.owner_id}>"


class TransferLedger(db.Model):
    """Append-only, hash-chained record of every file transfer.

    Formerly named "Blockchain". It is not a blockchain (no distributed
    consensus); it is a tamper-evident audit ledger. Each row stores the
    hash of the previous row, so any retroactive edit to history is
    detectable by re-walking the chain (see verify_chain()).
    """
    __tablename__ = "transfer_ledger"

    id = db.Column(db.Integer, primary_key=True)
    sent_by = db.Column(db.String(150), nullable=False)
    sent_to = db.Column(db.String(150), nullable=False)
    stored_name = db.Column(db.String(300), nullable=False)
    file_extension = db.Column(db.String(20))
    content_hash = db.Column(db.String(64), nullable=False)
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=_utcnow, nullable=False)

    def __repr__(self):
        return f"<TransferLedger {self.sent_by}->{self.sent_to} {self.entry_hash[:8]}>"
