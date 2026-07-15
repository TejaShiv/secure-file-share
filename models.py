from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    lock_time = db.Column(db.DateTime)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)          # original, human-readable name
    stored_name = db.Column(db.String(300), unique=True, nullable=False)  # randomised on-disk name
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    upload_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])
    shared_user = db.relationship('User', foreign_keys=[shared_with_user_id])

class TransferLedger(db.Model):
    """Append-only, hash-chained record of every file transfer.

    Formerly named "Blockchain". It is not a blockchain (there is no
    distributed consensus); it is a tamper-evident audit ledger. Each row
    stores the hash of the previous row, so any retroactive edit to history
    is detectable by re-walking the chain (see verify_chain in app.py).
    """
    __tablename__ = "transfer_ledger"
    id = db.Column(db.Integer, primary_key=True)
    sent_by = db.Column(db.String(150), nullable=False)
    sent_to = db.Column(db.String(150), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_extension = db.Column(db.String(20))
    content_hash = db.Column(db.String(64), nullable=False)
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
