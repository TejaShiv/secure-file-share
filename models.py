from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    lock_time = db.Column(db.DateTime)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    upload_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])
    shared_user = db.relationship('User', foreign_keys=[shared_with_user_id])

class Blockchain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sent_by = db.Column(db.String(150), nullable=False)
    sent_to = db.Column(db.String(150), nullable=False)
    filename = db.Column(db.String(150), nullable=False)
    file_extension = db.Column(db.String(10))
    file_hash = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
