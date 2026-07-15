from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import os
import datetime
import re
import hashlib
from cryptography.fernet import Fernet
from io import BytesIO
from collections import Counter
from flask_migrate import Migrate

# Initialize the app and configurations
app = Flask(__name__)
app.secret_key = "secretkey"

# File paths for cross-platform compatibility
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
KEY_PATH = os.path.join(BASE_DIR, "secret.key")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'file_storage.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size 16 MB

# Initialize database and socket
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

# Encryption Key
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "wb") as key_file:
        key_file.write(Fernet.generate_key())
with open(KEY_PATH, "rb") as key_file:
    ENCRYPTION_KEY = key_file.read()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Online users set
online_users = set()

# Import models after db is initialized
from models import User, File, Blockchain

# ------------------ Routes ------------------ #

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password) or not re.search(r"[A-Z]", password):
            flash("Password must be strong.", 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    lock_time_remaining = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user:
            if user.lock_time and datetime.datetime.utcnow() < user.lock_time:
                lock_time_remaining = int((user.lock_time - datetime.datetime.utcnow()).total_seconds())
                flash("Account locked. Try later.", 'danger')
                return render_template('login.html', lock_time_remaining=lock_time_remaining)
            if check_password_hash(user.password, password):
                user.failed_attempts = 0
                user.lock_time = None
                db.session.commit()
                session['username'] = username
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lock_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
                    lock_time_remaining = 30
                db.session.commit()
                flash("Invalid credentials.", 'danger')
        else:
            flash("Invalid credentials.", 'danger')
    return render_template('login.html', lock_time_remaining=lock_time_remaining)

@app.route('/logout')
def logout():
    if 'username' in session:
        online_users.discard(session['username'])
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get total users and online users count
    total_users = User.query.count()
    all_users = User.query.all()
    online_set = set(online_users)

    # Get file sharing and file extension statistics
    all_files = Blockchain.query.all()
    total_files_shared = len(all_files)

    # Collect file types (extensions) and count them
    file_extensions = [entry.file_extension.lower() for entry in all_files if entry.file_extension]
    ext_counter = Counter(file_extensions)
    file_type_labels = list(ext_counter.keys())
    file_type_counts = list(ext_counter.values())

    return render_template('dashboard.html',
                           total_users=total_users,
                           users_list=all_users,
                           online_users=online_set,
                           session_shared_count=total_files_shared,
                           file_type_labels=file_type_labels,
                           file_type_counts=file_type_counts)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = User.query.filter(User.username != session['username']).all()
    if request.method == 'POST':
        file = request.files['file']
        shared_user_id = request.form.get('shared_with')
        if file:
            filename = file.filename
            ext = filename.split('.')[-1]
            path = os.path.join(UPLOAD_FOLDER, filename)
            encrypted = cipher_suite.encrypt(file.read())
            with open(path, 'wb') as f:
                f.write(encrypted)
            file_hash = hashlib.sha256(encrypted).hexdigest()
            db.session.add(File(filename=filename, user_id=session['user_id'], shared_with_user_id=shared_user_id))
            shared_user = User.query.get(shared_user_id)
            if shared_user:
                db.session.add(Blockchain(sent_by=session['username'], sent_to=shared_user.username,
                                          filename=filename, file_extension=ext, file_hash=file_hash))
                db.session.commit()
                socketio.emit('new_file_shared', {'shared_to': shared_user.username})
                flash("File uploaded and shared!", 'success')
                return redirect(url_for('upload'))
            else:
                flash("Invalid recipient.", 'danger')
    return render_template('upload.html', users=users)

@app.route('/shared')
def shared_files():
    if 'username' not in session:
        return redirect(url_for('login'))
    files = File.query.filter_by(shared_with_user_id=session['user_id']).order_by(File.upload_time.desc()).all()
    return render_template('shared_files.html', files=files)

@app.route('/view_blockchain')
def view_blockchain():
    if 'username' not in session:
        return redirect(url_for('login'))
    entries = Blockchain.query.order_by(Blockchain.timestamp.desc()).all()
    return render_template('view_blockchain.html', blockchain=entries)

@app.route('/uploaded')
def uploaded_files():
    if 'username' not in session:
        return redirect(url_for('login'))
    files = File.query.filter_by(user_id=session['user_id']).all()
    return render_template('uploaded_files.html', files=files)

@app.route('/delete_shared/<int:file_id>', methods=['POST'])
def delete_shared(file_id):
    if 'user_id' not in session:
        flash("Login required.", 'danger')
        return redirect(url_for('login'))

    file = File.query.get(file_id)
    if not file or file.shared_with_user_id != session['user_id']:
        flash("You are not authorized to delete this file.", 'danger')
        return redirect(url_for('shared_files'))

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(file)
    db.session.commit()

    flash("File removed from your shared list.", 'success')
    return redirect(url_for('shared_files'))

@app.route('/preview/<int:file_id>')
def preview(file_id):
    if 'user_id' not in session:
        flash("Login required.", 'danger')
        return redirect(url_for('login'))

    file = File.query.get(file_id)
    if not file or file.shared_with_user_id != session['user_id']:
        flash("You are not authorized to preview this file.", 'danger')
        return redirect(url_for('dashboard'))

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    if not os.path.exists(file_path):
        flash("File not found.", 'danger')
        return redirect(url_for('dashboard'))

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
    except:
        flash("Decryption failed.", 'danger')
        return redirect(url_for('dashboard'))

    return send_file(BytesIO(decrypted_data), download_name=file.filename, as_attachment=False)

@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' not in session:
        flash("Login required.", 'danger')
        return redirect(url_for('login'))
    file = File.query.get(file_id)
    if not file or (file.user_id != session['user_id'] and file.shared_with_user_id != session['user_id']):
        flash("Unauthorized access.", 'danger')
        return redirect(url_for('dashboard'))
    with open(os.path.join(UPLOAD_FOLDER, file.filename), 'rb') as f:
        try:
            data = cipher_suite.decrypt(f.read())
        except:
            flash("Decryption failed.", 'danger')
            return redirect(url_for('dashboard'))
    return send_file(BytesIO(data), download_name=file.filename, as_attachment=True)

# ------------------ Socket Events ------------------ #
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        online_users.add(session['username'])
        socketio.emit('update_online_users', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        online_users.discard(session['username'])
        socketio.emit('update_online_users', list(online_users), broadcast=True)

# ------------------ Main ------------------ #
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)

from models import db

with app.app_context():
    db.create_all()
