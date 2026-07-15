from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
import os
import uuid
import datetime
import re
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from io import BytesIO
from collections import Counter
from flask_migrate import Migrate

app = Flask(__name__)

# SECRET_KEY signs session cookies. A hardcoded/guessable key would let anyone
# forge a logged-in session for any user, so it must come from the environment.
# A development fallback keeps `flask run` working locally.
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-not-for-production")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
KEY_PATH = os.path.join(BASE_DIR, "secret.key")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'file_storage.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

# Encryption key: prefer the environment; fall back to a local key file in dev.
_env_key = os.environ.get("ENCRYPTION_KEY")
if _env_key:
    ENCRYPTION_KEY = _env_key.encode()
else:
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as key_file:
            key_file.write(Fernet.generate_key())
    with open(KEY_PATH, "rb") as key_file:
        ENCRYPTION_KEY = key_file.read()
cipher_suite = Fernet(ENCRYPTION_KEY)

online_users = set()

from models import User, File, TransferLedger

GENESIS_PREV_HASH = "0" * 64


def _compute_ledger_hash(prev_hash, sent_by, sent_to, filename, content_hash, timestamp_iso):
    """Hash an entry together with the previous entry's hash. This linkage is
    what makes the ledger tamper-evident: altering any past row changes its
    hash and breaks every hash after it."""
    payload = "|".join([prev_hash, sent_by, sent_to, filename, content_hash, timestamp_iso])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _append_ledger_entry(sent_by, sent_to, filename, file_extension, content_hash):
    prev = TransferLedger.query.order_by(TransferLedger.id.desc()).first()
    prev_hash = prev.entry_hash if prev else GENESIS_PREV_HASH
    entry = TransferLedger(sent_by=sent_by, sent_to=sent_to, filename=filename,
                           file_extension=file_extension, content_hash=content_hash,
                           prev_hash=prev_hash)
    db.session.add(entry)
    db.session.flush()  # populate timestamp before hashing, without committing
    entry.entry_hash = _compute_ledger_hash(prev_hash, sent_by, sent_to, filename,
                                            content_hash, entry.timestamp.isoformat())
    return entry


def verify_ledger_chain():
    """Walk the ledger oldest-first; return (ok, first_broken_id)."""
    entries = TransferLedger.query.order_by(TransferLedger.id.asc()).all()
    expected_prev = GENESIS_PREV_HASH
    for entry in entries:
        if entry.prev_hash != expected_prev:
            return False, entry.id
        recomputed = _compute_ledger_hash(entry.prev_hash, entry.sent_by, entry.sent_to,
                                          entry.filename, entry.content_hash,
                                          entry.timestamp.isoformat())
        if recomputed != entry.entry_hash:
            return False, entry.id
        expected_prev = entry.entry_hash
    return True, None


def safe_storage_name(original_filename):
    """Collision-free, traversal-safe name to store a file under.

    secure_filename strips path separators and traversal sequences (../); the
    UUID prefix stops two users' identical filenames from overwriting each
    other and stops the on-disk name from being used to reach another file.
    """
    cleaned = secure_filename(original_filename) or "file"
    return f"{uuid.uuid4().hex}_{cleaned}"


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if len(password) < 8 or not re.search(r"[a-z]", password) or not re.search(r"\d", password) or not re.search(r"[A-Z]", password):
            flash("Password must be at least 8 characters and include upper, lower, and a number.", 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", 'danger')
            return redirect(url_for('register'))
        db.session.add(User(username=username, password=generate_password_hash(password)))
        db.session.commit()
        flash("Registration successful!", 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    lock_time_remaining = None
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
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
                session.clear()
                session['username'] = username
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lock_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
                    user.failed_attempts = 0
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
    total_users = User.query.count()
    all_users = User.query.all()
    online_set = set(online_users)
    all_files = TransferLedger.query.all()
    total_files_shared = len(all_files)
    file_extensions = [entry.file_extension.lower() for entry in all_files if entry.file_extension]
    ext_counter = Counter(file_extensions)
    return render_template('dashboard.html',
                           total_users=total_users,
                           users_list=all_users,
                           online_users=online_set,
                           session_shared_count=total_files_shared,
                           file_type_labels=list(ext_counter.keys()),
                           file_type_counts=list(ext_counter.values()))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = User.query.filter(User.username != session['username']).all()
    if request.method == 'POST':
        file = request.files.get('file')
        raw_recipient = request.form.get('shared_with')

        if not file or file.filename == '':
            flash("Please choose a file to upload.", 'danger')
            return redirect(url_for('upload'))

        # Validate recipient BEFORE writing anything to disk or the DB.
        try:
            recipient_id = int(raw_recipient)
        except (TypeError, ValueError):
            flash("Please select a valid recipient.", 'danger')
            return redirect(url_for('upload'))
        shared_user = User.query.get(recipient_id)
        if shared_user is None or shared_user.id == session['user_id']:
            flash("Please select a valid recipient.", 'danger')
            return redirect(url_for('upload'))

        original_name = file.filename
        stored_name = safe_storage_name(original_name)
        ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
        path = os.path.join(UPLOAD_FOLDER, stored_name)
        encrypted = cipher_suite.encrypt(file.read())
        file_hash = hashlib.sha256(encrypted).hexdigest()

        with open(path, 'wb') as f:
            f.write(encrypted)

        try:
            db.session.add(File(filename=original_name, stored_name=stored_name,
                                user_id=session['user_id'], shared_with_user_id=shared_user.id))
            _append_ledger_entry(sent_by=session['username'], sent_to=shared_user.username,
                                 filename=original_name, file_extension=ext, content_hash=file_hash)
            db.session.commit()
        except Exception:
            db.session.rollback()
            if os.path.exists(path):
                os.remove(path)
            flash("Upload failed. Please try again.", 'danger')
            return redirect(url_for('upload'))

        socketio.emit('new_file_shared', {'shared_to': shared_user.username})
        flash("File uploaded and shared!", 'success')
        return redirect(url_for('upload'))
    return render_template('upload.html', users=users)

@app.route('/shared')
def shared_files():
    if 'username' not in session:
        return redirect(url_for('login'))
    files = File.query.filter_by(shared_with_user_id=session['user_id']).order_by(File.upload_time.desc()).all()
    return render_template('shared_files.html', files=files)

@app.route('/ledger')
def view_ledger():
    if 'username' not in session:
        return redirect(url_for('login'))
    entries = TransferLedger.query.order_by(TransferLedger.timestamp.desc()).all()
    chain_ok, broken_id = verify_ledger_chain()
    return render_template('view_ledger.html', ledger=entries,
                           chain_ok=chain_ok, broken_id=broken_id)

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
    file_path = os.path.join(UPLOAD_FOLDER, file.stored_name)
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
    if not file or (file.shared_with_user_id != session['user_id'] and file.user_id != session['user_id']):
        flash("You are not authorized to preview this file.", 'danger')
        return redirect(url_for('dashboard'))
    file_path = os.path.join(UPLOAD_FOLDER, file.stored_name)
    if not os.path.exists(file_path):
        flash("File not found.", 'danger')
        return redirect(url_for('dashboard'))
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
    except InvalidToken:
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
    with open(os.path.join(UPLOAD_FOLDER, file.stored_name), 'rb') as f:
        try:
            data = cipher_suite.decrypt(f.read())
        except InvalidToken:
            flash("Decryption failed.", 'danger')
            return redirect(url_for('dashboard'))
    return send_file(BytesIO(data), download_name=file.filename, as_attachment=True)

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

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
