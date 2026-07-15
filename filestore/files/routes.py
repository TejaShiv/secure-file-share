"""File upload, sharing, preview, download and deletion."""
import os
from io import BytesIO

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, send_file, session, url_for)

from ..auth.routes import login_required
from ..extensions import db, socketio
from ..ledger import append_entry
from ..models import File, User
from ..security import (InvalidToken, file_extension, safe_storage_name,
                        sha256_hex)

files_bp = Blueprint("files", __name__)


def _upload_path(stored_name):
    return os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name)


def _current_encryptor():
    return current_app.extensions["encryptor"]


@files_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    recipients = User.query.filter(User.id != session["user_id"]).all()

    if request.method == "POST":
        uploaded = request.files.get("file")
        raw_recipient = request.form.get("shared_with")

        if not uploaded or uploaded.filename == "":
            flash("Please choose a file to upload.", "danger")
            return redirect(url_for("files.upload"))

        # Validate the recipient BEFORE writing anything to disk or DB.
        try:
            recipient_id = int(raw_recipient)
        except (TypeError, ValueError):
            flash("Please select a valid recipient.", "danger")
            return redirect(url_for("files.upload"))

        recipient = User.query.get(recipient_id)
        if recipient is None or recipient.id == session["user_id"]:
            flash("Please select a valid recipient.", "danger")
            return redirect(url_for("files.upload"))

        original_name = uploaded.filename
        stored_name = safe_storage_name(original_name)
        raw_bytes = uploaded.read()
        encrypted = _current_encryptor().encrypt(raw_bytes)
        content_hash = sha256_hex(encrypted)

        # Write the encrypted blob, then record it. If the DB commit fails we
        # remove the orphaned file so disk and database stay consistent.
        path = _upload_path(stored_name)
        with open(path, "wb") as fh:
            fh.write(encrypted)

        try:
            db.session.add(File(
                original_name=original_name,
                stored_name=stored_name,
                owner_id=session["user_id"],
                shared_with_id=recipient.id,
            ))
            append_entry(
                sent_by=session["username"],
                sent_to=recipient.username,
                stored_name=stored_name,
                file_extension=file_extension(original_name),
                content_hash=content_hash,
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            if os.path.exists(path):
                os.remove(path)
            flash("Upload failed. Please try again.", "danger")
            return redirect(url_for("files.upload"))

        socketio.emit("new_file_shared", {"shared_to": recipient.username})
        flash("File uploaded and shared.", "success")
        return redirect(url_for("files.upload"))

    return render_template("upload.html", users=recipients)


@files_bp.route("/uploaded")
@login_required
def uploaded_files():
    files = File.query.filter_by(owner_id=session["user_id"]).order_by(
        File.upload_time.desc()).all()
    return render_template("uploaded_files.html", files=files)


@files_bp.route("/shared")
@login_required
def shared_files():
    files = File.query.filter_by(shared_with_id=session["user_id"]).order_by(
        File.upload_time.desc()).all()
    return render_template("shared_files.html", files=files)


def _authorized_file_or_none(file_id, *, owner_ok=True):
    """Return the File if the session user may access it, else None."""
    file = File.query.get(file_id)
    if file is None:
        return None
    uid = session["user_id"]
    if file.shared_with_id == uid:
        return file
    if owner_ok and file.owner_id == uid:
        return file
    return None


def _decrypt_or_flash(file):
    """Read and decrypt a file's bytes, or flash an error and return None."""
    path = _upload_path(file.stored_name)
    if not os.path.exists(path):
        flash("File not found.", "danger")
        return None
    with open(path, "rb") as fh:
        encrypted = fh.read()
    try:
        return _current_encryptor().decrypt(encrypted)
    except InvalidToken:
        flash("File could not be decrypted.", "danger")
        return None


@files_bp.route("/preview/<int:file_id>")
@login_required
def preview(file_id):
    file = _authorized_file_or_none(file_id, owner_ok=True)
    if file is None:
        flash("You are not authorized to view this file.", "danger")
        return redirect(url_for("main.dashboard"))
    data = _decrypt_or_flash(file)
    if data is None:
        return redirect(url_for("main.dashboard"))
    return send_file(BytesIO(data), download_name=file.original_name,
                     as_attachment=False)


@files_bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    file = _authorized_file_or_none(file_id, owner_ok=True)
    if file is None:
        flash("You are not authorized to download this file.", "danger")
        return redirect(url_for("main.dashboard"))
    data = _decrypt_or_flash(file)
    if data is None:
        return redirect(url_for("main.dashboard"))
    return send_file(BytesIO(data), download_name=file.original_name,
                     as_attachment=True)


@files_bp.route("/delete_shared/<int:file_id>", methods=["POST"])
@login_required
def delete_shared(file_id):
    # Only the recipient may remove a file from their shared list.
    file = File.query.get(file_id)
    if file is None or file.shared_with_id != session["user_id"]:
        flash("You are not authorized to delete this file.", "danger")
        return redirect(url_for("files.shared_files"))

    path = _upload_path(file.stored_name)
    if os.path.exists(path):
        os.remove(path)
    db.session.delete(file)
    db.session.commit()
    flash("File removed from your shared list.", "success")
    return redirect(url_for("files.shared_files"))
