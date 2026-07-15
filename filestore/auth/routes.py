"""Authentication: registration, login with lockout, logout."""
import datetime
import functools
import re

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from ..extensions import db
from ..models import User

auth_bp = Blueprint("auth", __name__)

# At least 8 chars, containing a lowercase letter, an uppercase letter, and a digit.
_PASSWORD_RULES = [
    (re.compile(r".{8,}"), "at least 8 characters"),
    (re.compile(r"[a-z]"), "a lowercase letter"),
    (re.compile(r"[A-Z]"), "an uppercase letter"),
    (re.compile(r"\d"), "a number"),
]


def login_required(view):
    """Redirect to login if there is no authenticated session."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "danger")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def _password_problems(password):
    return [msg for rule, msg in _PASSWORD_RULES if not rule.search(password)]


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username:
            flash("Username is required.", "danger")
            return redirect(url_for("auth.register"))

        problems = _password_problems(password)
        if problems:
            flash("Password must contain " + ", ".join(problems) + ".", "danger")
            return redirect(url_for("auth.register"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("auth.register"))

        db.session.add(User(username=username,
                            password_hash=generate_password_hash(password)))
        db.session.commit()
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    lock_time_remaining = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()

        # Generic message whether or not the user exists, to avoid leaking
        # which usernames are registered.
        invalid = "Invalid username or password."

        if user is None:
            flash(invalid, "danger")
            return render_template("login.html", lock_time_remaining=None)

        if user.is_locked():
            lock_time_remaining = user.lock_seconds_remaining()
            flash("Account temporarily locked. Please try again later.", "danger")
            return render_template("login.html", lock_time_remaining=lock_time_remaining)

        if check_password_hash(user.password_hash, password):
            user.failed_attempts = 0
            user.lock_time = None
            db.session.commit()
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("main.dashboard"))

        # Wrong password: count the failure and lock after the threshold.
        user.failed_attempts += 1
        max_attempts = current_app.config["MAX_FAILED_ATTEMPTS"]
        if user.failed_attempts >= max_attempts:
            lockout = current_app.config["LOCKOUT_SECONDS"]
            user.lock_time = (datetime.datetime.now(datetime.timezone.utc)
                              + datetime.timedelta(seconds=lockout))
            user.failed_attempts = 0
            lock_time_remaining = lockout
        db.session.commit()
        flash(invalid, "danger")

    return render_template("login.html", lock_time_remaining=lock_time_remaining)


@auth_bp.route("/logout")
def logout():
    online = current_app.extensions["online_users"]
    online.discard(session.get("username"))
    session.clear()
    return redirect(url_for("main.home"))
