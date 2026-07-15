"""Public home page, dashboard, and the ledger view."""
from collections import Counter

from flask import (Blueprint, current_app, render_template, session)

from ..auth.routes import login_required
from ..ledger import verify_chain
from ..models import TransferLedger, User

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def home():
    return render_template("home.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    all_users = User.query.all()
    online = set(current_app.extensions["online_users"])

    entries = TransferLedger.query.all()
    extensions = [e.file_extension.lower() for e in entries if e.file_extension]
    counts = Counter(extensions)

    return render_template(
        "dashboard.html",
        total_users=len(all_users),
        users_list=all_users,
        online_users=online,
        session_shared_count=len(entries),
        file_type_labels=list(counts.keys()),
        file_type_counts=list(counts.values()),
    )


@main_bp.route("/ledger")
@login_required
def view_ledger():
    entries = TransferLedger.query.order_by(TransferLedger.timestamp.desc()).all()
    chain_ok, broken_id = verify_chain()
    return render_template(
        "view_ledger.html",
        ledger=entries,
        chain_ok=chain_ok,
        broken_id=broken_id,
    )
