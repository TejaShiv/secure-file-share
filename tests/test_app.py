import io

from filestore.ledger import verify_chain
from filestore.models import TransferLedger, User
from tests.conftest import login, register


def test_register_rejects_weak_password(client):
    resp = register(client, "alice", "weak")
    assert b"Password must contain" in resp.data
    with client.application.app_context():
        assert User.query.filter_by(username="alice").first() is None


def test_register_and_login(client):
    register(client, "alice", "Password1")
    resp = login(client, "alice", "Password1")
    assert b"dashboard" in resp.data.lower() or resp.status_code == 200


def test_lockout_after_repeated_failures(client):
    register(client, "bob", "Password1")
    for _ in range(3):
        login(client, "bob", "WrongPass1")
    resp = login(client, "bob", "WrongPass1")
    assert b"locked" in resp.data.lower()


def test_upload_requires_valid_recipient(client, app):
    register(client, "carol", "Password1")
    login(client, "carol", "Password1")
    # No such recipient id -> rejected, nothing stored.
    resp = client.post("/upload", data={
        "file": (io.BytesIO(b"hello"), "note.txt"),
        "shared_with": "9999",
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"valid recipient" in resp.data.lower()
    with app.app_context():
        assert TransferLedger.query.count() == 0


def test_upload_creates_linked_ledger_entries(client, app):
    register(client, "dave", "Password1")
    register(client, "erin", "Password1")
    login(client, "dave", "Password1")
    with app.app_context():
        erin = User.query.filter_by(username="erin").first()
        erin_id = erin.id

    for i in range(2):
        client.post("/upload", data={
            "file": (io.BytesIO(f"file-{i}".encode()), f"f{i}.txt"),
            "shared_with": str(erin_id),
        }, content_type="multipart/form-data", follow_redirects=True)

    with app.app_context():
        assert TransferLedger.query.count() == 2
        ok, broken = verify_chain()
        assert ok and broken is None


def test_tampering_breaks_the_chain(client, app):
    register(client, "frank", "Password1")
    register(client, "grace", "Password1")
    login(client, "frank", "Password1")
    with app.app_context():
        grace_id = User.query.filter_by(username="grace").first().id
    client.post("/upload", data={
        "file": (io.BytesIO(b"secret"), "s.txt"),
        "shared_with": str(grace_id),
    }, content_type="multipart/form-data", follow_redirects=True)

    with app.app_context():
        from filestore.extensions import db
        entry = TransferLedger.query.first()
        entry.sent_to = "attacker"  # retroactively alter history
        db.session.commit()
        ok, broken = verify_chain()
        assert not ok and broken == entry.id
