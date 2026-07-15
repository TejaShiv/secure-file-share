import os
import tempfile

import pytest

from filestore import create_app
from filestore.extensions import db


@pytest.fixture
def app():
    tmp_upload = tempfile.mkdtemp()
    os.environ["UPLOAD_FOLDER"] = tmp_upload
    app = create_app("testing")
    app.config["UPLOAD_FOLDER"] = tmp_upload
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username, password):
    return client.post("/register", data={"username": username, "password": password},
                       follow_redirects=True)


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=True)
