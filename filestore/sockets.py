"""Socket.IO handlers tracking which users are currently connected."""
from flask import current_app, session

from .extensions import socketio


def _broadcast_online():
    online = current_app.extensions["online_users"]
    socketio.emit("update_online_users", list(online))


@socketio.on("connect")
def handle_connect():
    username = session.get("username")
    if username:
        current_app.extensions["online_users"].add(username)
        _broadcast_online()


@socketio.on("disconnect")
def handle_disconnect():
    username = session.get("username")
    if username:
        current_app.extensions["online_users"].discard(username)
        _broadcast_online()
