"""Development / production entrypoint.

    flask --app run run              # dev server
    gunicorn "run:app" ...           # WSGI (see Procfile)

For Socket.IO support in development, `python run.py` uses socketio.run.
"""
from filestore import create_app
from filestore.extensions import socketio

app = create_app()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
