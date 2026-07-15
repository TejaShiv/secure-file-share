from app import db
from app import app

# Create all tables within the application context
with app.app_context():
    db.create_all()
    print("Database initialized successfully.")
