from app import create_app
from models import db, User

app = create_app()

with app.app_context():
    username = "Org1"
    new_password = "password123"
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.set_password(new_password)
        db.session.commit()
        print(f"Successfully reset password for user '{username}' to '{new_password}'")
    else:
        print(f"User '{username}' not found!")
