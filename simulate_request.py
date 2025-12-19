from app import create_app, db
from models import User

app = create_app()

def simulate_request():
    with app.app_context():
        user = User.query.filter_by(username='Student1').first()
        if user:
            user.deletion_requested = True
            user.deletion_reason = "I want to delete my account for testing purposes."
            db.session.commit()
            print(f"Simulated deletion request for {user.username}")
        else:
            print("Student1 not found")

if __name__ == '__main__':
    simulate_request()
