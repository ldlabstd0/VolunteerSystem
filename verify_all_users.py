from app import create_app
from models import User

app = create_app()

def verify_users():
    with app.app_context():
        users = User.query.all()
        if not users:
            print("No user accounts found in the database.")
        else:
            print(f"Found {len(users)} user account(s):")
            print("-" * 80)
            print(f"{'ID':<5} | {'Username':<20} | {'Email':<30} | {'Role':<15} | {'Active':<6}")
            print("-" * 80)
            for user in users:
                print(f"{user.id:<5} | {user.username:<20} | {user.email:<30} | {user.role:<15} | {str(user.is_active):<6}")
            print("-" * 80)

if __name__ == '__main__':
    verify_users()
