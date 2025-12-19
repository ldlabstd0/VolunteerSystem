from app import create_app
from models import db, User, Student

app = create_app()

with app.app_context():
    print("--- Users to check ---")
    users_to_check = ['Dreb', 'Org1', 'Org2']
    for username in users_to_check:
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"Found User: ID={user.id}, Username={user.username}, Role={user.role}")
        else:
            print(f"User '{username}' not found.")

    print("\n--- Students to check ---")
    # Checking for 'Ledz' in first_name or surname
    students = Student.query.filter((Student.first_name.ilike('%Ledz%')) | (Student.surname.ilike('%Ledz%'))).all()
    if students:
        for s in students:
            print(f"Found Student: ID={s.id}, UserID={s.user_id}, Name={s.first_name} {s.surname}")
            # Also check if this student corresponds to a user we might want to delete
            user = User.query.get(s.user_id)
            if user:
                print(f"  -> Linked User: ID={user.id}, Username={user.username}")
    else:
        print("No student found with name 'Ledz'.")
