from app import create_app
from models import db, User, Admin

app = create_app()

with app.app_context():
    # Find the admin user
    user = User.query.filter_by(username='Admin').first()
    if not user:
        # Try finding by role if username is different
        user = User.query.filter_by(role='admin').first()
    
    if user:
        print(f"Found admin user: {user.username}")
        if user.admin:
            admin = user.admin
            # Only update if empty
            if not admin.first_name:
                admin.first_name = 'Admin'
                print("Set First Name to 'Admin'")
            if not admin.surname:
                admin.surname = 'User'
                print("Set Surname to 'User'")
            if not admin.phone_number:
                admin.phone_number = '000-000-0000'
                print("Set Phone Number to '000-000-0000'")
            
            db.session.commit()
            print("Admin profile updated successfully.")
        else:
            print("Admin profile record not found for user. Creating one...")
            admin = Admin(user_id=user.id, first_name='Admin', surname='User', phone_number='000-000-0000')
            db.session.add(admin)
            db.session.commit()
            print("Admin profile created.")
    else:
        print("No admin user found.")
