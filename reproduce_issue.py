import sys
from app import create_app
from models import db, User
from forms import StudentRegistrationForm
from flask import Flask

def reproduce_registration_issue():
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing script

    with app.app_context():
        # Clean up test user if exists
        test_username = "testuser_repro"
        test_email = "testuser_repro@example.com"
        
        existing = User.query.filter_by(username=test_username).first()
        if existing:
            print(f"Deleting existing test user: {test_username}")
            db.session.delete(existing)
            db.session.commit()
            
        existing_email = User.query.filter_by(email=test_email).first()
        if existing_email:
             print(f"Deleting existing test email: {test_email}")
             db.session.delete(existing_email)
             db.session.commit()

        # Simulate form data
        with app.test_request_context('/auth/register/student', method='POST', data={
            'first_name': 'Test',
            'surname': 'User', 
            'school': 'Test University',
            'username': test_username,
            'email': test_email,
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        }):
            form = StudentRegistrationForm()
            print("Validating form...")
            if form.validate_on_submit():
                print("Form validation SUCCESS.")
                
                # Simulate the logic in blueprints.py
                username = form.username.data.strip()
                email = form.email.data.strip().lower()

                if User.query.filter_by(username=username).first():
                    print("Error: Username already exists check failed (should not happen for fresh user)")
                elif User.query.filter_by(email=email).first():
                    print("Error: Email already exists check failed (should not happen for fresh user)")
                else:
                    print("Backend logic: Would proceed to create user.")
                    
                    # Actually attempt to create user as in blueprints.py
                    try:
                        user = User(
                            username=username,
                            email=email,
                            role='student'
                        )
                        user.set_password(form.password.data)
                        db.session.add(user)
                        db.session.commit()
                        print("User successfully created in DB.")
                    except Exception as e:
                        print(f"Exception during DB commit: {e}")
                        db.session.rollback()

            else:
                print("Form validation FAILED.")
                print(f"Errors: {form.errors}")

if __name__ == "__main__":
    reproduce_registration_issue()
