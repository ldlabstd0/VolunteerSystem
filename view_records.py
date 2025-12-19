from app import create_app
from models import db, User, Student, Organization

app = create_app()

def print_table(title, headers, rows):
    print(f"\n{'='*len(title)}")
    print(title)
    print(f"{'='*len(title)}")
    
    if not rows:
        print("(No records found)")
        return

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))
    
    # Create format string
    fmt = " | ".join([f"{{:<{w}}}" for w in widths])
    
    # Print header
    print(fmt.format(*headers))
    print("-" * (sum(widths) + 3 * (len(headers) - 1)))
    
    # Print rows
    for row in rows:
        print(fmt.format(*[str(val) for val in row]))

with app.app_context():
    # USERS
    users = User.query.all()
    user_rows = [(u.id, u.username, u.email, u.role, u.is_active) for u in users]
    print_table("ALL USERS", ["ID", "Username", "Email", "Role", "Active"], user_rows)

    # STUDENTS
    students = Student.query.all()
    student_rows = [(s.id, s.user.username, s.first_name, s.surname) for s in students]
    print_table("REGISTERED STUDENTS", ["ID", "Username", "First Name", "Surname"], student_rows)

    # ORGANIZATIONS
    orgs = Organization.query.all()
    org_rows = [(o.id, o.user.username, o.organization_name, "Yes" if o.is_approved else "No") for o in orgs]
    print_table("REGISTERED ORGANIZATIONS", ["ID", "Username", "Org Name", "Approved"], org_rows)
