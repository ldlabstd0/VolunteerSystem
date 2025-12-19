import sqlite3
import os

# Path to database
db_path = os.path.join('instance', 'database.db')

if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
    exit(1)

print(f"Connecting to database at {db_path}...")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check if columns exist
cursor.execute("PRAGMA table_info(users)")
columns = [info[1] for info in cursor.fetchall()]

if 'reset_code' not in columns:
    print("Adding reset_code column...")
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN reset_code VARCHAR(6)")
        print("Success.")
    except Exception as e:
        print(f"Error adding reset_code: {e}")
else:
    print("reset_code column already exists.")

if 'reset_code_expiry' not in columns:
    print("Adding reset_code_expiry column...")
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN reset_code_expiry DATETIME")
        print("Success.")
    except Exception as e:
        print(f"Error adding reset_code_expiry: {e}")
else:
    print("reset_code_expiry column already exists.")

    print("reset_code_expiry column already exists.")

# Check students table
cursor.execute("PRAGMA table_info(students)")
student_columns = [info[1] for info in cursor.fetchall()]

if 'school' not in student_columns:
    print("Adding school column to students...")
    try:
        cursor.execute("ALTER TABLE students ADD COLUMN school VARCHAR(200)")
        print("Success.")
    except Exception as e:
        print(f"Error adding school column: {e}")
else:
    print("school column already exists in students.")
cursor.execute("PRAGMA table_info(notifications)")
notif_columns = [info[1] for info in cursor.fetchall()]

if 'link' not in notif_columns:
    print("Adding link column to notifications...")
    try:
        cursor.execute("ALTER TABLE notifications ADD COLUMN link VARCHAR(200)")
        print("Success.")
    except Exception as e:
        print(f"Error adding link column: {e}")
else:
    print("link column already exists in notifications.")

# Check organizations table
cursor.execute("PRAGMA table_info(organizations)")
org_columns = [info[1] for info in cursor.fetchall()]

new_org_columns = {
    'contact_person': 'VARCHAR(100)',
    'contact_phone': 'VARCHAR(20)',
    'contact_email': 'VARCHAR(120)'
}

for col_name, col_type in new_org_columns.items():
    if col_name not in org_columns:
        print(f"Adding {col_name} column to organizations...")
        try:
            cursor.execute(f"ALTER TABLE organizations ADD COLUMN {col_name} {col_type}")
            print("Success.")
        except Exception as e:
            print(f"Error adding {col_name}: {e}")
    else:
        print(f"{col_name} column already exists in organizations.")

conn.commit()
conn.close()
print("Database schema update complete.")
