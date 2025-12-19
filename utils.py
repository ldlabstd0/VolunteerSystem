from functools import wraps
from flask import abort, request, current_app
from flask_login import current_user
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid

def role_required(*roles):
    """
    Decorator to require specific roles
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def save_uploaded_file(file, subfolder=''):
    """
    Save uploaded file and return the file path
    """
    if file and file.filename:
        # Generate unique filename
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        
        # Create directory if not exists
        upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], subfolder)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file
        filepath = os.path.join(upload_dir, unique_filename)
        file.save(filepath)
        
        # Return relative path from static folder (force forward slashes for web)
        path = os.path.join('uploads', subfolder, unique_filename)
        return path.replace('\\', '/')
    return None

def log_activity(user_id, activity_type, description, ip_address=None):
    """
    Log user activity
    """
    from models import db, ActivityLog
    
    if ip_address is None:
        ip_address = request.remote_addr
    
    activity = ActivityLog(
        user_id=user_id,
        activity_type=activity_type,
        description=description,
        ip_address=ip_address
    )
    
    db.session.add(activity)
    db.session.commit()

def generate_certificate_number():
    """
    Generate unique certificate number
    """
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_str = uuid.uuid4().hex[:6].upper()
    return f"CERT-{timestamp}-{random_str}"

def calculate_student_stats(student_id):
    """
    Calculate student statistics - FIXED VERSION
    """
    from models import db, EventRegistration, Certificate
    
    try:
        # Get all registrations for student
        registrations = EventRegistration.query.filter_by(
            student_id=student_id,
            is_verified=True
        ).all()
        
        # Calculate total hours safely
        total_hours = 0.0
        for reg in registrations:
            if reg.hours_earned:
                try:
                    total_hours += float(reg.hours_earned)
                except (TypeError, ValueError):
                    pass  # Skip invalid hours_earned values
        
        completed_events = len([reg for reg in registrations if reg.attendance_status == 'present'])
        
        # Count certificates
        certificates = Certificate.query.filter_by(student_id=student_id).all()
        certificates_count = len(certificates)
        
        return {
            'total_hours': total_hours,
            'completed_events': completed_events,
            'certificates_count': certificates_count
        }
    except Exception as e:
        print(f"Error calculating student stats: {e}")
        return {
            'total_hours': 0.0,
            'completed_events': 0,
            'certificates_count': 0
        }
