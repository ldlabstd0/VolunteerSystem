from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'organization', 'student'
    is_active = db.Column(db.Boolean, default=True)
    deletion_requested = db.Column(db.Boolean, default=False)
    deletion_reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Password Reset
    reset_code = db.Column(db.String(6), nullable=True)
    reset_code_expiry = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    admin = db.relationship('Admin', backref='user', uselist=False, cascade='all, delete-orphan')
    organization = db.relationship('Organization', backref='user', uselist=False, cascade='all, delete-orphan')
    student = db.relationship('Student', backref='user', uselist=False, cascade='all, delete-orphan')
    activities = db.relationship('ActivityLog', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_role_model(self):
        if self.role == 'admin':
            return self.admin
        elif self.role == 'organization':
            return self.organization
        elif self.role == 'student':
            return self.student
        return None

class Admin(db.Model):
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    first_name = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))

class Organization(db.Model):
    __tablename__ = 'organizations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    organization_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    about_us = db.Column(db.Text)
    about_us = db.Column(db.Text)
    contact_person = db.Column(db.String(100))
    contact_phone = db.Column(db.String(20))
    contact_email = db.Column(db.String(120))
    logo_path = db.Column(db.String(500))
    digital_signature_path = db.Column(db.String(500))
    is_approved = db.Column(db.Boolean, default=False)
    
    # Relationships
    events = db.relationship('Event', backref='organization', lazy='dynamic')
    certificates = db.relationship('Certificate', backref='organization', lazy='dynamic')

class Student(db.Model):
    __tablename__ = 'students'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    surname = db.Column(db.String(100), nullable=False)
    school = db.Column(db.String(200)) # Added school field
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(500))
    skills = db.Column(db.Text)  # JSON string of skills
    
    # Relationships
    event_registrations = db.relationship('EventRegistration', backref='student', lazy='dynamic')
    certificates = db.relationship('Certificate', backref='student', lazy='dynamic')

class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    events = db.relationship('Event', backref='category', lazy='dynamic')

class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    duration_hours = db.Column(db.Float, nullable=False, default=2.0)
    slots_available = db.Column(db.Integer, nullable=False)
    slots_filled = db.Column(db.Integer, default=0)
    skill_requirements = db.Column(db.Text)
    location = db.Column(db.String(200))
    image_path = db.Column(db.String(500))
    status = db.Column(db.String(20), default='draft')  # 'draft', 'active', 'completed', 'cancelled'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    registrations = db.relationship('EventRegistration', backref='event', lazy='dynamic')

    @property
    def end_time(self):
        return self.date_time + timedelta(hours=self.duration_hours)

    @property
    def current_status(self):
        # Administrative statuses override time
        if self.status == 'cancelled':
            return 'Cancelled'
        if self.status == 'draft':
            return 'Draft'
            
        now = datetime.utcnow()
        if now < self.date_time:
            return 'Upcoming'
        elif now <= self.end_time:
            return 'Ongoing'
        else:
            return 'Finished'

class EventRegistration(db.Model):
    __tablename__ = 'event_registrations'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    attendance_status = db.Column(db.String(20), default='pending')  # 'pending', 'present', 'absent'
    hours_earned = db.Column(db.Float, default=0.0)
    is_verified = db.Column(db.Boolean, default=False)
    verification_date = db.Column(db.DateTime)
    
    # Ensure one student can only register once per event
    __table_args__ = (db.UniqueConstraint('event_id', 'student_id', name='unique_event_student'),)

class Certificate(db.Model):
    __tablename__ = 'certificates'
    
    id = db.Column(db.Integer, primary_key=True)
    event_registration_id = db.Column(db.Integer, db.ForeignKey('event_registrations.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    certificate_number = db.Column(db.String(100), unique=True, nullable=False)
    hours_earned = db.Column(db.Float, nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    pdf_path = db.Column(db.String(500))
    
    # Relationship
    event_registration = db.relationship('EventRegistration', backref=db.backref('certificate', uselist=False))

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    activity_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notification_type = db.Column(db.String(50))  # 'system', 'event', 'approval', etc.
    link = db.Column(db.String(200))  # URL to redirect to when clicked
    
    # Relationship
    user = db.relationship('User', backref='notifications')
