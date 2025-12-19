from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import os
from functools import wraps

# Import configurations and models
from config import Config
from models import db, User, Admin, Organization, Student, Category, Event, EventRegistration, Certificate, ActivityLog, Notification
from forms import *
from utils import role_required, save_uploaded_file, log_activity, calculate_student_stats, generate_certificate_number
from email_service import EmailService
from certificate_generator import CertificateGenerator

def timesince_filter(dt, default="just now"):
    """
    Returns string representing "time since" e.g.
    3 days ago, 5 hours ago etc.
    """
    if not dt:
        return default
    
    now = datetime.utcnow()
    diff = now - dt
    
    periods = (
        (diff.days // 365, "year", "years"),
        (diff.days // 30, "month", "months"),
        (diff.days // 7, "week", "weeks"),
        (diff.days, "day", "days"),
        (diff.seconds // 3600, "hour", "hours"),
        (diff.seconds // 60, "minute", "minutes"),
        (diff.seconds, "second", "seconds"),
    )
    
    for period, singular, plural in periods:
        if period:
            return f"{period} {singular if period == 1 else plural} ago"
    
    return default

def safe_float(value, default=0.0):
    """Safely convert value to float"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def get_dashboard_route():
    """Helper function to get dashboard route based on user role"""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return 'admin.dashboard'
        elif current_user.role == 'organization':
            return 'organization.dashboard'
        elif current_user.role == 'student':
            return 'student.dashboard'
    return 'auth.login'

def get_profile_route():
    """Helper function to get profile route based on user role"""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return 'admin.admin_settings'
        elif current_user.role == 'organization':
            return 'organization.profile'
        elif current_user.role == 'student':
            return 'student.profile'
    return 'auth.login'

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    
    # Register custom filters
    app.jinja_env.filters['timesince'] = timesince_filter
    app.jinja_env.filters['safe_float'] = safe_float
    
    # Initialize login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Create tables
    with app.app_context():
        db.create_all()
        create_default_admin()
    
    # Register blueprints
    from blueprints import auth_bp, admin_bp, organization_bp, student_bp, main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(organization_bp)
    app.register_blueprint(student_bp)
    app.register_blueprint(main_bp)
    
    # Error handlers
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500
    
    # Context processors
    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}
    
    @app.context_processor
    def inject_notifications():
        if current_user.is_authenticated:
            # Get unread count
            unread_count = Notification.query.filter_by(
                user_id=current_user.id,
                is_read=False
            ).count()
            
            # Get recent 5 notifications
            notifications = Notification.query.filter_by(
                user_id=current_user.id
            ).order_by(Notification.created_at.desc()).limit(5).all()
            
            return {
                'unread_notifications': unread_count,
                'current_user_notifications': notifications
            }
        return {'unread_notifications': 0, 'current_user_notifications': []}
    
    @app.context_processor
    def inject_admin_check():
        admin_exists = User.query.filter_by(role='admin').first() is not None
        return {'admin_exists': admin_exists}
    
    @app.context_processor
    def inject_helper_functions():
        """Inject helper functions into all templates"""
        return {
            'get_dashboard_route': get_dashboard_route,
            'get_profile_route': get_profile_route,
            'safe_float': safe_float
        }
    
    # Before request checks
    @app.before_request
    def check_admin_setup():
        """Check if admin setup is needed"""
        if request.endpoint == 'main.index' and not current_user.is_authenticated:
            admin_exists = User.query.filter_by(role='admin').first()
            if not admin_exists:
                return redirect(url_for('auth.admin_register'))
    
    # Main index route
    @app.route('/')
    def index():
        """Main index route"""
        if current_user.is_authenticated:
            # Redirect based on role
            if current_user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif current_user.role == 'organization':
                return redirect(url_for('organization.dashboard'))
            elif current_user.role == 'student':
                return redirect(url_for('student.dashboard'))
        return redirect(url_for('auth.login'))
    
    return app

def create_default_admin():
    """Check if admin exists, if not, inform user about setup"""
    admin_user = User.query.filter_by(role='admin').first()
    if not admin_user:
        print("=" * 60)
        print("NO ADMINISTRATOR ACCOUNT FOUND")
        print("=" * 60)
        print("Please visit /auth/admin/setup to create the initial admin account.")
        print("=" * 60)
        return False
    return True

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
