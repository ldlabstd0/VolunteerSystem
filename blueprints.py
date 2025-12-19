from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_file, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import os
from sqlalchemy import or_
from models import db, User, Admin, Organization, Student, Category, Event, EventRegistration, Certificate, ActivityLog, Notification
from sqlalchemy.exc import IntegrityError
from forms import *
from utils import role_required, save_uploaded_file, log_activity, calculate_student_stats, generate_certificate_number
from email_service import EmailService
from certificate_generator import CertificateGenerator
from report_generator import ReportGenerator

# Auth Blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Main Blueprint for shared routes
main_bp = Blueprint('main', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redirect based on role
        if current_user.role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif current_user.role == 'organization':
            return redirect(url_for('organization.dashboard'))
        elif current_user.role == 'student':
            return redirect(url_for('student.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Strip whitespace from username/email input
        login_input = form.username.data.strip() if form.username.data else ''
        
        # Check if input matches username OR email (case-insensitive)
        user = User.query.filter(or_(User.username.ilike(login_input), User.email.ilike(login_input))).first()
        
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account is deactivated. Please contact administrator.', 'danger')
                return redirect(url_for('auth.login'))
            
            login_user(user, remember=form.remember.data)
            
            # Log activity
            log_activity(user.id, 'login', f'User {user.username} logged in')
            
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif user.role == 'organization':
                return redirect(url_for('organization.dashboard'))
            elif user.role == 'student':
                return redirect(url_for('student.dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout', f'User {current_user.username} logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('student.dashboard'))
        
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generate 6-digit code
            import random
            code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            user.reset_code = code
            user.reset_code_expiry = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
            
            # Send email
            success, message = EmailService.send_password_reset_code(user.email, code)
            if success:
                flash('A verification code has been sent to your email.', 'success')
                return redirect(url_for('auth.reset_password', email=user.email))
            else:
                flash(f'Error sending email: {message}', 'danger')
        else:
            # Don't reveal if email exists or not for security
            flash('If an account exists with this email, you will receive a verification code.', 'info')
            return redirect(url_for('auth.reset_password', email=form.email.data))
            
    return render_template('auth/forgot_password.html', form=form)

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('student.dashboard'))
        
    form = ResetPasswordForm()
    email = request.args.get('email')
    
    if email and not form.email.data:
        form.email.data = email
        
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.reset_code == form.code.data:
                if user.reset_code_expiry and user.reset_code_expiry > datetime.utcnow():
                    user.set_password(form.password.data)
                    user.reset_code = None
                    user.reset_code_expiry = None
                    db.session.commit()
                    flash('Your password has been reset. You can now login.', 'success')
                    return redirect(url_for('auth.login'))
                else:
                    flash('Verification code has expired. Please request a new one.', 'danger')
            else:
                flash('Invalid verification code.', 'danger')
        else:
             flash('Invalid email or code.', 'danger')
             
    return render_template('auth/reset_password.html', form=form)

@auth_bp.route('/register/student', methods=['GET', 'POST'])
def register_student():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif current_user.role == 'organization':
            return redirect(url_for('organization.dashboard'))
        elif current_user.role == 'student':
            return redirect(url_for('student.dashboard'))
    
    form = StudentRegistrationForm()
    if form.validate_on_submit():
        # Clean input data
        username = form.username.data.strip() if form.username.data else ''
        email = form.email.data.strip().lower() if form.email.data else ''

        # Check if username or email already exists
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            form.username.errors.append('Username already exists')
            return render_template('auth/register_student.html', form=form)
        
        if User.query.filter_by(email=email).first():
            form.email.errors.append('Email already registered')
            return render_template('auth/register_student.html', form=form)
        
        # Create user
        user = User(
            username=username,
            email=email,
            role='student'
        )
        user.set_password(form.password.data)
        try:
            db.session.add(user)
            db.session.commit()
            
            # Create student profile
            student = Student(
                user_id=user.id,
                first_name=form.first_name.data,
                surname=form.surname.data,
                school=form.school.data
            )
            db.session.add(student)
            db.session.commit()
            
            # Log activity
            log_activity(user.id, 'registration', 'Student account created')
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
            
        except IntegrityError:
            db.session.rollback()
            flash('An account with this email or username already exists.', 'danger')
            return redirect(url_for('auth.register_student'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration. Please try again.', 'danger')
            print(f"Registration error: {e}")
            return redirect(url_for('auth.register_student'))
    
    else:
        if request.method == 'POST':
            print(f"Validation errors: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')

    return render_template('auth/register_student.html', form=form)

@auth_bp.route('/notifications/mark-read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@auth_bp.route('/register/organization', methods=['GET', 'POST'])
def register_organization():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif current_user.role == 'organization':
            return redirect(url_for('organization.dashboard'))
        elif current_user.role == 'student':
            return redirect(url_for('student.dashboard'))
    
    form = OrganizationRegistrationForm()
    if form.validate_on_submit():
        # Clean input data
        username = form.username.data.strip() if form.username.data else ''
        email = form.email.data.strip().lower() if form.email.data else ''

        # Check if username or email already exists
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            form.username.errors.append('Username already exists')
            return render_template('auth/register_organization.html', form=form)
        
        if User.query.filter_by(email=email).first():
            form.email.errors.append('Email already registered')
            return render_template('auth/register_organization.html', form=form)
        
        # Create user
        user = User(
            username=username,
            email=email,
            role='organization'
        )
        user.set_password(form.password.data)
        try:
            db.session.add(user)
            db.session.commit()
            
            # Create organization profile (pending approval)
            organization = Organization(
                user_id=user.id,
                organization_name=form.organization_name.data,
                is_approved=False
            )
            db.session.add(organization)
            # db.session.commit() # Defer commit until after notification
            
            # Create notification for admin
            admin_user = User.query.filter_by(role='admin').first()
            if admin_user:
                notification = Notification(
                    user_id=admin_user.id,
                    title='New Organization Registration',
                    message=f'{organization.organization_name} has requested to register as an organization.',
                    notification_type='approval',
                    link=url_for('admin.user_management', role='organization')
                )
                db.session.add(notification)
            
            db.session.commit() # Commit user, organization, and notification together
            
            # Send pending registration email
            EmailService.send_organization_pending_email(user.email, organization.organization_name)
            
            # Log activity
            log_activity(user.id, 'registration', 'Organization registration request submitted')
            
            flash('Registration submitted! Your account is pending admin approval.', 'info')
            return redirect(url_for('auth.login'))
            
        except IntegrityError:
            db.session.rollback()
            flash('An account with this email or username already exists.', 'danger')
            return redirect(url_for('auth.register_organization'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration. Please try again.', 'danger')
            print(f"Registration error: {e}")
            return redirect(url_for('auth.register_organization'))
    
    else:
        if request.method == 'POST':
            print(f"Validation errors: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')

    return render_template('auth/register_organization.html', form=form)

@auth_bp.route('/admin/setup', methods=['GET', 'POST'])
def admin_register():
    """
    Special setup route for creating the initial admin account
    This should only be accessible when no admin exists
    """
    # Check if admin already exists
    admin_exists = User.query.filter_by(role='admin').first()
    if admin_exists:
        flash('Administrator account already exists. Please login instead.', 'warning')
        return redirect(url_for('auth.login'))
    
    form = AdminRegistrationForm()
    
    if form.validate_on_submit():
        try:
            # Create admin user
            user = User(
                username=form.username.data,
                email=form.email.data,
                role='admin'
            )
            user.set_password(form.password.data)
            user.is_active = True
            db.session.add(user)
            db.session.commit()
            
            # Create admin profile
            admin = Admin(user_id=user.id)
            db.session.add(admin)
            db.session.commit()
            
            # Create initial categories
            initial_categories = [
                ('Education', 'Tutoring, mentoring, and educational support'),
                ('Environment', 'Cleanup, conservation, and sustainability'),
                ('Healthcare', 'Medical support and health awareness'),
                ('Community', 'Local community support and development'),
                ('Technology', 'Digital literacy and tech support'),
                ('Elderly Care', 'Support for senior citizens'),
                ('Animal Welfare', 'Animal shelter and care activities'),
                ('Arts & Culture', 'Cultural preservation and arts programs')
            ]
            
            for name, description in initial_categories:
                category = Category(name=name, description=description)
                db.session.add(category)
            
            db.session.commit()
            
            # Log activity
            log_activity(user.id, 'system_setup', 'Initial system setup completed')
            
            flash('System setup completed successfully! Administrator account created. Please login.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error during setup: {str(e)}', 'danger')
            return redirect(url_for('auth.admin_register'))
    
    return render_template('auth/admin_register.html', form=form)

# Admin Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/dashboard')
@login_required
@role_required('admin')
def dashboard():
    # Get statistics
    total_students = Student.query.count()
    
    # Calculate total hours from verified registrations - FIXED
    try:
        total_hours_result = db.session.query(db.func.sum(EventRegistration.hours_earned)).filter(
            EventRegistration.is_verified == True
        ).scalar()
        total_hours = float(total_hours_result) if total_hours_result else 0.0
    except (TypeError, ValueError):
        total_hours = 0.0
    
    pending_orgs = Organization.query.filter_by(is_approved=False).count()
    active_orgs = Organization.query.filter_by(is_approved=True).count()
    
    # Recent activities
    recent_activities = ActivityLog.query.order_by(
        ActivityLog.timestamp.desc()
    ).limit(10).all()
    
    # Recent notifications
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Notification.created_at.desc()
    ).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_students=total_students,
                         total_hours=total_hours,
                         pending_orgs=pending_orgs,
                         active_orgs=active_orgs,
                         recent_activities=recent_activities,
                         notifications=notifications)

@admin_bp.route('/export_dashboard')
@login_required
@role_required('admin')
def export_dashboard():
    # Get statistics
    total_students = Student.query.count()
    
    # Calculate total hours
    try:
        total_hours_result = db.session.query(db.func.sum(EventRegistration.hours_earned)).filter(
            EventRegistration.is_verified == True
        ).scalar()
        total_hours = float(total_hours_result) if total_hours_result else 0.0
    except (TypeError, ValueError):
        total_hours = 0.0
        
    pending_orgs = Organization.query.filter_by(is_approved=False).count()
    active_orgs = Organization.query.filter_by(is_approved=True).count()
    
    stats = {
        'total_students': total_students,
        'total_hours': total_hours,
        'pending_orgs': pending_orgs,
        'active_orgs': active_orgs
    }
    
    # Recent Activities
    recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(20).all()
    
    # Generate Report
    from report_generator import ReportGenerator
    pdf_path = ReportGenerator.generate_admin_dashboard_report(stats, recent_activities)
    
    return send_file(pdf_path, as_attachment=True)

@admin_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def profile():
    form = AdminSettingsForm()
    user = current_user
    admin = user.admin
    
    if form.validate_on_submit():
        if form.username.data != user.username:
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken', 'danger')
                return redirect(url_for('admin.profile'))
        
        if form.email.data != user.email:
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already taken', 'danger')
                return redirect(url_for('admin.profile'))
                
        user.username = form.username.data
        user.email = form.email.data
        
        # Update admin specific fields
        if admin:
            admin.first_name = form.first_name.data
            admin.surname = form.surname.data
            admin.phone_number = form.phone_number.data
        else:
            # Create admin profile if it doesn't exist (though it should)
            admin = Admin(
                user_id=user.id,
                first_name=form.first_name.data,
                surname=form.surname.data,
                phone_number=form.phone_number.data
            )
            db.session.add(admin)
        
        if form.new_password.data:
            if not user.check_password(form.current_password.data):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('admin.profile'))
            user.set_password(form.new_password.data)
            flash('Password updated successfully', 'success')
            
        db.session.commit()
        flash('Profile updated successfully', 'success')
        log_activity(user.id, 'profile_update', 'Admin profile updated')
        return redirect(url_for('admin.profile'))
        
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        if admin:
            form.first_name.data = admin.first_name
            form.surname.data = admin.surname
            form.phone_number.data = admin.phone_number
        
    return render_template('admin/profile.html', form=form)

@admin_bp.route('/users/<role>')
@login_required
@role_required('admin')
def user_management(role):
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    search_id = request.args.get('search_id', '').strip()
    status = request.args.get('status', '')
    date_registered = request.args.get('date', '')
    
    # Base query based on role
    if role == 'student':
        query = User.query.filter_by(role='student')
        if search:
            search_term = f"%{search}%"
            # Join Student to search by name
            query = query.join(Student).filter(
                or_(
                    Student.first_name.ilike(search_term),
                    Student.surname.ilike(search_term),
                    User.username.ilike(search_term),
                    User.email.ilike(search_term)
                )
            )
    elif role == 'organization':
        query = User.query.filter_by(role='organization')
        if search:
            search_term = f"%{search}%"
            # Join Organization to search by name
            query = query.join(Organization).filter(
                or_(
                    Organization.organization_name.ilike(search_term),
                    User.username.ilike(search_term),
                    User.email.ilike(search_term)
                )
            )
    else:
        flash('Invalid user type', 'danger')
        return redirect(url_for('admin.dashboard'))
        
    # Filter by ID
    if search_id:
        try:
            query = query.filter(User.id == int(search_id))
        except ValueError:
            pass # Ignore invalid ID
            
    # Filter by Status
    if status:
        if status == 'active':
            query = query.filter(User.is_active == True)
        elif status == 'inactive':
            query = query.filter(User.is_active == False)
            
    # Filter by Date Registered
    if date_registered:
        try:
            # Robust date handling
            from datetime import datetime
            search_date = datetime.strptime(date_registered, '%Y-%m-%d')
            # Create a range for the whole day (00:00:00 to 23:59:59)
            next_day = search_date + timedelta(days=1)
            query = query.filter(
                User.created_at >= search_date,
                User.created_at < next_day
            )
        except ValueError:
            pass # Ignore invalid date format
            
    # Execute Query
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin/user_management.html',
                         users=users,
                         role=role,
                         search=search,
                         search_id=search_id,
                         status=status,
                         date_registered=date_registered)

@admin_bp.route('/toggle_user_status/<int:user_id>')
@login_required
@role_required('admin')
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    action = 'activated' if user.is_active else 'deactivated'
    flash(f'User {action} successfully', 'success')
    log_activity(current_user.id, 'user_management', f'{action.capitalize()} user {user.username}')
    
    return redirect(request.referrer or url_for('admin.dashboard'))

@admin_bp.route('/handle_deletion_request/<int:user_id>/<action>', methods=['POST'])
@login_required
@role_required('admin')
def handle_deletion_request(user_id, action):
    user = User.query.get_or_404(user_id)
    
    if action == 'approve':
        user.is_active = False
        user.deletion_requested = False
        # Keep the reason for record, or clear it if desired. Let's keep it.
        flash(f'User {user.username} has been deactivated.', 'success')
        log_activity(current_user.id, 'user_management', f'Approved deletion request for {user.username}')
        
        # Notify user (optional, as they can't login anyway)
        
    elif action == 'reject':
        user.deletion_requested = False
        # We might want to clear the reason or keep it. Let's clear logic flags.
        
        flash(f'Deletion request for {user.username} rejected.', 'info')
        log_activity(current_user.id, 'user_management', f'Rejected deletion request for {user.username}')
        
        # Notify user
        notification = Notification(
            user_id=user.id,
            title='Deletion Request Rejected',
            message='Your account deletion request has been reviewed and rejected by an administrator. Your account remains active.',
            notification_type='system',
            link='#'
        )
        db.session.add(notification)
        
    db.session.commit()
    return redirect(request.referrer or url_for('admin.user_management', role=user.role))

@admin_bp.route('/approve_organization/<int:org_id>')
@login_required
@role_required('admin')
def approve_organization(org_id):
    organization = Organization.query.get_or_404(org_id)
    
    if organization.is_approved:
        flash('Organization already approved', 'info')
        return redirect(request.referrer or url_for('admin.dashboard'))
    
    # Get user
    user = User.query.get(organization.user_id)
    
    organization.is_approved = True
    
    # Send email
    if EmailService.send_organization_approval_email(
        user.email, user.username
    ):
        flash('Organization approved and email sent successfully', 'success')
    else:
        flash('Organization approved but email failed to send', 'warning')
    
    # Create notification for organization
    notification = Notification(
        user_id=user.id,
        title='Registration Approved',
        message='Your organization registration has been approved by the administrator.',
        notification_type='approval'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    log_activity(current_user.id, 'approval', f'Approved organization {organization.organization_name}')
    
    return redirect(request.referrer or url_for('admin.dashboard'))

@admin_bp.route('/categories', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def categories():
    form = CategoryForm()
    
    if form.validate_on_submit():
        category = Category(
            name=form.name.data,
            description=form.description.data
        )
        db.session.add(category)
        db.session.commit()
        
        flash('Category added successfully', 'success')
        log_activity(current_user.id, 'category_management', f'Added category: {form.name.data}')
        
        return redirect(url_for('admin.categories'))
    
    
    # Get params
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'name_asc')

    # Build query
    query = Category.query

    if search:
        query = query.filter(Category.name.ilike(f'%{search}%'))

    if sort == 'name_desc':
        query = query.order_by(Category.name.desc())
    elif sort == 'newest':
        query = query.order_by(Category.created_at.desc())
    elif sort == 'oldest':
        query = query.order_by(Category.created_at.asc())
    else: # name_asc
        query = query.order_by(Category.name.asc())

    categories_list = query.all()
    
    return render_template('admin/categories.html',
                         form=form,
                         categories=categories_list)

@admin_bp.route('/delete_category/<int:category_id>')
@login_required
@role_required('admin')
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    # Check if category is used
    if category.events.count() > 0:
        flash('Cannot delete category that is being used by events', 'danger')
    else:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully', 'success')
        log_activity(current_user.id, 'category_management', f'Deleted category: {category.name}')
    
    return redirect(url_for('admin.categories'))

@admin_bp.route('/update_category/<int:category_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    # We can rely on the same form logic or simple request.form since it's likely a modal edit
    # But let's check if the form data is passed.
    # Usually in these templates it's a simple form submission
    
    name = request.form.get('name')
    description = request.form.get('description')
    
    if name:
        category.name = name
        if description:
            category.description = description
            
        try:
            db.session.commit()
            flash('Category updated successfully', 'success')
            log_activity(current_user.id, 'category_management', f'Updated category: {category.name}')
        except IntegrityError:
            db.session.rollback()
            flash(f'Category name "{name}" already exists', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Error updating category', 'danger')
            
    return redirect(url_for('admin.categories'))

@admin_bp.route('/activity_logs')
@login_required
@role_required('admin')
def activity_logs():
    page = request.args.get('page', 1, type=int)
    
    # Get filter parameters
    user_type = request.args.get('user_type', '')
    activity_type = request.args.get('activity_type', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = ActivityLog.query
    
    # Apply filters
    if user_type:
        query = query.join(User).filter(User.role == user_type)
        
    if activity_type:
        query = query.filter(ActivityLog.activity_type.contains(activity_type))
        
    if date_from:
        try:
            start_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(ActivityLog.timestamp >= start_date)
        except ValueError:
            pass
            
    if date_to:
        try:
            end_date = datetime.strptime(date_to, '%Y-%m-%d')
            # Set time to end of day
            end_date = end_date.replace(hour=23, minute=59, second=59)
            query = query.filter(ActivityLog.timestamp <= end_date)
        except ValueError:
            pass
            
    activities = query.order_by(
        ActivityLog.timestamp.desc()
    ).paginate(page=page, per_page=50, error_out=False)
    
    return render_template('admin/activity_logs.html', 
                         activities=activities,
                         user_type=user_type,
                         activity_type=activity_type,
                         date_from=date_from,
                         date_to=date_to)

@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_settings():
    form = AdminSettingsForm()
    user = current_user
    admin = user.admin
    
    if form.validate_on_submit():
        # Check current password if changing password
        if form.new_password.data:
            if not user.check_password(form.current_password.data):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('admin.admin_settings'))
            
            user.set_password(form.new_password.data)
            flash('Password updated successfully', 'success')
        
        # Update username
        if user.username != form.username.data:
            user.username = form.username.data
            flash('Username updated successfully', 'success')

        # Update email
        if user.email != form.email.data:
            user.email = form.email.data
            flash('Email updated successfully', 'success')
            
        # Update Admin Profile Fields
        if admin:
            admin.first_name = form.first_name.data
            admin.surname = form.surname.data
            admin.phone_number = form.phone_number.data
        else:
            admin = Admin(
                user_id=user.id,
                first_name=form.first_name.data,
                surname=form.surname.data,
                phone_number=form.phone_number.data
            )
            db.session.add(admin)
        
        db.session.commit()
        log_activity(user.id, 'settings', 'Updated admin settings')
        
        return redirect(url_for('admin.admin_settings'))
    
    # Pre-populate form
    form.username.data = current_user.username
    form.email.data = current_user.email
    if admin:
        form.first_name.data = admin.first_name
        form.surname.data = admin.surname
        form.phone_number.data = admin.phone_number
    
    # Calculate stats for the dashboard
    total_students = Student.query.count()
    active_orgs = Organization.query.filter_by(is_approved=True).count()
    pending_orgs = Organization.query.filter_by(is_approved=False).count()
    
    # Calculate total hours (sum of all hours_earned from EventRegistration)
    from sqlalchemy import func
    total_hours_result = db.session.query(func.sum(EventRegistration.hours_earned)).scalar()
    total_hours = total_hours_result if total_hours_result else 0.0
    
    return render_template('admin/settings.html', 
                         form=form,
                         total_students=total_students,
                         active_orgs=active_orgs,
                         pending_orgs=pending_orgs,
                         total_hours=total_hours)

@admin_bp.route('/clear_logs', methods=['POST'])
@login_required
@role_required('admin')
def clear_logs():
    try:
        # Delete all activity logs
        db.session.query(ActivityLog).delete()
        db.session.commit()
        
        # Log this action (it will be the only log!)
        log_activity(current_user.id, 'system_maintenance', 'Cleared all activity logs')
        
        flash('Activity logs cleared successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error clearing logs: {str(e)}', 'danger')
        
    return redirect(url_for('admin.admin_settings'))

# Organization Blueprint
organization_bp = Blueprint('organization', __name__, url_prefix='/organization')

@organization_bp.route('/dashboard')
@login_required
@role_required('organization')
def dashboard():
    org = current_user.organization
    
    if not org.is_approved:
        flash('Your account is pending admin approval', 'warning')
        return render_template('organization/pending_approval.html', org=org)
    
    # Get upcoming events
    upcoming_events = Event.query.filter_by(
        organization_id=org.id,
        status='active'
    ).filter(
        Event.date_time > datetime.utcnow()
    ).order_by(Event.date_time).limit(5).all()
    
    # Get recent notifications
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()
    
    # Get past events count
    past_events_count = Event.query.filter_by(
        organization_id=org.id,
        status='completed'
    ).count()
    
    # Calculate statistics - FIXED
    # Calculate statistics - FIXED
    total_volunteers = db.session.query(db.func.count(EventRegistration.id)).select_from(EventRegistration).join(Event).filter(
        Event.organization_id == org.id,
        EventRegistration.attendance_status != 'cancelled'
    ).scalar() or 0
    
    try:
        total_hours_result = db.session.query(db.func.sum(EventRegistration.hours_earned)).select_from(EventRegistration).join(Event).filter(
            Event.organization_id == org.id,
            EventRegistration.is_verified == True
        ).scalar()
        total_hours = float(total_hours_result) if total_hours_result else 0.0
    except (TypeError, ValueError):
        total_hours = 0.0
    
    certificates_issued = Certificate.query.filter_by(
        organization_id=org.id
    ).count()
    
    # Get recent volunteers for display (optional - you can add this if needed)
    # Get recent volunteers (signups for organization's events)
    recent_volunteers = EventRegistration.query.join(Event).filter(
        Event.organization_id == org.id,
        EventRegistration.attendance_status != 'cancelled'
    ).order_by(EventRegistration.registration_date.desc()).limit(10).all()
    
    # Get cancellation requests
    cancellation_requests = EventRegistration.query.join(Event).filter(
        Event.organization_id == org.id,
        EventRegistration.attendance_status == 'cancellation_requested'
    ).all()
    
    return render_template('organization/dashboard.html',
                         org=org,
                         upcoming_events=upcoming_events,
                         notifications=notifications,
                         past_events_count=past_events_count,
                         total_volunteers=total_volunteers,
                         total_hours=total_hours,
                         certificates_issued=certificates_issued,
                         recent_volunteers=recent_volunteers,
                         cancellation_requests=cancellation_requests)

@organization_bp.route('/create_opportunity', methods=['GET', 'POST'])
@login_required
@role_required('organization')
def create_opportunity():
    org = current_user.organization
    
    if not org.is_approved:
        flash('Your account must be approved to create opportunities', 'warning')
        return redirect(url_for('organization.dashboard'))
    
    form = CreateOpportunityForm()
    
    # Populate categories
    form.category_id.choices = [(c.id, c.name) for c in Category.query.order_by('name').all()]
    
    if form.validate_on_submit():
        start_dt = datetime.combine(form.date.data, form.start_time.data)
        end_dt = datetime.combine(form.date.data, form.end_time.data)
        
        if end_dt < start_dt:
            end_dt += timedelta(days=1)
            
        duration = (end_dt - start_dt).total_seconds() / 3600
        
        event = Event(
            organization_id=org.id,
            category_id=form.category_id.data,
            title=form.title.data,
            description=form.description.data,
            date_time=start_dt,
            duration_hours=duration,
            slots_available=form.slots_available.data,
            skill_requirements=", ".join(form.skill_requirements.data),
            location=form.location.data,
            status='draft' if 'save_draft' in request.form else 'active'
        )
        
        db.session.add(event)
        db.session.commit()
        
        action = 'saved as draft' if 'save_draft' in request.form else 'published'
        flash(f'Event {action} successfully', 'success')
        log_activity(current_user.id, 'event_management', 
                    f'Created event: {event.title} ({action})')
        
        return redirect(url_for('organization.my_opportunities'))
    
    # Get popular categories for display
    # Only show categories that have events
    popular_categories = [c for c in Category.query.order_by(Category.name).all() if c.events.count() > 0][:5]
    
    return render_template('organization/create_opportunity.html', 
                         form=form,
                         popular_categories=popular_categories,
                         title="Create Opportunity",
                         action_url=url_for('organization.create_opportunity'),
                         is_edit=False)

@organization_bp.route('/edit_opportunity/<int:event_id>', methods=['GET', 'POST'])
@login_required
@role_required('organization')
def edit_opportunity(event_id):
    org = current_user.organization
    event = Event.query.get_or_404(event_id)
    
    if event.organization_id != org.id:
        abort(403)
        
    form = CreateOpportunityForm(obj=event)
    
    # Populate categories
    form.category_id.choices = [(c.id, c.name) for c in Category.query.order_by('name').all()]
    
    if request.method == 'GET':
        if event.date_time:
            form.date.data = event.date_time.date()
            form.start_time.data = event.date_time.time()
            if event.duration_hours:
                end_dt = event.date_time + timedelta(hours=event.duration_hours)
                form.end_time.data = end_dt.time()
        if event.skill_requirements:
            form.skill_requirements.data = event.skill_requirements.split(", ")
    
    if form.validate_on_submit():
        event.title = form.title.data
        event.description = form.description.data
        event.category_id = form.category_id.data
        
        start_dt = datetime.combine(form.date.data, form.start_time.data)
        end_dt = datetime.combine(form.date.data, form.end_time.data)
        if end_dt < start_dt:
            end_dt += timedelta(days=1)
        duration = (end_dt - start_dt).total_seconds() / 3600
        
        event.date_time = start_dt
        event.duration_hours = duration

        slots_available = form.slots_available.data
        # Ensure slots available >= slots filled
        if slots_available < event.slots_filled:
            flash(f'Cannot reduce slots below current filled count ({event.slots_filled})', 'danger')
            return redirect(url_for('organization.edit_opportunity', event_id=event.id))
            
        event.slots_available = slots_available
        event.skill_requirements = ", ".join(form.skill_requirements.data)
        event.location = form.location.data
        
        if 'save_draft' in request.form:
             event.status = 'draft'
             action = 'saved as draft'
        elif 'publish' in request.form:
             event.status = 'active'
             action = 'published'
        elif 'update' in request.form:
             # Keep current status, unless it was draft and we want to allow staying draft
             # If it was draft, it stays draft. If active, stays active.
             action = 'updated'
        else:
             # Fallback
             action = 'updated'

        db.session.commit()
        
        flash(f'Event {action} successfully', 'success')
        log_activity(current_user.id, 'event_management', f'Updated event: {event.title} ({action})')
        
        return redirect(url_for('organization.my_opportunities'))
    
    # Get popular categories for display
    # Only show categories that have events
    popular_categories = [c for c in Category.query.order_by(Category.name).all() if c.events.count() > 0][:5]
    
    return render_template('organization/create_opportunity.html', 
                         form=form,
                         popular_categories=popular_categories,
                         title="Edit Opportunity",
                         action_url=url_for('organization.edit_opportunity', event_id=event.id),
                         is_edit=True)

@organization_bp.route('/delete_opportunity/<int:event_id>')
@login_required
@role_required('organization')
def delete_opportunity(event_id):
    org = current_user.organization
    event = Event.query.get_or_404(event_id)
    
    if event.organization_id != org.id:
        abort(403)
    
    if event.status == 'draft' or event.registrations.count() == 0:
        db.session.delete(event)
        flash('Event deleted successfully', 'success')
        action = 'deleted'
    else:
        event.status = 'cancelled'
        flash('Event cancelled successfully', 'success')
        action = 'cancelled'
        
    db.session.commit()
    log_activity(current_user.id, 'event_management', f'{action.capitalize()} event: {event.title}')
    
    return redirect(url_for('organization.my_opportunities'))

@organization_bp.route('/publish_opportunity/<int:event_id>')
@login_required
@role_required('organization')
def publish_opportunity(event_id):
    org = current_user.organization
    event = Event.query.get_or_404(event_id)
    
    if event.organization_id != org.id:
        abort(403)
        
    event.status = 'active'
    db.session.commit()
    
    flash('Event published successfully', 'success')
    log_activity(current_user.id, 'event_management', f'Published event: {event.title}')
    
    return redirect(url_for('organization.my_opportunities'))

@organization_bp.route('/verification_dashboard')
@login_required
@role_required('organization')
def verification_dashboard():
    org = current_user.organization
    
    # Get completed events (ready for verification/certificates)
    # Include both 'active' (but finished time-wise) and 'completed' (already verified)
    all_events = Event.query.filter(
        Event.organization_id == org.id,
        Event.status.in_(['active', 'completed'])
    ).order_by(Event.date_time.desc()).all()
    
    # Filter for events that are effectively finished based on time
    completed_events = [e for e in all_events if e.current_status == 'Finished']
    
    # Calculate stats for the view
    for event in completed_events:
        hours = db.session.query(db.func.sum(EventRegistration.hours_earned)).filter(
            EventRegistration.event_id == event.id,
            EventRegistration.attendance_status == 'present'
        ).scalar()
        event.total_hours_filled = float(hours) if hours else 0.0
        
        event.certificates_issued_count = Certificate.query.join(EventRegistration).filter(
            EventRegistration.event_id == event.id
        ).count()
        
    return render_template('organization/verification_dashboard.html',
                         completed_events=completed_events)

@main_bp.route('/notifications')
@login_required
def notifications():
    # Get all notifications for current user
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    pagination = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
        
    return render_template('notifications.html', pagination=pagination)

@organization_bp.route('/my_opportunities')
@login_required
@role_required('organization')
def my_opportunities():
    org = current_user.organization
    
    # Get events by status
    active_events = Event.query.filter_by(
        organization_id=org.id,
        status='active'
    ).order_by(Event.date_time).all()
    
    draft_events = Event.query.filter_by(
        organization_id=org.id,
        status='draft'
    ).order_by(Event.created_at.desc()).all()
    
    # Calculate statistics - FIXED
    # Note: completed_events query removed from here but count needed for stats if wanted, 
    # but we can query count directly or keep simple query if needed for stats card.
    # For now, let's keep the count query simple without full loading logic if needed.
    
    completed_count = Event.query.filter_by(organization_id=org.id, status='completed').count()
    total_events = len(active_events) + completed_count + len(draft_events)
    
    total_volunteers = db.session.query(db.func.count(EventRegistration.id)).select_from(EventRegistration).join(Event).filter(
        Event.organization_id == org.id,
        EventRegistration.attendance_status != 'cancelled'
    ).scalar() or 0
    
    try:
        total_hours_result = db.session.query(db.func.sum(EventRegistration.hours_earned)).select_from(EventRegistration).join(Event).filter(
            Event.organization_id == org.id,
            EventRegistration.is_verified == True
        ).scalar()
        total_hours = float(total_hours_result) if total_hours_result else 0.0
    except (TypeError, ValueError):
        total_hours = 0.0
    
    total_certificates = Certificate.query.filter_by(
        organization_id=org.id
    ).count()
    
    return render_template('organization/my_opportunities.html',
                         active_events=active_events,
                         draft_events=draft_events,
                         total_events=total_events,
                         total_volunteers=total_volunteers,
                         total_hours=total_hours,
                         total_certificates=total_certificates)

@organization_bp.route('/verify_attendance/<int:event_id>', methods=['GET', 'POST'])
@login_required
@role_required('organization')
def verify_attendance(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if event belongs to organization
    if event.organization_id != current_user.organization.id:
        abort(403)
    
    if request.method == 'POST':
        # Process attendance verification
        for reg in event.registrations:
            attendance_key = f'attendance_{reg.id}'
            hours_key = f'hours_{reg.id}'
            
            if attendance_key in request.form:
                reg.attendance_status = 'present'
                hours_value = request.form.get(hours_key, event.duration_hours)
                try:
                    reg.hours_earned = float(hours_value)
                except (TypeError, ValueError):
                    reg.hours_earned = event.duration_hours
            else:
                reg.attendance_status = 'absent'
                reg.hours_earned = 0.0
            
            reg.is_verified = True
            reg.verification_date = datetime.utcnow()
            
            # Auto-generate certificate if present and verified
            if reg.attendance_status == 'present' and not reg.certificate:
                try:
                    # Generate certificate
                    cert_number = generate_certificate_number()
                    
                    # Get paths safely
                    org_logo = event.organization.logo_path if event.organization.logo_path else None
                    signature_path = event.organization.digital_signature_path if event.organization.digital_signature_path else None
                    
                    # Generate PDF certificate
                    cert_path = CertificateGenerator.generate_certificate(
                        student_name=f"{reg.student.first_name} {reg.student.surname}",
                        org_name=event.organization.organization_name,
                        event_name=event.title,
                        hours_earned=reg.hours_earned,
                        issue_date=datetime.utcnow(),
                        certificate_number=cert_number,
                        org_logo=org_logo,
                        signature_path=signature_path
                    )
                    
                    # Create certificate record
                    certificate = Certificate(
                        event_registration_id=reg.id,
                        student_id=reg.student_id,
                        organization_id=event.organization_id,
                        certificate_number=cert_number,
                        hours_earned=reg.hours_earned,
                        pdf_path=cert_path
                    )
                    db.session.add(certificate)
                    
                    # Create notification for student
                    notification = Notification(
                        user_id=reg.student.user_id,
                        title='Certificate Earned!',
                        message=f'You have received a certificate for "{event.title}". View it in your history.',
                        notification_type='certificate',
                        link=url_for('student.volunteer_history', _external=True)
                    )
                    db.session.add(notification)
                    
                except Exception as e:
                    # Log error but don't fail the verification
                    print(f"Error generating certificate for {reg.student.first_name}: {e}")
                    # Could log to activity log or file
        
        event.status = 'completed'
        db.session.commit()
        
        flash('Attendance verified and certificates generated successfully', 'success')
        log_activity(current_user.id, 'verification', f'Verified attendance for event: {event.title}')
        
        return redirect(url_for('organization.verify_attendance', event_id=event_id))
    
    return render_template('organization/verify_attendance.html', event=event)

@organization_bp.route('/generate_certificates/<int:event_id>')
@login_required
@role_required('organization')
def generate_certificates(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if event belongs to organization
    if event.organization_id != current_user.organization.id:
        abort(403)
        
    generated_count = 0
    
    # Generate certificates for verified attendees who don't have one
    registrations = EventRegistration.query.filter_by(event_id=event.id, attendance_status='present', is_verified=True).all()
    
    for reg in registrations:
        if not reg.certificate:
            try:
                # Generate certificate
                cert_number = generate_certificate_number()
                
                # Get paths safely
                org_logo = event.organization.logo_path if event.organization.logo_path else None
                signature_path = event.organization.digital_signature_path if event.organization.digital_signature_path else None
                
                # Generate PDF certificate
                cert_path = CertificateGenerator.generate_certificate(
                    student_name=f"{reg.student.first_name} {reg.student.surname}",
                    org_name=event.organization.organization_name,
                    event_name=event.title,
                    hours_earned=reg.hours_earned,
                    issue_date=datetime.utcnow(),
                    certificate_number=cert_number,
                    org_logo=org_logo,
                    signature_path=signature_path
                )
                
                # Create certificate record
                certificate = Certificate(
                    event_registration_id=reg.id,
                    student_id=reg.student_id,
                    organization_id=event.organization_id,
                    certificate_number=cert_number,
                    hours_earned=reg.hours_earned,
                    pdf_path=cert_path
                )
                db.session.add(certificate)
                
                # Send notification to student
                notification = Notification(
                    user_id=reg.student.user_id,
                    title='Certificate Issued',
                    message=f'A certificate has been issued for your participation in "{event.title}"',
                    notification_type='certificate'
                )
                db.session.add(notification)
                
                generated_count += 1
            except Exception as e:
                db.session.rollback()
                print(f"Error generating certificate for reg {reg.id}: {e}")
                flash(f"Error generating certificate for {reg.student.first_name}: {str(e)}", "danger")
                continue

    if generated_count > 0:
        db.session.commit()
        flash(f'Successfully generated {generated_count} new certificates.', 'success')
    else:
        flash('No new certificates were generated.', 'info')

    return redirect(url_for('organization.verification_dashboard'))
    
@organization_bp.route('/generate_single_certificate/<int:registration_id>', methods=['POST'])
@login_required
@role_required('organization')
def generate_single_certificate(registration_id):
    # Get registration
    reg = EventRegistration.query.get_or_404(registration_id)
    event = reg.event
    
    # Check authorization
    if event.organization_id != current_user.organization.id:
        abort(403)
        
    # Check status
    if not reg.is_verified or reg.attendance_status != 'present':
        flash('Cannot generate certificate. Attendance not verified or student absent.', 'danger')
        return redirect(url_for('organization.verify_attendance', event_id=event.id))
        
    if reg.certificate:
        flash('Certificate already exists.', 'info')
        return redirect(url_for('organization.verify_attendance', event_id=event.id))
        
    try:
        # Generate certificate
        cert_number = generate_certificate_number()
        
        # Get paths safely
        org_logo = event.organization.logo_path if event.organization.logo_path else None
        signature_path = event.organization.digital_signature_path if event.organization.digital_signature_path else None
        
        # Generate PDF certificate
        cert_path = CertificateGenerator.generate_certificate(
            student_name=f"{reg.student.first_name} {reg.student.surname}",
            org_name=event.organization.organization_name,
            event_name=event.title,
            hours_earned=reg.hours_earned,
            issue_date=datetime.utcnow(),
            certificate_number=cert_number,
            org_logo=org_logo,
            signature_path=signature_path
        )
        
        # Create certificate record
        certificate = Certificate(
            event_registration_id=reg.id,
            student_id=reg.student_id,
            organization_id=event.organization_id,
            certificate_number=cert_number,
            hours_earned=reg.hours_earned,
            pdf_path=cert_path
        )
        db.session.add(certificate)
        
        # Send notification to student
        notification = Notification(
            user_id=reg.student.user_id,
            title='Certificate Issued',
            message=f'A certificate has been issued for your participation in "{event.title}"',
            notification_type='certificate'
        )
        db.session.add(notification)
        
        db.session.commit()
        flash(f'Certificate generated for {reg.student.first_name} {reg.student.surname}', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error generating certificate: {str(e)}', 'danger')
        
    return redirect(url_for('organization.verify_attendance', event_id=event.id))
    
@organization_bp.route('/view_certificate/<int:certificate_id>')
@login_required
@role_required('organization')
def view_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    
    # Check if certificate belongs to organization
    if certificate.organization_id != current_user.organization.id:
        abort(403)
        
    if not certificate.pdf_path:
        abort(404)
        
    # Convert relative path to absolute path
    import os
    from flask import current_app
    abs_path = os.path.join(current_app.root_path, certificate.pdf_path)
    
    if not os.path.exists(abs_path):
        abort(404)
        
    return send_file(abs_path, mimetype='application/pdf')
    

@organization_bp.route('/event_volunteers/<int:event_id>')
@login_required
@role_required('organization')
def get_event_volunteers(event_id):
    event = Event.query.get_or_404(event_id)
    if event.organization_id != current_user.organization.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    volunteers = []
    for reg in event.registrations:
        volunteers.append({
            'id': reg.id,
            'student_name': f"{reg.student.first_name} {reg.student.surname}",
            'student_id': reg.student.id,
            'registration_date': reg.registration_date.strftime('%Y-%m-%d'),
            'profile_picture': reg.student.profile_picture,
            'status': reg.attendance_status
        })
    
    return jsonify(volunteers)

@organization_bp.route('/get_event_details/<int:event_id>')
@login_required
@role_required('organization')
def get_event_details(event_id):
    event = Event.query.get_or_404(event_id)
    if event.organization_id != current_user.organization.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    return jsonify({
        'id': event.id,
        'title': event.title,
        'category': event.category.name,
        'description': event.description,
        'date': event.date_time.strftime('%Y-%m-%d'),
        'time': event.date_time.strftime('%I:%M %p'),
        'duration': event.duration_hours,
        'location': event.location or 'Online',
        'slots_filled': event.slots_filled,
        'slots_available': event.slots_available,
        'skill_requirements': event.skill_requirements,
        'status': event.status
    })

@organization_bp.route('/remove_volunteer/<int:registration_id>', methods=['POST'])
@login_required
@role_required('organization')
def remove_volunteer(registration_id):
    registration = EventRegistration.query.get_or_404(registration_id)
    event = registration.event
    
    if event.organization_id != current_user.organization.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        event.slots_filled -= 1
        db.session.delete(registration)
        db.session.commit()
        
        # Notify student
        notification = Notification(
            user_id=registration.student.user_id,
            title='Registration Cancelled',
            message=f'You have been removed from the event "{event.title}" by the organization.',
            notification_type='event'
        )
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@organization_bp.route('/accept_volunteer/<int:registration_id>', methods=['POST'])
@login_required
@role_required('organization')
def accept_volunteer(registration_id):
    registration = EventRegistration.query.get_or_404(registration_id)
    event = registration.event
    
    if event.organization_id != current_user.organization.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        registration.attendance_status = 'confirmed'
        db.session.commit()
        
        # Notify student
        notification = Notification(
            user_id=registration.student.user_id,
            title='Registration Accepted',
            message=f'Your registration for "{event.title}" has been accepted.',
            notification_type='event'
        )
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@organization_bp.route('/activity_logs')
@login_required
@role_required('organization')
def activity_logs():
    page = request.args.get('page', 1, type=int)
    activity_type = request.args.get('activity_type', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = ActivityLog.query.filter_by(user_id=current_user.id)
    
    if activity_type:
        query = query.filter(ActivityLog.activity_type.contains(activity_type))
        
    if date_from:
        try:
            start_date = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(ActivityLog.timestamp >= start_date)
        except ValueError:
            pass
            
    if date_to:
        try:
            end_date = datetime.strptime(date_to, '%Y-%m-%d')
            end_date = end_date.replace(hour=23, minute=59, second=59)
            query = query.filter(ActivityLog.timestamp <= end_date)
        except ValueError:
            pass
            
    activities = query.order_by(ActivityLog.timestamp.desc())\
        .paginate(page=page, per_page=20, error_out=False)
        
    return render_template('organization/activity_logs.html',
                         activities=activities,
                         activity_type=activity_type,
                         date_from=date_from,
                         date_to=date_to)

@organization_bp.route('/handle_cancellation_request/<int:registration_id>', methods=['POST'])
@login_required
@role_required('organization')
def handle_cancellation_request(registration_id):
    registration = EventRegistration.query.get_or_404(registration_id)
    event = registration.event
    
    if event.organization_id != current_user.organization.id:
        abort(403)
        
    action = request.form.get('action')
    
    if action == 'approve':
        registration.attendance_status = 'cancelled'
        flash('Cancellation request approved.', 'success')
        
        # Notify student
        notification = Notification(
            user_id=registration.student.user_id,
            title='Cancellation Approved',
            message=f'Your cancellation request for "{event.title}" has been approved.',
            notification_type='event'
        )
        db.session.add(notification)
        log_activity(current_user.id, 'event_management', f'Approved cancellation for {registration.student.first_name} in {event.title}')
        
    elif action == 'reject':
        registration.attendance_status = 'pending'
        event.slots_filled += 1
        flash('Cancellation request rejected. Student remains registered.', 'info')
        
        # Notify student
        notification = Notification(
            user_id=registration.student.user_id,
            title='Cancellation Rejected',
            message=f'Your cancellation request for "{event.title}" has been rejected. You remain registered.',
            notification_type='event'
        )
        db.session.add(notification)
        log_activity(current_user.id, 'event_management', f'Rejected cancellation for {registration.student.first_name} in {event.title}')
        
    db.session.commit()
    return redirect(url_for('organization.dashboard'))

@organization_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@role_required('organization')
def profile():
    org = current_user.organization
    form = OrganizationProfileForm()
    
    if form.validate_on_submit():
        org.organization_name = form.organization_name.data
        org.description = form.description.data
        org.about_us = form.about_us.data
        # Update contact info
        org.contact_person = form.contact_person.data
        org.contact_phone = form.contact_phone.data
        org.contact_email = form.contact_email.data
        
        # Update password if provided
        if form.new_password.data:
            if not current_user.check_password(form.current_password.data):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('organization.profile'))
            current_user.set_password(form.new_password.data)
            flash('Password updated successfully', 'success')
        
        if form.logo.data:
            logo_path = save_uploaded_file(form.logo.data, 'logos')
            if logo_path:
                org.logo_path = logo_path
        
        if form.digital_signature.data:
            signature_path = save_uploaded_file(form.digital_signature.data, 'signatures')
            if signature_path:
                org.digital_signature_path = signature_path
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        log_activity(current_user.id, 'profile', 'Updated organization profile')
        
        return redirect(url_for('organization.profile'))
    
    # Pre-populate form
    form.organization_name.data = org.organization_name
    form.description.data = org.description
    form.about_us.data = org.about_us
    form.contact_person.data = org.contact_person
    form.contact_phone.data = org.contact_phone
    form.contact_email.data = org.contact_email
    
    return render_template('organization/profile.html', form=form, org=org)

# Student Blueprint
student_bp = Blueprint('student', __name__, url_prefix='/student')

@student_bp.route('/dashboard')
@login_required
@role_required('student')
def dashboard():
    student = current_user.student
    
    # Calculate statistics
    stats = calculate_student_stats(student.id)
    
    # Get next event
    next_event_reg = EventRegistration.query.join(Event).filter(
        EventRegistration.student_id == student.id,
        EventRegistration.attendance_status == 'pending',
        Event.date_time > datetime.utcnow(),
        Event.status == 'active'
    ).order_by(Event.date_time).first()
    
    # Get recommended events (based on skills)
    student_skills = []
    if student.skills:
        try:
            student_skills = [s.strip() for s in student.skills.split(',')]
        except AttributeError:
            student_skills = []
    
    recommended_events = Event.query.filter(
        Event.status == 'active',
        Event.date_time > datetime.utcnow(),
        Event.slots_filled < Event.slots_available
    ).order_by(Event.created_at.desc()).limit(5).all()
    
    # Get notifications
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()
    
    # Get upcoming events count
    upcoming_count = EventRegistration.query.join(Event).filter(
        EventRegistration.student_id == student.id,
        EventRegistration.attendance_status == 'pending',
        Event.date_time > datetime.utcnow(),
        Event.status == 'active'
    ).count()
    
    # Get pending verification count
    pending_verification = EventRegistration.query.join(Event).filter(
        EventRegistration.student_id == student.id,
        EventRegistration.is_verified == False,
        Event.date_time <= datetime.utcnow()
    ).count()
    
    return render_template('student/dashboard.html',
                         student=student,
                         stats=stats,
                         next_event=next_event_reg.event if next_event_reg else None,
                         recommended_events=recommended_events,
                         notifications=notifications,
                         upcoming_count=upcoming_count,
                         pending_verification=pending_verification)

@student_bp.route('/opportunity_feed')
@login_required
@role_required('student')
def opportunity_feed():
    form = SearchForm()
    
    # Get filter parameters
    category_id = request.args.get('category', type=int)
    search = request.args.get('search', '')
    
    # Build query
    query = Event.query.filter(
        Event.status == 'active',
        Event.date_time > datetime.utcnow(),
        Event.slots_filled < Event.slots_available
    )

    # Exclude events student is already registered for
    student = current_user.student
    registered_event_ids = [reg.event_id for reg in student.event_registrations]
    if registered_event_ids:
        query = query.filter(~Event.id.in_(registered_event_ids))
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search:
        query = query.filter(
            (Event.title.contains(search)) |
            (Event.description.contains(search)) |
            (Event.location.contains(search))
        )
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    pagination = query.order_by(Event.date_time).paginate(
        page=page, per_page=9, error_out=False
    )
    events = pagination.items
    
    # Get categories for dropdown
    categories = Category.query.order_by('name').all()
    form.category.choices = [(0, 'All Categories')] + [(c.id, c.name) for c in categories]
    
    return render_template('student/opportunity_feed.html',
                         events=events,
                         form=form,
                         search=search,
                         category_id=category_id,
                         total_pages=pagination.pages,
                         page=page,
                         categories=categories)

@student_bp.route('/signup_event/<int:event_id>')
@login_required
@role_required('student')
def signup_event(event_id):
    event = Event.query.get_or_404(event_id)
    student = current_user.student
    
    # Check if already registered
    existing_reg = EventRegistration.query.filter_by(
        event_id=event_id,
        student_id=student.id
    ).first()
    
    if existing_reg:
        flash('You are already registered for this event', 'warning')
        return redirect(url_for('student.opportunity_feed'))
    
    # Check if event has available slots
    if event.slots_filled >= event.slots_available:
        flash('This event is already full', 'danger')
        return redirect(url_for('student.opportunity_feed'))
    
    # Check if event has started
    if event.date_time <= datetime.utcnow():
        flash('This event has already started', 'danger')
        return redirect(url_for('student.opportunity_feed'))
    
    # Create registration
    registration = EventRegistration(
        event_id=event_id,
        student_id=student.id
    )
    db.session.add(registration)
    
    # Update slots filled
    event.slots_filled += 1
    
    # Create notification for organization
    notification = Notification(
        user_id=event.organization.user_id,
        title='New Event Registration',
        message=f'{student.first_name} {student.surname} has signed up for "{event.title}"',
        notification_type='event'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    flash('Successfully registered for the event', 'success')
    log_activity(current_user.id, 'event_registration', f'Registered for event: {event.title}')
    
    return redirect(url_for('student.volunteer_history'))



@student_bp.route('/cancel_registration/<int:registration_id>')
@login_required
@role_required('student')
def cancel_registration(registration_id):
    registration = EventRegistration.query.get_or_404(registration_id)
    
    # Check if registration belongs to student
    if registration.student_id != current_user.student.id:
        abort(403)
    
    # Check if event starts in more than 24 hours
    if (registration.event.date_time - datetime.utcnow()) <= timedelta(hours=24):
        flash('Cannot cancel registration within 24 hours of event start', 'danger')
        return redirect(url_for('student.volunteer_history'))
    
    # Update event slots - Immediate cancellation
    registration.attendance_status = 'cancelled'
    
    # Decrement slots filled
    if registration.event.slots_filled > 0:
        registration.event.slots_filled -= 1
        
    db.session.commit()
    
    flash('Registration cancelled successfully.', 'success')
    log_activity(current_user.id, 'event_registration', f'Cancelled registration for event: {registration.event.title}')
    
    return redirect(url_for('student.volunteer_history'))

@student_bp.route('/volunteer_history')
@login_required
@role_required('student')
def volunteer_history():
    student = current_user.student
    
    # Get upcoming events (exclude cancelled)
    upcoming = EventRegistration.query.join(Event).filter(
        EventRegistration.student_id == student.id,
        EventRegistration.attendance_status.in_(['pending', 'confirmed', 'cancellation_requested']),
        Event.date_time > datetime.utcnow(),
        Event.status == 'active'
    ).order_by(Event.date_time).all()
    
    # Get completed events
    completed = EventRegistration.query.join(Event).filter(
        EventRegistration.student_id == student.id,
        EventRegistration.is_verified == True,
        EventRegistration.attendance_status == 'present'
    ).order_by(Event.date_time.desc()).all()
    
    # Get cancelled events
    cancelled = EventRegistration.query.join(Event).filter(
        EventRegistration.student_id == student.id,
        EventRegistration.attendance_status == 'cancelled'
    ).order_by(Event.date_time.desc()).all()
    
    # Get certificates
    certificates = Certificate.query.filter_by(
        student_id=student.id
    ).join(EventRegistration).join(Event).order_by(
        Certificate.issue_date.desc()
    ).all()
    
    # Calculate totals
    total_hours = 0.0
    for reg in completed:
        try:
            total_hours += float(reg.hours_earned) if reg.hours_earned else 0.0
        except (TypeError, ValueError):
            pass
    
    certificate_count = len(certificates)
    
    # Get unique organizations
    organizations = set()
    for reg in completed:
        if reg.event and reg.event.organization:
            organizations.add(reg.event.organization.organization_name)
    
    return render_template('student/volunteer_history.html',
                         upcoming=upcoming,
                         completed=completed,
                         cancelled=cancelled,
                         certificates=certificates,
                         total_hours=total_hours,
                         certificate_count=certificate_count,
                         organizations=organizations)

@student_bp.route('/generate_report', methods=['GET', 'POST'])
@login_required
@role_required('student')
def generate_report():
    student = current_user.student
    
    # Get all verified registrations
    all_registrations = EventRegistration.query.filter_by(
        student_id=student.id,
        is_verified=True,
        attendance_status='present'
    ).join(Event).order_by(Event.date_time).all()
    
    if request.method == 'POST':
        # Get selected registration IDs
        selected_ids = request.form.getlist('registration_ids')
        if not selected_ids:
            flash('Please select at least one event to include in the report.', 'warning')
            return redirect(url_for('student.generate_report'))
            
        # Filter registrations
        selected_ids = [int(id) for id in selected_ids]
        registrations = [reg for reg in all_registrations if reg.id in selected_ids]
        
        # Calculate total hours for selected events
        total_hours = 0.0
        for reg in registrations:
            try:
                total_hours += float(reg.hours_earned) if reg.hours_earned else 0.0
            except (TypeError, ValueError):
                pass
                
        # Generate PDF Report
        try:
            pdf_path = ReportGenerator.generate_summary_report(student, registrations, total_hours)
            return send_file(pdf_path, as_attachment=True, download_name=f"Volunteer_Report_{student.user.username}.pdf")
        except Exception as e:
            flash(f'Error generating report: {str(e)}', 'danger')
            return redirect(url_for('student.generate_report'))
            
    # GET: Render options page
    return render_template('student/report_options.html', registrations=all_registrations)

@student_bp.route('/activity_logs')
@login_required
@role_required('student')
def activity_logs():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    activity_type = request.args.get('activity_type', '')
    per_page = 20
    
    query = ActivityLog.query.filter_by(user_id=current_user.id)
    
    if search:
        query = query.filter(
            (ActivityLog.description.contains(search)) |
            (ActivityLog.ip_address.contains(search))
        )
        
    if activity_type:
        query = query.filter(ActivityLog.activity_type == activity_type)
    
    logs = query.order_by(
        ActivityLog.timestamp.desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get unique activity types for filter
    activity_types = db.session.query(ActivityLog.activity_type)\
        .filter_by(user_id=current_user.id)\
        .distinct().order_by(ActivityLog.activity_type).all()
    activity_types = [t[0] for t in activity_types]
    
    return render_template('student/activity_logs.html', 
                         logs=logs,
                         search=search,
                         activity_type=activity_type,
                         activity_types=activity_types)

@student_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@role_required('student')
def profile():
    student = current_user.student
    form = StudentProfileForm()
    
    if form.validate_on_submit():
        # Update basic info
        if 'first_name' in request.form:
            student.first_name = request.form['first_name']
        if 'surname' in request.form:
            student.surname = request.form['surname']
        
        student.school = form.school.data
            
        student.bio = form.bio.data
        if form.bio.data:
            student.bio = form.bio.data
            
        # Handle skills - join list to string
        if form.skills.data:
            student.skills = ", ".join(form.skills.data)
        
        # Handle profile picture upload
        if form.profile_picture.data:
            profile_path = save_uploaded_file(form.profile_picture.data, 'profile_pictures')
            if profile_path:
                student.profile_picture = profile_path
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        log_activity(current_user.id, 'profile', 'Updated student profile')
        
        return redirect(url_for('student.profile'))
    
    # Pre-populate form
    form.school.data = student.school
    form.bio.data = student.bio
    # Handle skills - split string to list
    if student.skills:
        form.skills.data = student.skills.split(", ")
    
    # Get last login time (you can implement this if needed)
    last_login = None
    
    # Calculate statistics
    stats = calculate_student_stats(student.id)
    
    return render_template('student/profile.html', form=form, student=student, last_login=last_login, stats=stats)

@student_bp.route('/change_password', methods=['POST'])
@login_required
@role_required('student')
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'danger')
        return redirect(url_for('student.profile'))
        
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('student.profile'))
        
    if len(new_password) < 8:
        flash('Password must be at least 8 characters', 'danger')
        return redirect(url_for('student.profile'))
        
    if not current_user.check_password(current_password):
        flash('Incorrect current password', 'danger')
        return redirect(url_for('student.profile'))
        
    current_user.set_password(new_password)
    db.session.commit()
    flash('Password updated successfully', 'success')
    return redirect(url_for('student.profile'))

@student_bp.route('/download_certificate/<int:certificate_id>')
@login_required
@role_required('student')
def download_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    
    # Check if certificate belongs to student
    if certificate.student_id != current_user.student.id:
        abort(403)
    
    if not certificate.pdf_path:
        flash('Certificate file not found', 'danger')
        return redirect(url_for('student.volunteer_history'))
    
    # Convert relative path to absolute path
    import os
    from flask import current_app
    abs_path = os.path.join(current_app.root_path, certificate.pdf_path)
    
    if not os.path.exists(abs_path):
        flash('Certificate file not found on server', 'danger')
        return redirect(url_for('student.volunteer_history'))
    
    return send_file(abs_path, as_attachment=True, download_name=f"certificate_{certificate.certificate_number}.pdf")

@student_bp.route('/request_deletion', methods=['POST'])
@login_required
@role_required('student')
def request_deletion():
    reason = request.form.get('reason')
    
    # Update user status
    current_user.deletion_requested = True
    current_user.deletion_reason = reason
    db.session.commit()
    
    # Notify all admins
    admins = User.query.filter_by(role='admin').all()
    for admin in admins:
        notification = Notification(
            user_id=admin.id,
            title='Account Deletion Request',
            message=f'Student {current_user.student.first_name} {current_user.student.surname} ({current_user.username}) requested account deletion.\nReason: {reason}',
            notification_type='admin_alert',
            link=url_for('admin.user_management', role='student', search=current_user.username)
        )
        db.session.add(notification)
    
    db.session.commit()
    
    flash('Deletion request submitted. An admin will review your request.', 'info')
    return redirect(url_for('student.profile'))


# Additional helper routes if needed
@student_bp.route('/mark_notification_read/<int:notification_id>')
@login_required
@role_required('student')
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        abort(403)
    
    notification.is_read = True
    db.session.commit()
    
    return redirect(request.referrer or url_for('student.dashboard'))

@organization_bp.route('/mark_notification_read/<int:notification_id>')
@login_required
@role_required('organization')
def org_mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        abort(403)
    
    notification.is_read = True
    db.session.commit()
    
    return redirect(request.referrer or url_for('organization.dashboard'))

@admin_bp.route('/mark_notification_read/<int:notification_id>')
@login_required
@role_required('admin')
def admin_mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        abort(403)
    
    notification.is_read = True
    db.session.commit()
    
    return redirect(request.referrer or url_for('admin.dashboard'))
