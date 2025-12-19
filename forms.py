from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, FloatField, SelectField, DateField, TimeField, BooleanField, SelectMultipleField, widgets
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional
from wtforms.fields import DateTimeLocalField
from flask_wtf.file import FileField, FileAllowed
import re

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Code')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class StudentRegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    surname = StringField('Surname', validators=[DataRequired(), Length(max=100)])
    school = StringField('School/University', validators=[DataRequired(), Length(max=200)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

class OrganizationRegistrationForm(FlaskForm):
    organization_name = StringField('Organization Name', validators=[DataRequired(), Length(max=200)])
    email = StringField('Organization Email', validators=[DataRequired(), Email(), Length(max=120)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=64, message='Username must be between 3 and 64 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(), 
        Length(max=120, message='Email must not exceed 120 characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    
    def validate_password(self, field):
        password = field.data
        errors = []
        
        # Check for uppercase letter
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        
        # Check for lowercase letter
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        
        # Check for number
        if not re.search(r'\d', password):
            errors.append('Password must contain at least one number')
        
        # Check for special character
        if not re.search(r'[!@#$%^&*]', password):
            errors.append('Password must contain at least one special character (!@#$%^&*)')
        
        if errors:
            raise ValidationError(' '.join(errors))

class CreateOpportunityForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    category_id = SelectField('Category', coerce=int, validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    start_time = TimeField('Start Time', validators=[DataRequired()])
    end_time = TimeField('End Time', validators=[DataRequired()])
    # duration_hours is calculated from start/end time
    slots_available = IntegerField('Available Slots', validators=[DataRequired()])
    skill_requirements = SelectMultipleField('Skill Requirements', choices=[
        ('Event Planning', 'Event Planning'),
        ('Teaching/Tutoring', 'Teaching/Tutoring'),
        ('First Aid/CPR', 'First Aid/CPR'),
        ('Cooking/Baking', 'Cooking/Baking'),
        ('Technical Support', 'Technical Support'),
        ('Art & Design', 'Art & Design'),
        ('Public Speaking', 'Public Speaking'),
        ('Physical Labor', 'Physical Labor'),
        ('Administrative', 'Administrative'),
        ('Social Media', 'Social Media'),
        ('Environment/Gardening', 'Environment/Gardening')
    ], option_widget=widgets.CheckboxInput(), widget=widgets.ListWidget(prefix_label=False))
    location = StringField('Location', validators=[Length(max=200)])
    
    def validate_slots_available(self, field):
        if field.data <= 0:
            raise ValidationError('Available slots must be greater than 0')

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')

class StudentProfileForm(FlaskForm):
    school = StringField('School/University', validators=[Length(max=200)])
    bio = TextAreaField('Bio')
    profile_picture = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')
    ])
    skills = SelectMultipleField('Skills', choices=[
        ('Event Planning', 'Event Planning'),
        ('Teaching/Tutoring', 'Teaching/Tutoring'),
        ('First Aid/CPR', 'First Aid/CPR'),
        ('Cooking/Baking', 'Cooking/Baking'),
        ('Technical Support', 'Technical Support'),
        ('Art & Design', 'Art & Design'),
        ('Public Speaking', 'Public Speaking'),
        ('Physical Labor', 'Physical Labor'),
        ('Administrative', 'Administrative'),
        ('Social Media', 'Social Media'),
        ('Environment/Gardening', 'Environment/Gardening')
    ], option_widget=widgets.CheckboxInput(), widget=widgets.ListWidget(prefix_label=False))

class OrganizationProfileForm(FlaskForm):
    organization_name = StringField('Organization Name', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description')
    about_us = TextAreaField('About Us')
    
    # New Contact Fields
    contact_person = StringField('Contact Person', validators=[Length(max=100)])
    contact_phone = StringField('Phone Number', validators=[Length(max=20)])
    contact_email = StringField('Contact Email', validators=[Length(max=120), Optional(), Email()])
    
    logo = FileField('Logo', validators=[
        FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')
    ])
    digital_signature = FileField('Digital Signature', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'svg'], 'Images only!')
    ])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[
        EqualTo('new_password', message='Passwords must match')
    ])

class AdminSettingsForm(FlaskForm):
    first_name = StringField('First Name', validators=[Length(max=100)])
    surname = StringField('Surname', validators=[Length(max=100)])
    phone_number = StringField('Phone Number', validators=[Length(max=20)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[
        EqualTo('new_password', message='Passwords must match')
    ])

class VerificationForm(FlaskForm):
    attendance = BooleanField('Present')
    hours_earned = FloatField('Hours Earned', validators=[Optional()])

class SearchForm(FlaskForm):
    search = StringField('Search', validators=[Optional()])
    category = SelectField('Category', coerce=int, validators=[Optional()])
    start_date = DateField('Start Date', validators=[Optional()])
    end_date = DateField('End Date', validators=[Optional()])
