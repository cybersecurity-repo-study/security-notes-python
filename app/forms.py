"""
WTForms definitions for the Secure Notes Application.

All forms include CSRF protection automatically via Flask-WTF.
This prevents Cross-Site Request Forgery attacks (OWASP A01:2021).

How CSRF protection works:
1. Flask-WTF generates a unique token for each session
2. Token is embedded in forms as a hidden field
3. On submission, token is validated against session
4. If mismatch, request is rejected
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from app.models import User


class RegistrationForm(FlaskForm):
    """
    User registration form with validation.
    
    Security features:
    - CSRF token (automatic from FlaskForm)
    - Input length limits
    - Email format validation
    - Password confirmation
    - Custom password strength validation
    """
    
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=30, message="Username must be 3-30 characters")
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address"),
        Length(max=120, message="Email is too long")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])
    
    submit = SubmitField('Register')
    
    def validate_username(self, field):
        """Check if username is already taken."""
        # Use filter_by instead of raw SQL - prevents injection
        user = User.query.filter_by(username=field.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose another.')
    
    def validate_email(self, field):
        """Check if email is already registered."""
        user = User.query.filter_by(email=field.data).first()
        if user:
            raise ValidationError('Email already registered. Please use another or login.')
    
    def validate_password(self, field):
        """
        Custom password strength validation.
        Checks for complexity requirements.
        """
        password = field.data
        
        errors = []
        
        if not any(c.isupper() for c in password):
            errors.append("one uppercase letter")
        if not any(c.islower() for c in password):
            errors.append("one lowercase letter")
        if not any(c.isdigit() for c in password):
            errors.append("one digit")
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            errors.append("one special character (!@#$%^&*...)")
        
        if errors:
            raise ValidationError(f"Password must contain at least: {', '.join(errors)}")


class LoginForm(FlaskForm):
    """
    User login form.
    
    Security features:
    - CSRF protection
    - No indication of which field is wrong (prevents enumeration)
    - Remember me option with secure cookie
    """
    
    username = StringField('Username', validators=[
        DataRequired(message="Username is required")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])
    
    remember_me = BooleanField('Remember Me')
    
    submit = SubmitField('Login')


class NoteForm(FlaskForm):
    """
    Form for creating and editing notes.
    
    Security features:
    - CSRF protection
    - Input length limits (DoS prevention)
    - Content will be sanitized before storage (in routes)
    """
    
    title = StringField('Title', validators=[
        DataRequired(message="Title is required"),
        Length(min=1, max=200, message="Title must be 1-200 characters")
    ])
    
    content = TextAreaField('Content', validators=[
        DataRequired(message="Content is required"),
        Length(min=1, max=10000, message="Content must be 1-10000 characters")
    ])
    
    submit = SubmitField('Save Note')


class DeleteForm(FlaskForm):
    """
    Simple form for delete confirmation.
    Mainly exists to provide CSRF protection on delete actions.
    """
    submit = SubmitField('Delete')


class ChangePasswordForm(FlaskForm):
    """
    Form for changing user password.
    Requires current password to prevent unauthorized changes.
    """
    
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Current password is required")
    ])
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required"),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Please confirm your new password"),
        EqualTo('new_password', message="Passwords must match")
    ])
    
    submit = SubmitField('Change Password')
    
    def validate_new_password(self, field):
        """Password strength validation for new password."""
        password = field.data
        
        errors = []
        
        if not any(c.isupper() for c in password):
            errors.append("one uppercase letter")
        if not any(c.islower() for c in password):
            errors.append("one lowercase letter")
        if not any(c.isdigit() for c in password):
            errors.append("one digit")
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            errors.append("one special character")
        
        if errors:
            raise ValidationError(f"Password must contain: {', '.join(errors)}")

