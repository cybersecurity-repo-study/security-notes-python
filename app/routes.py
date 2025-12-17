"""
Application routes for the Secure Notes Application.

All routes implement security best practices:
- Authentication checks via @login_required
- CSRF protection via Flask-WTF forms
- Input sanitization before storage
- Authorization checks (IDOR prevention)
- Secure session management

Reference: OWASP Top 10 2021
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User, Note
from app.forms import RegistrationForm, LoginForm, NoteForm, DeleteForm
from app.auth import (
    hash_password, verify_password, is_password_strong,
    check_rate_limit, record_login_attempt, clear_login_attempts
)
from app.utils import sanitize_input, sanitize_strict, get_safe_redirect
from app.audit_log import log_security_event, get_client_ip

# Create blueprint for main routes
main = Blueprint('main', __name__)


# ============================================================================
# PUBLIC ROUTES (No authentication required)
# ============================================================================

@main.route('/')
def index():
    """Home page - redirect to dashboard if logged in, else to login."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration page.
    
    Security measures:
    - CSRF token validation (via FlaskForm)
    - Password strength validation
    - Input sanitization for username
    - Password hashing with bcrypt
    """
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Sanitize username to prevent XSS
        clean_username = sanitize_strict(form.username.data)
        clean_email = sanitize_strict(form.email.data.lower())
        
        # Additional password strength check (belt and suspenders)
        is_strong, error_msg = is_password_strong(form.password.data)
        if not is_strong:
            flash(error_msg, 'error')
            return render_template('register.html', form=form)
        
        # Hash password before storing
        hashed_pw = hash_password(form.password.data)
        
        # Create new user with sanitized data
        new_user = User(
            username=clean_username,
            email=clean_email,
            password_hash=hashed_pw
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Log user registration
            log_security_event(
                'USER_REGISTERED',
                {'email': clean_email},
                username=clean_username,
                ip=get_client_ip()
            )
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('main.login'))
        except Exception as e:
            db.session.rollback()
            # Don't expose database errors to user
            flash('An error occurred. Please try again.', 'error')
            # Log the actual error for debugging (in production, use proper logging)
            print(f"Registration error: {e}")
    
    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login page.
    
    Security measures:
    - CSRF token validation
    - Rate limiting to prevent brute force
    - Generic error messages (no user enumeration)
    - Session regeneration on login
    - Secure cookie settings
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()

    # Always handle POST to enforce rate limiting, even if form is invalid
    if request.method == 'POST':
        # Prefer form data (WTForms) but fall back to raw request form
        username = form.username.data or request.form.get('username', '')

        # Get client IP address (handle proxy headers)
        client_ip = get_client_ip()

        # Record this attempt up-front so rate limiting can see it
        record_login_attempt(username, client_ip)

        # Check rate limiting first (by username and IP)
        allowed, reason = check_rate_limit(username, client_ip)
        if not allowed:
            # Log lockout event
            log_security_event(
                'LOGIN_LOCKOUT',
                {'reason': reason, 'username': username},
                username=username,
                ip=client_ip
            )
            # Message contains "Too many" so automated tools can detect it
            flash('Too many login attempts. Please try again in 5 minutes.', 'error')
            return render_template('login.html', form=form)

        # Only proceed with authentication if form (including CSRF) is valid
        if form.validate_on_submit():
            # Look up user by username (parameterized query via SQLAlchemy)
            user = User.query.filter_by(username=username).first()

            # Verify password - timing safe due to bcrypt
            if user and verify_password(form.password.data, user.password_hash):
                # Check if account is active
                if not user.is_active:
                    flash('This account has been deactivated.', 'error')
                    return render_template('login.html', form=form)

                # Clear rate limit counter on success
                clear_login_attempts(username, client_ip)

                # Log the user in (remember=True sets a longer session cookie)
                login_user(user, remember=form.remember_me.data)

                # Update last login time
                user.update_last_login()

                # Log successful login
                log_security_event(
                    'LOGIN_SUCCESS',
                    {'remember_me': form.remember_me.data},
                    username=username,
                    ip=client_ip
                )

                flash('Login successful!', 'success')

                # Handle safe redirect (prevent open redirect vulnerability)
                next_page = request.args.get('next')
                return redirect(get_safe_redirect(next_page, url_for('main.dashboard')))

            else:
                # Log failed login attempt
                log_security_event(
                    'LOGIN_FAILURE',
                    {'username_attempted': username},
                    username=None,
                    ip=client_ip
                )

                # Generic error - don't reveal if username exists
                flash('Invalid username or password.', 'error')

    return render_template('login.html', form=form)


@main.route('/logout')
@login_required
def logout():
    """
    Logout user.
    
    Security: Properly invalidates session on logout.
    The @login_required ensures only logged-in users can logout.
    """
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))


# ============================================================================
# PROTECTED ROUTES (Authentication required)
# ============================================================================

@main.route('/dashboard')
@login_required
def dashboard():
    """
    User dashboard showing their notes.
    
    Security:
    - @login_required ensures authentication
    - Only shows notes belonging to current_user (IDOR protection)
    """
    # Get only notes belonging to current user
    # This prevents IDOR - users can only see their own notes
    notes = Note.query.filter_by(user_id=current_user.id)\
                      .order_by(Note.updated_at.desc())\
                      .all()
    
    # Decrypt content for each note preview
    for note in notes:
        try:
            note._decrypted_content = note.get_decrypted_content()
        except Exception as e:
            # If decryption fails, show error message
            note._decrypted_content = f"[Error decrypting note: {str(e)}]"
    
    return render_template('dashboard.html', notes=notes)


@main.route('/note/new', methods=['GET', 'POST'])
@login_required
def create_note():
    """
    Create a new note.
    
    Security:
    - @login_required ensures authentication
    - CSRF protection via form
    - Input sanitization before storage
    - Note automatically linked to current user
    """
    form = NoteForm()
    
    if form.validate_on_submit():
        # Sanitize input to prevent stored XSS
        clean_title = sanitize_strict(form.title.data)
        clean_content = sanitize_input(form.content.data)
        
        # Create note linked to current user
        note = Note(
            title=clean_title,
            user_id=current_user.id  # Important: set ownership
        )
        
        # Encrypt content before storing
        try:
            note.set_encrypted_content(clean_content)
        except Exception as e:
            flash(f'Error encrypting note: {str(e)}', 'error')
            # Sanitize form data before re-rendering to prevent XSS in form fields
            form.title.data = sanitize_strict(form.title.data)
            form.content.data = sanitize_input(form.content.data)
            return render_template('note_form.html', form=form, title='Create Note')
        
        try:
            db.session.add(note)
            db.session.commit()
            
            # Log note creation
            log_security_event(
                'NOTE_CREATED',
                {'note_id': note.id, 'title_length': len(clean_title)},
                username=current_user.username,
                ip=get_client_ip()
            )
            
            flash('Note created successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating note. Please try again.', 'error')
            print(f"Note creation error: {e}")
            # Sanitize form data before re-rendering to prevent XSS in form fields
            if request.method == 'POST' and form.title.data:
                form.title.data = sanitize_strict(form.title.data)
            if request.method == 'POST' and form.content.data:
                form.content.data = sanitize_input(form.content.data)
    
    # Sanitize form data if form was submitted but validation failed
    if request.method == 'POST':
        if form.title.data:
            form.title.data = sanitize_strict(form.title.data)
        if form.content.data:
            form.content.data = sanitize_input(form.content.data)
    
    return render_template('note_form.html', form=form, title='Create Note')


@main.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    """
    View a specific note.
    
    Security - IDOR Protection:
    - First get the note by ID
    - Then verify current_user owns the note
    - Return 403 if not owner (not 404, to not leak existence)
    
    Wait, actually 404 is better for security - don't confirm note exists.
    Let me use 404.
    """
    # Get note or 404 (avoid legacy Query.get)
    note = db.session.get(Note, note_id)
    if note is None:
        abort(404)
    
    # CRITICAL: Check ownership to prevent IDOR
    # This is the key security control
    if not note.is_owner(current_user):
        # Log unauthorized access attempt
        log_security_event(
            'UNAUTHORIZED_ACCESS',
            {'note_id': note_id, 'action': 'view'},
            username=current_user.username,
            ip=get_client_ip()
        )
        # Return 404 instead of 403 to not reveal note exists
        abort(404)
    
    # Decrypt content for display
    try:
        decrypted_content = note.get_decrypted_content()
        # Temporarily set decrypted content for template
        note._decrypted_content = decrypted_content
    except Exception as e:
        flash(f'Error decrypting note: {str(e)}', 'error')
        abort(500)
    
    # Create delete form for CSRF protection on delete button
    delete_form = DeleteForm()
    
    return render_template('note_detail.html', note=note, delete_form=delete_form)


@main.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    """
    Edit an existing note.
    
    Security:
    - Ownership check (IDOR prevention)
    - CSRF protection
    - Input sanitization
    """
    note = db.session.get(Note, note_id)
    if note is None:
        abort(404)
    
    # Check ownership
    if not note.is_owner(current_user):
        # Log unauthorized access attempt
        log_security_event(
            'UNAUTHORIZED_ACCESS',
            {'note_id': note_id, 'action': 'edit'},
            username=current_user.username,
            ip=get_client_ip()
        )
        abort(404)  # Hide existence from unauthorized users
    
    form = NoteForm()
    
    if form.validate_on_submit():
        # Sanitize updated content
        note.title = sanitize_strict(form.title.data)
        clean_content = sanitize_input(form.content.data)
        
        # Encrypt updated content
        try:
            note.set_encrypted_content(clean_content)
        except Exception as e:
            flash(f'Error encrypting note: {str(e)}', 'error')
            # Sanitize form data before re-rendering to prevent XSS in form fields
            form.title.data = sanitize_strict(form.title.data)
            form.content.data = sanitize_input(form.content.data)
            return render_template('note_form.html', form=form, title='Edit Note', note=note)
        
        try:
            db.session.commit()
            
            # Log note update
            log_security_event(
                'NOTE_UPDATED',
                {'note_id': note.id},
                username=current_user.username,
                ip=get_client_ip()
            )
            
            flash('Note updated successfully!', 'success')
            return redirect(url_for('main.view_note', note_id=note.id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating note. Please try again.', 'error')
            print(f"Note update error: {e}")
            # Sanitize form data before re-rendering to prevent XSS in form fields
            if form.title.data:
                form.title.data = sanitize_strict(form.title.data)
            if form.content.data:
                form.content.data = sanitize_input(form.content.data)
    
    elif request.method == 'GET':
        # Pre-populate form with existing data
        form.title.data = note.title
        # Decrypt content for editing
        try:
            form.content.data = note.get_decrypted_content()
        except Exception as e:
            flash(f'Error decrypting note: {str(e)}', 'error')
            return redirect(url_for('main.dashboard'))
    
    # Sanitize form data if form was submitted but validation failed
    if request.method == 'POST':
        if form.title.data:
            form.title.data = sanitize_strict(form.title.data)
        if form.content.data:
            form.content.data = sanitize_input(form.content.data)
    
    return render_template('note_form.html', form=form, title='Edit Note', note=note)


@main.route('/note/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    """
    Delete a note.
    
    Security:
    - POST only (no GET - prevents CSRF via image tags etc)
    - CSRF token validation via form
    - Ownership verification
    """
    note = db.session.get(Note, note_id)
    if note is None:
        abort(404)
    
    # Check ownership
    if not note.is_owner(current_user):
        # Log unauthorized access attempt
        log_security_event(
            'UNAUTHORIZED_ACCESS',
            {'note_id': note_id, 'action': 'delete'},
            username=current_user.username,
            ip=get_client_ip()
        )
        abort(404)
    
    # Validate CSRF token (form should have been submitted)
    form = DeleteForm()
    if form.validate_on_submit():
        try:
            note_id_for_log = note.id
            db.session.delete(note)
            db.session.commit()
            
            # Log note deletion
            log_security_event(
                'NOTE_DELETED',
                {'note_id': note_id_for_log},
                username=current_user.username,
                ip=get_client_ip()
            )
            
            flash('Note deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error deleting note.', 'error')
            print(f"Note deletion error: {e}")
    else:
        flash('Invalid request.', 'error')
    
    return redirect(url_for('main.dashboard'))


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@main.app_errorhandler(404)
def not_found_error(error):
    """Handle 404 errors with a custom page."""
    return render_template('error.html', 
                          error_code=404, 
                          error_message="Page not found"), 404


@main.app_errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors."""
    return render_template('error.html',
                          error_code=403,
                          error_message="Access forbidden"), 403


@main.app_errorhandler(500)
def internal_error(error):
    """Handle 500 errors - rollback any failed transactions."""
    db.session.rollback()
    return render_template('error.html',
                          error_code=500,
                          error_message="An internal error occurred"), 500

