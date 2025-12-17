"""
Flask Application Factory for Secure Notes Application.

This module creates and configures the Flask application instance.
Uses the factory pattern for better testing and configuration management.

Security configurations applied here:
- Session security settings
- HTTP security headers
- CSRF protection initialization
- Login manager setup
"""

import os
import time
import logging
from flask import Flask, session, g, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import get_config
from app.models import db, Note, User

# Initialize extensions (will be bound to app in create_app)
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_class=None):
    """
    Application factory function.
    
    Args:
        config_class: Configuration class to use (optional)
        
    Returns:
        Configured Flask application instance
    """
    # Create Flask app
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    
    # Load configuration
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)
    
    # Ensure instance folder exists and fix database path
    instance_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    
    # Override relative SQLite path with absolute path
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if db_uri == 'sqlite:///instance/secure_notes.db':
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{instance_path}/secure_notes.db'
    
    # Initialize database
    from app.models import db, init_db
    db.init_app(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Initialize CSRF protection
    # This automatically protects all forms
    csrf.init_app(app)
    
    # Configure login manager
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Session security - regenerate session on login (done in Flask-Login)
    # Additional session configuration
    login_manager.session_protection = 'strong'  # Prevents session fixation
    
    # User loader callback for Flask-Login
    from app.models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login session management."""
        return db.session.get(User, int(user_id))
    
    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)
    
    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        """
        Add security headers to every response.
        
        These headers provide additional security against various attacks.
        Reference: OWASP Secure Headers Project
        """
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Enable XSS filter in older browsers
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy - don't leak full URL
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy - restrict resource loading
        # This is a basic CSP - adjust based on your needs
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "  # unsafe-inline for basic styling
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        )
        response.headers['Content-Security-Policy'] = csp
        
        # Permissions Policy (formerly Feature Policy)
        response.headers['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=()'
        )
        
        return response
    
    # Session timeout handling
    @app.before_request
    def make_session_permanent():
        """
        Make sessions permanent but with a timeout.
        This allows PERMANENT_SESSION_LIFETIME to be enforced.
        """
        session.permanent = True
    
    # Record request start time for response time calculation
    @app.before_request
    def record_start_time():
        """Record request start time for access logging."""
        g.start_time = time.time()
    
    # Security monitoring: log querystring and detect attacks
    @app.before_request
    def security_monitoring():
        """
        Monitor requests for security threats:
        - Log querystring parameters
        - Detect SQL injection attempts
        - Detect XSS attempts
        """
        from app.audit_log import (
            log_querystring, 
            check_request_for_attacks, 
            log_security_event,
            get_client_ip
        )
        from flask_login import current_user
        
        # Log querystring if present
        log_querystring()
        
        # Check for attacks
        attack_results = check_request_for_attacks()
        
        # Get user info for logging
        username = None
        if current_user.is_authenticated:
            username = current_user.username
        ip = get_client_ip()
        
        # Log SQL injection attempts
        if attack_results['sql_injection']['found']:
            for location in attack_results['sql_injection']['locations']:
                log_security_event(
                    'SQL_INJECTION_ATTEMPT',
                    {
                        'location_type': location['type'],
                        'parameter': location['parameter'],
                        'value': location['value'],
                        'patterns': ', '.join(location['patterns']),
                        'path': request.path,
                        'method': request.method
                    },
                    username=username,
                    ip=ip
                )
        
        # Log XSS attempts
        if attack_results['xss']['found']:
            for location in attack_results['xss']['locations']:
                log_security_event(
                    'XSS_ATTEMPT',
                    {
                        'location_type': location['type'],
                        'parameter': location['parameter'],
                        'value': location['value'],
                        'patterns': ', '.join(location['patterns']),
                        'path': request.path,
                        'method': request.method
                    },
                    username=username,
                    ip=ip
                )
    
    # Enhanced access logging
    @app.after_request
    def log_access_request(response):
        """
        Log HTTP access with enhanced details.
        Replaces default Werkzeug logger with more detailed logging.
        """
        from app.audit_log import log_access
        log_access(response)
        return response
    
    # Disable default Werkzeug logger if access logging is enabled
    if app.config.get('ACCESS_LOG_ENABLED', True):
        # Suppress Werkzeug's default request logging
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.ERROR)  # Only show errors, not access logs
    
    return app


# For running directly with `flask run`
app = create_app()


if __name__ == '__main__':
    # Only for local development - use gunicorn in production
    # Debug mode should be controlled via configuration / env vars,
    # not hard-coded, to avoid accidental insecure deployments.
    app.run(host='127.0.0.1', port=5001, debug=os.environ.get('FLASK_ENV') == 'development')

