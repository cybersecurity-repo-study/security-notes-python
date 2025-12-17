"""
Configuration module for the Secure Notes Application.
Separates development and production settings for security.

Security Note: All sensitive values should come from environment variables
in production. Never hardcode secrets in source code (OWASP A02:2021).
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration with security defaults."""
    
    # Secret key for session signing - MUST be set in production
    # Using os.urandom would be better but we need consistency across restarts
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration - SQLite for simplicity
    # In production, you'd want PostgreSQL or MySQL
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///instance/secure_notes.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable for performance
    
    # Session security settings (OWASP Session Management)
    SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Prevent JS access to session cookie
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection for cookies
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # Session timeout
    
    # CSRF protection enabled by default with Flask-WTF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour CSRF token validity
    
    # Password hashing settings
    BCRYPT_LOG_ROUNDS = 12  # Cost factor for bcrypt (higher = slower but more secure)
    
    # Rate limiting settings
    RATE_LIMIT_MAX_ATTEMPTS = 5  # Maximum login attempts allowed
    RATE_LIMIT_WINDOW_SECONDS = 300  # Time window in seconds (5 minutes)
    RATE_LIMIT_PER_IP = True  # Enable IP-based rate limiting
    
    # Audit logging settings
    AUDIT_LOG_ENABLED = True
    AUDIT_LOG_FILE = 'logs/security_audit.log'
    AUDIT_LOG_LEVEL = 'INFO'
    
    # Access logging settings
    ACCESS_LOG_ENABLED = True
    ACCESS_LOG_FILE = 'logs/access.log'
    ACCESS_LOG_LEVEL = 'INFO'
    
    # Encryption settings
    ENCRYPTION_MASTER_KEY = os.environ.get('ENCRYPTION_MASTER_KEY')  # 32 bytes for AES-256


class DevelopmentConfig(Config):
    """Development configuration - less strict for testing."""
    
    DEBUG = True
    TESTING = False
    
    # In dev, we can use a simpler secret key but still should be random
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-not-for-production-123'


class ProductionConfig(Config):
    """Production configuration - maximum security."""
    
    DEBUG = False
    TESTING = False
    
    # These MUST be set via environment variables in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Enforce secure cookies in production
    SESSION_COOKIE_SECURE = True
    
    # Stricter session lifetime in production
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Higher bcrypt rounds for production
    BCRYPT_LOG_ROUNDS = 14


class TestingConfig(Config):
    """Testing configuration for unit tests."""
    
    TESTING = True
    DEBUG = True
    
    # Use in-memory SQLite for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for easier testing (be careful with this)
    WTF_CSRF_ENABLED = False
    
    # Faster hashing for tests
    BCRYPT_LOG_ROUNDS = 4


# Config dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on FLASK_ENV environment variable."""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])

