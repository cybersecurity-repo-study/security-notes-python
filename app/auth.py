"""
Authentication helpers for the Secure Notes Application.

Handles password hashing and verification using bcrypt.
bcrypt is chosen because:
- Built-in salt generation
- Configurable work factor (cost)
- Resistant to rainbow table attacks
- Industry standard (OWASP recommended)

Reference: OWASP A07:2021 - Identification and Authentication Failures
"""

import bcrypt
from flask import current_app


def hash_password(password):
    """
    Hash a password using bcrypt with salt.
    
    Args:
        password: Plain text password from user
        
    Returns:
        Hashed password string (safe to store in database)
    
    The salt is automatically generated and embedded in the hash.
    Work factor is configurable via BCRYPT_LOG_ROUNDS in config.
    """
    # Get rounds from config, default to 12 if not set
    rounds = current_app.config.get('BCRYPT_LOG_ROUNDS', 12)
    
    # bcrypt needs bytes, not string
    password_bytes = password.encode('utf-8')
    
    # Generate salt and hash in one step
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    
    # Return as string for database storage
    return hashed.decode('utf-8')


def verify_password(password, hashed_password):
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password to check
        hashed_password: bcrypt hash from database
        
    Returns:
        True if password matches, False otherwise
    
    Note: bcrypt.checkpw handles salt extraction automatically.
    This function uses constant-time comparison to prevent timing attacks.
    """
    try:
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        
        # bcrypt.checkpw does constant-time comparison internally
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        # If anything goes wrong, fail closed (deny access)
        # This prevents oracle attacks on malformed hashes
        return False


def is_password_strong(password):
    """
    Check if password meets minimum strength requirements.
    
    Requirements (OWASP guidelines):
    - At least 8 characters
    - Contains uppercase letter
    - Contains lowercase letter
    - Contains digit
    - Contains special character
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
    
    if not has_upper:
        return False, "Password must contain at least one uppercase letter"
    if not has_lower:
        return False, "Password must contain at least one lowercase letter"
    if not has_digit:
        return False, "Password must contain at least one digit"
    if not has_special:
        return False, "Password must contain at least one special character"
    
    return True, None


# Simple rate limiting helper (basic implementation)
# In production, you'd use Redis or similar for distributed rate limiting
# Tracks attempts by both username and IP address
_login_attempts = {
    'by_username': {},
    'by_ip': {}
}

def check_rate_limit(username, client_ip=None, max_attempts=5, window_seconds=300):
    """
    Rate limiting for login attempts by username and IP address.
    
    Helps prevent brute force attacks (OWASP A07:2021).
    Checks both username-based and IP-based limits.
    
    Args:
        username: Username attempting login
        client_ip: IP address of the client (optional)
        max_attempts: Maximum attempts allowed in window
        window_seconds: Time window in seconds
        
    Returns:
        Tuple of (allowed: bool, reason: str)
        - (True, None) if allowed
        - (False, reason) if blocked, reason indicates why (username or IP)
    
    Note: This is a simple in-memory implementation.
    For production, use Redis or a database-backed solution.
    """
    import time
    
    current_time = time.time()
    config = current_app.config
    
    # Get config values with defaults
    max_attempts = config.get('RATE_LIMIT_MAX_ATTEMPTS', max_attempts)
    window_seconds = config.get('RATE_LIMIT_WINDOW_SECONDS', window_seconds)
    per_ip_enabled = config.get('RATE_LIMIT_PER_IP', True)
    
    # Check username-based rate limit
    if username not in _login_attempts['by_username']:
        _login_attempts['by_username'][username] = []
    
    # Clean old attempts outside the window
    _login_attempts['by_username'][username] = [
        t for t in _login_attempts['by_username'][username]
        if current_time - t < window_seconds
    ]
    
    # Check if over limit for username
    if len(_login_attempts['by_username'][username]) >= max_attempts:
        # Log rate limit exceeded by username
        try:
            from app.audit_log import log_security_event
            log_security_event(
                'RATE_LIMIT_EXCEEDED',
                {'limit_type': 'username', 'username': username},
                username=username,
                ip=client_ip
            )
        except:
            pass  # Don't fail if audit logging is not available
        return False, 'username'
    
    # Check IP-based rate limit if enabled and IP provided
    if per_ip_enabled and client_ip:
        if client_ip not in _login_attempts['by_ip']:
            _login_attempts['by_ip'][client_ip] = []
        
        # Clean old attempts outside the window
        _login_attempts['by_ip'][client_ip] = [
            t for t in _login_attempts['by_ip'][client_ip]
            if current_time - t < window_seconds
        ]
        
        # Check if over limit for IP
        if len(_login_attempts['by_ip'][client_ip]) >= max_attempts:
            # Log rate limit exceeded by IP
            try:
                from app.audit_log import log_security_event
                log_security_event(
                    'RATE_LIMIT_EXCEEDED',
                    {'limit_type': 'ip', 'ip': client_ip},
                    username=username,
                    ip=client_ip
                )
            except:
                pass  # Don't fail if audit logging is not available
            return False, 'ip'
    
    return True, None  # OK to proceed


def record_login_attempt(username, client_ip=None):
    """
    Record a failed login attempt for rate limiting.
    
    Args:
        username: Username that failed login
        client_ip: IP address of the client (optional)
    """
    import time
    
    current_time = time.time()
    config = current_app.config
    per_ip_enabled = config.get('RATE_LIMIT_PER_IP', True)
    
    # Record by username
    if username not in _login_attempts['by_username']:
        _login_attempts['by_username'][username] = []
    _login_attempts['by_username'][username].append(current_time)
    
    # Record by IP if enabled
    if per_ip_enabled and client_ip:
        if client_ip not in _login_attempts['by_ip']:
            _login_attempts['by_ip'][client_ip] = []
        _login_attempts['by_ip'][client_ip].append(current_time)


def clear_login_attempts(username, client_ip=None):
    """
    Clear login attempts after successful login.
    
    Args:
        username: Username that successfully logged in
        client_ip: IP address of the client (optional)
    """
    if username in _login_attempts['by_username']:
        del _login_attempts['by_username'][username]
    
    if client_ip and client_ip in _login_attempts['by_ip']:
        del _login_attempts['by_ip'][client_ip]

