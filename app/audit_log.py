"""
Audit logging module for the Secure Notes Application.

Provides structured logging of security events for compliance and monitoring.
Logs events such as login attempts, rate limiting, unauthorized access, etc.

Reference: OWASP A09:2021 - Security Logging and Monitoring Failures
"""

import os
import re
import logging
import time
from datetime import datetime
from flask import current_app, request, has_request_context, g
from functools import wraps


def setup_audit_logger():
    """
    Set up the audit logger with file handler.
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('security_audit')
    logger.setLevel(logging.INFO)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Get log file path from config
    if has_request_context():
        log_file = current_app.config.get('AUDIT_LOG_FILE', 'logs/security_audit.log')
        log_level = current_app.config.get('AUDIT_LOG_LEVEL', 'INFO')
    else:
        # Fallback for when app context is not available
        log_file = os.environ.get('AUDIT_LOG_FILE', 'logs/security_audit.log')
        log_level = os.environ.get('AUDIT_LOG_LEVEL', 'INFO')
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    return logger


def setup_access_logger():
    """
    Set up the access logger with file handler for HTTP access logs.
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('access')
    logger.setLevel(logging.INFO)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Get log file path from config
    if has_request_context():
        log_file = current_app.config.get('ACCESS_LOG_FILE', 'logs/access.log')
        log_level = current_app.config.get('ACCESS_LOG_LEVEL', 'INFO')
    else:
        # Fallback for when app context is not available
        log_file = os.environ.get('ACCESS_LOG_FILE', 'logs/access.log')
        log_level = os.environ.get('ACCESS_LOG_LEVEL', 'INFO')
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Create formatter - use a simple format for access logs
    formatter = logging.Formatter('%(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    # Also add console handler for development
    if has_request_context() and current_app.config.get('DEBUG', False):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger


def get_client_ip():
    """Get client IP address from request, handling proxy headers."""
    if not has_request_context():
        return 'unknown'
    
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip:
        # X-Forwarded-For can contain multiple IPs, take the first one
        return ip.split(',')[0].strip()
    return request.remote_addr or 'unknown'


# SQL Injection detection patterns
SQL_INJECTION_PATTERNS = [
    r"(\bUNION\b.*\bSELECT\b)",
    r"(\bSELECT\b.*\bFROM\b)",
    r"(\bINSERT\b.*\bINTO\b)",
    r"(\bDELETE\b.*\bFROM\b)",
    r"(\bUPDATE\b.*\bSET\b)",
    r"(\bDROP\b.*\bTABLE\b)",
    r"(\bEXEC\b|\bEXECUTE\b)",
    r"(\bOR\b\s*['\"]?\s*1\s*=\s*1)",
    r"(\bOR\b\s*['\"]?\s*['\"]?\s*=\s*['\"]?)",
    r"('.*OR.*'.*=.*')",
    r"(--|\#|\/\*|\*\/)",
    r"(\bAND\b\s*['\"]?\s*1\s*=\s*1)",
    r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
    r"(;\s*(DROP|DELETE|INSERT|UPDATE|SELECT))",
    r"(\bCONCAT\b|\bCONCAT_WS\b)",
    r"(\bCHAR\b\s*\()",
    r"(\bLOAD_FILE\b|\bINTO\s+OUTFILE\b)",
]


# XSS detection patterns
XSS_PATTERNS = [
    r"<script[^>]*>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onfocus\s*=",
    r"<iframe[^>]*>",
    r"<img[^>]*src\s*=\s*['\"]?javascript:",
    r"<svg[^>]*onload\s*=",
    r"<body[^>]*onload\s*=",
    r"<input[^>]*onfocus\s*=",
    r"<link[^>]*href\s*=\s*['\"]?javascript:",
    r"<style[^>]*>.*expression\s*\(",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"eval\s*\(",
    r"alert\s*\(",
    r"document\.cookie",
    r"document\.write",
    r"window\.location",
    r"String\.fromCharCode",
]


def detect_sql_injection(value):
    """
    Detect SQL injection patterns in a string value.
    
    Args:
        value: String to check
        
    Returns:
        List of matched patterns, or empty list if none found
    """
    if not value or not isinstance(value, str):
        return []
    
    matches = []
    
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            matches.append(pattern)
    
    return matches


def detect_xss(value):
    """
    Detect XSS patterns in a string value.
    
    Args:
        value: String to check
        
    Returns:
        List of matched patterns, or empty list if none found
    """
    if not value or not isinstance(value, str):
        return []
    
    matches = []
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            matches.append(pattern)
    
    return matches


def check_request_for_attacks():
    """
    Check request querystring and form data for SQL injection and XSS attacks.
    
    Returns:
        Dictionary with attack detection results:
        {
            'sql_injection': {'found': bool, 'locations': list},
            'xss': {'found': bool, 'locations': list}
        }
    """
    if not has_request_context():
        return {'sql_injection': {'found': False, 'locations': []},
                'xss': {'found': False, 'locations': []}}
    
    sql_locations = []
    xss_locations = []
    
    # Check querystring parameters
    for key, value in request.args.items():
        if isinstance(value, str):
            sql_matches = detect_sql_injection(value)
            xss_matches = detect_xss(value)
            
            if sql_matches:
                sql_locations.append({
                    'type': 'querystring',
                    'parameter': key,
                    'value': value[:200],  # Truncate for logging
                    'patterns': sql_matches
                })
            
            if xss_matches:
                xss_locations.append({
                    'type': 'querystring',
                    'parameter': key,
                    'value': value[:200],
                    'patterns': xss_matches
                })
    
    # Check form data (POST)
    if request.form:
        for key, value in request.form.items():
            if isinstance(value, str):
                sql_matches = detect_sql_injection(value)
                xss_matches = detect_xss(value)
                
                if sql_matches:
                    sql_locations.append({
                        'type': 'form',
                        'parameter': key,
                        'value': value[:200],
                        'patterns': sql_matches
                    })
                
                if xss_matches:
                    xss_locations.append({
                        'type': 'form',
                        'parameter': key,
                        'value': value[:200],
                        'patterns': xss_matches
                    })
    
    return {
        'sql_injection': {
            'found': len(sql_locations) > 0,
            'locations': sql_locations
        },
        'xss': {
            'found': len(xss_locations) > 0,
            'locations': xss_locations
        }
    }


def log_querystring():
    """
    Log querystring parameters for security monitoring.
    Only logs if querystring is present.
    """
    if not has_request_context():
        return
    
    if not request.args:
        return
    
    logger = setup_audit_logger()
    
    # Get IP and username
    ip = get_client_ip()
    username = None
    try:
        from flask_login import current_user
        if current_user.is_authenticated:
            username = current_user.username
    except:
        pass
    
    # Build querystring representation
    query_params = []
    for key, value in request.args.items():
        # Truncate long values for logging
        value_str = str(value)[:200] if len(str(value)) > 200 else str(value)
        query_params.append(f"{key}={value_str}")
    
    querystring = "&".join(query_params)
    
    # Build log message
    message_parts = [
        "EVENT=QUERYSTRING_ACCESS",
        f"IP={ip}",
        f"PATH={request.path}",
        f"METHOD={request.method}",
        f"QUERYSTRING={querystring}"
    ]
    
    if username:
        message_parts.insert(1, f"USER={username}")
    
    log_message = " | ".join(message_parts)
    logger.info(log_message)


def log_security_event(event_type, details=None, username=None, ip=None):
    """
    Log a security event.
    
    Args:
        event_type: Type of event (e.g., 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'RATE_LIMIT_EXCEEDED')
        details: Dictionary with additional event details
        username: Username associated with the event (if available)
        ip: IP address (if not provided, will try to get from request context)
    
    Event types:
        - LOGIN_SUCCESS: Successful login
        - LOGIN_FAILURE: Failed login attempt
        - LOGIN_LOCKOUT: Account locked due to rate limiting
        - RATE_LIMIT_EXCEEDED: Rate limit exceeded (by username or IP)
        - UNAUTHORIZED_ACCESS: Attempted access to unauthorized resource
        - NOTE_CREATED: Note created
        - NOTE_UPDATED: Note updated
        - NOTE_DELETED: Note deleted
        - USER_REGISTERED: New user registration
        - SQL_INJECTION_ATTEMPT: SQL injection attack detected
        - XSS_ATTEMPT: XSS attack detected
        - QUERYSTRING_ACCESS: Querystring parameters accessed
    """
    if not has_request_context():
        # Try to get config from environment if no app context
        enabled = os.environ.get('AUDIT_LOG_ENABLED', 'True').lower() == 'true'
        if not enabled:
            return
    else:
        enabled = current_app.config.get('AUDIT_LOG_ENABLED', True)
        if not enabled:
            return
    
    logger = setup_audit_logger()
    
    # Get IP if not provided
    if ip is None:
        ip = get_client_ip()
    
    # Build log message
    message_parts = [f"EVENT={event_type}"]
    
    if username:
        message_parts.append(f"USER={username}")
    
    message_parts.append(f"IP={ip}")
    
    if details:
        # Format details as key=value pairs
        detail_str = " | ".join([f"{k}={v}" for k, v in details.items()])
        if detail_str:
            message_parts.append(f"DETAILS={detail_str}")
    
    log_message = " | ".join(message_parts)
    
    # Log at appropriate level
    if event_type in ['LOGIN_LOCKOUT', 'RATE_LIMIT_EXCEEDED', 'UNAUTHORIZED_ACCESS', 
                      'SQL_INJECTION_ATTEMPT', 'XSS_ATTEMPT']:
        logger.warning(log_message)
    else:
        logger.info(log_message)


def audit_log_decorator(event_type):
    """
    Decorator to automatically log function calls as security events.
    
    Usage:
        @audit_log_decorator('NOTE_CREATED')
        def create_note():
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try to get username from current_user if available
            username = None
            try:
                from flask_login import current_user
                if current_user.is_authenticated:
                    username = current_user.username
            except:
                pass
            
            # Call the original function
            result = func(*args, **kwargs)
            
            # Log the event
            log_security_event(event_type, username=username)
            
            return result
        return wrapper
    return decorator


def log_access(response=None):
    """
    Log HTTP access with enhanced details.
    
    Enhanced access log format includes:
    - IP address
    - Timestamp
    - HTTP method
    - Path
    - Query string (if present)
    - HTTP version
    - Status code
    - Response size
    - Response time
    - User agent
    - Referer
    - User (if authenticated)
    
    Args:
        response: Flask response object (optional, for after_request hook)
    """
    if not has_request_context():
        return response
    
    # Check if access logging is enabled
    if has_request_context():
        enabled = current_app.config.get('ACCESS_LOG_ENABLED', True)
    else:
        enabled = os.environ.get('ACCESS_LOG_ENABLED', 'True').lower() == 'true'
    
    if not enabled:
        return response
    
    logger = setup_access_logger()
    
    # Get request start time (set in before_request)
    start_time = getattr(g, 'start_time', None)
    if start_time:
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
    else:
        response_time = 0
    
    # Get client IP
    ip = get_client_ip()
    
    # Get user info
    username = '-'
    try:
        from flask_login import current_user
        if current_user.is_authenticated:
            username = current_user.username
    except:
        pass
    
    # Get request details
    method = request.method
    path = request.path
    query_string = request.query_string.decode('utf-8') if request.query_string else ''
    http_version = request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1')
    
    # Get response details
    if response:
        status_code = response.status_code
        response_size = response.content_length if response.content_length else len(response.get_data())
    else:
        status_code = '-'
        response_size = '-'
    
    # Get user agent
    user_agent = request.headers.get('User-Agent', '-')
    # Truncate long user agents
    if len(user_agent) > 150:
        user_agent = user_agent[:147] + '...'
    
    # Get referer
    referer = request.headers.get('Referer', '-')
    if referer != '-' and len(referer) > 100:
        referer = referer[:97] + '...'
    
    # Build query string part
    if query_string:
        if len(query_string) > 200:
            query_string = query_string[:197] + '...'
        path_with_query = f"{path}?{query_string}"
    else:
        path_with_query = path
    
    # Format: IP - USER [TIMESTAMP] "METHOD PATH?QUERY HTTP/VERSION" STATUS SIZE RESPONSE_TIME "REFERER" "USER_AGENT"
    # Similar to Apache/Nginx combined log format but with enhancements
    timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S')
    
    log_parts = [
        ip,
        username,
        f'[{timestamp}]',
        f'"{method} {path_with_query} {http_version}"',
        str(status_code),
        str(response_size) if response_size != '-' else '-',
        f'{response_time:.2f}ms' if response_time > 0 else '-',
        f'"{referer}"',
        f'"{user_agent}"'
    ]
    
    log_message = ' '.join(log_parts)
    
    # Log at appropriate level based on status code
    if response and status_code >= 500:
        logger.error(log_message)
    elif response and status_code >= 400:
        logger.warning(log_message)
    else:
        logger.info(log_message)
    
    return response
