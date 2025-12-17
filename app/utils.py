"""
Security utility functions for the Secure Notes Application.

Provides input sanitization and output encoding helpers.
These functions help prevent XSS attacks (OWASP A03:2021).
"""

import re
import bleach
from markupsafe import escape, Markup


# Allowed HTML tags for note content (if we want to allow some formatting)
# Being very restrictive here - only basic formatting allowed
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
ALLOWED_ATTRIBUTES = {}  # No attributes allowed - prevents onclick, onerror, etc.


def sanitize_input(text):
    """
    Sanitize user input to prevent XSS attacks.
    
    Uses bleach to strip dangerous HTML tags and attributes.
    This should be called BEFORE storing data in the database.
    
    Args:
        text: User-provided text input
        
    Returns:
        Sanitized text safe for storage and display
    
    Note: Jinja2 also auto-escapes on output, so this provides defense in depth.
    """
    if text is None:
        return None
    
    # First, use bleach to clean the HTML
    # This removes script tags, event handlers, etc.
    cleaned = bleach.clean(
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True  # Remove disallowed tags entirely
    )
    
    return cleaned


def sanitize_strict(text):
    """
    Strictly sanitize input - remove ALL HTML.
    
    Use this for fields that should never contain HTML,
    like usernames, email addresses, etc.
    """
    if text is None:
        return None
    
    # Remove all HTML tags
    cleaned = bleach.clean(text, tags=[], strip=True)
    
    # Also strip any remaining angle brackets just to be safe
    cleaned = cleaned.replace('<', '').replace('>', '')
    
    return cleaned.strip()


def escape_output(text):
    """
    Escape text for safe HTML output.
    
    This is mainly for manual escaping when needed.
    Jinja2 does this automatically with {{ variable }}.
    
    Args:
        text: Text to escape
        
    Returns:
        HTML-escaped text (Markup object)
    """
    if text is None:
        return ''
    
    return escape(text)


def validate_username(username):
    """
    Validate username format.
    
    Rules:
    - 3-30 characters
    - Alphanumeric and underscores only
    - Must start with a letter
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 30:
        return False, "Username must be at most 30 characters"
    
    # Only allow alphanumeric and underscore, must start with letter
    pattern = r'^[a-zA-Z][a-zA-Z0-9_]*$'
    if not re.match(pattern, username):
        return False, "Username must start with a letter and contain only letters, numbers, and underscores"
    
    return True, None


def validate_email(email):
    """
    Basic email validation.
    
    Note: This is a simple check. For production, consider
    using a library like email-validator or sending confirmation email.
    """
    if not email:
        return False, "Email is required"
    
    # Basic email pattern - not perfect but catches obvious issues
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Please enter a valid email address"
    
    if len(email) > 120:
        return False, "Email is too long"
    
    return True, None


def validate_note_title(title):
    """Validate note title."""
    if not title:
        return False, "Title is required"
    
    if len(title) > 200:
        return False, "Title must be at most 200 characters"
    
    # Sanitize the title
    sanitized = sanitize_strict(title)
    if len(sanitized) < 1:
        return False, "Title cannot be empty after sanitization"
    
    return True, None


def generate_csrf_token():
    """
    Generate a CSRF token.
    
    Note: Flask-WTF handles this automatically, but this is here
    as a backup/reference implementation.
    """
    import secrets
    return secrets.token_hex(32)


def is_safe_redirect_url(target):
    """
    Check if a redirect URL is safe (same origin).
    
    Prevents open redirect vulnerabilities (CWE-601).
    Only allows relative URLs or URLs to the same host.
    """
    from urllib.parse import urlparse, urljoin
    from flask import request
    
    if not target:
        return False
    
    # Get the base URL
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    
    # Only allow same scheme and netloc (host)
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_safe_redirect(target, fallback='/dashboard'):
    """
    Get a safe redirect URL, falling back to default if unsafe.
    """
    if target and is_safe_redirect_url(target):
        return target
    return fallback

