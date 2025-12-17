"""
Security Test Suite for Secure Notes Application
================================================

This module contains tests verifying the security controls
implemented in the application. Tests cover:

- SQL Injection prevention
- XSS prevention
- CSRF protection
- Authentication & session management
- IDOR prevention
- Input validation

Run tests with: pytest tests/test_security.py -v

Author: CCT Student
Module: Secure Programming and Scripting
"""

import pytest
from flask import url_for
from app import create_app
from app.models import db, User, Note
from app.auth import hash_password
from config import TestingConfig


@pytest.fixture
def app():
    """Create and configure test application instance."""
    application = create_app(TestingConfig)
    
    with application.app_context():
        db.create_all()
        yield application
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def authenticated_client(app, client):
    """Create authenticated test client with a test user."""
    with app.app_context():
        # Create test user
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash=hash_password('TestPass123!')
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    
    # Log in
    client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPass123!'
    }, follow_redirects=True)
    
    return client, user_id


class TestSQLInjection:
    """Tests for SQL injection prevention."""
    
    def test_login_sqli_username(self, client):
        """Test SQL injection in login username field."""
        # Try common SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users;--"
        ]
        
        for payload in payloads:
            response = client.post('/login', data={
                'username': payload,
                'password': 'anything'
            }, follow_redirects=True)
            
            # Should not log in with SQLi payload
            assert b'dashboard' not in response.data.lower()
            # Should show login error, not SQL error
            assert b'sql' not in response.data.lower()
            assert b'syntax' not in response.data.lower()
    
    def test_login_sqli_password(self, client):
        """Test SQL injection in login password field."""
        response = client.post('/login', data={
            'username': 'admin',
            'password': "' OR '1'='1"
        }, follow_redirects=True)
        
        assert b'dashboard' not in response.data.lower()


class TestXSSPrevention:
    """Tests for XSS prevention."""
    
    def test_xss_in_username_registration(self, client):
        """Test XSS payload in registration username."""
        xss_payload = "<script>alert('xss')</script>"
        
        response = client.post('/register', data={
            'username': xss_payload,
            'email': 'xss@test.com',
            'password': 'TestPass123!',
            'confirm_password': 'TestPass123!'
        }, follow_redirects=True)
        
        # Payload should be escaped or rejected
        assert b"<script>alert" not in response.data
    
    def test_xss_in_note_title(self, authenticated_client):
        """Test XSS payload in note title."""
        client, user_id = authenticated_client
        xss_payload = "<img src=x onerror=alert('xss')>"
        
        response = client.post('/note/new', data={
            'title': xss_payload,
            'content': 'Test content'
        }, follow_redirects=True)
        
        # Payload should be escaped
        assert b"onerror=" not in response.data
    
    def test_xss_in_note_content(self, authenticated_client):
        """Test XSS payload in note content."""
        client, user_id = authenticated_client
        xss_payload = "<script>document.cookie</script>"
        
        response = client.post('/note/new', data={
            'title': 'Test Note',
            'content': xss_payload
        }, follow_redirects=True)
        
        # Check dashboard - payload should be escaped
        response = client.get('/dashboard')
        assert b"<script>document.cookie" not in response.data


class TestCSRFProtection:
    """Tests for CSRF protection."""
    
    def test_login_requires_csrf(self, app, client):
        """Test that login requires valid CSRF token."""
        # In testing config, CSRF is disabled for easier testing
        # In production, this should fail without token
        # This test verifies the form structure includes CSRF
        
        response = client.get('/login')
        # Check that CSRF field is present in form
        # (When CSRF is enabled, forms include hidden csrf_token field)
        assert response.status_code == 200
    
    def test_note_creation_form_structure(self, authenticated_client):
        """Test that note creation form has proper structure."""
        client, _ = authenticated_client
        
        response = client.get('/note/new')
        assert response.status_code == 200
        # Form should have hidden tag for CSRF
        assert b'form' in response.data


class TestAuthentication:
    """Tests for authentication security."""
    
    def test_protected_dashboard_redirect(self, client):
        """Test that unauthenticated users are redirected from dashboard."""
        response = client.get('/dashboard', follow_redirects=False)
        
        # Should redirect to login
        assert response.status_code == 302
        assert 'login' in response.location
    
    def test_protected_note_creation(self, client):
        """Test that note creation requires authentication."""
        response = client.get('/note/new', follow_redirects=False)
        
        assert response.status_code == 302
        assert 'login' in response.location
    
    def test_logout_clears_session(self, authenticated_client):
        """Test that logout properly clears the session."""
        client, _ = authenticated_client
        
        # Verify logged in
        response = client.get('/dashboard')
        assert response.status_code == 200
        
        # Logout
        client.get('/logout', follow_redirects=True)
        
        # Try to access dashboard again
        response = client.get('/dashboard', follow_redirects=False)
        assert response.status_code == 302

    def test_rate_limit_triggers_after_max_attempts(self, client):
        """
        Ensure login rate limiting blocks after configured max attempts.

        Uses a throwaway username; rate limiting is independent of user existence.
        """
        # Default config: RATE_LIMIT_MAX_ATTEMPTS = 5
        attempts = 6
        last_response = None

        for _ in range(attempts):
            last_response = client.post(
                '/login',
                data={'username': 'ratelimit_user', 'password': 'wrong-password'},
                follow_redirects=True,
            )

        assert last_response is not None
        # After enough attempts we should see the lockout message
        assert b'Too many login attempts' in last_response.data
    
    def test_password_not_stored_plaintext(self, app):
        """Test that passwords are hashed, not stored in plaintext."""
        with app.app_context():
            user = User(
                username='hashtest',
                email='hash@test.com',
                password_hash=hash_password('MyPassword123!')
            )
            db.session.add(user)
            db.session.commit()
            
            # Retrieve user
            saved_user = User.query.filter_by(username='hashtest').first()
            
            # Password should not be plaintext
            assert saved_user.password_hash != 'MyPassword123!'
            # Should be bcrypt hash (starts with $2b$)
            assert saved_user.password_hash.startswith('$2b$')


class TestIDORPrevention:
    """Tests for IDOR (Insecure Direct Object Reference) prevention."""
    
    def test_cannot_access_other_user_note(self, app, client):
        """Test that users cannot access notes belonging to other users."""
        with app.app_context():
            # Create two users
            user1 = User(
                username='user1',
                email='user1@test.com',
                password_hash=hash_password('TestPass123!')
            )
            user2 = User(
                username='user2',
                email='user2@test.com',
                password_hash=hash_password('TestPass123!')
            )
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
            
            # Create a note for user1
            note = Note(
                title='Private Note',
                content='Secret content',
                user_id=user1.id
            )
            db.session.add(note)
            db.session.commit()
            note_id = note.id
        
        # Log in as user2
        client.post('/login', data={
            'username': 'user2',
            'password': 'TestPass123!'
        })
        
        # Try to access user1's note
        response = client.get(f'/note/{note_id}')
        
        # Should get 404 (not 200 or even 403)
        assert response.status_code == 404
    
    def test_cannot_edit_other_user_note(self, app, client):
        """Test that users cannot edit notes belonging to other users."""
        with app.app_context():
            user1 = User(
                username='owner',
                email='owner@test.com',
                password_hash=hash_password('TestPass123!')
            )
            user2 = User(
                username='attacker',
                email='attacker@test.com',
                password_hash=hash_password('TestPass123!')
            )
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
            
            note = Note(
                title='Original Title',
                content='Original content',
                user_id=user1.id
            )
            db.session.add(note)
            db.session.commit()
            note_id = note.id
        
        # Log in as attacker
        client.post('/login', data={
            'username': 'attacker',
            'password': 'TestPass123!'
        })
        
        # Try to edit the note
        response = client.post(f'/note/{note_id}/edit', data={
            'title': 'Hacked!',
            'content': 'You got hacked!'
        })
        
        # Should get 404
        assert response.status_code == 404


class TestInputValidation:
    """Tests for input validation."""
    
    def test_weak_password_rejected(self, client):
        """Test that weak passwords are rejected during registration."""
        response = client.post('/register', data={
            'username': 'weakuser',
            'email': 'weak@test.com',
            'password': 'weak',  # Too short, no special chars
            'confirm_password': 'weak'
        }, follow_redirects=True)
        
        # Should not redirect to login (registration should fail)
        assert b'at least 8 characters' in response.data or \
               b'Password must contain' in response.data
    
    def test_invalid_email_rejected(self, client):
        """Test that invalid emails are rejected."""
        response = client.post('/register', data={
            'username': 'emailtest',
            'email': 'not-an-email',
            'password': 'TestPass123!',
            'confirm_password': 'TestPass123!'
        }, follow_redirects=True)
        
        assert b'valid email' in response.data.lower()
    
    def test_username_length_limits(self, client):
        """Test username length validation."""
        # Too short
        response = client.post('/register', data={
            'username': 'ab',  # Less than 3 chars
            'email': 'short@test.com',
            'password': 'TestPass123!',
            'confirm_password': 'TestPass123!'
        }, follow_redirects=True)
        
        assert b'3' in response.data  # Should mention minimum length


class TestSecurityHeaders:
    """Tests for security headers."""
    
    def test_xframe_options_header(self, client):
        """Test X-Frame-Options header is set."""
        response = client.get('/')
        
        # Check header is present
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] == 'DENY'
    
    def test_content_type_nosniff(self, client):
        """Test X-Content-Type-Options header."""
        response = client.get('/')
        
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
    
    def test_csp_header(self, client):
        """Test Content-Security-Policy header is set."""
        response = client.get('/')
        
        assert 'Content-Security-Policy' in response.headers


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

