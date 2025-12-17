"""
Database models for the Secure Notes Application.

Uses SQLAlchemy ORM to prevent SQL injection attacks.
All queries are parameterized automatically by SQLAlchemy.
This addresses OWASP A03:2021 - Injection vulnerabilities.
"""

from datetime import datetime, timezone
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy - will be bound to app in __init__.py
db = SQLAlchemy()


class User(UserMixin, db.Model):
    """
    User model for authentication.
    
    Security considerations:
    - Password is stored as bcrypt hash, never plaintext
    - UserMixin provides Flask-Login integration
    - ID is used for session, not username (prevents enumeration)
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # bcrypt hash
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)  # For account deactivation
    
    # Relationship to notes - cascade delete for data cleanup
    notes = db.relationship('Note', backref='author', lazy='dynamic',
                           cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def update_last_login(self):
        """Update the last login timestamp."""
        self.last_login = datetime.now(timezone.utc)
        db.session.commit()


class Note(db.Model):
    """
    Note model for user content.
    
    Security considerations:
    - user_id foreign key ensures ownership (prevents IDOR)
    - Content is sanitized before storage (XSS prevention)
    - Content is encrypted at rest using AES-GCM (confidentiality)
    - All access must check user_id matches current user
    """
    __tablename__ = 'notes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    
    # Legacy content field (for backward compatibility with unencrypted notes)
    content = db.Column(db.Text, nullable=True)
    
    # Encryption fields
    content_encrypted = db.Column(db.Boolean, default=False, nullable=False)
    content_ciphertext = db.Column(db.Text, nullable=True)  # Encrypted content (base64)
    content_nonce = db.Column(db.String(24), nullable=True)  # Nonce (12 bytes -> 16 chars base64)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Foreign key to user - this is crucial for IDOR protection
    # Every note belongs to exactly one user
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __repr__(self):
        return f'<Note {self.id}: {self.title[:20]}>'
    
    def is_owner(self, user):
        """
        Check if user is the owner of this note.
        This is the key function for preventing IDOR attacks.
        
        OWASP A01:2021 - Broken Access Control
        """
        if user is None:
            return False
        return self.user_id == user.id
    
    def get_decrypted_content(self):
        """
        Get the decrypted content of the note.
        
        Returns:
            str: Decrypted plain text content
            
        Raises:
            ValueError: If decryption fails or encryption is not configured
        """
        if not self.content_encrypted:
            # Legacy unencrypted note
            return self.content or ''
        
        if not self.content_ciphertext or not self.content_nonce:
            raise ValueError("Note is marked as encrypted but missing ciphertext or nonce")
        
        try:
            from app.crypto import decrypt_note_content
            return decrypt_note_content(self.content_ciphertext, self.content_nonce)
        except Exception as e:
            raise ValueError(f"Failed to decrypt note content: {str(e)}")
    
    def set_encrypted_content(self, plaintext: str):
        """
        Encrypt and store note content.
        
        Args:
            plaintext: Plain text content to encrypt and store
        """
        try:
            from app.crypto import encrypt_note_content
            ciphertext_b64, nonce_b64 = encrypt_note_content(plaintext)
            
            self.content_ciphertext = ciphertext_b64
            self.content_nonce = nonce_b64
            self.content_encrypted = True
            # Clear legacy content field for security
            self.content = None
        except Exception as e:
            raise ValueError(f"Failed to encrypt note content: {str(e)}")


def init_db(app):
    """
    Initialize the database with the Flask app.
    Creates all tables if they don't exist.
    """
    db.init_app(app)
    with app.app_context():
        db.create_all()

