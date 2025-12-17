"""
Encryption module for the Secure Notes Application.

Provides AES-GCM encryption for note content at rest.
Uses authenticated encryption to ensure both confidentiality and integrity.

Reference: OWASP Cryptographic Storage Cheat Sheet
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from flask import current_app, has_app_context


def get_master_key():
    """
    Get the master encryption key from configuration.
    
    Returns:
        bytes: Master key (32 bytes for AES-256)
        
    Raises:
        ValueError: If master key is not configured or invalid
    """
    if has_app_context():
        key_str = current_app.config.get('ENCRYPTION_MASTER_KEY')
    else:
        key_str = os.environ.get('ENCRYPTION_MASTER_KEY')
    
    if not key_str:
        raise ValueError(
            "ENCRYPTION_MASTER_KEY not configured. "
            "Set it in environment variables or config."
        )
    
    # Key can be provided as base64 or raw string
    # Try to decode as base64 first, if that fails, use as-is
    try:
        # If it's base64, decode it
        if len(key_str) == 44:  # Base64 encoded 32 bytes = 44 chars
            key_bytes = base64.b64decode(key_str)
        else:
            # Use as raw string, pad or truncate to 32 bytes
            key_bytes = key_str.encode('utf-8')[:32].ljust(32, b'\0')
    except:
        # Fallback: use string as-is, pad to 32 bytes
        key_bytes = key_str.encode('utf-8')[:32].ljust(32, b'\0')
    
    if len(key_bytes) != 32:
        raise ValueError("ENCRYPTION_MASTER_KEY must be 32 bytes (or 44 chars base64)")
    
    return key_bytes


def encrypt_note_content(content: str, master_key: bytes = None) -> tuple[str, str]:
    """
    Encrypt note content using AES-GCM.
    
    Args:
        content: Plain text content to encrypt
        master_key: Master encryption key (if None, will be fetched from config)
        
    Returns:
        Tuple of (ciphertext_base64, nonce_base64)
        - ciphertext_base64: Encrypted content encoded as base64
        - nonce_base64: Nonce (12 bytes) encoded as base64
        
    Raises:
        ValueError: If master key is not available
    """
    if master_key is None:
        master_key = get_master_key()
    
    # Generate a random nonce (12 bytes for AES-GCM)
    nonce = os.urandom(12)
    
    # Create AESGCM cipher
    aesgcm = AESGCM(master_key)
    
    # Encrypt the content
    # AESGCM.encrypt(nonce, data, associated_data)
    # We use empty associated_data for simplicity
    ciphertext = aesgcm.encrypt(nonce, content.encode('utf-8'), None)
    
    # Encode both as base64 for storage
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    
    return ciphertext_b64, nonce_b64


def decrypt_note_content(ciphertext_base64: str, nonce_base64: str, master_key: bytes = None) -> str:
    """
    Decrypt note content using AES-GCM.
    
    Args:
        ciphertext_base64: Encrypted content encoded as base64
        nonce_base64: Nonce (12 bytes) encoded as base64
        master_key: Master encryption key (if None, will be fetched from config)
        
    Returns:
        str: Decrypted plain text content
        
    Raises:
        ValueError: If decryption fails (invalid key, corrupted data, etc.)
    """
    if master_key is None:
        master_key = get_master_key()
    
    try:
        # Decode from base64
        ciphertext = base64.b64decode(ciphertext_base64)
        nonce = base64.b64decode(nonce_base64)
        
        # Create AESGCM cipher
        aesgcm = AESGCM(master_key)
        
        # Decrypt the content
        # AESGCM.decrypt(nonce, data, associated_data)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Decode to string
        return plaintext_bytes.decode('utf-8')
    
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


def generate_master_key() -> str:
    """
    Generate a new master key for encryption.
    
    Returns:
        str: Base64-encoded master key (44 characters)
        
    Usage:
        key = generate_master_key()
        # Store this in ENCRYPTION_MASTER_KEY environment variable
    """
    key_bytes = os.urandom(32)  # 32 bytes for AES-256
    return base64.b64encode(key_bytes).decode('utf-8')
