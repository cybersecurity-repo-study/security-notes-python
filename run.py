#!/usr/bin/env python3
"""
Run script for Secure Notes Application.

This is a convenience script for development.
For production, use gunicorn directly:
    gunicorn 'app:create_app()' --bind 0.0.0.0:8000

Usage:
    python run.py
"""
import os
from app import create_app

if __name__ == '__main__':
    app = create_app()
    
    # Run in development mode
    # In production, set FLASK_ENV=production and use gunicorn
    app.run(
        host='127.0.0.1',  # Only allow localhost connections
        port=5001,
        debug=os.environ.get('FLASK_ENV') == 'development'  # Auto-reload on code changes
    )

