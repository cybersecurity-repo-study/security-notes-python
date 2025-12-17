# Secure Notes Application - Dockerfile
# Production-oriented image using Gunicorn

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user and app directory
ENV APP_USER=secnotes \
    APP_HOME=/app

RUN groupadd --system ${APP_USER} \
    && useradd --system --create-home --gid ${APP_USER} ${APP_USER}

WORKDIR ${APP_HOME}

# Install system dependencies needed by cryptography, bcrypt, etc.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies separately for better layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app ./app
COPY templates ./templates
COPY static ./static
COPY config.py ./config.py
COPY run.py ./run.py
COPY scripts ./scripts

# Runtime directories
RUN mkdir -p instance logs \
    && chown -R ${APP_USER}:${APP_USER} ${APP_HOME}

USER ${APP_USER}

# Environment defaults (override in real deployments)
ENV FLASK_ENV=production \
    SQLALCHEMY_DATABASE_URI="sqlite:///instance/secure_notes.db"

EXPOSE 8000

# Gunicorn entrypoint; bind to 0.0.0.0:8000
# In production, you may want to tune workers/threads via env vars
CMD ["gunicorn", "app:create_app()", "--bind", "0.0.0.0:8000", "--workers", "3"]
