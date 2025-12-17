## Author

College: CCT College Dublin Student  
Name: William
Module: Secure Programming and Scripting  
Academic Year: 2025/2026


# Secure Notes Application

A secure web application demonstrating best practices in web application security for the **Secure Programming and Scripting** module at CCT College Dublin.

## Overview

This project implements a secure notes application with user authentication, allowing users to create, read, update, and delete personal notes. The application demonstrates protection against common web vulnerabilities as outlined in the OWASP Top 10.

## Features

- User registration and authentication
- Secure password storage using bcrypt
- CRUD operations for personal notes
- Protection against common vulnerabilities:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Insecure Direct Object References (IDOR)
  - Session hijacking

## Technology Stack

- **Backend**: Flask 3.0+ (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login
- **Forms & CSRF**: Flask-WTF
- **Password Hashing**: bcrypt
- **Input Sanitization**: bleach
- **Production Server**: Gunicorn + Nginx

## Project Structure

```
SPS-CA2/
├── app/
│   ├── __init__.py          # Flask app factory, security headers
│   ├── models.py            # Database models (User, Note)
│   ├── routes.py            # Application routes with security controls
│   ├── forms.py             # WTForms with CSRF protection
│   ├── auth.py              # Password hashing, rate limiting
│   └── utils.py             # Input sanitization, validation helpers
├── templates/               # Jinja2 templates with auto-escaping
├── static/                  # CSS and static assets
├── Dockerfile               # Production Docker image (Gunicorn, non-root user)
├── .dockerignore            # Files/directories excluded from Docker build context
├── scripts/
│   ├── fuzzer.py              # Security testing script (DAST)
│   └── deployment_pipeline.sh # Security deployment pipeline (Semgrep + Docker)
├── .github/
│   └── workflows/
│       └── deploy-security-analysis.yml # CI/CD pipeline with security analysis
├── tests/                   # Security-focused unit tests
├── instance/                # SQLite database (gitignored)
├── config.py                # Configuration management
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Setup Steps

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd SPS-CA2
   ```

2. **Create virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment** (optional)

   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Run the application**

   ```bash
   # Development mode
   flask run --port 5001

   # Or directly with Python
   python -m app
   ```

6. **Access the application**
   Open your browser and navigate to: `http://localhost:5001`

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html --cov-report=term
# Coverage HTML report will be in htmlcov/ directory
```

## Cleaning Project Artifacts

To remove caches, test artifacts, logs, and reports:

```bash
# Make the script executable (first time only)
chmod +x scripts/clean_project.sh

# Run the cleanup script
./scripts/clean_project.sh
```

This script removes:

- Python cache files (`__pycache__`, `*.pyc`, `*.pyo`)
- Test artifacts (`.pytest_cache`, `.coverage`, `htmlcov/`, `.tox/`, `.hypothesis/`)
- Virtual environments (`venv/`, `.venv/`, etc.)
- Log files (`logs/*.log`, `*.log`)
- Reports directory contents (`reports/*`)
- Build artifacts (`build/`, `dist/`, `*.egg-info/`)
- IDE cache files (`.idea/`, `.vscode/`, `.cursor/`)
- Temporary and OS files

**Note**: Database files in `instance/` and `.env` files are **NOT** removed for safety.

## Security Fuzzing

The project includes a security fuzzing script that tests for common vulnerabilities:

```bash
# Make sure the app is running first
flask run &

# Run the fuzzer
python scripts/fuzzer.py --url http://localhost:5001 --output reports/security_report.txt

# With verbose output
python scripts/fuzzer.py --url http://localhost:5001 --verbose
```

The fuzzer tests for:

- SQL Injection payloads
- XSS (reflected and stored)
- Path traversal
- IDOR vulnerabilities
- CSRF protection
- Authentication bypass

## Security Deployment Pipeline (Semgrep + Docker)

The project includes a \"security deployment pipeline\" script that runs Semgrep SAST checks and then performs a **real Docker build** (with optional push/run) when all checks pass. Docker and a running Docker daemon are required for this pipeline.

```bash
# Make the pipeline script executable
chmod +x scripts/deployment_pipeline.sh

# Build and scan for a given environment (ENVIRONMENT can be dev, staging, prod, etc.)
ENVIRONMENT=dev ./scripts/deployment_pipeline.sh
```

This pipeline performs:

- **Environment checks**:
  - Ensures `python3`/`python`, `semgrep`, and `docker` are installed
  - Verifies the Docker daemon is running (`docker info`)
- **Semgrep SAST** over `app/`, `scripts`, and `tests/` using the `p/python` ruleset
- **Docker image build** from the project `Dockerfile`:
  - Default image name: `secure-notes`
  - Tag derived from `ENVIRONMENT` (e.g. `secure-notes:dev`, `secure-notes:prod`)
- **Optional image push** to a registry if `DOCKER_REGISTRY` is set
- **Optional container run** if `DOCKER_RUN=true`:
  - Stops/removes an existing container for that environment
  - Starts a new container mapping `DOCKER_PORT` (default `8000`) to the container
  - Binds `$(pwd)/instance` to `/app/instance` to persist the SQLite DB

The script **fails with non‑zero exit code** in the following cases:

- Semgrep finds blocking issues
- Required tools (`python3`/`python`, `semgrep`, `docker`) are missing
- Docker build or run fails

### Environment variables for the deployment pipeline

These variables control how Docker images and containers are named, tagged, and deployed:

- `ENVIRONMENT`: logical environment name used for tagging images and containers (e.g. `dev`, `staging`, `prod`).
- `IMAGE_NAME`: Docker image name (default: `secure-notes`).
- `IMAGE_TAG`: image tag override (default: derived from `ENVIRONMENT`).
- `DOCKER_REGISTRY`: optional container registry prefix (`docker.io/user`, `registry.example.com`, etc.).
- `DOCKER_RUN`: if set to `true`, the pipeline starts a container after building the image.
- `DOCKER_PORT`: host port to expose the app on (default: `8000`).

### Example usage

```bash
# Build only (no push, no run)
ENVIRONMENT=dev ./scripts/deployment_pipeline.sh

# Build and run container locally
ENVIRONMENT=dev DOCKER_RUN=true ./scripts/deployment_pipeline.sh

# Build, tag, and push to registry (no run)
ENVIRONMENT=staging DOCKER_REGISTRY=myregistry.com IMAGE_TAG=v1.0.0 ./scripts/deployment_pipeline.sh
```

## CI/CD Pipeline with GitHub Actions

The project includes a comprehensive CI/CD pipeline that automatically runs security analysis and simulates deployment on every push and pull request. The workflow is defined in `.github/workflows/deploy-security-analysis.yml`.

### Workflow Overview

The pipeline consists of 6 jobs that run in parallel and sequence:

1. **SAST Security Analysis** - Static code analysis
2. **Dependency Security Scan** - Vulnerability scanning for Python packages
3. **Test** - Unit tests with coverage
4. **Build Docker & Container Scan** - Docker build and container vulnerability scanning
5. **Simulate Deployment** - Deploy container and run DAST tests
6. **Security Analysis Summary** - Generates summary report

### Trigger Events

The workflow automatically runs on:

- **Push** to `main`, `master`, or `develop` branches
- **Pull requests** targeting `main`, `master`, or `develop` branches
- **Manual trigger** via GitHub Actions UI (`workflow_dispatch`)

### Job Details

#### 1. SAST Security Analysis

Performs static application security testing using two tools:

- **Semgrep**: Scans Python code using `p/python` ruleset for security vulnerabilities

  - Checks for WARNING and ERROR severity issues
  - Scans `app/`, `scripts/`, and `tests/` directories
  - Fails the job if blocking issues are found

- **Bandit**: Python-specific security linter
  - Identifies common security issues in Python code
  - Flags HIGH and MEDIUM severity vulnerabilities
  - Generates JSON reports for artifact storage

**Artifacts**: `semgrep-report.json`, `bandit-report.json`

#### 2. Dependency Security Scan

Scans Python dependencies for known vulnerabilities:

- **Safety**: Checks `requirements.txt` against Safety DB
- **pip-audit**: Alternative dependency vulnerability scanner
  - Uses PyPI Advisory Database
  - Provides comprehensive vulnerability information

**Artifacts**: `safety-report.json`, `pip-audit-report.json`

#### 3. Test

Runs the test suite with coverage reporting:

- Executes all tests in `tests/` directory
- Generates coverage reports (XML and HTML)
- Uses pytest with pytest-cov plugin

**Artifacts**: `coverage-report/` (HTML coverage report)

#### 4. Build Docker & Container Scan

Builds the Docker image and performs container security scanning:

- **Docker Build**: Creates production image using Dockerfile

  - Image tagged with commit SHA: `secure-notes:${{ github.sha }}`
  - Uses GitHub Actions cache for faster builds

- **Trivy Scanner**: Scans the built Docker image for vulnerabilities
  - Checks for CRITICAL and HIGH severity issues
  - Generates SARIF format for GitHub Security tab
  - Uploads results to GitHub Advanced Security

**Artifacts**: `trivy-results.sarif`

#### 5. Simulate Deployment

Simulates a production deployment and runs dynamic security tests:

- **Container Deployment**: Starts the Docker container

  - Runs in production mode (`FLASK_ENV=production`)
  - Exposes application on port 8000
  - Waits for health check to pass

- **Health Check**: Verifies application is responding

  - Tests root endpoint availability
  - Ensures container is running correctly

- **DAST Testing**: Runs security fuzzer against running application

  - Executes `scripts/fuzzer.py` with production URL
  - Tests for SQL injection, XSS, IDOR, CSRF, and authentication bypass
  - Generates security test report

- **Cleanup**: Stops and removes test container

**Artifacts**: `fuzzer-report/security_report.txt`

#### 6. Security Analysis Summary

Generates a summary of all security checks:

- Downloads all security reports
- Creates a summary in GitHub Actions UI
- Provides links to detailed reports

### Pipeline Flow

```
┌─────────────────────┐
│  Code Push/PR       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│  Parallel Jobs (1-3)                    │
│  ├─ SAST Security Analysis              │
│  ├─ Dependency Security Scan            │
│  └─ Test                                │
└──────────┬──────────────────────────────┘
           │
           ▼ (All must pass)
┌─────────────────────────────────────────┐
│  Build Docker & Container Scan          │
└──────────┬──────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│  Simulate Deployment                    │
│  ├─ Start Container                     │
│  ├─ Health Check                        │
│  └─ DAST Testing                        │
└──────────┬──────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│  Security Analysis Summary              │
└─────────────────────────────────────────┘
```

### Accessing Results

1. **GitHub Actions Tab**: View workflow runs and job status

   - Navigate to: `Actions` → `Deploy with Security Analysis`

2. **Artifacts**: Download detailed reports

   - Available for 30 days after workflow completion
   - Click on workflow run → Download artifacts

3. **GitHub Security Tab**: View Trivy scan results

   - Navigate to: `Security` → `Code scanning alerts`
   - Shows container vulnerabilities in SARIF format

4. **Coverage Reports**: View test coverage
   - Download `coverage-report` artifact
   - Open `htmlcov/index.html` in browser

### Workflow Configuration

The workflow uses the following environment variables:

- `PYTHON_VERSION`: Python version (default: `3.11`)
- `DOCKER_IMAGE_NAME`: Docker image name (default: `secure-notes`)
- `DOCKER_IMAGE_TAG`: Image tag (default: `${{ github.sha }}`)

### Failure Behavior

The pipeline fails if:

- Semgrep finds WARNING or ERROR severity issues
- Bandit finds HIGH or MEDIUM severity issues
- Safety detects vulnerable dependencies
- Tests fail
- Docker build fails
- Container health check fails

All security reports are still generated and uploaded as artifacts even if the pipeline fails, allowing you to review issues without re-running the workflow.

### Best Practices

1. **Review Security Reports**: Always check artifacts after each run
2. **Fix Blocking Issues**: Address HIGH/CRITICAL findings before merging
3. **Monitor Dependencies**: Keep dependencies updated to avoid vulnerabilities
4. **Test Coverage**: Maintain high test coverage for security-critical code
5. **Container Scanning**: Review Trivy results in GitHub Security tab

## Docker Deployment

The application includes a production-ready Dockerfile and can be deployed using Docker without running the pipeline script.

### Building the Docker image

```bash
docker build -t secure-notes:latest .
```

### Running with Docker

```bash
# Run container (development-style)
docker run -d \
  --name secure-notes \
  -p 8000:8000 \
  -v "$(pwd)/instance:/app/instance" \
  secure-notes:latest
```

For production, you should inject strong secrets via environment variables or an env-file:

```bash
# Example using an env-file
cat > .env.docker << 'EOF'
FLASK_ENV=production
SECRET_KEY=replace_with_strong_random_hex_value
ENCRYPTION_MASTER_KEY=replace_with_base64_key_from_generate_master_key
EOF

docker run -d \
  --name secure-notes-prod \
  --env-file .env.docker \
  -p 8000:8000 \
  -v "$(pwd)/instance:/app/instance" \
  secure-notes:latest
```

### Environment Variables for Docker Deployment

| Variable          | Description                    | Default                    |
| ----------------- | ------------------------------ | -------------------------- |
| `IMAGE_NAME`      | Docker image name              | `secure-notes`             |
| `IMAGE_TAG`       | Image tag                      | `latest` or `$ENVIRONMENT` |
| `DOCKER_REGISTRY` | Registry for push              | (none)                     |
| `DOCKER_RUN`      | Run container after build      | `false`                    |
| `DOCKER_PORT`     | Host port mapping to container | `8000`                     |

## Production Deployment

For production deployment on Ubuntu:

```bash
# Make the script executable
chmod +x scripts/deploy.sh

# Run as root
sudo ./scripts/deploy.sh
```

This script will:

1. Install required system packages
2. Create a dedicated application user
3. Set up Python virtual environment
4. Configure Gunicorn as WSGI server
5. Configure Nginx as reverse proxy with SSL
6. Set up UFW firewall (ports 22, 80, 443)
7. Generate self-signed SSL certificate
8. Create systemd service for auto-start

## Security Measures Implemented

### 1. SQL Injection Prevention (OWASP A03:2021)

- Uses SQLAlchemy ORM for all database operations
- All queries use parameterized statements
- No raw SQL queries in the codebase

### 2. XSS Prevention (OWASP A03:2021)

- Jinja2 auto-escaping enabled on all templates
- User input sanitized with `bleach` before storage
- Content Security Policy (CSP) headers configured
- HttpOnly flag set on session cookies

### 3. CSRF Protection (OWASP A01:2021)

- Flask-WTF CSRF tokens on all forms
- Tokens validated on every state-changing request
- SameSite cookie attribute set to 'Lax'

### 4. Authentication Security (OWASP A07:2021)

- Passwords hashed with bcrypt (cost factor 12)
- Rate limiting on login attempts (by username and IP address)
- Secure session management with Flask-Login
- Session regeneration on login
- Generic error messages (no user enumeration)
- Audit logging of authentication events

### 5. IDOR Prevention (OWASP A01:2021)

- All resource access checks user ownership
- Returns 404 for unauthorized access (not 403)
- User ID never exposed in URLs unnecessarily

### 6. Security Headers

- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy: Restrictive policy
- Referrer-Policy: strict-origin-when-cross-origin

### 7. Session Security

- HttpOnly cookies (prevent JS access)
- Secure flag enabled in production
- Session timeout (1 hour dev, 30 min prod)
- Session invalidation on logout

### 8. Encryption at Rest

- Note content encrypted using AES-GCM (256-bit)
- Master key stored in environment variable
- Each note encrypted with unique nonce
- Backward compatible with unencrypted notes

### 9. Audit Logging

- Security events logged to `logs/security_audit.log`
- Tracks login attempts, rate limiting, unauthorized access
- Logs note creation, updates, and deletions
- Structured format for easy analysis

## Configuration

### Environment Variables

| Variable                    | Description                                                  | Default                            |
| --------------------------- | ------------------------------------------------------------ | ---------------------------------- |
| `FLASK_ENV`                 | Environment (development/production)                         | development                        |
| `SECRET_KEY`                | Session signing key                                          | (random in dev)                    |
| `DATABASE_URL`              | Database connection string                                   | sqlite:///instance/secure_notes.db |
| `BCRYPT_LOG_ROUNDS`         | bcrypt cost factor                                           | 12                                 |
| `ENCRYPTION_MASTER_KEY`     | Master key for note encryption (32 bytes or 44 chars base64) | (required in production)           |
| `AUDIT_LOG_ENABLED`         | Enable security audit logging                                | True                               |
| `AUDIT_LOG_FILE`            | Path to audit log file                                       | logs/security_audit.log            |
| `RATE_LIMIT_PER_IP`         | Enable IP-based rate limiting                                | True                               |
| `RATE_LIMIT_MAX_ATTEMPTS`   | Maximum login attempts allowed                               | 5                                  |
| `RATE_LIMIT_WINDOW_SECONDS` | Rate limit time window (seconds)                             | 300 (5 minutes)                    |

### Production Checklist

- [ ] Set strong `SECRET_KEY` from environment
- [ ] Set `FLASK_ENV=production`
- [ ] Enable `SESSION_COOKIE_SECURE=True`
- [ ] Set `ENCRYPTION_MASTER_KEY` (generate with: `python -c "from app.crypto import generate_master_key; print(generate_master_key())"`)
- [ ] Use HTTPS (Let's Encrypt recommended)
- [ ] Configure firewall rules
- [ ] Set up log monitoring (review `logs/security_audit.log`)
- [ ] Regular security updates
- [ ] Review audit logs regularly for suspicious activity

## API Endpoints

| Method   | Endpoint            | Description       | Auth Required |
| -------- | ------------------- | ----------------- | ------------- |
| GET      | `/`                 | Home (redirects)  | No            |
| GET/POST | `/register`         | User registration | No            |
| GET/POST | `/login`            | User login        | No            |
| GET      | `/logout`           | User logout       | Yes           |
| GET      | `/dashboard`        | User dashboard    | Yes           |
| GET/POST | `/note/new`         | Create note       | Yes           |
| GET      | `/note/<id>`        | View note         | Yes (owner)   |
| GET/POST | `/note/<id>/edit`   | Edit note         | Yes (owner)   |
| POST     | `/note/<id>/delete` | Delete note       | Yes (owner)   |

## SAST vs DAST Comparison

### Static Application Security Testing (SAST)

- **Tool**: Bandit (for Python)
- **When**: During development, in CI/CD pipeline
- **What**: Analyzes source code without running it
- **Pros**: Early detection, finds code-level issues
- **Cons**: False positives, can't find runtime issues

```bash
# Example Bandit scan
pip install bandit
bandit -r app/ -f html -o reports/bandit_report.html
```

### Dynamic Application Security Testing (DAST)

- **Tool**: Our fuzzer.py, OWASP ZAP
- **When**: Against running application
- **What**: Tests application behavior at runtime
- **Pros**: Finds real exploitable issues
- **Cons**: Requires running app, can miss logic flaws

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [Flask Security](https://flask.palletsprojects.com/en/3.0.x/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## License

This project is created for educational purposes as part of the CCT College Dublin Cybersecurity program.