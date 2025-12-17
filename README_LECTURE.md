## Secure Notes – Quick classroom guide

**Dr. Shree Krishna Acharya**

This guide is for quickly bringing the project up during a lecture/lab on a machine that already has the code.

---

## 1. Simplest option (local development – no Docker)

Assumption: you already have the project folder on the machine (for example at `~/SPS-CA2`).

### 1.1. Go to the project directory

```bash
cd /path/to/SPS-CA2
```

### 1.2. Create and activate a virtualenv

```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 1.3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 1.4. Minimal environment configuration (optional for demo)

```bash
cp .env.example .env
# Optionally edit .env with SECRET_KEY, ENCRYPTION_MASTER_KEY, etc.
```

### 1.5. Run the application

```bash
flask run --port 5001
```

Or:

```bash
python -m app
```

### 1.6. Open in the browser

Go to: `http://localhost:5001`

---

## 2. Recommended in class: simple Docker (no pipeline)

Requires **Docker** installed and the daemon running.

### 2.1. Build the image

```bash
docker build -t secure-notes:latest .
```

### 2.2. Run a demo container

```bash
docker run -d \
  --name secure-notes-demo \
  -p 8000:8000 \
  -v "$(pwd)/instance:/app/instance" \
  secure-notes:latest
```

Then open: `http://localhost:8000`

To stop/remove:

```bash
docker stop secure-notes-demo
docker rm secure-notes-demo
```

---

## 3. “Security story” option: Semgrep + Docker pipeline

This option demonstrates the **Security Deployment Pipeline** (SAST + Docker build).

Prerequisites:

- `python3`
- `semgrep`
- `docker` (daemon running)

### 3.1. Make the script executable

```bash
chmod +x scripts/deployment_pipeline.sh
```

### 3.2. Run SAST + Docker build only

```bash
ENVIRONMENT=dev ./scripts/deployment_pipeline.sh
```

### 3.3. Run build + automatic container start

```bash
ENVIRONMENT=dev DOCKER_RUN=true ./scripts/deployment_pipeline.sh
```

The container will expose `DOCKER_PORT` (default `8000`), with `instance/` mounted to `/app/instance`.

### 3.4. Example with push to a registry (optional)

```bash
ENVIRONMENT=staging \
DOCKER_REGISTRY=myregistry.com \
IMAGE_TAG=v1.0.0 \
./scripts/deployment_pipeline.sh
```

---

## 4. “Real production” option: hardened Ubuntu deployment script

This option is for a quick demo of **deployment hardening** (Gunicorn + Nginx + UFW).

Prerequisites (clean Ubuntu 20.04/22.04 machine):

- Root or `sudo` access
- Project code already on the server (copied/scp’d into a directory)

### 4.1. Make the script executable

```bash
chmod +x scripts/deploy.sh
```

### 4.2. Run as root

```bash
sudo ./scripts/deploy.sh
```

The script will:

- Install required system packages
- Create a dedicated user for the app
- Set up a virtualenv, Gunicorn, and Nginx (with HTTPS and UFW firewall)
- Register a systemd service so the app starts automatically

---

## 5. Suggested 1–2 hour lecture flow

1. Briefly show the code (`app/`, `auth.py`, `crypto.py`, `tests/`).
2. Run the **local application** (Section 1) and create a few users/notes.
3. Run the **fuzzer** (optional, if there is time):
   ```bash
   python scripts/fuzzer.py --url http://localhost:5001 --output reports/security_report.txt
   ```
4. Demonstrate **simple Docker** (Section 2).
5. If there is extra time, show the **security pipeline** (Section 3) or the **hardened deployment** (Section 4).

---

## 6. Cleaning up after demo

To remove all caches, test artifacts, logs, and reports:

```bash
# Make executable (first time only)
chmod +x scripts/clean_project.sh

# Clean everything
./scripts/clean_project.sh
```

This removes Python caches, test artifacts, virtual environments, logs, and reports. Database files and `.env` are preserved.
