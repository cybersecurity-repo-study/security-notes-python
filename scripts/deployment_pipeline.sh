#!/usr/bin/env bash
set -euo pipefail

# deployment_pipeline.sh
# Security-focused deployment pipeline for the SPS-CA2 project.
# This script is referenced in the CA2 final report as the
# "security deployment pipeline" gate before any real deploy.
#
# Stages:
#   1. Environment and tool checks (python, semgrep, docker)
#   2. SAST-style scan with Semgrep over Python code
#   3. Docker image build and optional deployment

ENVIRONMENT=${ENVIRONMENT:-dev}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR%/scripts}"

log_ts() {
  date +"%Y-%m-%dT%H:%M:%S%z"
}

log_info() {
  echo "[INFO] $(log_ts) $*"
}

log_warn() {
  echo "[WARN] $(log_ts) $*" >&2
}

log_error() {
  echo "[ERROR] $(log_ts) $*" >&2
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Required command '$cmd' not found in PATH."
    return 1
  fi
}

check_environment() {
  log_info "Environment: ENVIRONMENT=${ENVIRONMENT}"

  # Python (either python or python3)
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    log_error "Neither 'python3' nor 'python' found. Aborting pipeline."
    return 1
  fi
  log_info "Using Python interpreter: ${PYTHON_BIN}"

  # Semgrep
  if ! require_cmd semgrep; then
    log_error "Semgrep is required. Install with e.g.: 'pip install semgrep' or see https://semgrep.dev/docs/installation/."
    return 1
  fi
  log_info "Semgrep detected: $(command -v semgrep)"

  # Docker
  if ! require_cmd docker; then
    log_error "Docker is required. Install Docker from https://docs.docker.com/get-docker/."
    return 1
  fi
  log_info "Docker detected: $(command -v docker)"

  # Verify Docker daemon is running
  if ! docker info >/dev/null 2>&1; then
    log_error "Docker daemon is not running. Please start Docker and try again."
    return 1
  fi
  log_info "Docker daemon is running"

  return 0
}

run_semgrep() {
  log_info "Running Semgrep SAST scan over Python sources..."

  local targets=()
  for d in "${PROJECT_ROOT}/app" "${PROJECT_ROOT}/scripts" "${PROJECT_ROOT}/tests"; do
    if [ -d "$d" ]; then
      targets+=("$d")
    fi
  done

  if [ ${#targets[@]} -eq 0 ]; then
    log_error "No target directories found for Semgrep (expected app/, scripts/, tests/)."
    return 1
  fi

  log_info "Semgrep targets: ${targets[*]}"

  # p/python: builtin Python security rules
  # --error makes Semgrep exit non-zero on findings of configured severities
  if semgrep \
    --config p/python \
    --error \
    --severity WARNING \
    --severity ERROR \
    "${targets[@]}"; then
    log_info "Semgrep scan completed: PASS (no blocking findings)."
    return 0
  else
    local exit_code=$?
    log_error "Semgrep scan completed: FAIL (blocking findings or error, exit code=${exit_code})."
    return "$exit_code"
  fi
}

deploy_docker() {
  log_info "All security checks passed. Proceeding with Docker deployment for ENVIRONMENT=${ENVIRONMENT}..."

  # Validate Dockerfile exists
  local dockerfile="${PROJECT_ROOT}/Dockerfile"
  if [ ! -f "$dockerfile" ]; then
    log_error "Dockerfile not found at ${dockerfile}. Aborting deployment."
    return 1
  fi

  # Determine image tag
  local image_name="${IMAGE_NAME:-secure-notes}"
  local image_tag="${IMAGE_TAG:-latest}"
  if [ "$ENVIRONMENT" != "dev" ]; then
    image_tag="${ENVIRONMENT}"
  fi
  local full_image_tag="${image_name}:${image_tag}"

  log_info "Building Docker image: ${full_image_tag}"

  # Build Docker image
  if ! docker build \
    --tag "${full_image_tag}" \
    --file "${dockerfile}" \
    "${PROJECT_ROOT}"; then
    log_error "Docker build failed. Aborting deployment."
    return 1
  fi

  log_info "Docker image built successfully: ${full_image_tag}"

  # Optional: Push to registry
  if [ -n "${DOCKER_REGISTRY:-}" ]; then
    local registry_tag="${DOCKER_REGISTRY}/${full_image_tag}"
    log_info "Tagging image for registry: ${registry_tag}"
    docker tag "${full_image_tag}" "${registry_tag}"

    log_info "Pushing image to registry: ${registry_tag}"
    if ! docker push "${registry_tag}"; then
      log_error "Docker push failed. Deployment may be incomplete."
      return 1
    fi
    log_info "Image pushed successfully to registry"
  fi

  # Optional: Run container
  if [ "${DOCKER_RUN:-false}" = "true" ]; then
    local container_name="${image_name}-${ENVIRONMENT}"
    local docker_port="${DOCKER_PORT:-8000}"

    # Stop and remove existing container if it exists
    if docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
      log_info "Stopping existing container: ${container_name}"
      docker stop "${container_name}" >/dev/null 2>&1 || true
      log_info "Removing existing container: ${container_name}"
      docker rm "${container_name}" >/dev/null 2>&1 || true
    fi

    log_info "Starting container: ${container_name} on port ${docker_port}"
    if ! docker run -d \
      --name "${container_name}" \
      --publish "${docker_port}:8000" \
      --volume "${PROJECT_ROOT}/instance:/app/instance" \
      --restart unless-stopped \
      "${full_image_tag}"; then
      log_error "Failed to start container. Deployment incomplete."
      return 1
    fi

    log_info "Container started successfully: ${container_name}"
    log_info "Application available at http://localhost:${docker_port}"
  fi

  log_info "Docker deployment completed successfully."
  return 0
}

main() {
  log_info "Starting security deployment pipeline (Semgrep + Docker deploy)..."

  if ! check_environment; then
    log_error "Environment/tool checks failed. Aborting pipeline."
    exit 1
  fi

  if ! run_semgrep; then
    log_error "Pipeline failed at Semgrep stage."
    exit 1
  fi

  if ! deploy_docker; then
    log_error "Pipeline failed at Docker deployment stage."
    exit 1
  fi

  log_info "Security deployment pipeline (Semgrep + Docker deploy) completed successfully."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
