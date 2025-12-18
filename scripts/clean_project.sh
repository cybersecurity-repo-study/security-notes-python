#!/bin/bash
# Clean project script - removes caches, test artifacts, logs, and reports
# Usage: ./scripts/clean_project.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "Cleaning project artifacts..."

# Python cache and bytecode
echo "  - Removing Python cache (__pycache__, *.pyc, *.pyo)..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
find . -type f -name "*.pyd" -delete 2>/dev/null || true
find . -type f -name ".Python" -delete 2>/dev/null || true

# Test artifacts
echo "  - Removing test cache and coverage reports..."
rm -rf .pytest_cache 2>/dev/null || true
rm -rf .coverage* 2>/dev/null || true
rm -rf htmlcov/ 2>/dev/null || true
rm -rf .tox/ 2>/dev/null || true
rm -rf .nox/ 2>/dev/null || true
rm -rf .hypothesis/ 2>/dev/null || true
rm -rf *.cover 2>/dev/null || true
rm -rf *.prof 2>/dev/null || true

# Virtual environments
echo "  - Removing virtual environments..."
rm -rf venv/ 2>/dev/null || true
rm -rf ENV/ 2>/dev/null || true
rm -rf env/ 2>/dev/null || true
rm -rf .venv/ 2>/dev/null || true
rm -rf virtualenv/ 2>/dev/null || true

# Logs
echo "  - Removing log files..."
rm -rf logs/*.log 2>/dev/null || true
rm -f *.log 2>/dev/null || true
rm -f logs/*.log.* 2>/dev/null || true

# Reports directory (keep directory, remove contents)
echo "  - Cleaning reports directory..."
if [ -d "reports" ]; then
    rm -rf reports/* 2>/dev/null || true
    # Keep .gitkeep if it exists
    if [ -f "reports/.gitkeep" ]; then
        rm -rf reports/* 2>/dev/null || true
        touch reports/.gitkeep
    fi
else
    mkdir -p reports
fi

# Distribution/packaging artifacts
echo "  - Removing build artifacts..."
rm -rf build/ 2>/dev/null || true
rm -rf dist/ 2>/dev/null || true
rm -rf *.egg-info/ 2>/dev/null || true
rm -rf .eggs/ 2>/dev/null || true

# IDE and editor files
echo "  - Removing IDE cache files..."
rm -rf .idea/ 2>/dev/null || true
rm -rf .vscode/ 2>/dev/null || true
rm -f *.swp 2>/dev/null || true
rm -f *.swo 2>/dev/null || true
rm -f *~ 2>/dev/null || true

# OS files
echo "  - Removing OS files..."
find . -name ".DS_Store" -delete 2>/dev/null || true
find . -name "Thumbs.db" -delete 2>/dev/null || true

# Temporary files
echo "  - Removing temporary files..."
rm -rf tmp/ 2>/dev/null || true
rm -rf temp/ 2>/dev/null || true
rm -f *.tmp 2>/dev/null || true
rm -f *.bak 2>/dev/null || true
rm -f *.backup 2>/dev/null || true

# Flask session files
echo "  - Removing Flask session files..."
rm -rf flask_session/ 2>/dev/null || true

echo ""
echo "✓ Project cleaned successfully!"
echo ""
echo "Note: Database files in instance/ and .env files were NOT removed."
echo "      To remove them, delete manually if needed."



