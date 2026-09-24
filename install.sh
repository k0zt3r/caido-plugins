#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Caido Plugins - install & build script
#
# Запуск из корня репозитория:
#
#   chmod +x install.sh
#   ./install.sh
#
# ============================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

JS_PLUGIN_DIR="$ROOT_DIR/plugins/js-analyzer-plus"
SQLMAP_PLUGIN_DIR="$ROOT_DIR/plugins/sqlmap-manager"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

log() {
    printf '\n\033[1;34m==> %s\033[0m\n' "$1"
}

success() {
    printf '\033[1;32m[OK]\033[0m %s\n' "$1"
}

warning() {
    printf '\033[1;33m[WARN]\033[0m %s\n' "$1"
}

error() {
    printf '\033[1;31m[ERROR]\033[0m %s\n' "$1" >&2
}

# ------------------------------------------------------------
# Sudo
# ------------------------------------------------------------

if [[ "$EUID" -eq 0 ]]; then
    SUDO=""
else
    if ! command -v sudo >/dev/null 2>&1; then
        error "sudo is required to install system packages."
        exit 1
    fi

    SUDO="sudo"
fi

# ------------------------------------------------------------
# APT
# ------------------------------------------------------------

apt_update() {
    log "Updating apt package index"

    $SUDO apt-get update

    success "apt package index updated"
}

install_apt_packages() {
    local packages=("$@")

    if [[ ${#packages[@]} -eq 0 ]]; then
        return 0
    fi

    echo
    echo "Installing missing packages:"
    printf '  - %s\n' "${packages[@]}"
    echo

    apt_update

    $SUDO apt-get install -y "${packages[@]}"

    success "Missing system packages installed"
}

# ------------------------------------------------------------
# Check repository
# ------------------------------------------------------------

log "Checking repository"

if [[ ! -d "$JS_PLUGIN_DIR" ]]; then
    error "JS Analyzer Plus directory not found:"
    error "$JS_PLUGIN_DIR"
    exit 1
fi

if [[ ! -d "$SQLMAP_PLUGIN_DIR" ]]; then
    error "SQLmap Manager directory not found:"
    error "$SQLMAP_PLUGIN_DIR"
    exit 1
fi

success "Repository structure looks correct"

# ------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------

log "Checking system dependencies"

MISSING_PACKAGES=()

REQUIRED_PACKAGES=(
    ca-certificates
    curl
    git
    unzip
    zip
    build-essential
    python3
    python3-pip
    python3-venv
    python3-dev
    npm
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    if dpkg -s "$package" >/dev/null 2>&1; then
        success "$package"
    else
        MISSING_PACKAGES+=("$package")
    fi
done

if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
    install_apt_packages "${MISSING_PACKAGES[@]}"
else
    success "All required system packages are installed"
fi

# ------------------------------------------------------------
# Python
# ------------------------------------------------------------

log "Checking Python"

if ! command -v python3 >/dev/null 2>&1; then
    error "Python 3 is not available."
    exit 1
fi

PYTHON="python3"

PYTHON_VERSION="$($PYTHON --version 2>&1)"

success "$PYTHON_VERSION"

# ------------------------------------------------------------
# Node.js
# ------------------------------------------------------------

log "Checking Node.js"

if ! command -v node >/dev/null 2>&1; then
    warning "Node.js was not found."

    apt_update

    $SUDO apt-get install -y nodejs
fi

if ! command -v node >/dev/null 2>&1; then
    error "Node.js installation failed."
    exit 1
fi

NODE_VERSION="$(node --version)"

success "Node.js $NODE_VERSION"

# ------------------------------------------------------------
# npm
# ------------------------------------------------------------

log "Checking npm"

if ! command -v npm >/dev/null 2>&1; then
    warning "npm was not found."

    apt_update

    $SUDO apt-get install -y npm
fi

if ! command -v npm >/dev/null 2>&1; then
    error "npm installation failed."
    exit 1
fi

NPM_VERSION="$(npm --version)"

success "npm $NPM_VERSION"

# ------------------------------------------------------------
# pnpm
# ------------------------------------------------------------

log "Checking pnpm"

if command -v pnpm >/dev/null 2>&1; then

    PNPM="pnpm"

    PNPM_VERSION="$($PNPM --version)"

    success "pnpm $PNPM_VERSION"

else

    warning "pnpm was not found."

    # Try Corepack first.
    if command -v corepack >/dev/null 2>&1; then

        echo "Installing pnpm through Corepack..."

        corepack enable
        corepack prepare pnpm@latest --activate

    else

        # Ubuntu Node.js packages sometimes don't provide Corepack.
        echo "Corepack is unavailable."
        echo "Installing pnpm through npm..."

        $SUDO npm install --global pnpm

    fi

    if ! command -v pnpm >/dev/null 2>&1; then
        error "pnpm installation failed."
        exit 1
    fi

    PNPM="pnpm"

    PNPM_VERSION="$($PNPM --version)"

    success "pnpm $PNPM_VERSION"
fi

# ------------------------------------------------------------
# Final dependency check
# ------------------------------------------------------------

log "Running final dependency check"

REQUIRED_COMMANDS=(
    git
    curl
    unzip
    zip
    python3
    pip3
    node
    npm
    pnpm
)

for command in "${REQUIRED_COMMANDS[@]}"; do
    if command -v "$command" >/dev/null 2>&1; then
        success "$command"
    else
        error "Required command is missing: $command"
        exit 1
    fi
done

# ------------------------------------------------------------
# JS Analyzer Plus
# ------------------------------------------------------------

log "Preparing JS Analyzer Plus"

cd "$JS_PLUGIN_DIR"

# pnpm 10+ blocks dependency build scripts by default.
# Allow esbuild to execute its build/postinstall scripts.
"$PNPM" config set --location=project onlyBuiltDependencies esbuild

success "esbuild build scripts allowed"

# ------------------------------------------------------------
# Install JS dependencies
# ------------------------------------------------------------

log "Installing JS Analyzer Plus dependencies"

"$PNPM" install --frozen-lockfile

success "JS Analyzer Plus dependencies installed"

# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

log "Running JS Analyzer Plus tests"

"$PNPM" test

success "JS Analyzer Plus tests passed"

# ------------------------------------------------------------
# Typecheck
# ------------------------------------------------------------

log "Running JS Analyzer Plus typecheck"

"$PNPM" typecheck

success "JS Analyzer Plus typecheck passed"

# ------------------------------------------------------------
# Build JS Analyzer Plus
# ------------------------------------------------------------

log "Building JS Analyzer Plus"

"$PNPM" build

JS_PACKAGE="$JS_PLUGIN_DIR/dist/plugin_package.zip"

if [[ ! -f "$JS_PACKAGE" ]]; then
    error "JS Analyzer Plus package was not created:"
    error "$JS_PACKAGE"
    exit 1
fi

success "JS Analyzer Plus package created"

# ------------------------------------------------------------
# SQLmap Manager
# ------------------------------------------------------------

log "Building SQLmap Manager"

cd "$SQLMAP_PLUGIN_DIR"

"$PYTHON" build.py

SQLMAP_PACKAGE="$SQLMAP_PLUGIN_DIR/dist/plugin_package.zip"

if [[ ! -f "$SQLMAP_PACKAGE" ]]; then
    error "SQLmap Manager package was not created:"
    error "$SQLMAP_PACKAGE"
    exit 1
fi

success "SQLmap Manager package created"

# ------------------------------------------------------------
# Final output
# ------------------------------------------------------------

cd "$ROOT_DIR"

printf '\n'
printf '\033[1;32m============================================\033[0m\n'
printf '\033[1;32m       Installation completed successfully \033[0m\n'
printf '\033[1;32m============================================\033[0m\n'
printf '\n'

printf 'JS Analyzer Plus:\n'
printf '  %s\n' "$JS_PACKAGE"
printf '\n'

printf 'SQLmap Manager:\n'
printf '  %s\n' "$SQLMAP_PACKAGE"
printf '\n'

printf 'Build completed successfully.\n'
