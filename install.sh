#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Caido Plugins - build/install script
#
# Запуск из корня репозитория:
#   chmod +x install.sh
#   ./install.sh
#
# Результат:
#   plugins/js-analyzer-plus/dist/plugin_package.zip
#   plugins/sqlmap-manager/dist/plugin_package.zip
# ============================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

JS_PLUGIN_DIR="$ROOT_DIR/plugins/js-analyzer-plus"
SQLMAP_PLUGIN_DIR="$ROOT_DIR/plugins/sqlmap-manager"

log() {
    printf '\n\033[1;34m==> %s\033[0m\n' "$1"
}

success() {
    printf '\033[1;32m[OK]\033[0m %s\n' "$1"
}

error() {
    printf '\033[1;31m[ERROR]\033[0m %s\n' "$1" >&2
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------
# Проверяем структуру репозитория
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
# Проверяем Python
# ------------------------------------------------------------

log "Checking Python"

PYTHON=""

if command_exists python3; then
    PYTHON="python3"
elif command_exists python; then
    if python --version 2>&1 | grep -q "Python 3"; then
        PYTHON="python"
    fi
fi

if [[ -z "$PYTHON" ]]; then
    error "Python 3 is required but was not found."
    error "Install Python 3 and run this script again."
    exit 1
fi

PYTHON_VERSION="$($PYTHON --version 2>&1)"
success "$PYTHON_VERSION"

# ------------------------------------------------------------
# Проверяем Node.js
# ------------------------------------------------------------

log "Checking Node.js"

if ! command_exists node; then
    error "Node.js is required for JS Analyzer Plus."
    error "Install Node.js (preferably an LTS version) and run this script again."
    exit 1
fi

NODE_VERSION="$(node --version)"
success "Node.js $NODE_VERSION"

# ------------------------------------------------------------
# Проверяем pnpm
# ------------------------------------------------------------

log "Checking pnpm"

if command_exists pnpm; then
    PNPM="pnpm"
else
    # Современный Node.js обычно содержит Corepack.
    if command_exists corepack; then
        echo "pnpm was not found. Enabling it through Corepack..."

        corepack enable

        # package.json/lockfile в репозитории не фиксируют версию pnpm,
        # поэтому используем актуальную stable-версию.
        corepack prepare pnpm@latest --activate

        if ! command_exists pnpm; then
            error "Corepack was unable to make pnpm available."
            exit 1
        fi

        PNPM="pnpm"
    else
        error "pnpm was not found and Corepack is unavailable."
        error "Install pnpm manually:"
        error "https://pnpm.io/installation"
        exit 1
    fi
fi

PNPM_VERSION="$($PNPM --version)"
success "pnpm $PNPM_VERSION"

# ------------------------------------------------------------
# JS Analyzer Plus
# ------------------------------------------------------------

log "Installing JS Analyzer Plus dependencies"

cd "$JS_PLUGIN_DIR"

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
    error "JS Analyzer Plus build finished but package was not found:"
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
    error "SQLmap Manager build finished but package was not found:"
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
printf '\033[1;32m        Build completed successfully       \033[0m\n'
printf '\033[1;32m============================================\033[0m\n'
printf '\n'

printf 'JS Analyzer Plus:\n'
printf '  %s\n' "$JS_PACKAGE"
printf '\n'

printf 'SQLmap Manager:\n'
printf '  %s\n' "$SQLMAP_PACKAGE"
printf '\n'

printf 'Install both ZIP files in Caido via:\n'
printf '  Plugins -> Install\n'
printf '\n'
