#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$SCRIPT_DIR"
VENV_DIR="$PROJECT_ROOT/.venv"
BOOTSTRAP_MARKER="$VENV_DIR/.forensic-bootstrap"
LOCK_DIR="$PROJECT_ROOT/.forensic-image-scanner-bootstrap.lock"

ACTION="gui"
DEV_MODE=0
PYTHON_BIN=""
PYTHON_VERSION=""
PYPROJECT_HASH=""
MODEL_DIR=""
MODEL_LIST=""
LOCK_HELD=0
MARKER_PENDING=0
PENDING_EXTRAS=""

usage() {
    cat <<'EOF'
Usage:
  ./start.sh
  ./start.sh --check
  ./start.sh --repair
  ./start.sh --dev
  ./start.sh --cli [arguments]
  ./start.sh --help

Prepare the local .venv and launch the desktop GUI by default.
Model weights are never downloaded. No system packages or settings are changed.
EOF
}

log_info() {
    printf '[INFO] %s\n' "$1"
}

log_ok() {
    printf '[OK] %s\n' "$1"
}

error() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

handle_error() {
    local status="$1"
    local line="$2"
    local command="$3"
    printf 'ERROR: command failed (exit %s) at line %s: %s\n' \
        "$status" "$line" "$command" >&2
}

cleanup_lock() {
    if (( LOCK_HELD )); then
        rmdir -- "$LOCK_DIR" 2>/dev/null || true
        LOCK_HELD=0
    fi
}

acquire_lock() {
    if ! mkdir -- "$LOCK_DIR" 2>/dev/null; then
        error "Another bootstrap may be running (or a stale lock exists): $LOCK_DIR"
    fi
    LOCK_HELD=1
}

detect_python() {
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python)"
    else
        error "Python 3.11 or newer is required; install Python and try again."
    fi
}

check_python_version() {
    local version
    if ! version="$("$PYTHON_BIN" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"; then
        error "Unable to run the detected Python interpreter: $PYTHON_BIN"
    fi

    local major minor
    IFS=. read -r major minor _ <<< "$version"
    if (( major < 3 || (major == 3 && minor < 11) )); then
        printf 'ERROR: Python 3.11 or newer is required.\n' >&2
        exit 1
    fi

    PYTHON_VERSION="$version"
    log_ok "Python $PYTHON_VERSION"
}

setup_venv() {
    if [[ -e "$VENV_DIR" ]]; then
        if [[ ! -d "$VENV_DIR" || ! -f "$VENV_DIR/bin/activate" \
            || ! -x "$VENV_DIR/bin/python" || ! -x "$VENV_DIR/bin/pip" ]]; then
            printf 'ERROR: The virtual environment appears corrupted.\n' >&2
            printf 'Remove .venv manually and run ./start.sh again.\n' >&2
            exit 1
        fi
        log_ok "Virtual environment found."
        return
    fi

    log_info "Creating virtual environment..."
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
        error "Could not create .venv. Check Python's venv support and directory permissions."
    fi
    log_ok "Virtual environment created."
}

activate_venv() {
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    hash -r

    local python_path pip_path prefix
    python_path="$(command -v python || true)"
    pip_path="$(command -v pip || true)"
    if [[ "$python_path" != "$VENV_DIR/bin/"* || "$pip_path" != "$VENV_DIR/bin/"* ]]; then
        printf 'ERROR: python and pip must both resolve inside .venv.\n' >&2
        printf 'The virtual environment appears corrupted. Remove .venv manually and run ./start.sh again.\n' >&2
        exit 1
    fi
    if ! prefix="$(python -c 'import os, sys; print(os.path.realpath(sys.prefix))')" \
        || [[ "$prefix" != "$(cd -- "$VENV_DIR" && pwd -P)" ]]; then
        printf 'ERROR: Python is not running from the project virtual environment.\n' >&2
        printf 'The virtual environment appears corrupted. Remove .venv manually and run ./start.sh again.\n' >&2
        exit 1
    fi
    if ! python -m pip --version >/dev/null 2>&1; then
        printf 'ERROR: pip is unavailable inside .venv.\n' >&2
        printf 'The virtual environment appears corrupted. Remove .venv manually and run ./start.sh again.\n' >&2
        exit 1
    fi
    log_ok "Virtual environment"
}

hash_pyproject() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$PROJECT_ROOT/pyproject.toml" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$PROJECT_ROOT/pyproject.toml" | cut -d ' ' -f 1
    else
        error "A SHA-256 utility (sha256sum or shasum) is required to check project dependencies."
    fi
}

install_project() {
    local force="${1:-0}"
    local requested_extras="gui"
    local stored_hash=""
    local stored_extras=""
    local should_install=0

    if (( DEV_MODE )); then
        requested_extras="gui,dev"
    fi
    PYPROJECT_HASH="$(hash_pyproject)"
    if [[ -f "$BOOTSTRAP_MARKER" ]]; then
        read -r stored_hash stored_extras < "$BOOTSTRAP_MARKER" || true
    fi

    if (( force )); then
        log_info "Repair requested. Reinstalling the editable package and GUI extra..."
        should_install=1
    elif [[ "$stored_hash" != "$PYPROJECT_HASH" ]]; then
        if [[ -n "$stored_hash" ]]; then
            log_info "Dependencies changed. Updating environment..."
        else
            log_info "Preparing the editable package and GUI dependencies..."
        fi
        should_install=1
    elif (( DEV_MODE )) && [[ "$stored_extras" != "gui,dev" ]]; then
        log_info "Development extras requested. Updating environment..."
        should_install=1
    else
        log_ok "Dependencies already satisfied."
    fi

    if (( should_install )); then
        if ! python -m pip install -e ".[$requested_extras]"; then
            error "Package installation failed. Review pip's output; .venv was not removed."
        fi
        MARKER_PENDING=1
        PENDING_EXTRAS="$requested_extras"
    fi
}

check_environment() {
    local package_version
    local gui_path

    if ! python -m pip check >/dev/null; then
        printf 'ERROR: Dependency consistency check failed.\n' >&2
        printf 'Run ./start.sh --repair to reinstall the editable package and GUI extra.\n' >&2
        exit 1
    fi
    if ! package_version="$(python -c \
        'from importlib.metadata import version; print(version("forensic-image-scanner"))')"; then
        printf 'ERROR: forensic-image-scanner is not installed in .venv.\n' >&2
        printf 'Run ./start.sh --repair to reinstall it.\n' >&2
        exit 1
    fi
    if ! gui_path="$(command -v forensic-image-scanner-gui)"; then
        printf 'ERROR: GUI entrypoint is missing. Run ./start.sh --repair.\n' >&2
        exit 1
    fi
    if [[ "$gui_path" != "$VENV_DIR/bin/"* ]]; then
        error "GUI entrypoint does not resolve inside .venv: $gui_path"
    fi

    if (( MARKER_PENDING )); then
        printf '%s %s\n' "$PYPROJECT_HASH" "$PENDING_EXTRAS" > "$BOOTSTRAP_MARKER"
    fi
    log_ok "Dependencies"
    log_ok "Package forensic-image-scanner $package_version"
    log_ok "GUI"
}

resolve_model_dir() {
    if ! MODEL_DIR="$(python -c \
        'from forensic_image_scanner.model_paths import resolve_model_directory; p = resolve_model_directory(None); p.mkdir(parents=True, exist_ok=True); print(p)')"; then
        error "Could not resolve or create the application's model directory."
    fi
}

show_model_status() {
    resolve_model_dir
    if ! MODEL_LIST="$(forensic-image-scanner model list --model-dir "$MODEL_DIR")"; then
        error "Could not read model status using the application's model registry CLI."
    fi

    printf 'Models:\n'
    while IFS= read -r line; do
        printf '  %s\n' "$line"
    done <<< "$MODEL_LIST"

    local usable_models
    usable_models="$(printf '%s\n' "$MODEL_LIST" | awk 'NR > 1 && $NF == "yes" { print $1 }')"
    if [[ -z "$usable_models" ]]; then
        log_info "No usable model installed"
    else
        log_ok "Usable model: $(printf '%s' "$usable_models" | paste -sd ', ' -)"
    fi
}

show_check_summary() {
    local display_model_dir="$MODEL_DIR"
    if [[ "$display_model_dir" == "$HOME/"* ]]; then
        display_model_dir="~/${display_model_dir#"$HOME"/}"
    fi

    printf '\nForensic Image Scanner\n\n'
    printf 'Python          %s\n' "$PYTHON_VERSION"
    printf 'Environment     .venv\n'
    printf 'Package         installed\n'
    printf 'GUI             available\n'
    printf 'Models dir      %s\n' "$display_model_dir"
    local usable_models
    usable_models="$(printf '%s\n' "$MODEL_LIST" | awk 'NR > 1 && $NF == "yes" { print $1 }')"
    if [[ -z "$usable_models" ]]; then
        printf 'Usable model    none\n'
    else
        printf 'Usable model    %s\n' "$(printf '%s' "$usable_models" | paste -sd ', ' -)"
    fi
    printf 'Network mode    offline-by-design\n\n'
    printf 'Environment OK\n'
}

launch_gui() {
    log_info "Starting Forensic Image Scanner..."
    cleanup_lock
    exec forensic-image-scanner-gui
}

main() {
    local force_repair=0

    case "${1:-}" in
        --help|-h)
            usage
            return 0
            ;;
        --check)
            [[ "$#" -eq 1 ]] || error "--check does not accept additional arguments."
            ACTION="check"
            ;;
        --repair)
            [[ "$#" -eq 1 ]] || error "--repair does not accept additional arguments."
            ACTION="repair"
            ;;
        --dev)
            [[ "$#" -eq 1 ]] || error "--dev does not accept additional arguments."
            DEV_MODE=1
            ;;
        --cli)
            ACTION="cli"
            shift
            ;;
        "")
            [[ "$#" -eq 0 ]] || error "Unexpected arguments. Use ./start.sh --help."
            ;;
        *)
            error "Unknown option: $1. Use ./start.sh --help."
            ;;
    esac

    trap cleanup_lock EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'handle_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

    cd -- "$PROJECT_ROOT"
    acquire_lock
    detect_python
    check_python_version
    setup_venv
    activate_venv

    export HF_HUB_OFFLINE=1
    export TRANSFORMERS_OFFLINE=1
    export HF_HUB_DISABLE_TELEMETRY=1

    if [[ "$ACTION" == "repair" ]]; then
        force_repair=1
    fi
    install_project "$force_repair"
    check_environment
    show_model_status

    case "$ACTION" in
        check)
            show_check_summary
            ;;
        repair)
            log_ok "Repair complete"
            ;;
        cli)
            if ! command -v forensic-image-scanner >/dev/null 2>&1; then
                error "CLI entrypoint is missing. Run ./start.sh --repair."
            fi
            cleanup_lock
            exec forensic-image-scanner "$@"
            ;;
        gui)
            launch_gui
            ;;
    esac
}

main "$@"
