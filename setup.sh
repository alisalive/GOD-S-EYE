#!/usr/bin/env bash
# GOD'S EYE — Kali Linux / Debian setup
# Supports root and non-root, externally-managed-environment distros
set -e

echo "============================================"
echo " GOD'S EYE v1.0.0 - Setup"
echo " For authorized security testing only"
echo "============================================"
echo

# ── Python version check ───────────────────────────────────────────────────────
python3 -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'" || {
    echo "ERROR: Python 3.11+ is required."
    exit 1
}

# ── System dependencies ────────────────────────────────────────────────────────
echo "Installing system dependencies..."
if [ "$EUID" -eq 0 ]; then
    apt-get update -qq
    apt-get install -y -qq python3-pip python3-venv libpango-1.0-0 libcairo2 \
        libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info 2>/dev/null || true
else
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3-pip python3-venv libpango-1.0-0 libcairo2 \
        libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info 2>/dev/null || true
fi

# ── pip install — root vs non-root ────────────────────────────────────────────
# Root:     --break-system-packages  (installs to system site-packages)
# Non-root: --user                   (installs to ~/.local, no sudo needed)
echo "Installing Python dependencies..."
if [ "$EUID" -eq 0 ]; then
    pip3 install -r requirements.txt --break-system-packages --ignore-installed
else
    pip3 install -r requirements.txt --user
fi

# ── Playwright browser ─────────────────────────────────────────────────────────
echo "Installing Playwright browser..."
playwright install chromium || echo "WARNING: Playwright install failed. Screenshots will be disabled."

# ── Project directories ────────────────────────────────────────────────────────
echo "Creating directories..."
mkdir -p reports/screenshots logs config/wordlists

# ── Editable install (godseye command) ────────────────────────────────────────
echo "Installing as editable package (godseye command)..."
if [ "$EUID" -eq 0 ]; then
    pip3 install -e . --break-system-packages --ignore-installed 2>/dev/null || \
        echo "NOTE: pip install -e . failed — use python3 main.py directly"
else
    pip3 install -e . --user 2>/dev/null || \
        echo "NOTE: pip install -e . failed — use python3 main.py directly"
fi

# ── PATH fix (non-root only — root already has /usr/local/bin in PATH) ─────────
if [ "$EUID" -ne 0 ]; then
    echo "Adding ~/.local/bin to PATH..."
    export PATH="$HOME/.local/bin:$PATH"
    # Persist across sessions for bash and zsh
    grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc 2>/dev/null || \
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' ~/.zshrc 2>/dev/null || \
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true
    source ~/.bashrc 2>/dev/null || true
fi

echo
echo "============================================"
echo " Setup complete!"
echo "============================================"
echo
echo "Usage:"
echo "  python3 main.py --target 127.0.0.1 --mode pentest"
echo "  godseye --target TARGET --mode redteam --stealth --subdomains --screenshot"
echo

# ── Final verification ─────────────────────────────────────────────────────────
if command -v godseye &> /dev/null; then
    echo "SUCCESS: godseye --target <IP> is ready!"
else
    echo "Run this then restart terminal: export PATH=\$HOME/.local/bin:\$PATH"
fi
