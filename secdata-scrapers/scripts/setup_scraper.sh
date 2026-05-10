#!/bin/bash
# Setup script for the scraper VPS.
# Tested on Ubuntu 22.04, Ubuntu 24.04, Debian 12. Run as root or with sudo.
set -e

echo "=== Installing system dependencies ==="
apt-get update -qq
apt-get install -y --no-install-recommends \
    git \
    tmux \
    p7zip-full \
    curl \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    python3-full

echo ""
echo "=== Creating Python virtual environment ==="
# Modern Debian/Ubuntu (PEP 668) blocks system-wide pip installs.
# Using a venv is both the safe option and the recommended one.
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Created venv/"
else
    echo "venv/ already exists, skipping creation"
fi

echo ""
echo "=== Installing Python packages into venv ==="
# Activate the venv for the rest of this script
# shellcheck disable=SC1091
source venv/bin/activate

pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo ""
echo "=== Setup complete ==="
echo ""
echo "IMPORTANT: this scraper runs inside a Python virtual environment."
echo "Every time you SSH back in, activate the venv before running anything:"
echo ""
echo "    cd ~/secdata-scrapers"
echo "    source venv/bin/activate"
echo ""
echo "You'll know it's active when your prompt starts with (venv)."
echo ""
echo "Next steps:"
echo "  1. cp config.yaml.example config.yaml"
echo "  2. Edit config.yaml — add github_token (free at github.com/settings/tokens)"
echo "  3. Read ETHICAL_USE.md"
echo "  4. python3 main.py --estimate    # see all sources"
echo "  5. python3 main.py --fast        # run fast sources first (~2 hrs)"
echo "  6. python3 main.py --se-dumps    # download Stack Exchange dumps"
echo ""
echo "Run long scrapers in tmux to survive disconnects:"
echo "  tmux new -s scrape"
echo "  source venv/bin/activate"
echo "  python3 main.py --nvd --ctftime --hackerone --exploitdb"
echo "  # Press Ctrl+B then D to detach"
echo ""
