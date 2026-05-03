#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

## Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "[-] Python 3 is required but not found."
    exit 1
fi

## Check pip
if ! command -v pip3 &>/dev/null; then
    echo "[-] pip3 is required but not found."
    exit 1
fi

## Install dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt"

## Copy .env if not present
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    echo "[!] .env created from .env.example — fill in your values before running."
else
    echo "[*] .env already exists, skipping."
fi

## Make launcher executable
chmod +x "$SCRIPT_DIR/logalyzer-ng_launcher.sh"
echo "[*] Launcher is executable."

## Optional: cron setup
echo ""
echo "[*] To run the launcher daily at 7am, add this to root's crontab (sudo crontab -e):"
echo "    0 7 * * * $SCRIPT_DIR/logalyzer-ng_launcher.sh"

echo ""
echo "[+] Setup complete."
