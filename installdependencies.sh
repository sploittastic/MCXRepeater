#!/usr/bin/env bash
# Installs what mcxrepeater.py needs on Raspberry Pi OS / Debian, from apt
# (Raspberry Pi OS refuses system-wide pip installs).
#   ./installdependencies.sh
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

echo "Installing Python packages from apt..."
$SUDO apt-get update
$SUDO apt-get install -y python3 python3-serial python3-cryptography

# The KISS modems are /dev/ttyACM* or /dev/ttyUSB*, owned by the dialout group.
USER_NAME="${SUDO_USER:-$(id -un)}"
if [ "$USER_NAME" != "root" ] && ! id -nG "$USER_NAME" | grep -qw dialout; then
    echo "Adding $USER_NAME to the dialout group (serial port access)..."
    $SUDO usermod -aG dialout "$USER_NAME"
    echo "Log out and back in (or reboot) for the serial port access to take effect."
fi

cd "$(dirname "$0")"
if [ ! -f config.json ]; then
    cp config.example.json config.json
    echo "Created config.json from config.example.json: edit the serial ports, frequencies and web_password."
fi

python3 -c "import serial, cryptography" && echo "Dependencies OK. Start it with: python3 mcxrepeater.py --config config.json"
