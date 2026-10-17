#!/usr/bin/env bash
# Installs what mcxrepeater.py needs on Raspberry Pi OS / Debian, from apt
# (Raspberry Pi OS refuses system-wide pip installs).
#   ./installdependencies.sh
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

if python3 -c "import serial, cryptography" 2>/dev/null; then
    echo "python3-serial and python3-cryptography are already installed: skipping apt."
else
    echo "Installing Python packages from apt..."
    # A stale package list gives "404 Not Found" / "Unable to fetch some archives": refresh it first,
    # and keep going if only some (e.g. third-party) repositories fail to refresh.
    $SUDO apt-get update || echo "apt-get update reported errors (see above); trying the install anyway..."
    if ! $SUDO apt-get install -y python3 python3-serial python3-cryptography; then
        echo "Retrying with --fix-missing..."
        $SUDO apt-get install -y --fix-missing python3 python3-serial python3-cryptography || {
            echo
            echo "apt could not download the packages. Check the errors above: usually a repository in"
            echo "/etc/apt/sources.list or /etc/apt/sources.list.d/ is wrong or no longer exists"
            echo "(cat /etc/os-release shows which release this Pi runs)."
            exit 1
        }
    fi
fi

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
