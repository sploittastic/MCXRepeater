#!/usr/bin/env bash
# Installs what mcxrepeater.py needs (pyserial, cryptography).
#   ./installdependencies.sh
# 1. apt packages (python3-serial, python3-cryptography): the normal route on Raspberry Pi OS / Debian.
# 2. If apt can't get them (e.g. an end-of-life release whose mirrors are gone): pip into ./venv,
#    or pip --user if venv isn't available. The script then prints the python to run mcxrepeater.py with.
set -uo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi
PY=python3

have_deps() { "$1" -c "import serial, cryptography" 2>/dev/null; }

if have_deps python3; then
    echo "pyserial and cryptography are already installed."
elif have_deps "$HERE/venv/bin/python"; then
    PY="$HERE/venv/bin/python"
    echo "pyserial and cryptography are already installed in ./venv."
else
    echo "Installing python3-serial and python3-cryptography from apt..."
    # "404 Not Found" lines from a repository or architecture (e.g. i386) that no longer exists are only
    # warnings here: the install below is what counts.
    $SUDO apt-get update || echo "apt-get update reported errors (see above); trying the install anyway..."
    $SUDO apt-get install -y python3 python3-serial python3-cryptography || true

    if ! have_deps python3; then
        echo
        echo "apt could not install them. Falling back to pip..."
        if python3 -m venv "$HERE/venv" 2>/dev/null && "$HERE/venv/bin/python" -m pip --version >/dev/null 2>&1; then
            "$HERE/venv/bin/python" -m pip install --upgrade pip
            "$HERE/venv/bin/python" -m pip install pyserial cryptography
            PY="$HERE/venv/bin/python"
        elif python3 -m pip --version >/dev/null 2>&1; then
            rm -rf "$HERE/venv"
            python3 -m pip install --user pyserial cryptography
        else
            rm -rf "$HERE/venv"
            echo
            echo "No working apt, venv or pip. Fix apt first; on Debian 11 (bullseye), which is end of life, point"
            echo "/etc/apt/sources.list at the archive:"
            echo "    deb http://archive.debian.org/debian bullseye main"
            echo "    deb http://archive.debian.org/debian-security bullseye-security main"
            echo "then: sudo apt-get update && ./installdependencies.sh"
            exit 1
        fi
    fi
fi

if ! have_deps "$PY"; then
    echo "Installing the dependencies failed: see the errors above."
    exit 1
fi

# The KISS modems are /dev/ttyACM* or /dev/ttyUSB*, owned by the dialout group.
USER_NAME="${SUDO_USER:-$(id -un)}"
if [ "$USER_NAME" != "root" ] && ! id -nG "$USER_NAME" | grep -qw dialout; then
    echo "Adding $USER_NAME to the dialout group (serial port access)..."
    $SUDO usermod -aG dialout "$USER_NAME"
    echo "Log out and back in (or reboot) for the serial port access to take effect."
fi

if [ ! -f config.json ]; then
    cp config.example.json config.json
    echo "Created config.json from config.example.json: edit the serial ports, frequencies and web_password."
fi

echo
echo "Dependencies OK. Start it with:"
echo "    $PY $HERE/mcxrepeater.py --config $HERE/config.json"
if [ "$PY" != "python3" ]; then
    echo "(use that python in ExecStart if you install mcxrepeater.service)"
fi
