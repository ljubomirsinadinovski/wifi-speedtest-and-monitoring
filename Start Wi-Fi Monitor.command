#!/bin/zsh
# Double-click this file in Finder to start Wi-Fi Monitor.
# Keep this Terminal window open while using it; close it (or press Ctrl+C) to stop.
cd "$(dirname "$0")"
PY="$(command -v python3 || echo /usr/bin/python3)"
exec "$PY" wifimon.py "$@"
