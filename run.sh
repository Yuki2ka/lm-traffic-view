#!/usr/bin/env sh
# Usage: ./run.sh        (HTTP proxy modes)
#        sudo ./run.sh   (also sniff mode – needs raw capture rights)
set -e
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "[*] Creating .venv ..."
    python3 -m venv .venv
fi
if ! .venv/bin/python -c "import fastapi, uvicorn, httpx, scapy" 2>/dev/null; then
    echo "[*] Installing dependencies ..."
    .venv/bin/python -m pip install -q -r requirements.txt
fi
[ "$(id -u)" = "0" ] || echo "[i] Not root: sniff mode will not work, HTTP proxy modes will."
exec .venv/bin/python app.py
