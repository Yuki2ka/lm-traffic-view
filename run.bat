@echo off
cd /d "%~dp0"

:: venv + deps: installed into .\.venv only when missing
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating .venv ...
    python -m venv .venv || (echo [!] Python 3.10+ not found on PATH & pause & exit /b 1)
)
.venv\Scripts\python.exe -c "import fastapi, uvicorn, httpx, scapy" 2>nul || (
    echo [*] Installing dependencies ...
    .venv\Scripts\python.exe -m pip install -q -r requirements.txt || (echo [!] pip install failed & pause & exit /b 1)
)

:: sniff mode needs Admin + Npcap ("Support loopback traffic"): https://npcap.com/#download
net session >nul 2>&1 || echo [i] Not Administrator: sniff mode will not work, HTTP proxy modes will.

.venv\Scripts\python.exe app.py
pause
