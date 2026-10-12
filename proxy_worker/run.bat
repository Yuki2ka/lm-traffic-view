@echo off
cd /d "%~dp0"

:: ── install once if venv missing ──────────────────────────────────
if not exist ".venv\Scripts\activate.bat" (
    echo [*] First run — creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [!] Failed to create venv. Is Python installed and on PATH?
        pause & exit /b 1
    )
    call .venv\Scripts\activate.bat
    echo [*] Installing dependencies...
    pip install fastapi uvicorn[standard] httpx
    if errorlevel 1 (
        echo [!] pip install failed.
        pause & exit /b 1
    )
    echo [*] Done.
) else (
    call .venv\Scripts\activate.bat
)

:: ── run ───────────────────────────────────────────────────────────
echo.
echo   ============================================
echo    LM Studio Proxy Debugger
echo    Management UI: http://127.0.0.1:19999/_ui
echo   ============================================
echo.
uvicorn proxy:app --host 127.0.0.1 --port 19999
pause
