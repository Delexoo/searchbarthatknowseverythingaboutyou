@echo off
echo ========================================
echo    searchbarthatknowseverythingaboutyou
echo ========================================
echo.

where node >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo Install it from https://nodejs.org/ then run start.bat again.
    pause
    exit /b 1
)

echo Starting local server on http://localhost:8080
echo Press Ctrl+C to stop.
echo.

node server.js
pause
