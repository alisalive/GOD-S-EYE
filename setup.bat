@echo off
echo ============================================
echo  GOD'S EYE v1.0.0 - Setup
echo  For authorized security testing only
echo ============================================
echo.
echo Installing dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo ERROR: pip install failed. Make sure Python 3.11+ is installed.
    pause
    exit /b 1
)
echo.
echo Installing Playwright browser...
playwright install chromium
if %ERRORLEVEL% neq 0 (
    echo WARNING: Playwright install failed. Screenshots will be disabled.
    echo Run manually: playwright install chromium
)
echo.
echo Installing as editable package (enables 'godseye' command)...
pip install -e .
if %ERRORLEVEL% neq 0 (
    echo WARNING: pip install -e . failed. Use 'python main.py' directly.
)
echo.
echo Creating directories...
if not exist "reports" mkdir reports
if not exist "reports\screenshots" mkdir reports\screenshots
if not exist "logs" mkdir logs
if not exist "config\wordlists" mkdir config\wordlists
echo.
echo Setup complete!
echo.
echo Usage:
echo   python main.py --target 127.0.0.1 --mode pentest
echo   python main.py --target TARGET --mode redteam --stealth --subdomains --screenshot --dirbrute
echo   godseye --target TARGET --mode redteam --stealth --subdomains --screenshot
echo.
pause
