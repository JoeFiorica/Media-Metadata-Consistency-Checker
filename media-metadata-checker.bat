@echo off
setlocal
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python 3.11 or newer is required. Install Python and enable its PATH option. 1>&2
    exit /b 2
)
python -B "%~dp0media_metadata_checker.py" %*
exit /b %errorlevel%
