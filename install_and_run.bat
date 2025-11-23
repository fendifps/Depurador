@echo off
setlocal enabledelayedexpansion
title Depurador v2.0 - Automatic Installation System
color 0A

:: ============================================================================
:: DEPURADOR v2.0 - AUTOMATIC INSTALLATION AND SETUP SCRIPT
:: Version: 2.0.0 - With ML Classifier Integration
:: Compatible: Windows 10/11
:: ============================================================================

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo [!] WARNING: Not running as Administrator
    echo [!] Some features may require elevated privileges
    echo.
    timeout /t 3 >nul
)

cls
echo.
echo ===============================================================================
echo.
echo    ####   #####  ####   #   #  ####    ###   ####    ###   ####  
echo    #   #  #      #   #  #   #  #   #  #   #  #   #  #   #  #   # 
echo    #   #  ####   ####   #   #  ####   #####  #   #  #   #  ####  
echo    #   #  #      #      #   #  #   #  #   #  #   #  #   #  #   # 
echo    ####   #####  #       ###   #   #  #   #  ####    ###   #   # 
echo.
echo         MALWARE SCANNER ELITE v2.0 - AUTO INSTALLER
echo              WITH ML CLASSIFIER INTEGRATION
echo.
echo ===============================================================================
echo.

:: Define paths
set "PROJECT_DIR=%~dp0Depurador"
set "VENV_DIR=%PROJECT_DIR%\depurador_env"
set "SRC_DIR=%PROJECT_DIR%\src"
set "LOGS_DIR=%PROJECT_DIR%\logs"
set "SIGNATURES_DIR=%PROJECT_DIR%\signatures"

echo [1/9] Checking Python installation...
echo -------------------------------------------------------------------------------

:: Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [X] Python is not installed or not in PATH
    echo.
    echo [!] INSTALLATION REQUIRED
    echo [i] Please download and install Python 3.8 or higher from:
    echo [i] https://www.python.org/downloads/
    echo [i] Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
) else (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
    echo [√] Python !PYTHON_VERSION! detected
)

echo.
echo [2/9] Creating project structure...
echo -------------------------------------------------------------------------------

:: Create project directories
if not exist "%PROJECT_DIR%" mkdir "%PROJECT_DIR%"
if not exist "%SRC_DIR%" mkdir "%SRC_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"
if not exist "%SIGNATURES_DIR%" mkdir "%SIGNATURES_DIR%"

echo [√] Project directories created
echo     - %PROJECT_DIR%
echo     - %SRC_DIR%
echo     - %LOGS_DIR%
echo     - %SIGNATURES_DIR%

echo.
echo [3/9] Creating virtual environment...
echo -------------------------------------------------------------------------------

if exist "%VENV_DIR%" (
    echo [i] Virtual environment already exists, removing...
    rmdir /s /q "%VENV_DIR%"
)

python -m venv "%VENV_DIR%"
if %errorLevel% neq 0 (
    echo [X] Failed to create virtual environment
    pause
    exit /b 1
)

echo [√] Virtual environment created: %VENV_DIR%

echo.
echo [4/9] Activating virtual environment...
echo -------------------------------------------------------------------------------

call "%VENV_DIR%\Scripts\activate.bat"
if %errorLevel% neq 0 (
    echo [X] Failed to activate virtual environment
    pause
    exit /b 1
)

echo [√] Virtual environment activated

echo.
echo [5/9] Upgrading pip...
echo -------------------------------------------------------------------------------

python -m pip install --upgrade pip --quiet
echo [√] pip upgraded successfully

echo.
echo [6/9] Installing dependencies...
echo -------------------------------------------------------------------------------
echo [i] This may take a few minutes...
echo.

:: Install required packages
echo [*] Installing colorama...
pip install colorama --quiet
if %errorLevel% neq 0 echo [!] Warning: colorama installation had issues

echo [*] Installing pefile...
pip install pefile --quiet
if %errorLevel% neq 0 echo [!] Warning: pefile installation had issues

echo.
echo [√] All dependencies installed successfully

echo.
echo [7/9] Verifying installation...
echo -------------------------------------------------------------------------------

python -c "import colorama; import pefile; import hashlib; import json; print('[√] All imports successful')" 2>nul
if %errorLevel% neq 0 (
    echo [!] Warning: Some modules may not have installed correctly
    echo [i] Depurador will attempt to run anyway
) else (
    echo [√] All required modules verified
)

echo.
echo [8/9] Checking project files...
echo -------------------------------------------------------------------------------

set "FILES_OK=1"

if not exist "%SRC_DIR%\main.py" (
    echo [X] Missing: main.py
    set "FILES_OK=0"
) else (
    echo [√] Found: main.py
)

if not exist "%SRC_DIR%\scanner.py" (
    echo [X] Missing: scanner.py
    set "FILES_OK=0"
) else (
    echo [√] Found: scanner.py
)

if not exist "%SRC_DIR%\analyzer.py" (
    echo [X] Missing: analyzer.py
    set "FILES_OK=0"
) else (
    echo [√] Found: analyzer.py
)

if not exist "%SRC_DIR%\signature_engine.py" (
    echo [X] Missing: signature_engine.py
    set "FILES_OK=0"
) else (
    echo [√] Found: signature_engine.py
)

if not exist "%SRC_DIR%\logger.py" (
    echo [X] Missing: logger.py
    set "FILES_OK=0"
) else (
    echo [√] Found: logger.py
)

if not exist "%SRC_DIR%\ml_classifier.py" (
    echo [!] Warning: ml_classifier.py not found
    echo [i] ML Classifier will be disabled
    echo [i] Download ml_classifier.py to enable ML features
) else (
    echo [√] Found: ml_classifier.py (ML Classifier available!)
)

if not exist "%PROJECT_DIR%\config.json" (
    echo [X] Missing: config.json
    set "FILES_OK=0"
) else (
    echo [√] Found: config.json
)

if not exist "%SIGNATURES_DIR%\malware_hashes.json" (
    echo [!] Warning: malware_hashes.json not found
    echo [i] Creating empty signature database...
    echo {"hashes": {}, "version": "2.0.0"} > "%SIGNATURES_DIR%\malware_hashes.json"
)

if not exist "%SIGNATURES_DIR%\heuristic_rules.json" (
    echo [!] Warning: heuristic_rules.json not found
    echo [i] Creating empty rules database...
    echo {"rules": [], "version": "2.0.0"} > "%SIGNATURES_DIR%\heuristic_rules.json"
)

if not exist "%SIGNATURES_DIR%\behavioral_patterns.json" (
    echo [!] Warning: behavioral_patterns.json not found
    echo [i] Creating empty patterns database...
    echo {"patterns": [], "filename_patterns": [], "version": "2.0.0"} > "%SIGNATURES_DIR%\behavioral_patterns.json"
)

echo.
echo [9/9] Initializing ML Classifier...
echo -------------------------------------------------------------------------------

if exist "%SRC_DIR%\ml_classifier.py" (
    python -c "import sys; sys.path.insert(0, r'%SRC_DIR%'); from ml_classifier import RecursiveClassifier; c = RecursiveClassifier(); print('[√] ML Classifier initialized successfully')" 2>nul
    if %errorLevel% neq 0 (
        echo [!] Warning: ML Classifier initialization had issues
        echo [i] ML features may not work correctly
    ) else (
        echo [√] ML Classifier ready - False positive reduction enabled
    )
) else (
    echo [!] ML Classifier not available (ml_classifier.py missing)
    echo [i] Depurador will run with heuristics only
)

echo.
echo ===============================================================================
echo                        INSTALLATION COMPLETE
echo ===============================================================================
echo.

if "%FILES_OK%"=="0" (
    echo [!] WARNING: Some required files are missing
    echo [!] Please ensure all Python files are in the src\ directory
    echo.
    pause
    exit /b 1
)

echo [√] All systems ready
echo [√] Virtual environment: %VENV_DIR%
echo [√] Project directory: %PROJECT_DIR%
if exist "%SRC_DIR%\ml_classifier.py" (
    echo [√] ML Classifier: ENABLED
) else (
    echo [!] ML Classifier: DISABLED
)
echo.
echo ===============================================================================
echo.

:: Ask user if they want to start the scanner
choice /C YN /M "Do you want to start Depurador v2.0 now"
if errorlevel 2 goto :end
if errorlevel 1 goto :run

:run
cls
echo.
echo ===============================================================================
echo                  LAUNCHING DEPURADOR v2.0 SCANNER
echo ===============================================================================
echo.

cd /d "%SRC_DIR%"
python main.py

goto :end

:end
echo.
echo ===============================================================================
echo.
echo [i] To run Depurador later, use:
echo     %VENV_DIR%\Scripts\activate.bat
echo     cd %SRC_DIR%
echo     python main.py
echo.
echo [i] Or simply run: run_depurador.bat
echo.
if exist "%PROJECT_DIR%\demo_ml_classifier.py" (
    echo [i] To test ML Classifier, run:
    echo     python demo_ml_classifier.py
    echo.
)
echo ===============================================================================
echo.
pause
endlocal