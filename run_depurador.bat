@echo off
:: ============================================================================
:: DEPURADOR v2.0 - QUICK RUN SCRIPT
:: Ejecuta Depurador después de la instalación
:: With ML Classifier Support
:: ============================================================================

title Depurador v2.0 - Quick Run
color 0A

set "PROJECT_DIR=%~dp0Depurador"
set "VENV_DIR=%PROJECT_DIR%\depurador_env"
set "SRC_DIR=%PROJECT_DIR%\src"

echo.
echo ===============================================================================
echo                DEPURADOR v2.0 - MALWARE SCANNER
echo              WITH ML CLASSIFIER INTEGRATION
echo ===============================================================================
echo.

:: Verificar que existe el entorno virtual
if not exist "%VENV_DIR%" (
    echo [X] Virtual environment not found!
    echo [!] Please run install_and_run.bat first
    echo.
    pause
    exit /b 1
)

:: Verificar que existen los archivos
if not exist "%SRC_DIR%\main.py" (
    echo [X] main.py not found in src directory!
    echo [!] Please ensure all files are in the correct location
    echo.
    pause
    exit /b 1
)

echo [*] Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

:: Verificar ML Classifier
echo [*] Checking ML Classifier status...
if exist "%SRC_DIR%\ml_classifier.py" (
    python -c "import sys; sys.path.insert(0, r'%SRC_DIR%'); from ml_classifier import RecursiveClassifier; print('[√] ML Classifier: ENABLED')" 2>nul
    if %errorLevel% neq 0 (
        echo [!] ML Classifier: DISABLED (initialization error)
    )
) else (
    echo [!] ML Classifier: DISABLED (ml_classifier.py not found)
    echo [i] Download ml_classifier.py to enable ML features
)

echo [*] Starting Depurador v2.0...
echo.

cd /d "%SRC_DIR%"
python main.py

echo.
echo ===============================================================================
echo                       DEPURADOR v2.0 CLOSED
echo ===============================================================================
echo.

:: Mostrar opciones adicionales
if exist "%PROJECT_DIR%\demo_ml_classifier.py" (
    echo [i] Additional options:
    echo     - Run ML demo: python demo_ml_classifier.py
    echo     - Run tests: python test_suite.py
    echo.
)

pause