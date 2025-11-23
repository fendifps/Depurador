@echo off
:: ============================================================================
:: DEPURADOR - QUICK RUN SCRIPT
:: Ejecuta Depurador después de la instalación
:: ============================================================================

title Depurador - Quick Run
color 0A

set "PROJECT_DIR=%~dp0Depurador"
set "VENV_DIR=%PROJECT_DIR%\depurador_env"
set "SRC_DIR=%PROJECT_DIR%\src"

echo.
echo ===============================================================================
echo                    DEPURADOR - MALWARE SCANNER
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

echo [*] Starting Depurador...
echo.

cd /d "%SRC_DIR%"
python main.py

echo.
echo ===============================================================================
echo                         DEPURADOR CLOSED
echo ===============================================================================
echo.
pause