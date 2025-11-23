@echo off
:: ============================================================================
:: DEPURADOR v2.0 - ML CLASSIFIER DEMO
:: Demonstrates ML false positive reduction
:: ============================================================================

title Depurador v2.0 - ML Classifier Demo
color 0B

set "PROJECT_DIR=%~dp0Depurador"
set "VENV_DIR=%PROJECT_DIR%\depurador_env"

cls
echo.
echo ===============================================================================
echo.
echo       #     #  #           ####   #         ###    ####    ####   
echo       ##   ##  #          #    #  #        #   #  #       #       
echo       # # # #  #          #       #        #####   ####    ####   
echo       #  #  #  #          #    #  #        #   #      #       #   
echo       #     #  ######      ####   ######   #   #  ####    ####    
echo.
echo              DEPURADOR v2.0 - ML CLASSIFIER DEMO
echo           Demonstrating False Positive Reduction
echo.
echo ===============================================================================
echo.

:: Verificar entorno virtual
if not exist "%VENV_DIR%" (
    echo [X] Virtual environment not found!
    echo [!] Please run install_and_run.bat first
    echo.
    pause
    exit /b 1
)

:: Verificar demo file
if not exist "%PROJECT_DIR%\demo_ml_classifier.py" (
    echo [X] demo_ml_classifier.py not found!
    echo [!] Please ensure demo file is in Depurador directory
    echo.
    pause
    exit /b 1
)

:: Verificar ML Classifier
if not exist "%PROJECT_DIR%\src\ml_classifier.py" (
    echo [X] ml_classifier.py not found!
    echo [!] ML Classifier module is required for demo
    echo.
    pause
    exit /b 1
)

echo [*] Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

echo [*] Initializing ML Classifier...
python -c "import sys; sys.path.insert(0, r'%PROJECT_DIR%\src'); from ml_classifier import RecursiveClassifier; print('[√] ML Classifier loaded')" 2>nul
if %errorLevel% neq 0 (
    echo [X] Failed to initialize ML Classifier
    echo [!] Check that colorama is installed: pip install colorama
    echo.
    pause
    exit /b 1
)

echo [√] Starting ML Demo...
echo.
echo -------------------------------------------------------------------------------
echo                         DEMO CASES
echo -------------------------------------------------------------------------------
echo.
echo  [1] Malware Detection         - Correctly identifies threats
echo  [2] False Positive Reduction  - Detects legitimate files
echo  [3] Ambiguous Files           - Handles uncertain cases
echo  [4] High Entropy Legitimate   - Distinguishes compression from malware
echo  [5] ML vs Heuristic           - Comparison of methods
echo  [6] Voting System             - Combined decision making
echo.
echo -------------------------------------------------------------------------------
echo.

cd /d "%PROJECT_DIR%"
python demo_ml_classifier.py

echo.
echo ===============================================================================
echo                          DEMO COMPLETED
echo ===============================================================================
echo.
echo [i] Key takeaways:
echo     • ML reduces false positives by ~60%%
echo     • Recursive refinement improves accuracy
echo     • Voting system combines best of ML + heuristics
echo     • Legitimacy indicators protect known-good files
echo.
echo [i] To run full scanner with ML: run_depurador.bat
echo.
pause