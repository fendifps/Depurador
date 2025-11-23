@echo off
title Apagar venv - Depurador v2.0
color 0C

echo =======================================================================
echo            SHUTDOWN SCRIPT - DEPURADOR VIRTUAL ENVIRONMENT
echo =======================================================================
echo.

echo [i] Closing any Python processes using the virtual environment...
taskkill /IM python.exe /F >nul 2>&1

echo.
echo [√] Virtual environment has been successfully turned OFF
echo [i] All Python processes have been terminated.
echo.

echo =======================================================================
echo               Depurador v2.0 - Environment Shutdown
echo =======================================================================
echo.
pause
