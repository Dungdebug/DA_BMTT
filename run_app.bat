@echo off
title He Thong Phat Hien Ma Doc Lai (DA_BMTT)
chcp 65001 >nul
echo ======================================================================
echo   HE THONG PHAT HIEN MA DOC LAI (HYBRID MALWARE DETECTOR) - DA_BMTT
echo ======================================================================
echo.

cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    echo [INFO] Dang su dung moi truong ao (.venv)...
    start http://127.0.0.1:5000
    ".venv\Scripts\python.exe" app.py
) else (
    echo [INFO] Dang su dung Python he thong...
    start http://127.0.0.1:5000
    python app.py
)

pause
