@echo off
title Huan Luyen Toan Bo 3 Thuat Toan AI (DA_BMTT)
chcp 65001 >nul
echo ======================================================================
echo   HUAN LUYEN TOAN BO 3 THUAT TOAN AI: RANDOM FOREST, KNN, SVM
echo ======================================================================
echo.

cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    echo [INFO] Dang su dung moi truong ao (.venv)...
    ".venv\Scripts\python.exe" train_all.py
) else (
    echo [INFO] Dang su dung Python he thong...
    python train_all.py
)

pause
