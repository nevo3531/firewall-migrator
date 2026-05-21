@echo off
title FireWall Migrator Pro - Build EXE
color 0A
echo.
echo  ==========================================
echo    FireWall Migrator Pro -- Build EXE
echo  ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python לא נמצא!
    echo         הורד מ: https://python.org/downloads
    echo         חשוב: סמן "Add Python to PATH" בהתקנה
    pause & exit /b 1
)
echo [OK] Python: 
python --version

echo.
echo [1/3] מתקין תלויות Python...
pip install flask flask-cors paramiko pyinstaller --quiet
if %errorlevel% neq 0 (
    echo [WARN] שגיאה בהתקנה, מנסה שוב...
    pip install flask flask-cors paramiko pyinstaller
)

echo.
echo [2/3] בונה EXE...
echo       (זה עשוי לקחת 2-5 דקות)
echo.
pyinstaller firewall_migrator.spec --clean --noconfirm

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] הבנייה נכשלה!
    pause & exit /b 1
)

echo.
echo [3/3] הושלם!
echo.
echo  ==========================================
echo    הקובץ נמצא ב:
echo    dist\FirewallMigratorPro.exe
echo  ==========================================
echo.
echo  לחיצה כפולה על ה-EXE תפתח את האפליקציה
echo  בדפדפן אוטומטית.
echo.

if exist dist\FirewallMigratorPro.exe (
    echo האם לפתוח את תיקיית הפלט? [Y/N]
    set /p choice=
    if /i "%choice%"=="Y" explorer dist
)
pause
