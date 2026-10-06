@echo off
title Push Password Strength Checker to GitHub
cls
echo ======================================================================
echo  MIT - WORLD PEACE UNIVERSITY ^| CSE (Cyber Security and Forensics)
echo  PUSH PROJECT TO GITHUB
echo  Student: Ativeer Rajawat ^| Roll No: 35 ^| PRN: 1262243024
echo ======================================================================
echo.
cd /d "%~dp0"

git remote get-url origin >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Remote repository already configured.
    echo Pushing latest commits to GitHub...
    git push -u origin main
    goto done
)

echo Step 1: Create a new repository on GitHub:
echo   1. Go to: https://github.com/new
echo   2. Repository name: password-strength-checker (or any name you prefer)
echo   3. Leave it Public and do NOT initialize with README (already created)
echo   4. Click "Create repository"
echo.
set /p REPO_URL="Enter your GitHub Repository URL (e.g. https://github.com/Git-Heet/password-strength-checker.git): "

if "%REPO_URL%"=="" (
    echo No URL provided. Aborting.
    pause
    exit /b
)

echo.
echo Adding remote origin: %REPO_URL%
git remote add origin %REPO_URL%
echo.
echo Pushing code to GitHub...
git push -u origin main

:done
echo.
echo ======================================================================
echo  PROJECT SUCCESSFULLY PUSHED TO GITHUB!
echo ======================================================================
echo.
pause
