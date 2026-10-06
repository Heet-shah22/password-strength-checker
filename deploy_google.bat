@echo off
title Deploy Password Strength Checker to Google Firebase
cls
echo ======================================================================
echo  MIT - WORLD PEACE UNIVERSITY ^| CSE (Cyber Security and Forensics)
echo  DEPLOYING TO GOOGLE CLOUD / FIREBASE HOSTING
echo  Student: Ativeer Rajawat ^| Roll No: 35 ^| PRN: 1262243024
echo ======================================================================
echo.
cd /d "%~dp0"
echo Current project directory: %cd%
echo.

echo Step 1: Checking Google authentication...
echo (A browser window will open to sign in with your Google account)
echo.
call npx -y firebase-tools login
echo.

if not exist ".firebaserc" (
    echo Step 2: Setting up Google Firebase project...
    echo You can select an existing Google Firebase project or create a new one.
    echo (Choose "Hosting: Configure files for Firebase Hosting" if prompted)
    echo.
    call npx -y firebase-tools init hosting
    echo.
)

echo Step 3: Deploying live to Google's Global CDN...
echo.
call npx -y firebase-tools deploy --only hosting
echo.
echo ======================================================================
echo  DEPLOYMENT COMPLETE!
echo  Your project is now live on Google's worldwide network (.web.app).
echo ======================================================================
echo.
pause
