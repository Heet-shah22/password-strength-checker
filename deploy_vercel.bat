@echo off
title Deploy Password Strength Checker to Vercel
cls
echo ======================================================================
echo  PASSWORD STRENGTH CHECKING SYSTEM
echo  DEPLOYING TO VERCEL PLATFORM
echo ======================================================================
echo.
cd /d "%~dp0"
echo Current project directory: %cd%
echo.
echo Step 1: Logging into Vercel...
echo (A browser window may open to verify your account)
echo.
call npx vercel login
echo.
echo Step 2: Deploying project...
call npx vercel
echo.
pause
