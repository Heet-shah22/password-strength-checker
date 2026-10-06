@echo off
title MIT-WPU Password Strength Checking Simulation
cls
echo ======================================================================
echo  MIT - WORLD PEACE UNIVERSITY ^| CSE (Cyber Security and Forensics)
echo  PASSWORD STRENGTH CHECKING SIMULATION PLATFORM
echo  Student: Heet Shah ^| Roll No: 35 ^| PRN: 1262243024
echo ======================================================================
echo.
echo Launching Interactive Simulation Dashboard...
start http://localhost:3000
echo.
echo If the server is not already active, starting local Node.js server...
node server.js
pause
