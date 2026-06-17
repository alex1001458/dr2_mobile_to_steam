@echo off
title Danganronpa 2 Mobile to Steam Save Converter
cd /d "%~dp0"
echo Danganronpa 2 Mobile to Steam Save Converter
echo.
echo This creates candidate savedata.vfs files. It will not modify your inputs.
echo Back up your Steam saves and disable Steam Cloud before testing.
echo.
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 dr2_mobile_to_steam.py wizard
) else (
    python dr2_mobile_to_steam.py wizard
)
echo.
pause
