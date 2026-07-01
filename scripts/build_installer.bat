@echo off
REM ThreatOne Enterprise - Installer Build Script (Windows)
REM Builds the application and packages it using Qt Installer Framework

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
set BUILD_DIR=%PROJECT_ROOT%\build
set INSTALLER_DIR=%PROJECT_ROOT%\installer
set OUTPUT_DIR=%PROJECT_ROOT%\dist

REM Build configuration
if "%BUILD_TYPE%"=="" set BUILD_TYPE=Release
if "%JOBS%"=="" set JOBS=%NUMBER_OF_PROCESSORS%

echo ================================================
echo   ThreatOne Enterprise - Installer Builder
echo ================================================
echo.

REM Step 1: Build the application
echo [1/4] Building ThreatOne Enterprise (%BUILD_TYPE%)...
cmake -B "%BUILD_DIR%" ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DCMAKE_INSTALL_PREFIX="%INSTALLER_DIR%\packages\com.threatone.core\data" ^
    "%PROJECT_ROOT%"
if errorlevel 1 (
    echo ERROR: CMake configuration failed.
    exit /b 1
)

cmake --build "%BUILD_DIR%" --config %BUILD_TYPE% -j %JOBS%
if errorlevel 1 (
    echo ERROR: Build failed.
    exit /b 1
)

REM Step 2: Install to package data directory
echo [2/4] Installing to package data directory...
cmake --install "%BUILD_DIR%" --config %BUILD_TYPE%
if errorlevel 1 (
    echo ERROR: Installation failed.
    exit /b 1
)

REM Step 3: Check for binarycreator
echo [3/4] Checking for Qt Installer Framework tools...

set BINARYCREATOR=
where binarycreator >nul 2>&1
if not errorlevel 1 (
    set BINARYCREATOR=binarycreator
    goto :found_ifw
)

if defined QT_IFW_DIR (
    if exist "%QT_IFW_DIR%\bin\binarycreator.exe" (
        set BINARYCREATOR=%QT_IFW_DIR%\bin\binarycreator.exe
        goto :found_ifw
    )
)

REM Check common Qt installation paths
for /d %%D in ("C:\Qt\Tools\QtInstallerFramework\*") do (
    if exist "%%D\bin\binarycreator.exe" (
        set BINARYCREATOR=%%D\bin\binarycreator.exe
    )
)

if "!BINARYCREATOR!"=="" (
    echo ERROR: binarycreator not found.
    echo.
    echo Please install Qt Installer Framework and either:
    echo   - Add it to your PATH
    echo   - Set QT_IFW_DIR environment variable to the IFW installation directory
    echo   - Install it to C:\Qt\Tools\QtInstallerFramework\
    echo.
    echo Download from: https://download.qt.io/official_releases/qt-installer-framework/
    exit /b 1
)

:found_ifw
echo   Found: %BINARYCREATOR%

REM Step 4: Build installer
echo [4/4] Building installer package...
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set INSTALLER_NAME=ThreatOneEnterprise-1.0.0-windows-installer.exe

"%BINARYCREATOR%" ^
    --offline-only ^
    -c "%INSTALLER_DIR%\config\config.xml" ^
    -p "%INSTALLER_DIR%\packages" ^
    "%OUTPUT_DIR%\%INSTALLER_NAME%"
if errorlevel 1 (
    echo ERROR: Installer creation failed.
    exit /b 1
)

echo.
echo ================================================
echo   Installer built successfully!
echo   Output: %OUTPUT_DIR%\%INSTALLER_NAME%
echo ================================================

endlocal
