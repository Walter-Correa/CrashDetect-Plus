@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo  CrashDetect Plus - Building with MSVC (Win32 / x86)
echo ========================================================

cd /d "%~dp0"

:: Auto-detect CMake in PATH, WinGet, or Visual Studio 2022
where cmake >nul 2>nul
if errorlevel 1 (
    for /d %%D in ("%LOCALAPPDATA%\Microsoft\WinGet\Packages\Kitware.CMake_*") do (
        for /d %%C in ("%%D\cmake-*\bin") do (
            if exist "%%C\cmake.exe" set "PATH=%%C;!PATH!"
        )
    )
)
where cmake >nul 2>nul
if errorlevel 1 (
    for %%E in (BuildTools Community Professional Enterprise) do (
        if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
            set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;!PATH!"
        ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
            set "PATH=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;!PATH!"
        )
    )
)

where cmake >nul 2>nul
if errorlevel 1 (
    echo [ERROR] CMake could not be found. Please ensure CMake or Visual Studio 2022 is installed.
    exit /b 1
)

:: 1. Configure & Build Win32 (x86 - SA-MP 0.3.7/DL + open.mp x86)
echo.
echo [1/4] Configuring CMake (Win32 / x86)...
cmake -B "build-msvc" -G "Visual Studio 17 2022" -A Win32
if errorlevel 1 (
    echo [ERROR] Win32 CMake configuration failed.
    exit /b %errorlevel%
)

echo [2/4] Compiling Win32 Release binaries...
cmake --build "build-msvc" --config Release
if errorlevel 1 (
    echo [ERROR] Win32 compilation failed.
    exit /b %errorlevel%
)

echo [3/4] Running Win32 automated test suite...
ctest --test-dir "build-msvc" -C Release --output-on-failure
if errorlevel 1 (
    echo [ERROR] Win32 automated tests failed.
    exit /b %errorlevel%
)

:: 2. Package Win32 Zip archive into dist\
echo.
echo [4/4] Creating release package in dist\...
if not exist "dist" mkdir "dist"

call :PackageArch "build-msvc" "package-msvc" "dist\CrashDetect-Plus-Windows.zip"
if errorlevel 1 exit /b %errorlevel%

:: Optional deployment if target server path is passed as %1 or %OMP_SERVER_DIR%
set "TARGET_DIR=%~1"
if "%TARGET_DIR%"=="" set "TARGET_DIR=%OMP_SERVER_DIR%"

if not "%TARGET_DIR%"=="" (
    if exist "%TARGET_DIR%" (
        echo.
        echo Deploying Win32 binaries ^& include to: %TARGET_DIR%
        if exist "build-msvc\components\crashdetect.dll" if exist "%TARGET_DIR%\components" copy /Y "build-msvc\components\crashdetect.dll" "%TARGET_DIR%\components\crashdetect.dll" >nul
        if exist "build-msvc\plugins\crashdetect.dll" if exist "%TARGET_DIR%\plugins" copy /Y "build-msvc\plugins\crashdetect.dll" "%TARGET_DIR%\plugins\crashdetect.dll" >nul
        if exist "crashdetect.inc" if exist "%TARGET_DIR%\pawno\include" copy /Y "crashdetect.inc" "%TARGET_DIR%\pawno\include\crashdetect.inc" >nul
        if exist "crashdetect.inc" if exist "%TARGET_DIR%\qawno\include" copy /Y "crashdetect.inc" "%TARGET_DIR%\qawno\include\crashdetect.inc" >nul
        echo Deployment complete.
    )
)

:: Clean temporary build folders so repository stays clean
if exist "build-msvc" rmdir /s /q "build-msvc"

echo.
echo [SUCCESS] Package created:
echo   - dist\CrashDetect-Plus-Windows.zip (x86 Plugin + open.mp Component)
echo ========================================================
echo  Build ^& verification finished successfully!
echo ========================================================
exit /b 0

:PackageArch
set "SRC_BUILD=%~1"
set "STAGE_DIR=%~2"
set "ZIP_OUT=%~3"

if exist "%STAGE_DIR%" rmdir /s /q "%STAGE_DIR%"
mkdir "%STAGE_DIR%\plugins"
mkdir "%STAGE_DIR%\components"
mkdir "%STAGE_DIR%\include"

if exist "%SRC_BUILD%\plugins\crashdetect.dll" (
    copy /Y "%SRC_BUILD%\plugins\crashdetect.dll" "%STAGE_DIR%\plugins\crashdetect.dll" >nul
)
if exist "%SRC_BUILD%\components\crashdetect.dll" (
    copy /Y "%SRC_BUILD%\components\crashdetect.dll" "%STAGE_DIR%\components\crashdetect.dll" >nul
)
if exist "crashdetect.inc" (
    copy /Y "crashdetect.inc" "%STAGE_DIR%\include\crashdetect.inc" >nul
)
if exist "crashdetect_example.pwn" (
    copy /Y "crashdetect_example.pwn" "%STAGE_DIR%\crashdetect_example.pwn" >nul
)
if exist "LICENSE" (
    copy /Y "LICENSE" "%STAGE_DIR%\LICENSE" >nul
)
if exist "THIRD_PARTY_NOTICES.txt" (
    copy /Y "THIRD_PARTY_NOTICES.txt" "%STAGE_DIR%\THIRD_PARTY_NOTICES.txt" >nul
)

if exist "%ZIP_OUT%" del /f /q "%ZIP_OUT%"
where tar.exe >nul 2>nul
if not errorlevel 1 (
    tar.exe -a -c -f "%ZIP_OUT%" -C "%STAGE_DIR%" *
) else (
    powershell -NoProfile -Command "Compress-Archive -Path '%STAGE_DIR%\*' -DestinationPath '%ZIP_OUT%' -Force"
)

if exist "%STAGE_DIR%" rmdir /s /q "%STAGE_DIR%"
exit /b 0
