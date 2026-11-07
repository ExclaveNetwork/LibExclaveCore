@echo off

setlocal

set FLAVOR=%1

if "%FLAVOR%"=="ossRelease" goto :ossRelease
if "%FLAVOR%"=="legacyRelease" goto :legacyRelease
if "%FLAVOR%"=="ossDebug" goto :ossDebug
if "%FLAVOR%"=="legacyDebug" goto :legacyDebug
set FLAVOR=ossRelease
goto :ossRelease

:ossRelease
set CGO_LDFLAGS="-Wl,-z,max-page-size=16384,--pack-dyn-relocs=android"
set ANDROID_API=24
set LDFLAGS="-s -buildid="
goto :end_flavor

:legacyRelease
set CGO_LDFLAGS="-Wl,-z,max-page-size=16384"
set ANDROID_API=21
set LDFLAGS="-s -buildid="
goto :end_flavor

:ossDebug
set CGO_LDFLAGS="-Wl,-z,max-page-size=16384,--pack-dyn-relocs=android"
set ANDROID_API=24
set LDFLAGS=""
goto :end_flavor

:legacyDebug
set CGO_LDFLAGS="-Wl,-z,max-page-size=16384"
set ANDROID_API=21
set LDFLAGS=""
goto :end_flavor

:end_flavor

pushd %~dp0

gomobile bind -v -androidapi %ANDROID_API% -trimpath -ldflags=%LDFLAGS% -tags="with_clash" -o "./libexclavecore-%FLAVOR%.aar" "github.com/exclavenetwork/libexclavecore"
if errorlevel 1 (
    goto :end
)

set "proj=..\..\app\libs"

if exist "%proj%" (
    copy /Y "./libexclavecore-%FLAVOR%.aar" "%proj%"
)

:end

popd

endlocal
