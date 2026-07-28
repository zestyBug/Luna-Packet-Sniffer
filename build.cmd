@echo off
setlocal

set "ROOT=%~dp0"
set "VS_INSTALL=%ProgramFiles%\Microsoft Visual Studio\18\Community"

if not exist "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" (
    echo Visual Studio 2026 Community with the C++ desktop tools was not found.
    exit /b 1
)

call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b %errorlevel%

set "PATH=%VS_INSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"

pushd "%ROOT%"

echo Building native dependencies...
cmake --preset windows-x64
if errorlevel 1 goto :error

cmake --build --preset windows-x64-debug
if errorlevel 1 goto :error

echo Building LunaPacketSniffer...
dotnet build LunaPacketSniffer.sln --configuration Debug --no-restore
if errorlevel 1 goto :error

popd
echo Build completed successfully.
exit /b 0

:error
set "BUILD_ERROR=%errorlevel%"
popd
exit /b %BUILD_ERROR%
