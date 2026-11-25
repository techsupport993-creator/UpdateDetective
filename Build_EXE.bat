@echo off
setlocal
cd /d "%~dp0"
where dotnet >nul 2>&1
if errorlevel 1 (
  echo Install the .NET 8 SDK: winget install Microsoft.DotNet.SDK.8
  pause
  exit /b 1
)
echo Building Update Detective 1.2.0...
dotnet publish UpdateDetective.csproj -c Release --self-contained false -p:PublishSingleFile=false -p:PublishTrimmed=false -p:EnableTrimAnalyzer=false -p:EnableSingleFileAnalyzer=false -o "%~dp0Release"
if errorlevel 1 (
  echo Retrying with the official NuGet package source...
  dotnet publish UpdateDetective.csproj -c Release --self-contained false -p:PublishSingleFile=false -p:PublishTrimmed=false -p:EnableTrimAnalyzer=false -p:EnableSingleFileAnalyzer=false --source https://api.nuget.org/v3/index.json -o "%~dp0Release"
  if errorlevel 1 (
    echo BUILD FAILED. Review the output above.
    pause
    exit /b 1
  )
)
echo Build complete: Release\UpdateDetective.exe
echo Keep all files in the Release folder together.
pause
