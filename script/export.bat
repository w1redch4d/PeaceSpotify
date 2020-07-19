@echo off
setlocal enabledelayedexpansion

D:\Languages\CPP\MicrosoftVisualStudio\2022\Community\VC\Tools\MSVC\14.39.33519\bin\Hostx64\x64\dumpbin.exe /OUT:libcef.txt /exports %APPDATA%\Spotify\libcef_orig.dll

set "file=libcef.txt"
set "output=libcef_cleaned.txt"
set "header=redir.h"

rem Find the line number where "ordinal hint RVA name" occurs
for /f "tokens=1 delims=:" %%a in ('findstr /n "ordinal hint RVA name" "%file%"') do set "start_line=%%a"

rem Find the line number where "Summary" occurs
for /f "tokens=1 delims=:" %%a in ('findstr /n "  Summary" "%file%"') do set "end_line=%%a"

rem Set range of lines to keep
set /a "start_line+=1"
set /a "end_line-=1"

rem Extract lines between start and end lines and save to temp file
(for /f "usebackq skip=%start_line% delims=" %%a in ("%file%") do (
    set "line=%%a"
    if "!line!" == "  Summary" (
        goto :endLoop
    )
    echo !line!
)) > "%output%"

:endLoop
    rem Replace original file with temp file
    move /y "%output%" "%file%"

    @REM for /f "tokens=1,4" %%a in (%file%) do (
        
    @REM     echo #pragma comment(linker, "/export:%%b=libcef_orig.%%b,@%%a")
    @REM )
    python export.py
    
