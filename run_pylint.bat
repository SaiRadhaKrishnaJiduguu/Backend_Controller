@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

REM Set the current directory as the root directory
SET "rootDir=%cd%"

REM Loop through each folder
FOR /D %%D IN ("%rootDir%\*") DO (
    REM Extract only the folder name
    SET "folderName=%%~nxD"

    REM Check if the folder name doesn't start with a dot
    IF "!folderName:~0,1!" NEQ "." (
        REM Loop through Python files in the current folder
        FOR %%F IN ("%%D\*.py") DO (
            echo "%%F"
            pylint --disable=W0718,E0401,E0213,R0903,E1135,E1136,E0211,C0301,R1702,R0912,R0914,R0911,W0719,C0206,R0915,E0611 "%%F"
        )
    )
)

ENDLOCAL
pause
