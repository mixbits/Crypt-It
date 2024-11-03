@echo off

:: Check if venv exists and activate it if found
if exist venv\Scripts\activate (
    call venv\Scripts\activate
    echo Activated existing virtual environment "venv"
) else (
    echo Virtual environment "venv" not found, creating a new one...
    python -m venv venv
)

:: Run the GLBtoOBJ.py script and keep the command prompt open
start "GLBtoOBJ Converter" python GLBtoOBJ.py
