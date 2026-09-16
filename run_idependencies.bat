@echo off
REM Use specific python to create/use local venv, install deps

set "PYTHON_EXE=C:\Users\Adan\Documents\Temporal\python311\python.exe"

REM switch to script directory
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" (
    "%PYTHON_EXE%" -m venv .venv
)

call ".venv\Scripts\activate.bat"

python -m pip install --upgrade pip

if exist requirements.txt (
    rem python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu128
    pip install -U -r requirements.txt
) else (
    echo requirements.txt not found.
    exit 1
)

deactivate
