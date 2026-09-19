@echo off

REM switch to script directory
cd /d "%~dp0"

call ".venv\Scripts\activate.bat"

python main.py 37976
python main.py 32484
python main.py 13044
python main.py 37360
python main.py 37220
python main.py 35068

deactivate
