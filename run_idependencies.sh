#!/usr/bin/env bash
# Create/use local venv, install deps, then exit

set -e

# switch to script directory
cd "$(dirname "$0")"

if [ ! -f ".venv/bin/activate" ]; then
    python3 -m venv .venv
fi

source ".venv/bin/activate"

python3 -m pip install --upgrade pip

if [ -f requirements.txt ]; then
    #python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu128
    pip install -U -r requirements.txt
else
    echo "requirements.txt not found."
    exit 1
fi

deactivate
