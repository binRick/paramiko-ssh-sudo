#!/bin/bash
set -e
MODULES="paramiko colorclass"
python3 -m venv .venv
source .venv/bin/activate
pip install $MODULES
