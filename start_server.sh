#!/bin/bash
set -a
source .env
set +a
source .venv/bin/activate
exec python main.py
