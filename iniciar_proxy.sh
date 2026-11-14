#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
set -a
source .env
set +a
mitmdump --mode reverse:http://127.0.0.1:9000 -p 8000 -s proxy_mitm.py
