#!/bin/bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="postgresql://username:password@localhost:5432/yourdbname"
unset DATABASE_URL
python app.py
