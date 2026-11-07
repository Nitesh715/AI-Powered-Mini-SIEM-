# AI-Powered Mini SIEM

A beginner-friendly Security Information and Event Management (SIEM) learning project. It imports security events from CSV/JSON, stores them in SQLite, applies explainable risk-scoring rules, and displays events and alerts in a Flask dashboard.

> Educational prototype, not a production SIEM. Detection currently uses transparent rule-based scoring; it is not a trained AI model.

## Features
- Dashboard with event and alert counts
- CSV and JSON event ingestion
- SQLite event and alert storage
- Explainable detection for failed logins, scanning, malware indicators, privilege changes, and suspicious script execution
- Alert severity and acknowledgement
- Searchable event list and built-in demo dataset
- Health endpoint at /health

## Requirements
- Python 3.10 or newer
- Windows, macOS, or Linux

## Run on Windows (PowerShell)

    py -m venv .venv
    .\\.venv\\Scripts\\Activate.ps1
    python -m pip install -r requirements.txt
    python app.py

If PowerShell blocks activation, run this in the current terminal:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Open http://127.0.0.1:5000 and click Load demo events.

## Run on Linux/macOS

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python app.py

## Import logs
Use the Ingest page to upload UTF-8 CSV or JSON. Required fields: timestamp, source, event_type. Optional fields: username, source_ip, details.

## Project structure
- app.py, database.py, detector.py, ingest.py
- requirements.txt and README.md
- data/ sample CSV and JSON files
- templates/ Flask HTML pages
- static/ stylesheet

## Detection logic
The prototype assigns risk points to recognizable event patterns. Rules are explainable so students can inspect and extend them. Private IP addresses are not treated as malicious by themselves. A future enhancement could add an ML model trained on a suitable labelled dataset.

## Safety and privacy
- Only ingest logs you are authorized to access.
- Do not upload logs containing passwords, tokens, or personal data.
- Run locally; do not expose the Flask development server to the public internet.
- Change the default SECRET_KEY and use a production WSGI server before real deployment.
