import csv, io, json
from datetime import datetime, timezone
from database import get_db
from detector import analyze_event, should_alert

REQUIRED = {"timestamp", "source", "event_type"}

def normalize(item):
    missing = REQUIRED - set(item.keys())
    if missing:
        raise ValueError("Missing required field(s): " + ", ".join(sorted(missing)))
    return {"timestamp": str(item.get("timestamp") or datetime.now(timezone.utc).isoformat()), "source": str(item.get("source", "unknown"))[:200], "event_type": str(item.get("event_type", "unknown"))[:200], "username": str(item.get("username", ""))[:120], "source_ip": str(item.get("source_ip", ""))[:64], "details": str(item.get("details", ""))[:2000]}

def parse_upload(uploaded):
    name = uploaded.filename.lower()
    raw = uploaded.read()
    try:
        if name.endswith(".json"):
            data = json.loads(raw.decode("utf-8-sig"))
            if isinstance(data, dict): data = data.get("events", [data])
            if not isinstance(data, list): raise ValueError("JSON must be a list of event objects or an object containing an events list.")
            return [normalize(x) for x in data]
        if name.endswith(".csv"):
            reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
            return [normalize(row) for row in reader]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Could not read file. Check that it is valid UTF-8 CSV or JSON.") from exc
    raise ValueError("Only .csv and .json files are supported.")

def ingest_events(items):
    count = alert_count = 0
    with get_db() as db:
        for raw in items:
            event = normalize(raw)
            result = analyze_event(event)
            cur = db.execute("INSERT INTO events (timestamp, source, event_type, username, source_ip, details, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)", (event["timestamp"], event["source"], event["event_type"], event["username"], event["source_ip"], event["details"], result["risk_score"]))
            count += 1
            if should_alert(result):
                db.execute("INSERT INTO alerts (event_id, severity, reason, created_at) VALUES (?, ?, ?, ?)", (cur.lastrowid, result["severity"], result["reason"], datetime.now(timezone.utc).isoformat()))
                alert_count += 1
        db.commit()
    return count, alert_count
