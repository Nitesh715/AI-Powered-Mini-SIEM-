from flask import Flask, render_template, request, redirect, url_for, flash
from database import init_db, get_db
from detector import analyze_event
from ingest import parse_upload, ingest_events
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
init_db()

@app.route("/")
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    open_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE status='Open'").fetchone()[0]
    critical = db.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical' AND status='Open'").fetchone()[0]
    recent = db.execute("""SELECT e.*, a.id AS alert_id, a.severity, a.reason, a.status
                           FROM events e LEFT JOIN alerts a ON a.event_id=e.id
                           ORDER BY e.id DESC LIMIT 12""").fetchall()
    by_severity = db.execute("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity").fetchall()
    return render_template("dashboard.html", total=total, open_alerts=open_alerts,
                           critical=critical, recent=recent, by_severity=by_severity)

@app.route("/events")
def events():
    db = get_db()
    q = request.args.get("q", "").strip()
    if q:
        rows = db.execute("""SELECT * FROM events WHERE source LIKE ? OR event_type LIKE ?
                             OR username LIKE ? OR source_ip LIKE ? ORDER BY id DESC LIMIT 200""",
                          tuple([f"%{q}%"]*4)).fetchall()
    else:
        rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("events.html", events=rows, q=q)

@app.route("/alerts")
def alerts():
    db = get_db()
    status = request.args.get("status", "")
    if status in ("Open", "Acknowledged"):
        rows = db.execute("""SELECT a.*, e.timestamp, e.source, e.event_type, e.username, e.source_ip
                             FROM alerts a JOIN events e ON e.id=a.event_id
                             WHERE a.status=? ORDER BY a.id DESC""", (status,)).fetchall()
    else:
        rows = db.execute("""SELECT a.*, e.timestamp, e.source, e.event_type, e.username, e.source_ip
                             FROM alerts a JOIN events e ON e.id=a.event_id ORDER BY a.id DESC""").fetchall()
    return render_template("alerts.html", alerts=rows, status=status)

@app.post("/alerts/<int:alert_id>/ack")
def acknowledge(alert_id):
    db = get_db()
    db.execute("UPDATE alerts SET status='Acknowledged' WHERE id=?", (alert_id,))
    db.commit()
    flash("Alert acknowledged.", "success")
    return redirect(url_for("alerts"))

@app.route("/ingest", methods=["GET", "POST"])
def ingest():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Choose a CSV or JSON file first.", "error")
            return redirect(url_for("ingest"))
        try:
            events_list = parse_upload(uploaded)
            count, alert_count = ingest_events(events_list)
            flash(f"Imported {count} events and generated {alert_count} alerts.", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("ingest"))
    return render_template("ingest.html")

@app.post("/demo")
def load_demo():
    path = os.path.join(app.root_path, "data", "sample_events.json")
    import json
    with open(path, encoding="utf-8") as f:
        items = json.load(f)
    count, alert_count = ingest_events(items)
    flash(f"Loaded {count} demo events and generated {alert_count} alerts.", "success")
    return redirect(url_for("dashboard"))

@app.route("/health")
def health():
    return {"status": "ok", "service": "AI-Powered Mini SIEM"}

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
