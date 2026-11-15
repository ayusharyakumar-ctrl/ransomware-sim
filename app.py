"""Ransomware Simulation & Detection System - Flask backend.

Pipeline:  Upload -> Sandbox -> Simulate -> Monitor (watchdog) -> Detect (heuristics + ML)
           -> Alerts -> Dashboard

Run locally:   python app.py      then open http://127.0.0.1:8000
"""
import csv
import io
import json
import os
import re
import shutil
import sqlite3
import time
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.utils import secure_filename

from backend import detector, ml_model, simulator
from backend.report_pdf import build_pdf
from backend.entropy import file_entropy
from backend.monitor import SandboxMonitor
from backend.url_checker import check_url

BASE = os.path.dirname(os.path.abspath(__file__))
SANDBOX_ROOT = os.path.join(BASE, "sandbox")
LOG_DIR = os.path.join(BASE, "logs")
SAMPLES_DIR = os.path.join(BASE, "sample_files")
DB_PATH = os.path.join(LOG_DIR, "history.db")

MAX_FILES = 25
MAX_FILE_MB = 5
SESSION_RE = re.compile(r"^[a-f0-9]{16,32}$")

os.makedirs(SANDBOX_ROOT, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILES * MAX_FILE_MB * 1024 * 1024

monitor = SandboxMonitor(SANDBOX_ROOT)
monitor.start()
ml_model.load()


# ------------------------------------------------------------------ storage (SQLite)
def db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT, time TEXT, mode TEXT,
        files INTEGER, rename_rate REAL, entropy_after REAL, speed REAL,
        score INTEGER, level TEXT, ml_probability REAL)""")
    return con


def write_log(session, level, message):
    line = f"{datetime.now().isoformat(timespec='seconds')} [{session[:8]}] {level}: {message}\n"
    with open(os.path.join(LOG_DIR, "activity.log"), "a") as f:
        f.write(line)


# ------------------------------------------------------------------ helpers
def session_dir():
    sid = request.headers.get("X-Session-Id", "")
    if not SESSION_RE.match(sid):
        raise ValueError("Missing or invalid session id")
    d = os.path.join(SANDBOX_ROOT, sid)
    os.makedirs(os.path.join(d, "files"), exist_ok=True)
    return sid, d


def cleanup_old_sessions(max_age_s=3 * 3600):
    now = time.time()
    for name in os.listdir(SANDBOX_ROOT):
        p = os.path.join(SANDBOX_ROOT, name)
        if os.path.isdir(p) and now - os.path.getmtime(p) > max_age_s:
            shutil.rmtree(p, ignore_errors=True)
    monitor.prune()


def file_list(d):
    files_dir = os.path.join(d, "files")
    out = []
    for name in simulator.list_files(d):
        p = os.path.join(files_dir, name)
        out.append({"name": name, "size": os.path.getsize(p), "entropy": file_entropy(p)})
    return out


@app.errorhandler(ValueError)
def bad_request(e):
    return jsonify({"error": str(e)}), 400


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"Upload too large (max {MAX_FILE_MB} MB per file)"}), 413


# ------------------------------------------------------------------ pages
@app.route("/")
def index():
    return render_template("index.html")


# ------------------------------------------------------------------ API
@app.get("/api/state")
def state():
    sid, d = session_dir()
    return jsonify({"files": file_list(d), "simulated": simulator.is_simulated(d),
                    "modes": simulator.MODES})


@app.post("/api/upload")
def upload():
    sid, d = session_dir()
    cleanup_old_sessions()
    simulator.restore(d)
    files_dir = os.path.join(d, "files")
    incoming = request.files.getlist("files")
    if not incoming:
        raise ValueError("No files received")
    existing = len(simulator.list_files(d))
    saved = []
    for f in incoming:
        if existing + len(saved) >= MAX_FILES:
            break
        name = secure_filename(f.filename or "")
        if not name:
            continue
        data = f.read()
        if len(data) > MAX_FILE_MB * 1024 * 1024:
            continue
        with open(os.path.join(files_dir, name), "wb") as out:
            out.write(data)
        saved.append(name)
    write_log(sid, "INFO", f"Loaded {len(saved)} file(s) into sandbox: {', '.join(saved)}")
    return jsonify({"saved": saved, "files": file_list(d)})


@app.post("/api/samples")
def load_samples():
    sid, d = session_dir()
    simulator.restore(d)
    files_dir = os.path.join(d, "files")
    names = []
    for name in sorted(os.listdir(SAMPLES_DIR)):
        src = os.path.join(SAMPLES_DIR, name)
        if os.path.isfile(src) and not name.startswith("."):
            shutil.copy(src, os.path.join(files_dir, name))
            names.append(name)
    write_log(sid, "INFO", f"Loaded {len(names)} sample file(s) into sandbox")
    return jsonify({"saved": names, "files": file_list(d)})


@app.post("/api/simulate")
def simulate():
    sid, d = session_dir()
    mode = (request.get_json(silent=True) or {}).get("mode", "ransomware")
    total = len(simulator.list_files(d))
    if simulator.is_simulated(d):
        simulator.restore(d)
        total = len(simulator.list_files(d))
    if total == 0:
        raise ValueError("Upload or load sample files first")

    files_dir = os.path.join(d, "files")
    originals = set(simulator.list_files(d))
    time.sleep(0.3)                      # let any restore events settle
    records, start, end = simulator.run_simulation(d, mode)
    time.sleep(0.5)                      # give watchdog time to deliver events
    events = [e for e in monitor.events_for(files_dir, since=start - 0.05) if e["time"] <= end + 0.5]

    new_files = set(simulator.list_files(d)) - originals - {r["final"] for r in records}
    detection = detector.analyze(records, events, start, end, total, new_files)
    ml = ml_model.predict(ml_model.features_from(records, detection))

    # hybrid decision: ML can escalate a SAFE result to WARNING
    final_level = detection["threat_level"]
    if ml["probability"] >= 0.8 and final_level == "SAFE":
        final_level = "WARNING"

    # ---- alerts + logs ----
    now = datetime.now().strftime("%H:%M:%S")
    alerts = []
    if final_level == "CRITICAL":
        alerts.append({"severity": "critical", "time": now,
                       "title": "Ransomware-like activity detected",
                       "detail": f"Threat score {detection['threat_score']}/100, "
                                 f"ML confidence {ml['probability']*100:.0f}%"})
    elif final_level == "WARNING":
        alerts.append({"severity": "warning", "time": now, "title": "Suspicious file activity",
                       "detail": f"Threat score {detection['threat_score']}/100, "
                                 f"ML confidence {ml['probability']*100:.0f}%"})
    for p in detection["patterns"]:
        if p["severity"] in ("critical", "warning"):
            alerts.append({"severity": p["severity"], "time": now, "title": p["name"],
                           "detail": p["detail"]})

    timeline = [{"t": round(e["time"] - start, 3), "event": e["event"],
                 "file": os.path.basename(e["src"]),
                 "dest": os.path.basename(e["dest"]) if e["dest"] else None} for e in events]
    logs = [{"time": now, "level": "INFO",
             "message": f"Simulation started: {simulator.MODES[mode]['label']} on {total} file(s)"}]
    for e in timeline:
        msg = f"[watchdog] {e['event'].upper()} {e['file']}" + (f" -> {e['dest']}" if e["dest"] else "")
        logs.append({"time": now, "level": "EVENT", "message": f"+{e['t']:.3f}s {msg}"})
    for r in records:
        logs.append({"time": now, "level": "SIM",
                     "message": f"{r['original']}: {r['action']} (entropy {r['entropy_before']} -> "
                                f"{r['entropy_after']}, {r['ms']} ms)"})
    logs.append({"time": now, "level": final_level,
                 "message": f"Detection result: {detection['verdict']} "
                            f"(score {detection['threat_score']}, ML {ml['probability']*100:.0f}%)"})
    for l in logs:
        if l["level"] in ("INFO", "SAFE", "WARNING", "CRITICAL"):
            write_log(sid, l["level"], l["message"])

    m = detection["metrics"]
    with db() as con:
        con.execute("INSERT INTO runs (session,time,mode,files,rename_rate,entropy_after,speed,score,"
                    "level,ml_probability) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (sid, datetime.now().isoformat(timespec="seconds"), mode, total, m["rename_rate"],
                     m["entropy_after"], m["speed"], detection["threat_score"], final_level,
                     ml["probability"]))

    result = {"mode": mode, "mode_label": simulator.MODES[mode]["label"], "records": records,
              "detection": detection, "ml": ml, "final_level": final_level, "alerts": alerts,
              "logs": logs, "timeline": timeline, "files": file_list(d)}
    with open(os.path.join(d, ".lastrun.json"), "w") as f:
        json.dump(result, f)
    return jsonify(result)


@app.post("/api/restore")
def restore():
    sid, d = session_dir()
    n = simulator.restore(d)
    write_log(sid, "INFO", f"Restored {n} file(s) (decrypted / renamed back)")
    return jsonify({"restored": n, "files": file_list(d)})


@app.post("/api/reset")
def reset():
    sid, d = session_dir()
    shutil.rmtree(d, ignore_errors=True)
    write_log(sid, "INFO", "Sandbox reset")
    return jsonify({"ok": True})


@app.post("/api/check-url")
def api_check_url():
    url = (request.get_json(silent=True) or {}).get("url", "")
    if not url.strip():
        raise ValueError("Enter a URL")
    return jsonify(check_url(url[:2000]))


@app.get("/api/history")
def history():
    sid, _ = session_dir()
    with db() as con:
        rows = con.execute("SELECT time,mode,files,rename_rate,entropy_after,speed,score,level,"
                           "ml_probability FROM runs WHERE session=? ORDER BY id DESC LIMIT 10",
                           (sid,)).fetchall()
    keys = ["time", "mode", "files", "rename_rate", "entropy_after", "speed", "score", "level",
            "ml_probability"]
    return jsonify([dict(zip(keys, r)) for r in rows])


@app.get("/api/ml")
def ml_info():
    m = ml_model.metrics()
    return jsonify({k: m.get(k) for k in ("model", "accuracy", "confusion_matrix", "feature_importance",
                                          "train_samples", "test_samples", "rules", "comparison")})


@app.get("/api/logs/export")
def export_logs():
    sid = request.args.get("sid", "")
    if not SESSION_RE.match(sid):
        raise ValueError("Invalid session id")
    p = os.path.join(SANDBOX_ROOT, sid, ".lastrun.json")
    if not os.path.exists(p):
        raise ValueError("Run a simulation first")
    with open(p) as f:
        run = json.load(f)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "level", "message"])
    for l in run["logs"]:
        w.writerow([l["time"], l["level"], l["message"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=detection_logs.csv"})


@app.get("/api/report.pdf")
def incident_report():
    sid = request.args.get("sid", "")
    if not SESSION_RE.match(sid):
        raise ValueError("Invalid session id")
    p = os.path.join(SANDBOX_ROOT, sid, ".lastrun.json")
    if not os.path.exists(p):
        raise ValueError("Run a simulation first")
    with open(p) as f:
        run = json.load(f)
    return Response(build_pdf(run, sid), mimetype="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=incident_report.pdf"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"\n  Ransomware Simulation & Detection System running at http://127.0.0.1:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
