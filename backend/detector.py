"""Detection Engine (heuristics).

Takes what the Monitoring Module observed and scores it with simple, explainable
threshold rules - the behaviour-based approach described in the report:

  Rule 1  Rename rate        - how many of the files were renamed
  Rule 2  Entropy            - did file contents become near-random (encrypted)?
  Rule 3  Modification speed - how many files were changed per minute
  Rule 4  Extension changes  - were files given ransomware-style extensions?

Each rule adds points to a threat score (0-100):
   0-29  SAFE      -> no alert
  30-69  WARNING   -> warning alert
  70-100 CRITICAL  -> critical "Ransomware-like activity" alert
"""
import os

# ---- thresholds (tweak these and explain them in the viva) ----
RENAME_CRITICAL = 70      # % of files renamed
RENAME_WARNING = 40
HIGH_ENTROPY = 7.5        # bits per byte (8.0 = perfectly random)
SPEED_CRITICAL = 300      # files modified per minute
SPEED_WARNING = 100
RANSOM_EXTS = {".locked", ".enc", ".crypt", ".encrypted", ".crypted"}
NOTE_WORDS = ("readme", "restore", "decrypt", "recover", "ransom", "how_to", "instructions")
NOTE_EXTS = (".txt", ".html", ".hta", ".rtf")


def is_ransom_note(name):
    n = name.lower()
    return n.endswith(NOTE_EXTS) and any(w in n for w in NOTE_WORDS)


def _level(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 30:
        return "WARNING"
    return "SAFE"


def analyze(records, events, start, end, total_files, new_files=()):
    total_files = max(total_files, 1)

    # ransom notes = NEW files whose names look like recovery instructions
    notes = {os.path.basename(e["src"]) for e in events
             if e["event"] == "created" and is_ransom_note(os.path.basename(e["src"]))}
    notes |= {n for n in new_files if is_ransom_note(n)}
    events = [e for e in events if os.path.basename(e["src"]) not in notes]

    # ---------- Monitoring metrics (from watchdog events) ----------
    renamed = {os.path.basename(e["src"]) for e in events if e["event"] == "renamed"}
    touched = {os.path.basename(e["src"]) for e in events
               if e["event"] in ("modified", "renamed")}
    source = "watchdog"
    if not touched:  # fallback if the OS did not deliver events in time
        renamed = {r["original"] for r in records if r["renamed"]}
        touched = {r["original"] for r in records}
        source = "simulator log"

    duration = max(end - start, 0.5)
    rename_rate = round(len(renamed) / total_files * 100, 1)
    speed = round(len(touched) / duration * 60, 1)

    changed = [r for r in records if r["content_changed"]]
    avg_before = round(sum(r["entropy_before"] for r in records) / len(records), 2) if records else 0
    avg_after = round(sum(r["entropy_after"] for r in records) / len(records), 2) if records else 0
    high_ent = [r for r in changed if r["entropy_after"] >= HIGH_ENTROPY]
    high_ent_ratio = len(high_ent) / total_files

    ext_changes = [r for r in records
                   if os.path.splitext(r["original"])[1] != os.path.splitext(r["final"])[1]]
    ransom_ext = [r for r in ext_changes
                  if os.path.splitext(r["final"])[1].lower() in RANSOM_EXTS]

    # ---------- Heuristic rules ----------
    score, patterns = 0, []

    def hit(points, name, severity, detail):
        nonlocal score
        score += points
        patterns.append({"name": name, "severity": severity, "points": points, "detail": detail})

    # Rule 1 - rename rate
    if rename_rate >= RENAME_CRITICAL:
        hit(35, "Mass file renaming", "critical",
            f"{len(renamed)}/{total_files} files renamed ({rename_rate}%) - above {RENAME_CRITICAL}% threshold")
    elif rename_rate >= RENAME_WARNING:
        hit(25, "Bulk file renaming", "warning",
            f"{len(renamed)}/{total_files} files renamed ({rename_rate}%) - above {RENAME_WARNING}% threshold")
    elif rename_rate > 0:
        hit(5, "Some files renamed", "info", f"{len(renamed)} file(s) renamed")

    # Rule 2 - entropy
    if high_ent_ratio >= 0.5:
        hit(35, "High entropy increase (likely encryption)", "critical",
            f"{len(high_ent)} file(s) now have entropy >= {HIGH_ENTROPY}/8 "
            f"(avg {avg_before} -> {avg_after})")
    elif high_ent:
        hit(15, "High entropy content", "warning",
            f"{len(high_ent)} file(s) rewritten with near-random data")

    # Rule 3 - modification speed
    if len(touched) >= 2 and speed >= SPEED_CRITICAL:
        hit(20, "Rapid file modification", "critical",
            f"{speed} files/min - above {SPEED_CRITICAL} files/min threshold")
    elif len(touched) >= 1 and speed >= SPEED_WARNING:
        hit(10, "Fast file modification", "warning",
            f"{speed} files/min - above {SPEED_WARNING} files/min threshold")

    # Rule 4 - extension changes
    if ransom_ext:
        hit(10, "Ransomware-style extension (.locked)", "critical",
            f"{len(ransom_ext)} file(s) given extensions like {os.path.splitext(ransom_ext[0]['final'])[1]}")
    elif ext_changes:
        hit(5, "File extension changes", "warning",
            f"{len(ext_changes)} file(s) changed extension")

    # Rule 5 - ransom note dropped
    if notes:
        hit(15, "Ransom note created", "critical",
            f"New file '{sorted(notes)[0]}' looks like ransom / recovery instructions")

    score = min(score, 100)
    level = _level(score)

    def status(value, warn, crit):
        return "Critical" if value >= crit else "Elevated" if value >= warn else "Normal"

    return {
        "threat_score": score,
        "threat_level": level,
        "verdict": {"SAFE": "No ransomware-like activity detected",
                    "WARNING": "Suspicious activity - keep monitoring",
                    "CRITICAL": "Ransomware-like activity detected!"}[level],
        "patterns": patterns,
        "metrics": {
            "total_files": total_files,
            "files_touched": len(touched),
            "files_renamed": len(renamed),
            "ransom_notes": sorted(notes),
            "rename_rate": rename_rate,
            "rename_status": status(rename_rate, RENAME_WARNING, RENAME_CRITICAL),
            "entropy_before": avg_before,
            "entropy_after": avg_after,
            "entropy_status": "High" if avg_after >= HIGH_ENTROPY and high_ent else "Normal",
            "speed": speed,
            "speed_status": status(speed, SPEED_WARNING, SPEED_CRITICAL) if touched else "Normal",
            "duration_s": round(end - start, 3),
            "events_captured": len(events),
            "metrics_source": source,
        },
        "thresholds": {
            "rename_warning": RENAME_WARNING, "rename_critical": RENAME_CRITICAL,
            "high_entropy": HIGH_ENTROPY,
            "speed_warning": SPEED_WARNING, "speed_critical": SPEED_CRITICAL,
        },
    }
