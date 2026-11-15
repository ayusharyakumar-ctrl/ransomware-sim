"""Simulation Module (SAFE).

Imitates ransomware-like behaviour ONLY on the copies of test files that the user
uploaded into this session's sandbox folder. It never touches any other path.

Three modes match the test cases in the project report:
  normal      -> ordinary user activity (small edits, no renaming)    => expect SAFE
  moderate    -> some files renamed, no encryption                     => expect WARNING
  ransomware  -> every file AES-256 encrypted + renamed to .locked     => expect CRITICAL

The AES key is stored inside the sandbox so the simulation can always be undone
with restore() - unlike real ransomware, nothing is ever lost.
"""
import json
import math
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .entropy import file_entropy

LOCKED_EXT = ".locked"
RANSOM_NOTE = "README_RESTORE_FILES.txt"
RANSOM_NOTE_TEXT = (
    "*** SIMULATED RANSOM NOTE - EDUCATIONAL DEMO ONLY ***\n\n"
    "This file was created by the Ransomware Simulation & Detection System.\n"
    "{n} test file(s) in this sandbox were encrypted to show how ransomware behaves.\n\n"
    "Real ransomware leaves a note like this to demand payment. Never pay - report it\n"
    "and restore from backups. Here, press 'Restore' on the dashboard to decrypt.\n"
)
TEXT_EXTS = {".txt", ".csv", ".md", ".json", ".log", ".html", ".xml", ".py", ".js", ".css"}

MODES = {
    "normal":     {"label": "Normal user activity",     "delay": 1.2},
    "moderate":   {"label": "Moderate (bulk renaming)", "delay": 0.4},
    "ransomware": {"label": "Ransomware-like attack",   "delay": 0.0},
}


def _files_dir(session_dir):
    return os.path.join(session_dir, "files")


def _manifest_path(session_dir):
    return os.path.join(session_dir, ".manifest.json")


def _key_path(session_dir):
    return os.path.join(session_dir, ".key")


def _safe_join(base, name):
    """Join and make sure the result stays inside `base` (no path tricks)."""
    path = os.path.abspath(os.path.join(base, name))
    if not path.startswith(os.path.abspath(base) + os.sep):
        raise ValueError("Path escapes sandbox")
    return path


def list_files(session_dir):
    d = _files_dir(session_dir)
    if not os.path.isdir(d):
        return []
    return sorted(f for f in os.listdir(d)
                  if not f.startswith(".") and os.path.isfile(os.path.join(d, f)))


def is_simulated(session_dir):
    return os.path.exists(_manifest_path(session_dir))


def _get_key(session_dir):
    kp = _key_path(session_dir)
    if os.path.exists(kp):
        with open(kp, "rb") as f:
            return f.read()
    key = AESGCM.generate_key(bit_length=256)
    with open(kp, "wb") as f:
        f.write(key)
    return key


def run_simulation(session_dir, mode="ransomware"):
    """Run the chosen simulation. Returns (records, start_time, end_time)."""
    if mode not in MODES:
        raise ValueError(f"Unknown mode: {mode}")
    if is_simulated(session_dir):
        restore(session_dir)  # always start from the clean uploaded files

    files_dir = _files_dir(session_dir)
    names = list_files(session_dir)
    delay = MODES[mode]["delay"]
    records, manifest = [], []

    if mode == "normal":
        targets = names[:3]                                # a user edits a few files
    elif mode == "moderate":
        targets = names[:max(1, math.ceil(len(names) * 0.6))]  # ~60% renamed
    else:
        targets = names                                    # ransomware hits everything

    key = _get_key(session_dir) if mode == "ransomware" else None
    start = time.time()

    for i, name in enumerate(targets):
        if i and delay:
            time.sleep(delay)
        t0 = time.time()
        path = _safe_join(files_dir, name)
        size = os.path.getsize(path)
        ent_before = file_entropy(path)
        final_name, renamed, changed = name, False, False
        op = {"original": name}

        if mode == "normal":
            ext = os.path.splitext(name)[1].lower()
            if ext in TEXT_EXTS:
                with open(path, "ab") as f:
                    f.write(b"\n# small edit made during normal activity\n")
                op.update(type="append", orig_size=size)
                changed = True
                action = "Edited (appended a line)"
            else:
                os.utime(path, None)  # just "opened/saved" - metadata only
                op.update(type="touch")
                action = "Opened & saved (no content change)"

        elif mode == "moderate":
            final_name = name + ".bak"
            os.rename(path, _safe_join(files_dir, final_name))
            op.update(type="rename", final=final_name)
            renamed = True
            action = "Renamed"

        else:  # ransomware
            with open(path, "rb") as f:
                plain = f.read()
            nonce = os.urandom(12)
            cipher = AESGCM(key).encrypt(nonce, plain, None)
            with open(path, "wb") as f:           # 1) overwrite with encrypted bytes
                f.write(nonce + cipher)
            final_name = name + LOCKED_EXT
            os.rename(path, _safe_join(files_dir, final_name))  # 2) rename to .locked
            op.update(type="encrypt", final=final_name)
            renamed, changed = True, True
            action = "AES-256 encrypted + renamed"

        final_path = _safe_join(files_dir, final_name)
        records.append({
            "original": name,
            "final": final_name,
            "size": size,
            "entropy_before": ent_before,
            "entropy_after": file_entropy(final_path),
            "renamed": renamed,
            "content_changed": changed,
            "action": action,
            "ms": round((time.time() - t0) * 1000, 1),
        })
        manifest.append(op)

    if mode == "ransomware":
        # Real ransomware drops a ransom note after encrypting. This one is clearly
        # labelled as a simulation and contains no payment details.
        with open(_safe_join(files_dir, RANSOM_NOTE), "w") as f:
            f.write(RANSOM_NOTE_TEXT.format(n=len(records)))
        manifest.append({"type": "note", "original": RANSOM_NOTE})

    end = time.time()
    with open(_manifest_path(session_dir), "w") as f:
        json.dump({"mode": mode, "ops": manifest}, f)
    return records, start, end


def restore(session_dir):
    """Undo the last simulation (decrypt + rename back). Returns count restored."""
    mp = _manifest_path(session_dir)
    if not os.path.exists(mp):
        return 0
    with open(mp) as f:
        manifest = json.load(f)
    files_dir = _files_dir(session_dir)
    restored = 0
    for op in manifest["ops"]:
        orig = _safe_join(files_dir, op["original"])
        if op["type"] == "encrypt":
            locked = _safe_join(files_dir, op["final"])
            if os.path.exists(locked):
                with open(locked, "rb") as f:
                    blob = f.read()
                plain = AESGCM(_get_key(session_dir)).decrypt(blob[:12], blob[12:], None)
                with open(orig, "wb") as f:
                    f.write(plain)
                os.remove(locked)
                restored += 1
        elif op["type"] == "rename":
            moved = _safe_join(files_dir, op["final"])
            if os.path.exists(moved):
                os.rename(moved, orig)
                restored += 1
        elif op["type"] == "note":
            if os.path.exists(orig):
                os.remove(orig)
        elif op["type"] == "append":
            if os.path.exists(orig):
                with open(orig, "r+b") as f:
                    f.truncate(op["orig_size"])
                restored += 1
    os.remove(mp)
    return restored
