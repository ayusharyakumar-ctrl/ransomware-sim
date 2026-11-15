"""Monitoring Module.

Uses the `watchdog` library to watch the sandbox folder in real time and record
every file-system event (created / modified / renamed / deleted) with a timestamp.
The detection engine later reads these events to compute rename rate and
modification speed.
"""
import os
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class SandboxMonitor(FileSystemEventHandler):
    def __init__(self, sandbox_root: str):
        super().__init__()
        self.sandbox_root = os.path.abspath(sandbox_root)
        self._events = []
        self._lock = threading.Lock()
        self._observer = None

    # ---------- lifecycle ----------
    def start(self):
        os.makedirs(self.sandbox_root, exist_ok=True)
        self._observer = Observer()
        self._observer.schedule(self, self.sandbox_root, recursive=True)
        self._observer.daemon = True
        self._observer.start()

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)

    # ---------- watchdog callbacks ----------
    def _record(self, kind, src, dest=None):
        if os.path.basename(src).startswith("."):
            return  # ignore hidden helper files (.key, .manifest)
        with self._lock:
            self._events.append({
                "time": time.time(),
                "event": kind,
                "src": os.path.abspath(src),
                "dest": os.path.abspath(dest) if dest else None,
            })

    def on_created(self, event):
        if not event.is_directory:
            self._record("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record("modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._record("renamed", event.src_path, event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._record("deleted", event.src_path)

    # ---------- queries ----------
    def events_for(self, folder: str, since: float = 0.0):
        """Return events inside `folder` that happened after `since`."""
        folder = os.path.abspath(folder) + os.sep
        with self._lock:
            return [e for e in self._events
                    if e["src"].startswith(folder) and e["time"] >= since]

    def prune(self, older_than_s: int = 3600):
        cutoff = time.time() - older_than_s
        with self._lock:
            self._events = [e for e in self._events if e["time"] >= cutoff]
