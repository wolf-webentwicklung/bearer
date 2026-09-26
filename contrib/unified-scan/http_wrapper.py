#!/usr/bin/env python3
"""Minimal HTTP wrapper around unified_scan.py (stdlib only) for use as an internal scanner
service, e.g. from a web form that accepts uploaded scripts.

  POST /scan   body = raw .zip/.7z archive, header X-Filename = original file name
               200 -> combined_report.json content (target = X-Filename), plus
                      "incomplete": bool and "failed_tools": [...] - tools that errored,
                      timed out or only partly ran for this archive
               422 -> {"error": "..."}  archive rejected (unsafe, invalid, too big, wrong type)
               5xx -> {"error": "..."}  scan failed / timed out - caller may retry
  GET /health  200 -> {"ok": true, "tools": {...}}

A job has a hard total time limit (UNIFIED_SCAN_TIMEOUT_SECONDS, default 600).
Every job gets its own directory under UNIFIED_SCAN_WORKDIR (default: the temp dir), which
also serves as TMPDIR for unified_scan.py and the scanners, and is deleted afterwards - also
on timeout, where the whole process group is killed. Leftovers from a crash are purged at
startup.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "unified_scan.py"
PORT = int(os.environ.get("UNIFIED_SCAN_PORT", "8080"))
TIMEOUT_SECONDS = int(os.environ.get("UNIFIED_SCAN_TIMEOUT_SECONDS", "600"))
MAX_UPLOAD_BYTES = int(os.environ.get("UNIFIED_SCAN_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
MAX_PARALLEL = int(os.environ.get("UNIFIED_SCAN_MAX_PARALLEL", "1"))
WORKDIR = Path(os.environ.get("UNIFIED_SCAN_WORKDIR") or tempfile.gettempdir())
JOB_PREFIX = "unified-scan-job-"
ARCHIVE_SUFFIXES = (".zip", ".7z")
TOOLS = ("guarddog", "bearer", "trufflehog", "trivy", "checkov", "git")
MAX_LINE = 10_000_000
# Per-tool meta keys meaning "this tool did not (fully) run for this archive".
_TOOL_FAILURE_KEYS = ("error", "image_errors", "ecosystem_errors")

# Scans are memory hungry - queue them instead of running them all at once.
_slots = threading.BoundedSemaphore(MAX_PARALLEL)


class ScanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def purge_stale_jobs(workdir: Path = WORKDIR) -> None:
    if not workdir.is_dir():
        return
    for entry in workdir.iterdir():
        if entry.name.startswith(JOB_PREFIX) and entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)


def _clean(value):
    """Scanner output is derived from untrusted files: strip NUL characters everywhere."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items()}
    return value


def annotate_report(report: dict, filename: str) -> dict:
    report = _clean(report)
    report["target"] = filename
    for finding in report.get("employee_findings") or []:
        line = finding.get("line")
        if isinstance(line, bool) or not isinstance(line, int) or not 0 < line <= MAX_LINE:
            finding["line"] = None
    tools = report.get("tools") or {}
    failed = sorted(name for name, meta in tools.items()
                    if isinstance(meta, dict) and any(meta.get(k) for k in _TOOL_FAILURE_KEYS))
    report["failed_tools"] = failed
    report["incomplete"] = bool(failed)
    return report


def run_scan(archive: Path, filename: str, job: Path, timeout: int = TIMEOUT_SECONDS) -> dict:
    """Runs unified_scan.py on the archive inside job/, returns the combined report."""
    out_dir = job / "report"
    env = {**os.environ, "TMPDIR": str(job)}
    proc = subprocess.Popen(
        [sys.executable, str(SCRIPT), str(archive), "--out", str(out_dir)],
        cwd=str(job), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        _out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # The scanners are grandchildren - kill the whole group, not just unified_scan.py.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise ScanError(504, f"Scan nach {timeout}s abgebrochen.")

    if proc.returncode == 3:
        reason = err.strip().splitlines()[-1] if err.strip() else "Archiv abgelehnt."
        raise ScanError(422, reason.removeprefix("Archiv abgelehnt: "))
    report_file = out_dir / "combined_report.json"
    # 0 = clean, 1 = at least one critical finding - both are successful scans.
    if proc.returncode not in (0, 1) or not report_file.is_file():
        tail = "\n".join(err.strip().splitlines()[-5:])
        raise ScanError(500, f"unified_scan.py exit {proc.returncode}: {tail}"[:2000])
    return annotate_report(json.loads(report_file.read_text()), filename)


class Handler(BaseHTTPRequestHandler):
    timeout = 60  # socket timeout: a stalled upload must not hold a thread forever

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            return self._json(200, {"ok": True, "tools": {t: bool(shutil.which(t)) for t in TOOLS}})
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        # Never drop a connection without an answer - the caller must be able to tell a
        # rejected archive (422) from a scanner failure (5xx, retry).
        try:
            self._handle_scan()
        except Exception as exc:  # noqa: BLE001
            try:
                self._json(500, {"error": f"Interner Fehler: {type(exc).__name__}"})
            except OSError:
                pass

    def _handle_scan(self) -> None:
        if self.path != "/scan":
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        filename = os.path.basename((self.headers.get("X-Filename") or "").replace("\\", "/"))
        suffix = os.path.splitext(filename.lower())[1]
        if length <= 0:
            return self._json(422, {"error": "Datei fehlt."})
        if length > MAX_UPLOAD_BYTES:
            return self._json(422, {"error": f"Datei ist zu groß (max. {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)."})
        if suffix not in ARCHIVE_SUFFIXES:
            return self._json(422, {"error": "Nur .zip und .7z werden unterstützt."})

        status, payload = self._scan_upload(length, filename, suffix)
        return self._json(status, payload)

    def _scan_upload(self, length: int, filename: str, suffix: str) -> tuple[int, dict]:
        """Returns (status, payload) - only after the job directory is gone."""
        job = Path(tempfile.mkdtemp(prefix=JOB_PREFIX, dir=WORKDIR))
        try:
            archive = job / f"upload{suffix}"
            remaining = length
            with open(archive, "wb") as out:
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
            if remaining:
                return 422, {"error": "Upload unvollständig."}
            with _slots:
                return 200, run_scan(archive, filename, job)
        except ScanError as exc:
            return exc.status, {"error": str(exc)}
        finally:
            shutil.rmtree(job, ignore_errors=True)

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    purge_stale_jobs()
    print(f"unified-scan http wrapper on :{PORT} (timeout {TIMEOUT_SECONDS}s, "
          f"max upload {MAX_UPLOAD_BYTES} bytes, parallel {MAX_PARALLEL})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
