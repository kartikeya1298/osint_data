"""
Military OSINT — Desktop Control Panel (pywebview)

Native Windows desktop wrapper around military_osint_tool_v2.py and
osint_dashboard.html. Runs entirely locally: no server, no cloud component.

  - Launches military_osint_tool_v2.py as a subprocess and streams its
    stdout/log lines to the control panel UI in real time.
  - Opens osint_dashboard.html (which auto-loads the master dataset that the
    tool embeds into it after every run) in its own native window.
  - Exposes small read-only helpers (module health, quota, run history,
    weekly delta) so the panel can show run status without re-implementing
    any of the tool's own logic.

Run:  python osint_gui_app.py
"""

import csv
import json
import os
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

import webview

BASE_DIR = Path(__file__).parent.resolve()
SCRIPT_PATH = BASE_DIR / "military_osint_tool_v2.py"
DASHBOARD_PATH = BASE_DIR / "osint_dashboard.html"
CONTROL_PANEL_HTML = BASE_DIR / "control_panel.html"

MASTER_CSV = BASE_DIR / "military_osint_master.csv"
HEALTH_FILE = BASE_DIR / "module_health_v2.json"
QUOTA_FILE = BASE_DIR / "api_quota_v2.json"
LOG_FILE = BASE_DIR / "osint_tool_v2.log"

MAX_BUFFERED_LINES = 8000


def _safe_within_base(path_str: str) -> Path | None:
    """Resolve a path and confirm it stays inside BASE_DIR. Returns None if not."""
    try:
        p = Path(path_str).resolve()
        p.relative_to(BASE_DIR)
        return p
    except Exception:
        return None


class Api:
    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()
        self.log_lines: list[str] = []
        self.state = "idle"  # idle | running | done | error | stopped
        self.mode = None  # "collect" | "clean"
        self.start_time = None
        self.end_time = None
        self.return_code = None
        self._window = None

    def set_window(self, window):
        self._window = window

    # ── run control ─────────────────────────────────────────────
    def _reset_for_run(self, mode):
        with self.lock:
            self.log_lines = []
            self.state = "running"
            self.mode = mode
            self.start_time = time.time()
            self.end_time = None
            self.return_code = None

    def _append(self, line: str):
        with self.lock:
            self.log_lines.append(line)
            if len(self.log_lines) > MAX_BUFFERED_LINES:
                self.log_lines = self.log_lines[-MAX_BUFFERED_LINES:]

    def _run_subprocess(self, args):
        try:
            popen_kwargs = dict(
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            self.proc = subprocess.Popen(
                [sys.executable, "-u", str(SCRIPT_PATH), *args], **popen_kwargs
            )
            for line in self.proc.stdout:
                self._append(line.rstrip("\n"))
            self.proc.wait()
            with self.lock:
                self.return_code = self.proc.returncode
                self.state = "done" if self.return_code == 0 else "error"
                self.end_time = time.time()
        except Exception as e:
            self._append(f"[GUI] Failed to launch tool: {e}")
            with self.lock:
                self.state = "error"
                self.end_time = time.time()

    def start_collection(self):
        with self.lock:
            if self.state == "running":
                return {"ok": False, "error": "A run is already in progress."}
        if not SCRIPT_PATH.exists():
            return {"ok": False, "error": f"Script not found: {SCRIPT_PATH.name}"}
        self._reset_for_run("collect")
        threading.Thread(target=self._run_subprocess, args=([],), daemon=True).start()
        return {"ok": True}

    def start_clean(self, input_csv: str, output_csv: str):
        with self.lock:
            if self.state == "running":
                return {"ok": False, "error": "A run is already in progress."}
        if not input_csv or not output_csv:
            return {"ok": False, "error": "Both input and output CSV paths are required."}
        if not Path(input_csv).exists():
            return {"ok": False, "error": f"Input CSV not found: {input_csv}"}
        self._reset_for_run("clean")
        threading.Thread(
            target=self._run_subprocess, args=(["--clean", input_csv, output_csv],), daemon=True
        ).start()
        return {"ok": True}

    def stop(self):
        with self.lock:
            proc = self.proc
            running = self.state == "running" and proc is not None and proc.poll() is None
        if not running:
            return {"ok": False, "error": "Nothing is running."}
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                proc.terminate()
        except Exception as e:
            self._append(f"[GUI] Stop failed: {e}")
        with self.lock:
            self.state = "stopped"
            self.end_time = time.time()
        self._append("[GUI] Run stopped by user.")
        return {"ok": True}

    def poll(self, since: int = 0):
        with self.lock:
            new_lines = self.log_lines[since:]
            return {
                "state": self.state,
                "mode": self.mode,
                "total_lines": len(self.log_lines),
                "new_lines": new_lines,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "return_code": self.return_code,
            }

    # ── dashboard / file helpers ─────────────────────────────────
    def open_dashboard(self):
        if not DASHBOARD_PATH.exists():
            return {"ok": False, "error": f"{DASHBOARD_PATH.name} not found yet — run a collection first."}
        webview.create_window(
            "Military OSINT Dashboard",
            url=DASHBOARD_PATH.as_uri(),
            width=1500,
            height=950,
        )
        return {"ok": True}

    def open_path(self, path_str: str):
        target = _safe_within_base(path_str)
        if target is None or not target.exists():
            return {"ok": False, "error": "File not found."}
        try:
            os.startfile(str(target))  # noqa: S606 - Windows-only desktop app
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def open_data_folder(self):
        try:
            os.startfile(str(BASE_DIR))  # noqa: S606
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def pick_csv_open(self):
        result = self._window.create_file_dialog(
            webview.OPEN_DIALOG,
            directory=str(BASE_DIR),
            file_types=("CSV Files (*.csv)", "All files (*.*)"),
        )
        if not result:
            return None
        return result[0]

    def pick_csv_save(self):
        result = self._window.create_file_dialog(
            webview.SAVE_DIALOG,
            directory=str(BASE_DIR),
            save_filename="cleaned_output.csv",
            file_types=("CSV Files (*.csv)", "All files (*.*)"),
        )
        if not result:
            return None
        return result if isinstance(result, str) else result[0]

    # ── status / stats ──────────────────────────────────────────
    def list_runs(self):
        runs = []
        for csv_path in sorted(BASE_DIR.glob("military_osint_data_v2_*.csv"), reverse=True)[:15]:
            ts = csv_path.stem.replace("military_osint_data_v2_", "")
            runs.append(
                {
                    "timestamp": ts,
                    "filename": csv_path.name,
                    "size_kb": round(csv_path.stat().st_size / 1024, 1),
                }
            )
        return runs

    def get_health(self):
        if not HEALTH_FILE.exists():
            return {}
        try:
            return json.loads(HEALTH_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def get_quota(self):
        if not QUOTA_FILE.exists():
            return {}
        try:
            return json.loads(QUOTA_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def get_master_stats(self):
        if not MASTER_CSV.exists():
            return {"rows": 0, "severity": {}, "category": {}}
        try:
            with open(MASTER_CSV, encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
            severity = Counter(r.get("severity", "UNKNOWN") or "UNKNOWN" for r in rows)
            category = Counter(r.get("category_code", "?") or "?" for r in rows)
            return {"rows": len(rows), "severity": dict(severity), "category": dict(category)}
        except Exception as e:
            return {"rows": 0, "severity": {}, "category": {}, "error": str(e)}

    def get_latest_delta(self):
        deltas = sorted(BASE_DIR.glob("weekly_delta_v2_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not deltas:
            return None
        try:
            return {"filename": deltas[0].name, "content": deltas[0].read_text(encoding="utf-8")}
        except Exception:
            return None


def main():
    api = Api()
    window = webview.create_window(
        "Military OSINT — Control Panel",
        url=CONTROL_PANEL_HTML.as_uri(),
        js_api=api,
        width=1360,
        height=880,
        min_size=(1000, 640),
    )
    api.set_window(window)

    def on_closing():
        with api.lock:
            proc = api.proc
            running = api.state == "running" and proc is not None and proc.poll() is None
        if running:
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                else:
                    proc.terminate()
            except Exception:
                pass

    window.events.closing += on_closing
    webview.start()


if __name__ == "__main__":
    main()
