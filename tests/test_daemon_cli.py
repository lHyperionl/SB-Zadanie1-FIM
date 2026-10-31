import json
import logging
import subprocess
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime

from fim.baseline import Baseline, initialize
from fim.daemon import watch
from fim.runtime import Runtime


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for monitor")


def test_event_detection_before_periodic_scan(config, monkeypatch):
    config = replace(config, scan_interval=30)
    initialize(config, datetime.now(config.zone))
    runtime = Runtime(config)
    baseline = Baseline.read(config)
    monkeypatch.setattr("fim.alerts.send", lambda *_: None)
    scanned = threading.Event()
    log = logging.getLogger("test.watch")

    class ScanHandler(logging.Handler):
        def emit(self, record):
            if record.getMessage() == "scan_completed":
                scanned.set()

    handler = ScanHandler()
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    stop = threading.Event()
    errors = []

    def run():
        try:
            watch(config, baseline, runtime, log, stop=stop)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert scanned.wait(3)
        (config.web_root / "style.css").write_text("attack via filesystem event")

        def detected():
            with runtime.connect() as conn:
                return conn.execute("SELECT count(*) FROM incidents WHERE path='style.css' AND kind='content_changed'").fetchone()[0]

        wait_for(detected, timeout=2)
    finally:
        stop.set()
        thread.join(timeout=12)
        log.removeHandler(handler)
    assert not thread.is_alive()
    assert not errors


def test_periodic_fallback_if_observer_cannot_start(config, monkeypatch):
    initialize(config, datetime.now(config.zone))
    runtime = Runtime(config)

    def no_observer():
        raise OSError("inotify unavailable")

    monkeypatch.setattr("fim.daemon.Observer", no_observer)
    monkeypatch.setattr("fim.alerts.send", lambda *_: None)
    stop = threading.Event()
    errors = []

    def run():
        try:
            watch(config, Baseline.read(config), runtime, logging.getLogger("test.fallback"), stop=stop)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        def degraded():
            with runtime.connect() as conn:
                return conn.execute("SELECT count(*) FROM incidents WHERE kind='event_monitor_unavailable'").fetchone()[0]
        wait_for(degraded)
        (config.web_root / "style.css").write_text("attack while events are offline")
        def detected():
            with runtime.connect() as conn:
                return conn.execute("SELECT count(*) FROM incidents WHERE path='style.css'").fetchone()[0]
        wait_for(detected)
    finally:
        stop.set()
        thread.join(timeout=12)
    assert not errors
    assert not thread.is_alive()


def test_cli_exit_codes_and_no_silent_baseline_creation(config):
    def call(command, *extra):
        return subprocess.run([sys.executable, "-m", "fim", command, "--config", str(config.source), *extra], capture_output=True, text=True, timeout=20)

    assert call("check").returncode == 2
    assert not config.baseline.exists()
    assert call("init").returncode == 0
    assert call("check").returncode == 0
    (config.web_root / "style.css").write_text("changed")
    result = call("check")
    assert result.returncode == 1
    records = [json.loads(line) for line in result.stderr.splitlines()]
    assert any(r["event"] == "incident_detected" and r["kind"] == "content_changed" for r in records)
    assert call("init").returncode == 2
    assert call("baseline-update", "--accept-current").returncode == 0
    assert call("check").returncode == 0
    config.baseline.write_bytes(b"corrupted")
    assert call("check").returncode == 2
