from __future__ import annotations

import fcntl
import logging
import os
import signal
import socket
import threading
import time
from contextlib import contextmanager
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .alerts import Sender
from .baseline import Baseline
from .config import Config, ConfigError
from .monitor import Finding, inspect
from .runtime import Runtime


@contextmanager
def process_lock(config: Config, *, allow_active: bool = False):
    fd = os.open(config.runtime_dir / "process.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    owns = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owns = True
        except BlockingIOError:
            if not allow_active:
                raise ConfigError("Another monitor/check process is running")
        yield owns
    finally:
        os.close(fd)


def notify(message: str) -> None:
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        client.sendto(message.encode(), address)


class Changes(FileSystemEventHandler):
    def __init__(self, dirty: threading.Event):
        self.dirty = dirty

    def on_any_event(self, event) -> None:
        # Scanner reads produce opened/closed_no_write events of their own.
        if event.event_type in ("created", "modified", "deleted", "moved", "closed"):
            self.dirty.set()


def watch(config: Config, baseline: Baseline, runtime: Runtime, log: logging.Logger, *, stop: threading.Event | None = None) -> None:
    stop = stop or threading.Event()
    dirty = threading.Event()
    observer = None
    retry_at = 0.0
    degraded = False
    dirty_at = None
    last_scan = float("-inf")
    last_day = None
    grace_checked = None
    last_notify = float("-inf")
    sender = Sender(runtime, config.smtp, log)
    clock = lambda: datetime.now(config.zone)
    old_signals = {}
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGTERM, signal.SIGINT):
            old_signals[signum] = signal.signal(signum, lambda *_: stop.set())
    sender.start()
    try:
        while not stop.is_set():
            monotonic = time.monotonic()
            if observer is None and monotonic >= retry_at:
                candidate = None
                try:
                    candidate = Observer()
                    candidate.schedule(Changes(dirty), str(config.web_root), recursive=True)
                    candidate.start()
                    observer = candidate
                    if degraded:
                        log.info("event_monitor_restored")
                    degraded = False
                    dirty.set()
                except Exception as exc:
                    if candidate is not None:
                        candidate.stop()
                        if candidate.is_alive():
                            candidate.join(timeout=5)
                    degraded = True
                    retry_at = monotonic + 30
                    log.error("event_monitor_unavailable", extra={"fields": {"error_type": type(exc).__name__}})
            if observer is not None and (not observer.is_alive() or any(not emitter.is_alive() for emitter in observer.emitters)):
                observer.stop()
                observer.join(timeout=5)
                observer = None
                degraded = True
                retry_at = monotonic + 5
                dirty.set()
                log.error("event_monitor_stopped")
            if dirty.is_set():
                dirty.clear()
                if dirty_at is None:
                    dirty_at = monotonic
            now = clock()
            seconds = now.hour * 3600 + now.minute * 60 + now.second + now.microsecond / 1e6
            grace_due = seconds >= config.midnight_grace and grace_checked != now.date()
            due = (
                monotonic - last_scan >= config.scan_interval
                or dirty_at is not None and monotonic - dirty_at >= config.debounce
                or last_day != now.date() or grace_due
            )
            if due:
                findings, blocked = inspect(config, baseline, clock)
                if degraded:
                    findings.append(Finding("@system/events", "event_monitor_unavailable", detail="Periodic scanning remains active"))
                runtime.record(findings, blocked, log)
                log.info("scan_completed", extra={"fields": {"findings": len(findings), "blocked_paths": sorted(blocked)}})
                last_scan, dirty_at, last_day = time.monotonic(), None, now.date()
                if seconds >= config.midnight_grace:
                    grace_checked = now.date()
                notify("READY=1\nWATCHDOG=1\nSTATUS=Monitoring website integrity")
                last_notify = time.monotonic()
            elif monotonic - last_notify >= 10:
                notify("WATCHDOG=1")
                last_notify = monotonic
            if not sender.thread.is_alive():
                raise RuntimeError("SMTP worker stopped")
            stop.wait(0.1)
    finally:
        if observer is not None:
            observer.stop()
            observer.join(timeout=5)
        sender.stop()
        for signum, previous in old_signals.items():
            signal.signal(signum, previous)
        notify("STOPPING=1")
