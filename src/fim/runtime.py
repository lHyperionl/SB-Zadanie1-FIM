from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager

from .config import Config, private_directory
from .monitor import Finding, under


class Runtime:
    """Writable state is deliberately separated from the read-only reference."""

    def __init__(self, config: Config):
        private_directory(config.runtime_dir)
        self.path = config.runtime_dir / "runtime.sqlite"
        if self.path.is_symlink():
            raise ValueError("Runtime database cannot be a symbolic link")
        with self.connect() as connection:
            connection.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS incidents(
                    id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, path TEXT NOT NULL,
                    kind TEXT NOT NULL, body TEXT NOT NULL, opened REAL NOT NULL,
                    closed REAL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS active_fingerprint
                    ON incidents(fingerprint) WHERE closed IS NULL;
                CREATE TABLE IF NOT EXISTS outbox(
                    id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL,
                    subject TEXT NOT NULL, body TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL, sent REAL
                );
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            connection.execute("PRAGMA trusted_schema=OFF")
            with connection:
                yield connection
        finally:
            connection.close()

    def record(self, findings: list[Finding], blocked: set[str], log: logging.Logger, *, now: float | None = None) -> list[str]:
        when = time.time() if now is None else now
        fingerprints = {item.fingerprint for item in findings}
        opened = []
        with self.connect() as connection:
            # Serialize the read/insert/dedup sequence with the sender's updates.
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute("SELECT id,fingerprint,path FROM incidents WHERE closed IS NULL").fetchall()
            for incident_id, fingerprint, path in active:
                if fingerprint not in fingerprints and not any(under(path, prefix) for prefix in blocked):
                    connection.execute("UPDATE incidents SET closed=? WHERE id=?", (when, incident_id))
                    log.info("incident_resolved", extra={"fields": {"incident_id": incident_id, "path": path}})
            existing = {fingerprint for _, fingerprint, _ in active}
            for finding in findings:
                if finding.fingerprint in existing:
                    continue
                incident_id = str(uuid.uuid4())
                body = json.dumps({"incident_id": incident_id, "detected_at": when, **finding.data()}, ensure_ascii=True, sort_keys=True)
                connection.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,NULL)", (
                    incident_id, finding.fingerprint, finding.path, finding.kind, body, when
                ))
                connection.execute("INSERT INTO outbox(incident_id,subject,body,next_attempt) VALUES(?,?,?,?)", (
                    incident_id, f"FIM incident: {finding.kind}", body, when
                ))
                opened.append(incident_id)
                existing.add(finding.fingerprint)
                log.error("incident_detected", extra={"fields": {"incident_id": incident_id, **finding.data()}})
        return opened

    def enqueue_test(self) -> None:
        with self.connect() as connection:
            incident_id = str(uuid.uuid4())
            connection.execute("INSERT INTO outbox(incident_id,subject,body,next_attempt) VALUES(?,?,?,?)", (
                incident_id, "FIM test alert", "Test doručenia e-mailového upozornenia FIM. ID: " + incident_id, time.time()
            ))

    def due(self, now: float) -> tuple | None:
        with self.connect() as connection:
            return connection.execute("SELECT id,subject,body,attempts,incident_id FROM outbox WHERE sent IS NULL AND next_attempt<=? ORDER BY id LIMIT 1", (now,)).fetchone()

    def delivered(self, message_id: int, now: float) -> None:
        with self.connect() as connection:
            connection.execute("UPDATE outbox SET sent=? WHERE id=?", (now, message_id))

    def failed(self, message_id: int, attempts: int, now: float) -> None:
        delay = (10, 30, 60)[attempts] if attempts < 3 else 300
        with self.connect() as connection:
            connection.execute("UPDATE outbox SET attempts=attempts+1,next_attempt=? WHERE id=?", (now + delay, message_id))
