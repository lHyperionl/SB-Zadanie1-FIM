from __future__ import annotations

import logging
import os
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from email.utils import formatdate

from .config import SMTP
from .runtime import Runtime


def send(settings: SMTP, subject: str, body: str, incident_id: str) -> None:
    message = EmailMessage()
    message["From"] = settings.sender
    message["To"] = ", ".join(settings.recipients)
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = f"<{incident_id}@fim.local>"
    message.set_content(body)
    with smtplib.SMTP(settings.host, settings.port, timeout=settings.timeout) as client:
        client.ehlo()
        if settings.mode == "starttls":
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        if settings.username:
            password = os.environ.get(settings.password_env)
            if not password:
                raise ValueError("SMTP password variable is missing")
            client.login(settings.username, password)
        refused = client.send_message(message)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


class Sender:
    def __init__(self, runtime: Runtime, settings: SMTP, log: logging.Logger):
        self.runtime, self.settings, self.log = runtime, settings, log
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="fim-smtp", daemon=True)

    def attempt_one(self, *, now: float | None = None) -> bool:
        when = time.time() if now is None else now
        item = self.runtime.due(when)
        if item is None:
            return False
        message_id, subject, body, attempts, incident_id = item
        try:
            send(self.settings, subject, body, incident_id)
        except Exception as exc:
            self.runtime.failed(message_id, attempts, when)
            # SMTP errors can contain server echoes of AUTH/credentials. Log
            # only the exception type, never its arbitrary text or config.
            self.log.error("alert_delivery_failed", extra={"fields": {"incident_id": incident_id, "error_type": type(exc).__name__, "attempt": attempts + 1}})
        else:
            self.runtime.delivered(message_id, when)
            self.log.info("alert_delivered", extra={"fields": {"incident_id": incident_id}})
        return True

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                worked = self.attempt_one()
            except Exception as exc:
                self.log.error("alert_worker_error", extra={"fields": {"error_type": type(exc).__name__}})
                worked = False
            self.stop_event.wait(0.1 if worked else 1)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=self.settings.timeout + 1)
