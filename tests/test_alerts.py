import logging
import socket
import ssl
from dataclasses import replace

from aiosmtpd.controller import Controller

from fim.alerts import Sender, send
from fim.monitor import Finding
from fim.runtime import Runtime


def test_persistent_outbox_retry_dedup_and_recovery(ready, monkeypatch, caplog):
    runtime = Runtime(ready)
    log = logging.getLogger("test.retry")
    finding = Finding("style.css", "content_changed", actual={"sha256": "bad"})
    assert len(runtime.record([finding], set(), log, now=100)) == 1
    assert not runtime.record([finding], set(), log, now=101)

    def failure(*_):
        raise ValueError("secret-password-must-not-appear")

    monkeypatch.setattr("fim.alerts.send", failure)
    sender = Sender(runtime, ready.smtp, log)
    with caplog.at_level(logging.INFO):
        assert sender.attempt_one(now=100)
    assert "secret-password" not in caplog.text
    assert not sender.attempt_one(now=109)
    restarted = Runtime(ready)
    assert restarted.due(110)[3] == 1
    monkeypatch.setattr("fim.alerts.send", lambda *_: None)
    assert Sender(restarted, ready.smtp, log).attempt_one(now=110)
    assert restarted.due(10000) is None
    # An unreadable subtree is not evidence of recovery.
    runtime.record([], {"."}, log, now=111)
    with runtime.connect() as conn:
        assert conn.execute("SELECT count(*) FROM incidents WHERE closed IS NULL").fetchone()[0] == 1
    runtime.record([], set(), log, now=112)
    with runtime.connect() as conn:
        assert conn.execute("SELECT count(*) FROM incidents WHERE closed IS NULL").fetchone()[0] == 0
    assert len(runtime.record([finding], set(), log, now=113)) == 1


def test_retry_schedule(ready, monkeypatch):
    runtime = Runtime(ready)
    log = logging.getLogger("test.schedule")
    runtime.record([Finding("x", "added")], set(), log, now=0)
    monkeypatch.setattr("fim.alerts.send", lambda *_: (_ for _ in ()).throw(OSError("offline")))
    sender = Sender(runtime, ready.smtp, log)
    for when, next_when in [(0, 10), (10, 40), (40, 100), (100, 400), (400, 700)]:
        assert sender.attempt_one(now=when)
        assert runtime.due(next_when - 0.1) is None
        assert runtime.due(next_when) is not None


def test_real_local_smtp_delivery(ready):
    messages = []

    class Receiver:
        async def handle_DATA(self, server, session, envelope):
            messages.append(envelope)
            return "250 accepted"

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    receiver = Controller(Receiver(), hostname="127.0.0.1", port=port)
    receiver.start()
    try:
        settings = replace(ready.smtp, port=port)
        runtime = Runtime(ready)
        runtime.record([Finding("index.html", "daily_content_changed")], set(), logging.getLogger("test.smtp"), now=0)
        assert Sender(runtime, settings, logging.getLogger("test.smtp")).attempt_one(now=0)
        assert len(messages) == 1
        assert messages[0].rcpt_tos == list(settings.recipients)
        assert b"daily_content_changed" in messages[0].content
        assert runtime.due(100) is None
    finally:
        receiver.stop()


def test_starttls_before_auth_and_certificate_verification(ready, monkeypatch):
    calls = []

    class SMTPClient:
        def __init__(self, *_, **__): pass
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def ehlo(self): calls.append("ehlo")
        def starttls(self, *, context):
            assert context.check_hostname
            assert context.verify_mode == ssl.CERT_REQUIRED
            calls.append("tls")
        def login(self, user, password):
            assert password == "test-only-secret"
            calls.append("auth")
        def send_message(self, message):
            calls.append("send")
            return {}

    monkeypatch.setattr("fim.alerts.smtplib.SMTP", SMTPClient)
    monkeypatch.setenv("FIM_SMTP_PASSWORD", "test-only-secret")
    send(replace(ready.smtp, mode="starttls", username="test"), "Test", "Body", "test-id")
    assert calls == ["ehlo", "tls", "ehlo", "auth", "send"]
