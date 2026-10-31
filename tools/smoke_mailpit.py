"""End-to-end test with a locally supplied, real Mailpit binary (no downloads)."""
import argparse
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if result := predicate():
                return result
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.05)
    raise RuntimeError("Timed out waiting for Mailpit/FIM")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    project = Path(__file__).resolve().parents[1]
    processes = []
    with tempfile.TemporaryDirectory(prefix="fim-mailpit-e2e-") as temporary:
        base = Path(temporary)
        config = Path(subprocess.check_output([
            sys.executable, str(project / "tools/create_demo.py"), "--directory", str(base / "demo")
        ], text=True).strip())
        smtp, http = port(), port()
        config.write_text(config.read_text().replace("port = 1025", f"port = {smtp}"))
        with (base / "mailpit.log").open("wb") as mail_log, (base / "monitor.log").open("wb") as monitor_log:
            try:
                mailpit = subprocess.Popen([
                    str(binary), "--listen", f"127.0.0.1:{http}", "--smtp", f"127.0.0.1:{smtp}",
                    "--database", str(base / "messages.db"), "--disable-version-check", "--smtp-disable-rdns",
                ], stdout=mail_log, stderr=mail_log)
                processes.append(mailpit)

                def messages():
                    with urllib.request.urlopen(f"http://127.0.0.1:{http}/api/v1/messages", timeout=1) as response:
                        return json.load(response)

                wait_for(messages)
                subprocess.run([sys.executable, "-m", "fim", "init", "--config", str(config)], check=True, stdout=monitor_log, stderr=monitor_log)
                reference = (base / "demo/reference/baseline.sqlite").read_bytes()
                monitor = subprocess.Popen([sys.executable, "-m", "fim", "watch", "--config", str(config)], stdout=monitor_log, stderr=monitor_log)
                processes.append(monitor)
                wait_for(lambda: '"event": "scan_completed"' in (base / "monitor.log").read_text())
                started = time.monotonic()
                (base / "demo/web/style.css").write_text("/* simulated content attack */")

                def delivered():
                    result = messages()
                    return result if any("content_changed" in message["Subject"] for message in result["messages"]) else None

                result = wait_for(delivered)
                assert (base / "demo/reference/baseline.sqlite").read_bytes() == reference
                print(json.dumps({"status": "passed", "real_mailpit_messages": result["total"], "detection_and_delivery_seconds": round(time.monotonic() - started, 3), "baseline_unchanged": True}))
            finally:
                for process in reversed(processes):
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
