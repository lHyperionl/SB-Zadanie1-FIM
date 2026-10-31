from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from . import __version__
from .alerts import Sender
from .baseline import Baseline, initialize, reference_lock
from .config import load
from .daemon import process_lock, watch
from .events import logger
from .monitor import Finding, inspect
from .page import publish
from .runtime import Runtime


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(prog="fim", description="Linux File Integrity Monitoring")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "check", "watch", "publish", "baseline-update", "test-alert"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True, help="Absolute path to the TOML configuration")
        if name == "baseline-update":
            command.add_argument("--accept-current", action="store_true", required=True,
                                 help="Explicitly approve the independently verified current website")
    args = parser.parse_args(argv)
    log = logger()
    runtime = config = None
    try:
        config = load(args.config)
        if not config.root_owned:
            log.warning("development_mode", extra={"fields": {"detail": "Root ownership enforcement is disabled; do not use on an exposed server"}})
        clock = lambda: datetime.now(config.zone)
        if args.command in ("init", "baseline-update"):
            initialize(config, clock(), update=args.command == "baseline-update")
            log.info("baseline_initialized" if args.command == "init" else "baseline_updated")
            return 0
        if args.command == "publish":
            with reference_lock(config):
                baseline = Baseline.read(config)
                changed = publish(config, baseline.recipe, clock())
                log.info("page_published" if changed else "page_already_current")
            return 0
        log = logger(config)
        runtime = Runtime(config)
        if args.command == "test-alert":
            with process_lock(config, allow_active=True) as owns:
                runtime.enqueue_test()
                log.info("test_alert_queued")
                if owns:
                    Sender(runtime, config.smtp, log).attempt_one()
            return 0
        with process_lock(config), reference_lock(config):
            baseline = Baseline.read(config)
            if args.command == "check":
                findings, blocked = inspect(config, baseline, clock)
                runtime.record(findings, blocked, log)
                log.info("scan_completed", extra={"fields": {"findings": len(findings), "blocked_paths": sorted(blocked)}})
                Sender(runtime, config.smtp, log).attempt_one()
                return 2 if blocked else 1 if findings else 0
            watch(config, baseline, runtime, log)
            return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        log.error("operation_failed", extra={"fields": {"error_type": type(exc).__name__, "detail": str(exc)}})
        if runtime is not None and config is not None and args.command != "test-alert":
            try:
                runtime.record([Finding("@system/monitor", "monitor_error", detail=str(exc))], {"."}, log)
                Sender(runtime, config.smtp, log).attempt_one()
            except Exception as reporting_error:
                log.error("failure_reporting_unavailable", extra={"fields": {"error_type": type(reporting_error).__name__}})
        return 2


if __name__ == "__main__":
    sys.exit(main())
