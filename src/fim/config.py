from __future__ import annotations

import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo


class ConfigError(ValueError):
    pass


def trusted_path(path: Path, *, root_owned: bool, directory: bool = False) -> None:
    """Inspect the lexical path; resolve() would conceal malicious symlinks."""
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"Absolute path without '..' required: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ConfigError(f"Symbolic link in trusted path: {current}")
        if root_owned and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ConfigError(f"Trusted path must be root-owned and not group/other writable: {current}")
    mode = path.lstat().st_mode
    if directory and not stat.S_ISDIR(mode):
        raise ConfigError(f"Directory required: {path}")
    if not directory and not stat.S_ISREG(mode):
        raise ConfigError(f"Regular file required: {path}")


def private_directory(path: Path) -> None:
    # The installer creates these directories. Never create a directory through
    # an attacker-controlled parent as a side effect of starting the daemon.
    trusted_path(path, root_owned=False, directory=True)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ConfigError(f"Private directory must belong to the current account and have mode 0700: {path}")


@dataclass(frozen=True)
class SMTP:
    host: str
    port: int
    mode: str
    sender: str
    recipients: tuple[str, ...]
    username: str = ""
    password_env: str = "FIM_SMTP_PASSWORD"
    timeout: float = 10


@dataclass(frozen=True)
class Config:
    source: Path
    web_root: Path
    baseline: Path
    runtime_dir: Path
    log_dir: Path
    staging_dir: Path
    template: Path
    calendar: Path
    timezone: str
    root_owned: bool
    read_group: str
    page_owner: str
    page_group: str
    page_mode: int
    scan_interval: float
    debounce: float
    midnight_grace: float
    max_file_bytes: int
    max_entries: int
    smtp: SMTP

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def lock_path(self) -> Path:
        return self.baseline.parent / ".baseline.lock"


def load(path: str | Path) -> Config:
    if sys.platform != "linux":
        raise ConfigError("This FIM requires Linux (use a Linux VM or WSL).")
    source = Path(os.path.abspath(path))
    trusted_path(source, root_owned=False)
    with source.open("rb") as stream:
        raw = tomllib.load(stream)
    try:
        security = raw.get("security", {})
        root_owned = security.get("require_root_owned", True)
        if not isinstance(root_owned, bool):
            raise ConfigError("security.require_root_owned must be a boolean")
        trusted_path(source, root_owned=root_owned)
        if root_owned:
            # Protect the interpreter, code and package directory as well as data.
            trusted_path(Path(sys.executable), root_owned=True)
            trusted_path(Path(__file__).absolute(), root_owned=True)
        paths = raw["paths"]

        def absolute(key: str) -> Path:
            result = Path(paths[key])
            if not result.is_absolute() or ".." in result.parts:
                raise ConfigError(f"paths.{key} must be an absolute path without '..'")
            return result

        values = {key: absolute(key) for key in (
            "web_root", "baseline", "runtime_dir", "log_dir", "staging_dir", "template", "calendar"
        )}
        web = values["web_root"]
        for key, value in values.items():
            if key != "web_root" and (value.is_relative_to(web) or web.is_relative_to(value)):
                raise ConfigError(f"paths.{key} must be outside and cannot contain the monitored website")
        for key in ("runtime_dir", "log_dir", "staging_dir"):
            for other in ("baseline", "template", "calendar"):
                if values[other].is_relative_to(values[key]):
                    raise ConfigError(f"Trusted {other} cannot be inside writable {key}")
        if source.is_relative_to(web) or any(source.is_relative_to(values[k]) for k in ("runtime_dir", "log_dir", "staging_dir")):
            raise ConfigError("Configuration cannot be inside a monitored or writable directory")
        monitor = raw.get("monitor", {})
        page = raw.get("page", {})
        timezone = page.get("timezone", "Europe/Bratislava")
        ZoneInfo(timezone)
        interval = float(monitor.get("scan_interval", 30))
        debounce = float(monitor.get("debounce", 0.2))
        grace = float(page.get("midnight_grace", 5))
        limit = int(monitor.get("max_file_bytes", 64 * 1024 * 1024))
        entries = int(monitor.get("max_entries", 10000))
        if not 1 <= interval <= 3600 or not 0.05 <= debounce <= 2 or not 0 <= grace <= 60:
            raise ConfigError("Invalid scan interval, debounce or midnight grace")
        if limit < 1 or entries < 1:
            raise ConfigError("Resource limits must be positive")
        page_mode = int(str(page.get("mode", "0664")), 8)
        if not 0 <= page_mode <= 0o777 or not page_mode & 0o400:
            raise ConfigError("Invalid page mode")
        mail = raw["smtp"]
        mode = mail.get("mode", "starttls")
        host = mail["host"]
        port = int(mail.get("port", 587))
        recipients = mail["recipients"]
        sender = mail["sender"]
        if mode not in ("starttls", "plain") or not 1 <= port <= 65535:
            raise ConfigError("Invalid SMTP mode/port")
        if mode == "plain" and host not in ("localhost", "127.0.0.1", "::1"):
            raise ConfigError("Plain SMTP is allowed only on loopback for the test receiver")
        if not isinstance(recipients, list) or not recipients:
            raise ConfigError("SMTP recipients must be a nonempty list")
        for address in [sender, *recipients]:
            if not isinstance(address, str) or not re.fullmatch(r"[^\s<>@,;]+@[^\s<>@,;]+", address):
                raise ConfigError("Invalid SMTP address")
        password_env = mail.get("password_env", "FIM_SMTP_PASSWORD")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", password_env):
            raise ConfigError("Invalid SMTP password variable name")
        return Config(
            source=source, **values, timezone=timezone, root_owned=root_owned,
            read_group=security.get("read_group", ""), page_owner=page.get("owner", ""),
            page_group=page.get("group", ""), page_mode=page_mode,
            scan_interval=interval, debounce=debounce, midnight_grace=grace,
            max_file_bytes=limit, max_entries=entries,
            smtp=SMTP(host, port, mode, sender, tuple(recipients), mail.get("username", ""), password_env),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"Invalid configuration: {exc}") from exc
