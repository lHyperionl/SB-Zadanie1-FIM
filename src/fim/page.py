from __future__ import annotations

import grp
import hashlib
import html
import json
import os
import pwd
import re
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from string import Template

from .config import Config, ConfigError, private_directory, trusted_path
from .safefs import open_directory, read_regular


@dataclass(frozen=True)
class Recipe:
    template: str
    calendar: dict[str, list[str]]

    @classmethod
    def from_sources(cls, config: Config) -> Recipe:
        for path in (config.template, config.calendar):
            trusted_path(path, root_owned=config.root_owned)
        recipe = cls(config.template.read_text(encoding="utf-8").replace("\r\n", "\n"),
                     json.loads(config.calendar.read_text(encoding="utf-8")))
        recipe.validate()
        return recipe

    def validate(self) -> None:
        day = date(2024, 1, 1)
        keys = set()
        while day.year == 2024:
            key = day.strftime("%m-%d")
            keys.add(key)
            names = self.calendar.get(key)
            if not isinstance(names, list) or any(not isinstance(n, str) or not n.strip() for n in names):
                raise ConfigError(f"Invalid/missing calendar entry: {key}")
            day += timedelta(days=1)
        if set(self.calendar) != keys:
            raise ConfigError("Calendar must contain exactly the 366 MM-DD keys")
        if 'datetime="$iso_date"' not in self.template:
            raise ConfigError('Template must contain datetime="$iso_date"')
        # Reject unknown placeholders, including substitution mistakes at setup.
        self.render(date(2024, 2, 29))

    def render(self, day: date) -> bytes:
        names = self.calendar[day.strftime("%m-%d")]
        message = "Dnes má meniny: " + ", ".join(names) + "." if names else "Dnes nie sú v kalendári uvedené meniny."
        return Template(self.template).substitute(
            iso_date=day.isoformat(), date=day.strftime("%d. %m. %Y"),
            namedays=html.escape(message, quote=True),
        ).encode("utf-8")

    def hashes(self, now: datetime, grace: float) -> set[str]:
        days = [now.date()]
        midnight = datetime.combine(now.date(), datetime.min.time(), tzinfo=now.tzinfo)
        if (now - midnight).total_seconds() < grace:
            days.append(now.date() - timedelta(days=1))
        return {hashlib.sha256(self.render(day)).hexdigest() for day in days}

    def is_canonical_past(self, content: bytes, today: date) -> bool:
        match = re.search(rb'<time datetime="(\d{4}-\d{2}-\d{2})"', content)
        if not match:
            return False
        try:
            day = date.fromisoformat(match[1].decode("ascii"))
            return day <= today and content == self.render(day)
        except (ValueError, KeyError):
            return False


def page_ids(config: Config) -> tuple[int, int]:
    uid = pwd.getpwnam(config.page_owner).pw_uid if config.page_owner else os.geteuid()
    gid = grp.getgrnam(config.page_group).gr_gid if config.page_group else os.getegid()
    return uid, gid


def publish(config: Config, recipe: Recipe, now: datetime, *, bootstrap: bool = False) -> bool:
    """Publish only canonical content; never use the scheduled job as recovery."""
    if not bootstrap:
        private_directory(config.staging_dir)
    else:
        trusted_path(config.staging_dir, root_owned=False, directory=True)
        if config.staging_dir.stat().st_mode & 0o077:
            raise ConfigError("Staging directory must have mode 0700")
    root = open_directory(config.web_root)
    stage = open_directory(config.staging_dir)
    temporary = None
    try:
        if os.fstat(root).st_dev != os.fstat(stage).st_dev:
            raise ConfigError("Staging directory and website must be on the same filesystem")
        content = recipe.render(now.date())
        current = None
        try:
            entry, current = read_regular(root, "index.html", config.max_file_bytes, capture=True)
            if not recipe.is_canonical_past(current, now.date()):
                raise ConfigError("Refusing to overwrite noncanonical index.html; inspect the incident first")
            uid, gid = page_ids(config)
            if (entry.mode, entry.uid, entry.gid) != (config.page_mode, uid, gid):
                raise ConfigError("Refusing to overwrite index.html with unexpected ownership/permissions")
        except FileNotFoundError:
            if not bootstrap:
                raise ConfigError("Refusing to recreate missing index.html; recovery requires administrator action")
        except OSError:
            # read_regular retries ENOENT; distinguish a missing path for init only.
            if not bootstrap:
                raise
            try:
                os.stat("index.html", dir_fd=root, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise
        if current == content:
            return False
        # mkstemp is anchored to the private directory via /proc/self/fd, not a
        # path that can be swapped after validation.
        fd, temporary = tempfile.mkstemp(prefix="page-", dir=f"/proc/self/fd/{stage}")
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), config.page_mode)
                uid, gid = page_ids(config)
                if (os.fstat(stream.fileno()).st_uid, os.fstat(stream.fileno()).st_gid) != (uid, gid):
                    os.fchown(stream.fileno(), uid, gid)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(Path(temporary).name, "index.html", src_dir_fd=stage, dst_dir_fd=root)
            temporary = None
            os.fsync(root)
            return True
        finally:
            if temporary is not None:
                os.unlink(Path(temporary).name, dir_fd=stage)
    finally:
        os.close(stage)
        os.close(root)
