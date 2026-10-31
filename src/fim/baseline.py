from __future__ import annotations

import fcntl
import grp
import json
import os
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath

from .config import Config, ConfigError, trusted_path
from .page import Recipe, page_ids, publish
from .safefs import Entry, scan


@contextmanager
def reference_lock(config: Config, *, exclusive: bool = False, create: bool = False):
    trusted_path(config.baseline.parent, root_owned=config.root_owned, directory=True)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if create:
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(config.lock_path, flags, 0o640)
    try:
        if create and config.read_group:
            os.fchown(fd, 0 if config.root_owned else -1, grp.getgrnam(config.read_group).gr_gid)
            os.fchmod(fd, 0o640)
        trusted_path(config.lock_path, root_owned=config.root_owned)
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ConfigError("Baseline is in use; stop the monitor/publisher before updating it") from exc
        yield
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Baseline:
    entries: dict[str, Entry]
    recipe: Recipe

    @classmethod
    def read(cls, config: Config) -> Baseline:
        trusted_path(config.baseline, root_owned=config.root_owned)
        connection = sqlite3.connect(config.baseline.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA trusted_schema=OFF")
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ConfigError("Baseline database failed integrity checking")
            if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ConfigError("Unsupported baseline schema")
            entries = {}
            for path, data in connection.execute("SELECT path,data FROM entries"):
                parsed = PurePosixPath(path)
                if not path or parsed.is_absolute() or ".." in parsed.parts or str(parsed) != path:
                    raise ConfigError("Unsafe path in baseline")
                entry = Entry(**json.loads(data))
                if entry.kind not in ("file", "directory"):
                    raise ConfigError("Unsupported object in baseline")
                entries[path] = entry
            if "." not in entries or "index.html" not in entries:
                raise ConfigError("Incomplete baseline")
            raw = connection.execute("SELECT template,calendar FROM page_recipe WHERE id=1").fetchone()
            if raw is None:
                raise ConfigError("Missing daily page recipe")
            recipe = Recipe(raw[0], json.loads(raw[1]))
            recipe.validate()
            return cls(entries, recipe)
        finally:
            connection.close()


def initialize(config: Config, now: datetime, *, update: bool = False) -> None:
    if config.root_owned and os.geteuid() != 0:
        raise ConfigError("Baseline administration requires root")
    with reference_lock(config, exclusive=True, create=True):
        if config.baseline.exists() and not update:
            raise ConfigError("Baseline already exists; init never overwrites it")
        if update and not config.baseline.exists():
            raise ConfigError("Cannot update a missing baseline; use init")
        recipe = Recipe.from_sources(config)
        # Initial setup may create the page. Updates must not silently erase an
        # untrusted daily page while approving unrelated static files.
        if not update:
            publish(config, recipe, now, bootstrap=True)
        snapshot = scan(config.web_root, config.max_file_bytes, config.max_entries)
        if snapshot.issues:
            raise ConfigError(f"Cannot baseline an unreadable/unstable tree: {snapshot.issues}")
        if any(entry.kind not in ("file", "directory") for entry in snapshot.entries.values()):
            raise ConfigError("Baseline cannot contain links or special objects")
        page = snapshot.entries.get("index.html")
        import hashlib
        if page is None or page.sha256 != hashlib.sha256(recipe.render(now.date())).hexdigest():
            raise ConfigError("Daily page must exactly match today's trusted recipe before approval")
        uid, gid = page_ids(config)
        if (page.mode, page.uid, page.gid) != (config.page_mode, uid, gid):
            raise ConfigError("Unexpected daily page metadata")
        fd, temporary = tempfile.mkstemp(prefix=".baseline-", dir=config.baseline.parent)
        os.close(fd)
        try:
            with closing(sqlite3.connect(temporary)) as connection, connection:
                connection.executescript("""
                    PRAGMA journal_mode=DELETE;
                    PRAGMA user_version=1;
                    CREATE TABLE entries(path TEXT PRIMARY KEY, data TEXT NOT NULL);
                    CREATE TABLE page_recipe(id INTEGER PRIMARY KEY CHECK(id=1),template TEXT NOT NULL,calendar TEXT NOT NULL);
                    CREATE TABLE metadata(created_at TEXT NOT NULL);
                """)
                connection.executemany("INSERT INTO entries VALUES(?,?)", (
                    (path, json.dumps(entry.data(), sort_keys=True)) for path, entry in snapshot.entries.items()
                ))
                connection.execute("INSERT INTO page_recipe VALUES(1,?,?)", (
                    recipe.template, json.dumps(recipe.calendar, ensure_ascii=False)
                ))
                connection.execute("INSERT INTO metadata VALUES(?)", (now.isoformat(),))
            os.chmod(temporary, 0o640)
            if config.read_group:
                os.chown(temporary, 0 if config.root_owned else -1, grp.getgrnam(config.read_group).gr_gid)
            with open(temporary, "rb") as stream:
                os.fsync(stream.fileno())
            os.replace(temporary, config.baseline)
            directory = os.open(config.baseline.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
