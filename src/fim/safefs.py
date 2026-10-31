from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


class Unstable(OSError):
    pass


@dataclass(frozen=True)
class Entry:
    kind: str
    mode: int
    uid: int
    gid: int
    size: int = 0
    sha256: str | None = None

    def data(self) -> dict:
        return asdict(self)


@dataclass
class Snapshot:
    entries: dict[str, Entry] = field(default_factory=dict)
    issues: dict[str, str] = field(default_factory=dict)


def open_directory(path: Path) -> int:
    """Walk from / with openat + O_NOFOLLOW for every directory component."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Unsafe directory path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino


def signature(info: os.stat_result) -> tuple:
    return (*identity(info), info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def metadata(info: os.stat_result, *, sha256: str | None = None) -> Entry:
    kind = "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"
    return Entry(kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid,
                 info.st_size if kind == "file" else 0, sha256)


def read_regular(parent: int, name: str, limit: int, *, capture: bool = False) -> tuple[Entry, bytes]:
    """Nonblocking open prevents a raced FIFO from hanging the scanner."""
    last = None
    for _ in range(3):
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise Unstable("File was replaced by a nonregular object")
            if before.st_size > limit:
                raise OSError(f"File exceeds configured size limit ({limit} bytes)")
            digest = hashlib.sha256()
            chunks = []
            total = 0
            while block := os.read(fd, 128 * 1024):
                total += len(block)
                if total > limit:
                    raise OSError(f"File exceeds configured size limit ({limit} bytes)")
                digest.update(block)
                if capture:
                    chunks.append(block)
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if signature(before) != signature(after) or signature(after) != signature(current) or total != after.st_size:
                raise Unstable("File changed while being read")
            return metadata(after, sha256=digest.hexdigest()), b"".join(chunks)
        except (Unstable, FileNotFoundError) as exc:
            last = exc
        finally:
            if fd is not None:
                os.close(fd)
        time.sleep(0.02)
    raise Unstable("File did not stabilize after three attempts") from last


def scan(root: Path, max_bytes: int, max_entries: int) -> Snapshot:
    """Take a bounded snapshot without following links. Retry directory races."""
    for attempt in range(3):
        result = Snapshot()
        count = 0

        def walk(fd: int, relative: str) -> None:
            nonlocal count
            before = os.fstat(fd)
            result.entries[relative] = metadata(before)
            try:
                names = sorted(os.listdir(fd))
            except OSError as exc:
                result.issues[relative] = str(exc)
                return
            for name in names:
                count += 1
                if count > max_entries:
                    raise OSError(f"Directory tree exceeds {max_entries} entries")
                path = name if relative == "." else f"{relative}/{name}"
                try:
                    name.encode("utf-8")
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            if identity(os.fstat(child)) != identity(info):
                                raise Unstable("Directory replaced before traversal")
                            walk(child, path)
                            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(info):
                                raise Unstable("Directory replaced during traversal")
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        result.entries[path] = read_regular(fd, name, max_bytes)[0]
                    else:
                        result.entries[path] = metadata(info)
                except Unstable:
                    raise
                except (OSError, UnicodeError) as exc:
                    result.issues[path] = str(exc)
            if signature(before) != signature(os.fstat(fd)):
                raise Unstable("Directory changed during traversal")

        fd = None
        try:
            fd = open_directory(root)
            initial = os.fstat(fd)
            walk(fd, ".")
            other = open_directory(root)
            try:
                if identity(initial) != identity(os.fstat(other)):
                    raise Unstable("Monitored root was replaced")
            finally:
                os.close(other)
            return result
        except Unstable as exc:
            if attempt == 2:
                return Snapshot(issues={".": str(exc)})
            time.sleep(0.02)
        except OSError as exc:
            return Snapshot(issues={".": str(exc)})
        finally:
            if fd is not None:
                os.close(fd)
    raise AssertionError("unreachable")
