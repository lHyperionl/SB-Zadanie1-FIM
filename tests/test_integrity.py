import os
from dataclasses import replace

import pytest

from fim.baseline import Baseline, initialize, reference_lock
from fim.config import ConfigError, load, trusted_path
from fim.monitor import inspect
from fim.safefs import Unstable, open_directory, read_regular, scan


def findings(config, now):
    return inspect(config, Baseline.read(config), lambda: now)[0]


def test_clean_site_and_baseline_is_read_only(ready, now):
    original = ready.baseline.read_bytes()
    assert not findings(ready, now)
    assert ready.baseline.read_bytes() == original
    assert ready.baseline.stat().st_mode & 0o222 == 0o200


def test_content_change_with_same_size_and_restored_mtime(ready, now):
    path = ready.web_root / "style.css"
    before = path.stat()
    path.write_text(path.read_text().replace("black", "white"))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_size == before.st_size
    assert any(f.path == "style.css" and f.kind == "content_changed" for f in findings(ready, now))


def test_add_remove_rename_and_directory_permissions(ready, now):
    (ready.web_root / "style.css").rename(ready.web_root / "renamed.css")
    (ready.web_root / "shell.php").write_text("<?php echo 'unexpected';")
    ready.web_root.chmod(0o755)
    actual = {(f.path, f.kind) for f in findings(ready, now)}
    assert {("style.css", "removed"), ("renamed.css", "added"), ("shell.php", "added"), (".", "metadata_changed")} <= actual


def test_symlink_and_fifo_are_never_read(ready, now, tmp_path):
    secret = tmp_path / "outside-secret"
    secret.write_text("DO NOT READ")
    (ready.web_root / "style.css").unlink()
    (ready.web_root / "style.css").symlink_to(secret)
    os.mkfifo(ready.web_root / "pipe")
    result = findings(ready, now)
    assert any(f.kind == "type_changed" and f.path == "style.css" for f in result)
    assert any(f.kind == "unexpected_type" and f.path == "pipe" for f in result)
    assert "DO NOT READ" not in repr(result)


def test_symlink_directory_component_is_rejected(ready, tmp_path):
    (tmp_path / "redirect").symlink_to(ready.web_root, target_is_directory=True)
    with pytest.raises(OSError):
        open_directory(tmp_path / "redirect")


def test_large_file_and_missing_root_fail_closed(ready, now):
    (ready.web_root / "large.bin").write_bytes(b"x" * 2048)
    bounded = replace(ready, max_file_bytes=1024)
    result, blocked = inspect(bounded, Baseline.read(ready), lambda: now)
    assert "large.bin" in blocked
    assert any(f.kind == "scan_error" for f in result)
    ready.web_root.rename(ready.web_root.with_name("moved"))
    assert scan(ready.web_root, 1024, 100).issues.keys() == {"."}


def test_size_limit_does_not_turn_into_baseline(ready, now):
    old = ready.baseline.read_bytes()
    (ready.web_root / "large").write_bytes(b"x" * 4096)
    with pytest.raises(ConfigError):
        initialize(replace(ready, max_file_bytes=1024), now, update=True)
    assert ready.baseline.read_bytes() == old


def test_reader_retries_and_reports_continuously_mutating_file(ready, monkeypatch):
    path = ready.web_root / "style.css"
    original_read = os.read
    counter = 0

    def mutate(fd, count):
        nonlocal counter
        data = original_read(fd, count)
        if data:
            counter += 1
            path.write_text(f"mutation-{counter}")
        return data

    parent = open_directory(ready.web_root)
    try:
        monkeypatch.setattr(os, "read", mutate)
        with pytest.raises(Unstable):
            read_regular(parent, "style.css", 4096)
    finally:
        os.close(parent)


def test_baseline_never_auto_initializes_or_overwrites(ready, now):
    original = ready.baseline.read_bytes()
    with pytest.raises(ConfigError, match="already exists"):
        initialize(ready, now)
    assert original == ready.baseline.read_bytes()
    ready.baseline.unlink()
    with pytest.raises(FileNotFoundError):
        Baseline.read(ready)
    assert not ready.baseline.exists()


def test_corrupt_baseline_is_rejected(ready):
    ready.baseline.write_bytes(b"not a database")
    with pytest.raises(Exception):
        Baseline.read(ready)


def test_baseline_update_requires_exclusive_lock(ready, now):
    with reference_lock(ready):
        with pytest.raises(ConfigError, match="in use"):
            initialize(ready, now, update=True)


def test_explicit_baseline_update_accepts_verified_static_change(ready, now):
    (ready.web_root / "style.css").write_text("approved revision")
    initialize(ready, now, update=True)
    assert not findings(ready, now)


def test_production_configuration_rejects_writable_ancestors(config):
    with pytest.raises(ConfigError):
        trusted_path(config.source, root_owned=True)


def test_config_rejects_baseline_in_website_and_plain_remote_smtp(config):
    source = config.source.read_text()
    config.source.write_text(source.replace(str(config.baseline), str(config.web_root / "baseline.sqlite")))
    with pytest.raises(ConfigError, match="outside"):
        load(config.source)
    config.source.write_text(source.replace('host = "127.0.0.1"', 'host = "smtp.example.test"'))
    with pytest.raises(ConfigError, match="loopback"):
        load(config.source)


def test_config_rejects_writable_runtime_containing_website(config):
    source = config.source.read_text()
    config.source.write_text(source.replace(str(config.runtime_dir), str(config.web_root.parent)))
    with pytest.raises(ConfigError, match="cannot contain"):
        load(config.source)
