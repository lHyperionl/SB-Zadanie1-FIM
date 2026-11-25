import logging
import os

from fim.baseline import Baseline
from fim.monitor import inspect
from fim.runtime import Runtime
from fim.safefs import MAX_DEPTH, scan


def test_invalid_filename_persists_alert_and_recovers(ready, now):
    bad = os.fsencode(ready.web_root) + b'/bad-\xff'
    fd = os.open(bad, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    runtime = Runtime(ready)
    baseline = Baseline.read(ready)
    log = logging.getLogger('test.invalid-name')
    findings, blocked = inspect(ready, baseline, lambda: now)
    assert blocked == {'.'}
    assert any(f.kind == 'scan_error' and 'UTF-8' in f.detail for f in findings)
    assert runtime.record(findings, blocked, log)
    assert runtime.due(10**12) is not None
    assert not runtime.record(findings, blocked, log)
    os.unlink(bad)
    findings, blocked = inspect(ready, baseline, lambda: now)
    assert not findings and not blocked
    runtime.record(findings, blocked, log)
    with runtime.connect() as connection:
        assert connection.execute('SELECT count(*) FROM incidents WHERE closed IS NULL').fetchone()[0] == 0


def test_deep_tree_reports_limit_without_recursion_failure(ready):
    current = ready.web_root
    for _ in range(MAX_DEPTH + 2):
        current /= 'd'
        current.mkdir()
    result = scan(ready.web_root, ready.max_file_bytes, 10000)
    assert 'depth limit' in result.issues['.']


def test_enumeration_stops_at_budget_before_materializing_all_names(ready, monkeypatch):
    consumed = 0
    class Item:
        name = 'unused'
    class WideDirectory:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def __iter__(self): return self
        def __next__(self):
            nonlocal consumed
            consumed += 1
            if consumed > 11:
                raise AssertionError('Enumeration continued beyond the limit')
            return Item()
    monkeypatch.setattr(os, 'scandir', lambda *_: WideDirectory())
    result = scan(ready.web_root, 4096, 10)
    assert consumed == 11
    assert 'exceeds 10 entries' in result.issues['.']


def test_entry_limit_covers_entire_tree(ready):
    for number in range(4):
        directory = ready.web_root / str(number)
        directory.mkdir()
        (directory / 'file').write_text('content')
    result = scan(ready.web_root, 4096, 6)
    assert 'exceeds 6 entries' in result.issues['.']
