from datetime import datetime, timedelta

import pytest

from fim.baseline import Baseline
from fim.config import ConfigError
from fim.monitor import inspect
from fim.page import Recipe, publish


def test_calendar_has_366_days_and_official_names(config):
    recipe = Recipe.from_sources(config)
    assert len(recipe.calendar) == 366
    assert recipe.calendar["02-29"] == ["Radomír"]
    assert recipe.calendar["10-31"] == ["Aurélia"]
    assert recipe.calendar["01-01"] == []
    assert "Dnes nie sú" in recipe.render(datetime(2026, 1, 1).date()).decode()


@pytest.mark.parametrize("day", ["2026-11-01", "2027-01-01", "2028-02-29", "2026-03-29", "2026-10-25"])
def test_midnight_transition_and_deadline(ready, day):
    baseline = Baseline.read(ready)
    midnight = datetime.fromisoformat(day).replace(tzinfo=ready.zone)
    path = ready.web_root / "index.html"
    path.write_bytes(baseline.recipe.render((midnight - timedelta(days=1)).date()))
    assert not inspect(ready, baseline, lambda: midnight + timedelta(seconds=4))[0]
    assert any(f.kind == "daily_content_changed" for f in inspect(ready, baseline, lambda: midnight + timedelta(seconds=5))[0])
    before = ready.baseline.read_bytes()
    publish(ready, baseline.recipe, midnight + timedelta(seconds=1))
    assert not inspect(ready, baseline, lambda: midnight + timedelta(seconds=6))[0]
    assert ready.baseline.read_bytes() == before


def test_malicious_midnight_change_is_not_accepted_or_overwritten(ready):
    baseline = Baseline.read(ready)
    now = datetime(2026, 11, 1, 0, 0, 1, tzinfo=ready.zone)
    path = ready.web_root / "index.html"
    attack = baseline.recipe.render(now.date()) + b"<script>alert('attack')</script>"
    path.write_bytes(attack)
    assert any(f.kind == "daily_content_changed" for f in inspect(ready, baseline, lambda: now)[0])
    with pytest.raises(ConfigError, match="noncanonical"):
        publish(ready, baseline.recipe, now)
    assert path.read_bytes() == attack


def test_publisher_does_not_recreate_deleted_file_or_follow_link(ready, now, tmp_path):
    baseline = Baseline.read(ready)
    path = ready.web_root / "index.html"
    path.unlink()
    with pytest.raises(OSError):
        publish(ready, baseline.recipe, now)
    assert not path.exists()
    target = tmp_path / "target"
    target.write_text("unchanged")
    path.symlink_to(target)
    with pytest.raises(OSError):
        publish(ready, baseline.recipe, now)
    assert target.read_text() == "unchanged"


def test_catch_up_after_long_outage(ready, now):
    baseline = Baseline.read(ready)
    future = now + timedelta(days=10)
    assert publish(ready, baseline.recipe, future)
    assert not inspect(ready, baseline, lambda: future)[0]
    assert not list(ready.staging_dir.iterdir())


def test_metadata_attack_is_not_erased_by_publisher(ready, now):
    baseline = Baseline.read(ready)
    (ready.web_root / "index.html").chmod(0o600)
    with pytest.raises(ConfigError, match="permissions"):
        publish(ready, baseline.recipe, now + timedelta(days=1))


def test_render_escapes_names(config):
    recipe = Recipe.from_sources(config)
    recipe.calendar["01-02"] = ["<script>&"]
    page = recipe.render(datetime(2026, 1, 2).date())
    assert b"&lt;script&gt;&amp;" in page
    assert b"<script>" not in page


def test_day_rollover_during_scan_uses_new_snapshot(ready, monkeypatch):
    import fim.monitor as module
    baseline = Baseline.read(ready)
    before = datetime(2026, 10, 31, 23, 59, 59, tzinfo=ready.zone)
    after = before + timedelta(seconds=10)
    values = iter([before, after, after])
    real_scan = module.scan
    calls = []

    def scan(*args):
        calls.append(True)
        if len(calls) == 2:
            publish(ready, baseline.recipe, after)
        return real_scan(*args)

    monkeypatch.setattr(module, "scan", scan)
    assert not inspect(ready, baseline, lambda: next(values))[0]
    assert len(calls) == 2
