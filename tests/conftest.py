import sys
from datetime import datetime
from pathlib import Path

import pytest

if sys.platform != "linux":
    pytest.skip("The security backend and integration tests require Linux", allow_module_level=True)

from fim.baseline import initialize
from fim.config import load

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config(tmp_path):
    for name in ("web", "reference", "runtime", "logs", "staging", "sources"):
        (tmp_path / name).mkdir(mode=0o700)
    (tmp_path / "web/style.css").write_text("body {color: black}\n")
    (tmp_path / "sources/template.html").write_bytes((ROOT / "data/index.template.html").read_bytes())
    (tmp_path / "sources/calendar.json").write_bytes((ROOT / "data/namedays.sk.json").read_bytes())
    path = tmp_path / "config.toml"
    path.write_text(f'''
[paths]
web_root = "{tmp_path}/web"
baseline = "{tmp_path}/reference/baseline.sqlite"
runtime_dir = "{tmp_path}/runtime"
log_dir = "{tmp_path}/logs"
staging_dir = "{tmp_path}/staging"
template = "{tmp_path}/sources/template.html"
calendar = "{tmp_path}/sources/calendar.json"
[security]
require_root_owned = false
[monitor]
scan_interval = 1
debounce = 0.05
[page]
timezone = "Europe/Bratislava"
mode = "0644"
midnight_grace = 5
[smtp]
host = "127.0.0.1"
port = 1
mode = "plain"
sender = "fim@example.test"
recipients = ["admin@example.test"]
''', encoding="utf-8")
    return load(path)


@pytest.fixture
def now(config):
    return datetime(2026, 10, 31, 12, tzinfo=config.zone)


@pytest.fixture
def ready(config, now):
    initialize(config, now)
    return config
