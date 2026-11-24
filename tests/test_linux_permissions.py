"""Cross-UID permission checks without creating accounts or changing the OS."""
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

import pytest


@pytest.mark.skipif(os.geteuid() != 0, reason="Cross-UID checks require root; run this file separately with sudo")
def test_web_writer_and_monitor_permissions_are_separate():
    with tempfile.TemporaryDirectory(prefix="fim-permissions-", dir="/var/tmp") as directory:
        base = Path(directory)
        base.chmod(0o755)
        for name, uid, gid, mode in [
            ("web", 0, 60001, 0o2775), ("reference", 0, 60003, 0o750),
            ("code", 0, 0, 0o755), ("runtime", 60002, 60002, 0o700),
        ]:
            path = base / name
            path.mkdir()
            os.chown(path, uid, gid)
            path.chmod(mode)
        for name, gid, mode in [
            ("web/style.css", 60001, 0o664), ("reference/baseline.sqlite", 60003, 0o640),
            ("reference/config.toml", 60003, 0o640), ("code/monitor.py", 0, 0o644),
        ]:
            path = base / name
            path.write_text("original")
            os.chown(path, 0, gid)
            path.chmod(mode)

        script = r'''
import json,os,sys
from pathlib import Path
base=Path(sys.argv[1])
out={}
for name in ("web/style.css", "reference/baseline.sqlite", "reference/config.toml", "code/monitor.py"):
    try:
        fd=os.open(base/name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
        os.write(fd,b" changed")
        os.close(fd)
        out[name]=True
    except PermissionError:
        out[name]=False
try:
    out["read_reference"]=(base/"reference/baseline.sqlite").read_text()=="original"
except PermissionError:
    out["read_reference"]=False
try:
    (base/"runtime/state").write_text("state")
    out["runtime"]=True
except PermissionError:
    out["runtime"]=False
try:
    (base/"web/replacement").write_text("replacement")
    os.replace(base/"web/replacement",base/"reference/baseline.sqlite")
    out["replace_reference"]=True
except PermissionError:
    out["replace_reference"]=False
print(json.dumps(out))
'''

        def run_as(uid, gid, groups):
            def demote():
                os.setgroups(groups)
                os.setgid(gid)
                os.setuid(uid)
            result = subprocess.run(["/usr/bin/python3", "-c", script, str(base)], preexec_fn=demote, text=True, capture_output=True, check=True)
            return json.loads(result.stdout)

        attacker = run_as(60001, 60001, [])
        assert attacker["web/style.css"]
        assert not any(attacker[key] for key in ("reference/baseline.sqlite", "reference/config.toml", "code/monitor.py", "runtime", "replace_reference"))
        monitor = run_as(60002, 60002, [60003])
        assert monitor["read_reference"] and monitor["runtime"]
        assert not any(monitor[key] for key in ("web/style.css", "reference/baseline.sqlite", "reference/config.toml", "code/monitor.py", "replace_reference"))
        assert (base / "reference/baseline.sqlite").read_text() == "original"


@pytest.mark.skipif(os.geteuid() != 0, reason="Cross-UID checks require root")
def test_unreadable_file_is_reported_by_real_scanner():
    with tempfile.TemporaryDirectory(prefix="fim-unreadable-", dir="/var/tmp") as directory:
        base = Path(directory)
        base.chmod(0o755)
        (base / "secret").write_text("not-readable-by-monitor")
        (base / "secret").chmod(0o600)
        source = Path(__file__).resolve().parents[1] / "src"
        script = "import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from fim.safefs import scan;print(json.dumps(scan(Path(sys.argv[2]),4096,100).issues))"

        def demote():
            os.setgroups([])
            os.setgid(60002)
            os.setuid(60002)

        result = subprocess.run(["/usr/bin/python3", "-c", script, str(source), str(base)], preexec_fn=demote, capture_output=True, text=True, check=True)
        assert "secret" in json.loads(result.stdout)
        assert "not-readable-by-monitor" not in result.stdout


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd tools unavailable")
def test_systemd_unit_syntax(tmp_path):
    deploy = Path(__file__).resolve().parents[1] / "deploy"
    units = []
    for source in [*deploy.glob("*.service"), *deploy.glob("*.timer")]:
        # Validation checks executable existence. The production /opt/fim is not
        # installed on the test host; substitute only executable paths here.
        text = source.read_text().replace("/opt/fim/venv/bin/python", "/usr/bin/python3").replace("/opt/fim/tools/mailpit", "/usr/bin/true")
        target = tmp_path / source.name
        target.write_text(text)
        units.append(str(target))
    result = subprocess.run(["systemd-analyze", "verify", *units], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_publisher_sandbox_allows_rename_from_staging_to_web():
    deploy = Path(__file__).resolve().parents[1] / "deploy"
    paths = tomllib.loads((deploy / "config.toml").read_text(encoding="utf-8"))["paths"]
    unit = (deploy / "fim-publish.service").read_text(encoding="utf-8")
    writable = [path for line in unit.splitlines() if line.startswith("ReadWritePaths=")
                for path in line.split("=", 1)[1].split()]
    # Each entry is a separate mount; rename across mounts fails with EXDEV.
    assert len(writable) == 1
    for key in ("web_root", "staging_dir"):
        assert Path(paths[key]).is_relative_to(writable[0])
