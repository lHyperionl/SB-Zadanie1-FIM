"""Root-only smoke test of a protected installed layout, without OS provisioning."""
import grp
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

import pytest
import watchdog


@pytest.mark.skipif(os.geteuid() != 0, reason="Protected /opt layout and UID switching require root")
def test_protected_installation_with_separate_accounts():
    root = Path(__file__).resolve().parents[1]
    publisher = pwd.getpwnam("nobody").pw_uid
    web_gid = grp.getgrnam("www-data").gr_gid
    read_gid = grp.getgrnam("nogroup").gr_gid
    monitor = 60002
    with tempfile.TemporaryDirectory(prefix="fim-smoke-", dir="/opt") as temporary:
        base = Path(temporary)
        base.chmod(0o755)
        # A system Python gives a root-owned stdlib as on the target server.
        subprocess.run(["/usr/bin/python3", "-m", "venv", "--without-pip", "--copies", str(base / "venv")], check=True)
        interpreter = base / "venv/bin/python"
        site = Path(subprocess.check_output([str(interpreter), "-I", "-c", "import sysconfig;print(sysconfig.get_paths()['purelib'])"], text=True).strip())
        for source, name in [(root / "src/fim", "fim"), (Path(watchdog.__file__).parent, "watchdog")]:
            target = site / name
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
            for path in [target, *target.rglob("*")]:
                path.chmod(0o755 if path.is_dir() else 0o644)
        for name, owner, group, mode in [
            ("web", 0, web_gid, 0o2775), ("staging", publisher, web_gid, 0o700),
            ("reference", 0, read_gid, 0o750), ("runtime", monitor, monitor, 0o700),
            ("logs", monitor, monitor, 0o700), ("data", 0, 0, 0o755),
        ]:
            path = base / name
            path.mkdir()
            os.chown(path, owner, group)
            path.chmod(mode)
        for name in ("index.template.html", "namedays.sk.json"):
            shutil.copyfile(root / "data" / name, base / "data" / name)
            (base / "data" / name).chmod(0o644)
        style = base / "web/style.css"
        style.write_text("body {color: black}\n")
        os.chown(style, 0, web_gid)
        style.chmod(0o664)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        text = (root / "deploy/config.toml").read_text()
        for old, new in {
            "/var/www/fim-demo": str(base / "web"), "/var/www/fim-staging": str(base / "staging"),
            "/var/lib/fim/reference/baseline.sqlite": str(base / "reference/baseline.sqlite"),
            "/var/lib/fim/runtime": str(base / "runtime"), "/var/log/fim": str(base / "logs"),
            "/opt/fim/data": str(base / "data"), 'read_group = "fim-read"': 'read_group = "nogroup"',
            'owner = "fim-publisher"': 'owner = "nobody"', 'group = "fim-web"': 'group = "www-data"',
            "port = 1025": f"port = {port}",
        }.items():
            text = text.replace(old, new)
        config = base / "config.toml"
        config.write_text(text)
        os.chown(config, 0, read_gid)
        config.chmod(0o640)

        def child(command, *, uid=0, gid=0, groups=(), code=None):
            def demote():
                os.setgroups(list(groups))
                os.setgid(gid)
                os.setuid(uid)
            args = [str(interpreter), "-I"]
            args += ["-c", code] if code else ["-m", "fim", command, "--config", str(config)]
            return subprocess.run(args, preexec_fn=demote, cwd="/", text=True, capture_output=True, timeout=20)

        initialized = child("init")
        assert initialized.returncode == 0, initialized.stderr
        original_reference = (base / "reference/baseline.sqlite").read_bytes()
        clean = child("check", uid=monitor, gid=monitor, groups=[read_gid])
        assert clean.returncode == 0, clean.stderr
        original_page = (base / "web/index.html").read_bytes()
        # Simulate a legitimate stale page after a missed midnight.
        stale = child("", code=f'''from fim.config import load
from fim.baseline import Baseline
from datetime import datetime,timedelta
c=load({str(config)!r})
(c.web_root/'index.html').write_bytes(Baseline.read(c).recipe.render(datetime.now(c.zone).date()-timedelta(days=1)))
''')
        assert stale.returncode == 0, stale.stderr
        published = child("publish", uid=publisher, gid=web_gid, groups=[read_gid])
        assert published.returncode == 0, published.stderr
        assert (base / "web/index.html").read_bytes() == original_page
        attack = child("", uid=publisher, gid=web_gid, groups=[read_gid], code=f"from pathlib import Path;Path({str(style)!r}).write_text('attack')")
        assert attack.returncode == 0, attack.stderr
        detected = child("check", uid=monitor, gid=monitor, groups=[read_gid])
        assert detected.returncode == 1, detected.stderr
        assert "content_changed" in detected.stderr
        assert (base / "reference/baseline.sqlite").read_bytes() == original_reference
        # An accidentally writable reference must fail the trust check.
        (base / "reference/baseline.sqlite").chmod(0o660)
        unsafe = child("check", uid=monitor, gid=monitor, groups=[read_gid])
        assert unsafe.returncode == 2
        assert "not group/other writable" in unsafe.stderr
