"""Create an isolated, unprivileged demo; never use this config in production."""
import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
import shutil


def main():
    if sys.platform != "linux":
        raise SystemExit("Run this tool on Linux or in WSL.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.directory:
        base = args.directory.absolute()
        base.mkdir(mode=0o700, parents=False, exist_ok=False)
    else:
        base = Path(tempfile.mkdtemp(prefix="tuke-fim-"))
    for name in ("web", "reference", "runtime", "logs", "staging", "sources"):
        (base / name).mkdir(mode=0o700)
    project = Path(__file__).resolve().parents[1]
    for source, target in [
        (project / "demo/style.css", base / "web/style.css"),
        (project / "data/index.template.html", base / "sources/index.template.html"),
        (project / "data/namedays.sk.json", base / "sources/namedays.sk.json"),
    ]:
        shutil.copyfile(source, target)
    values = {
        "web_root": base / "web", "baseline": base / "reference/baseline.sqlite",
        "runtime_dir": base / "runtime", "log_dir": base / "logs",
        "staging_dir": base / "staging", "template": base / "sources/index.template.html",
        "calendar": base / "sources/namedays.sk.json",
    }
    text = "[paths]\n" + "\n".join(f"{key} = {json.dumps(str(value))}" for key, value in values.items())
    text += '''

[security]
require_root_owned = false

[monitor]
scan_interval = 30
debounce = 0.2

[page]
timezone = "Europe/Bratislava"
mode = "0644"
midnight_grace = 5

[smtp]
host = "127.0.0.1"
port = 1025
mode = "plain"
sender = "fim@example.test"
recipients = ["admin@example.test"]
'''
    (base / "config.toml").write_text(text, encoding="utf-8")
    print(base / "config.toml")


if __name__ == "__main__":
    main()
