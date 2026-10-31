#!/usr/bin/env bash
# Fresh installation of the demonstration on an Ubuntu 24.04+ Linux VM.
set -euo pipefail
umask 022
if [[ $EUID -ne 0 ]]; then
    echo 'Run this installer as root on a dedicated Linux demonstration VM.' >&2
    exit 1
fi
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -e /opt/fim || -e /etc/fim/config.toml || -e /var/www/fim-demo || -e /var/lib/fim/reference/baseline.sqlite ]]; then
    echo 'An installation or web directory already exists. Refusing to replace it; see README.md.' >&2
    exit 1
fi
apt-get update
apt-get install -y python3 python3-venv nginx ca-certificates curl
for group in fim-monitor fim-web fim-read; do
    getent group "$group" >/dev/null || groupadd --system "$group"
done
for account in fim-monitor fim-publisher; do
    if id "$account" >/dev/null 2>&1; then
        echo "Account $account already exists; use a fresh VM to avoid inheriting unexpected privileges." >&2
        exit 1
    fi
done
useradd --system --gid fim-monitor --groups fim-read --no-create-home --shell /usr/sbin/nologin fim-monitor
useradd --system --gid fim-web --groups fim-read --no-create-home --shell /usr/sbin/nologin fim-publisher
install -d -m 0755 /opt/fim /opt/fim/data /opt/fim/tools /var/lib/fim
install -d -m 0750 -o root -g fim-read /etc/fim /var/lib/fim/reference
install -d -m 0700 -o fim-monitor -g fim-monitor /var/lib/fim/runtime /var/log/fim
install -d -m 0700 -o fim-publisher -g fim-web /var/www/fim-staging
install -d -m 2775 -o root -g fim-web /var/www/fim-demo
install -m 0644 "$project_dir/data/index.template.html" "$project_dir/data/namedays.sk.json" /opt/fim/data/
install -m 0664 -o root -g fim-web "$project_dir/demo/style.css" /var/www/fim-demo/style.css
install -m 0640 -o root -g fim-read "$project_dir/deploy/config.toml" /etc/fim/config.toml
python3 -m venv --copies /opt/fim/venv
build_dir=$(mktemp -d /tmp/fim-build.XXXXXXXX)
trap 'if [[ $build_dir == /tmp/fim-build.* ]]; then rm -rf -- "$build_dir"; fi' EXIT
mkdir "$build_dir/source"
cp -- "$project_dir/pyproject.toml" "$build_dir/source/"
cp -R -- "$project_dir/src" "$build_dir/source/src"
/opt/fim/venv/bin/python -m pip install --require-hashes -r "$project_dir/requirements.txt"
/opt/fim/venv/bin/python -m pip install --no-deps "$build_dir/source"
/opt/fim/venv/bin/python -I -m fim init --config /etc/fim/config.toml
install -m 0644 "$project_dir/deploy/fim-monitor.service" "$project_dir/deploy/fim-publish.service" "$project_dir/deploy/fim-publish.timer" /etc/systemd/system/
install -m 0644 "$project_dir/deploy/nginx.conf" /etc/nginx/sites-available/fim-demo
ln -s /etc/nginx/sites-available/fim-demo /etc/nginx/sites-enabled/fim-demo
nginx -t
systemctl daemon-reload
systemctl enable --now nginx
systemctl reload nginx
systemctl enable --now fim-monitor.service fim-publish.timer
echo 'Installed. Website: http://localhost:8080. Configure SMTP or install Mailpit using deploy/install-mailpit.sh.'
