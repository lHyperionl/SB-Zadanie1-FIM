#!/usr/bin/env bash
# Optional local receiver; the checksum is pinned to the official v1.33.0 asset.
set -euo pipefail
if [[ $EUID -ne 0 || ! -d /opt/fim ]]; then
    echo 'Install FIM first, then run this script as root.' >&2
    exit 1
fi
if [[ $(uname -m) != x86_64 ]]; then
    echo 'This pinned Mailpit download supports Linux x86_64 only.' >&2
    exit 1
fi
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=$(mktemp -d /tmp/fim-mailpit.XXXXXXXX)
trap 'if [[ $build_dir == /tmp/fim-mailpit.* ]]; then rm -rf -- "$build_dir"; fi' EXIT
curl --fail --location --proto '=https' --tlsv1.2 \
    https://github.com/axllent/mailpit/releases/download/v1.33.0/mailpit-linux-amd64.tar.gz \
    --output "$build_dir/mailpit.tar.gz"
printf '%s  %s\n' d0ec50080cbf3e7c1fa2cda2ee68125d7894175811084b1f8f47c6cfc6f487c8 "$build_dir/mailpit.tar.gz" | sha256sum --check --status
tar -xzf "$build_dir/mailpit.tar.gz" -C "$build_dir" mailpit
install -m 0755 "$build_dir/mailpit" /opt/fim/tools/mailpit
install -m 0644 "$project_dir/deploy/fim-mailpit.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now fim-mailpit.service
echo 'Mailpit UI: http://localhost:8025; test SMTP: 127.0.0.1:1025.'
