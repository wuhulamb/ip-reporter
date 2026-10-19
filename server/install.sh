#!/usr/bin/env bash
# Install / update the IP reporter server.
#
# Example:
#   sudo ./server/install.sh --dir /home/USER/ip-reporter --user USER
#
# The script only touches:
#   <dir>/server, <dir>/config, <dir>/data
#   /etc/systemd/system/ip-reporter-server.service
#
# It does not modify nginx automatically; see nginx-ip.ooops.dpdns.org.conf.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET_DIR="/opt/ip-reporter"
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_GROUP=""
PORT="8765"
FORCE="0"
UNINSTALL="0"
PURGE="0"

usage() {
    cat <<'EOF'
Usage: sudo ./server/install.sh [options]

Options:
  --dir PATH        install directory (default: /opt/ip-reporter)
  --user NAME       run the service as this user (default: $SUDO_USER or current)
  --group NAME      run the service as this group (default: user's group)
  --port PORT       local HTTP port behind nginx (default: 8765)
  --force           overwrite an existing config (rotates tokens!)
  --uninstall       stop and remove the systemd service
  --purge           with --uninstall, also delete config/data in --dir
  -h, --help        show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) TARGET_DIR="${2:?--dir needs a value}"; shift 2 ;;
        --user) RUN_USER="${2:?--user needs a value}"; shift 2 ;;
        --group) RUN_GROUP="${2:?--group needs a value}"; shift 2 ;;
        --port) PORT="${2:?--port needs a value}"; shift 2 ;;
        --force) FORCE="1"; shift ;;
        --uninstall) UNINSTALL="1"; shift ;;
        --purge) PURGE="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this script as root (sudo)" >&2
    exit 1
fi

if ! id -u "$RUN_USER" >/dev/null 2>&1; then
    echo "error: user does not exist: $RUN_USER" >&2
    exit 1
fi
if [ -z "$RUN_GROUP" ]; then
    RUN_GROUP="$(id -gn "$RUN_USER")"
fi

UNIT="/etc/systemd/system/ip-reporter-server.service"

if [ "$UNINSTALL" = "1" ]; then
    systemctl disable --now ip-reporter-server.service 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    echo "removed $UNIT"
    if [ "$PURGE" = "1" ]; then
        rm -rf "$TARGET_DIR"
        echo "removed $TARGET_DIR"
    else
        echo "kept $TARGET_DIR (use --purge to remove config and data)"
    fi
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required" >&2
    exit 1
fi
PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 8) else 0)')"
if [ "$PY_OK" != "1" ]; then
    echo "error: Python 3.8 or newer is required" >&2
    exit 1
fi

CONFIG_DIR="$TARGET_DIR/config"
DATA_DIR="$TARGET_DIR/data"
CONFIG="$CONFIG_DIR/server.json"

install -d -m 0755 -o "$RUN_USER" -g "$RUN_GROUP" "$TARGET_DIR"
install -d -m 0755 -o "$RUN_USER" -g "$RUN_GROUP" "$TARGET_DIR/server"
install -d -m 0700 -o "$RUN_USER" -g "$RUN_GROUP" "$CONFIG_DIR"
install -d -m 0700 -o "$RUN_USER" -g "$RUN_GROUP" "$DATA_DIR"

install_file() {
    local src="$1" dest="$2" mode="$3"
    if [ "$(readlink -f "$src")" = "$(readlink -f "$dest")" ]; then
        # Running the installer from the target checkout (in-place upgrade).
        chown "$RUN_USER:$RUN_GROUP" "$dest"
        chmod "$mode" "$dest"
    else
        install -m "$mode" -o "$RUN_USER" -g "$RUN_GROUP" "$src" "$dest"
    fi
}

install_file "$SCRIPT_DIR/ip_reporter_server.py" \
    "$TARGET_DIR/server/ip_reporter_server.py" 0755
install_file "$SCRIPT_DIR/dashboard.html" \
    "$TARGET_DIR/server/dashboard.html" 0644

if [ -f "$CONFIG" ] && [ "$FORCE" != "1" ]; then
    echo "keeping existing config: $CONFIG"
else
    if [ -f "$CONFIG" ]; then
        echo "warning: --force given, rotating report/admin tokens"
    fi
    python3 - "$CONFIG" "$PORT" <<'PY'
import json
import os
import secrets
import sys

path = sys.argv[1]
port = int(sys.argv[2])
cfg = {
    "listen_host": "127.0.0.1",
    "listen_port": port,
    "data_dir": "../data",
    "report_token": secrets.token_urlsafe(32),
    "admin_token": secrets.token_urlsafe(32),
    "trust_proxy": True,
    "online_threshold_seconds": 600,
    "history_retention_days": 90,
    "history_max_per_client": 1000,
    "dashboard_title": "内网 IP 上报",
}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
os.chmod(path, 0o600)
PY
    chown "$RUN_USER:$RUN_GROUP" "$CONFIG"
fi

# Validate the config before installing the unit.  --check creates the
# data directories, so make sure everything under data/ is owned by the
# service user afterwards.
python3 "$TARGET_DIR/server/ip_reporter_server.py" --config "$CONFIG" --check
chown -R "$RUN_USER:$RUN_GROUP" "$DATA_DIR"
chmod 0700 "$DATA_DIR"
find "$DATA_DIR" -type d -exec chmod 700 {} +
find "$DATA_DIR" -type f -exec chmod 600 {} +

sed \
    -e "s|@USER@|$RUN_USER|g" \
    -e "s|@GROUP@|$RUN_GROUP|g" \
    -e "s|@DIR@|$TARGET_DIR|g" \
    "$REPO_DIR/systemd/ip-reporter-server.service.in" > "$UNIT"
chmod 0644 "$UNIT"

systemctl daemon-reload
systemctl enable ip-reporter-server.service >/dev/null
systemctl restart ip-reporter-server.service

echo -n "waiting for server on 127.0.0.1:$PORT"
HEALTH=""
for _ in $(seq 1 30); do
    if HEALTH="$(curl -fsS --max-time 2 "http://127.0.0.1:$PORT/healthz" 2>/dev/null)"; then
        echo
        break
    fi
    echo -n "."
    sleep 0.5
done
if [ -z "$HEALTH" ]; then
    echo
    echo "error: server did not become healthy; recent logs:" >&2
    journalctl -u ip-reporter-server.service -n 40 --no-pager >&2 || true
    exit 1
fi
echo "$HEALTH"

echo
echo "installed: $TARGET_DIR"
echo "service:   ip-reporter-server.service (user $RUN_USER)"
echo "health:    http://127.0.0.1:$PORT/healthz"
echo
python3 - "$CONFIG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    cfg = json.load(fh)
print("report_token=" + cfg["report_token"])
print("admin_token=" + cfg["admin_token"])
PY
echo
echo "Keep these tokens secret. Clients only need report_token."
echo "Next: install the nginx site and obtain a TLS certificate for ip.ooops.dpdns.org."
echo "      See server/nginx-ip.ooops.dpdns.org.conf and README.md."
