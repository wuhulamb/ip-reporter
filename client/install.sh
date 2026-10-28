#!/usr/bin/env bash
# Install / update the IP reporter client on a Linux machine.
#
# Example:
#   sudo ./client/install.sh \
#       --server-url https://ip.ooops.dpdns.org \
#       --token 'REPORT_TOKEN_FROM_SERVER' \
#       --label guo
#
# Installed files:
#   /usr/local/bin/ip-reporter
#   /etc/ip-reporter/client.json          (mode 600)
#   /var/lib/ip-reporter/state.json       (client id / last report)
#   /etc/systemd/system/ip-reporter.service
#   /etc/systemd/system/ip-reporter.timer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SERVER_URL=""
TOKEN=""
CLIENT_ID=""
LABEL=""
HAS_LABEL="0"
INTERVAL_SECONDS="300"
FORCE="0"
UNINSTALL="0"
PURGE="0"

usage() {
    cat <<'EOF'
Usage: sudo ./client/install.sh [options]

Options:
  --server-url URL   server base URL, e.g. https://ip.ooops.dpdns.org
  --token TOKEN      report_token from the server config
  --client-id ID     optional fixed client id
  --label TEXT       required human-readable label, e.g. guo or office-pc
                     (with an existing config, updates only the label)
  --interval VALUE   report interval, e.g. 300, 5min, 1h (default: 300)
  --force            overwrite an existing /etc/ip-reporter/client.json
  --uninstall        stop and remove the systemd units and client binary
  --purge            with --uninstall, also delete config and state
  -h, --help         show this help
EOF
}

parse_interval() {
    local value="$1"
    case "$value" in
        *h) echo $(( ${value%h} * 3600 )) ;;
        *min) echo $(( ${value%min} * 60 )) ;;
        *s) echo "${value%s}" ;;
        *) echo "$value" ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --server-url) SERVER_URL="${2:?--server-url needs a value}"; shift 2 ;;
        --token) TOKEN="${2:?--token needs a value}"; shift 2 ;;
        --client-id) CLIENT_ID="${2:?--client-id needs a value}"; shift 2 ;;
        --label) LABEL="${2:?--label needs a value}"; HAS_LABEL="1"; shift 2 ;;
        --interval) INTERVAL_SECONDS="$(parse_interval "${2:?--interval needs a value}")"; shift 2 ;;
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

if [ "$UNINSTALL" = "1" ]; then
    systemctl disable --now ip-reporter.timer ip-reporter.service 2>/dev/null || true
    rm -f /etc/systemd/system/ip-reporter.service \
          /etc/systemd/system/ip-reporter.timer \
          /etc/NetworkManager/dispatcher.d/90-ip-reporter \
          /usr/local/bin/ip-reporter
    systemctl daemon-reload
    echo "removed client units and /usr/local/bin/ip-reporter"
    if [ "$PURGE" = "1" ]; then
        rm -rf /etc/ip-reporter /var/lib/ip-reporter
        echo "removed /etc/ip-reporter and /var/lib/ip-reporter"
    else
        echo "kept /etc/ip-reporter and /var/lib/ip-reporter (use --purge to remove)"
    fi
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required" >&2
    exit 1
fi

CONFIG="/etc/ip-reporter/client.json"

if [ ! -f "$CONFIG" ]; then
    if [ -z "$SERVER_URL" ] && [ -t 0 ]; then
        read -r -p "Server URL [https://ip.ooops.dpdns.org]: " SERVER_URL
        SERVER_URL="${SERVER_URL:-https://ip.ooops.dpdns.org}"
    fi
    if [ -z "$TOKEN" ] && [ -t 0 ]; then
        read -r -s -p "Report token: " TOKEN
        echo
    fi
    if [ -z "$LABEL" ] && [ -t 0 ]; then
        read -r -p "Client label (e.g. guo): " LABEL
    fi
fi

if [ -f "$CONFIG" ] && [ "$FORCE" != "1" ]; then
    if [ "$HAS_LABEL" = "1" ]; then
        LABEL="$LABEL" python3 - "$CONFIG" <<'PY'
import json
import os
import re
import sys

path = sys.argv[1]
label = os.environ.get("LABEL", "")
if re.search(r"[\x00-\x1f\x7f]", label):
    raise SystemExit("error: label contains control characters")
label = label.strip()
if not label:
    raise SystemExit("error: label is required")
if len(label) > 64:
    raise SystemExit("error: label is too long (max 64 characters)")
with open(path, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)
cfg["label"] = label
with open(path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
os.chmod(path, 0o600)
PY
        echo "updated label in existing config: $CONFIG"
    else
        if ! python3 - "$CONFIG" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
except Exception as exc:
    print(f"error: cannot read {sys.argv[1]}: {exc}", file=sys.stderr)
    raise SystemExit(1)
label = cfg.get("label")
raise SystemExit(0 if isinstance(label, str) and label.strip() else 1)
PY
        then
            echo "error: existing config has no label; rerun with --label TEXT" >&2
            exit 2
        fi
        echo "keeping existing config: $CONFIG (use --force to overwrite)"
    fi
else
    if [ -z "$SERVER_URL" ]; then
        echo "error: --server-url is required for a new config" >&2
        exit 2
    fi
    if [ -z "$TOKEN" ]; then
        echo "error: --token is required for a new config" >&2
        exit 2
    fi
    if [ -z "$LABEL" ]; then
        echo "error: --label is required for a new config" >&2
        exit 2
    fi

    install -d -m 0700 /etc/ip-reporter
    install -d -m 0700 /var/lib/ip-reporter

    SERVER_URL="$SERVER_URL" REPORT_TOKEN="$TOKEN" CLIENT_ID="$CLIENT_ID" \
    LABEL="$LABEL" python3 - "$CONFIG" <<'PY'
import json
import os
import re
import sys

path = sys.argv[1]
label = os.environ.get("LABEL", "")
if re.search(r"[\x00-\x1f\x7f]", label):
    raise SystemExit("error: label contains control characters")
label = label.strip()
if not label:
    raise SystemExit("error: label is required")
if len(label) > 64:
    raise SystemExit("error: label is too long (max 64 characters)")
cfg = {
    "server_url": os.environ["SERVER_URL"].strip(),
    "report_token": os.environ["REPORT_TOKEN"].strip(),
    "client_id": os.environ.get("CLIENT_ID", "").strip(),
    "label": label,
    "state_file": "/var/lib/ip-reporter/state.json",
    "timeout_seconds": 10,
    "retries": 3,
    "verify_tls": True,
    "ca_file": "",
    "include_interfaces": [],
    "exclude_interfaces": ["lo", "docker*", "veth*", "br-*", "virbr*"],
    "include_loopback": False,
    "extra_tags": {},
}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
os.chmod(path, 0o600)
PY
fi

if ! [[ "$INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || [ "$INTERVAL_SECONDS" -lt 30 ]; then
    echo "error: interval must be an integer >= 30 seconds" >&2
    exit 2
fi

install -d -m 0700 /var/lib/ip-reporter
if [ "$(readlink -f "$SCRIPT_DIR/ip_reporter.py")" = "$(readlink -f /usr/local/bin/ip-reporter)" ]; then
    chmod 0755 /usr/local/bin/ip-reporter
else
    install -m 0755 "$SCRIPT_DIR/ip_reporter.py" /usr/local/bin/ip-reporter
fi

install -m 0644 "$REPO_DIR/systemd/ip-reporter.service" \
    /etc/systemd/system/ip-reporter.service
sed "s/^OnUnitActiveSec=.*/OnUnitActiveSec=${INTERVAL_SECONDS}s/" \
    "$REPO_DIR/systemd/ip-reporter.timer" \
    > /etc/systemd/system/ip-reporter.timer
chmod 0644 /etc/systemd/system/ip-reporter.timer

if [ -d /etc/NetworkManager/dispatcher.d ]; then
    install -m 0755 "$REPO_DIR/systemd/90-ip-reporter-networkmanager" \
        /etc/NetworkManager/dispatcher.d/90-ip-reporter
fi

systemctl daemon-reload
systemctl enable --now ip-reporter.timer >/dev/null
systemctl start ip-reporter.service || true

echo
echo "installed client:"
echo "  binary:  /usr/local/bin/ip-reporter"
echo "  config:  $CONFIG"
echo "  state:   /var/lib/ip-reporter/state.json"
echo "  timer:   every ${INTERVAL_SECONDS}s"
echo
if systemctl show -p Result --value ip-reporter.service | grep -qx success; then
    echo "first report succeeded."
else
    echo "warning: first report did not succeed; recent logs:" >&2
    journalctl -u ip-reporter.service -n 30 --no-pager >&2 || true
    echo >&2
    echo "Check the URL/token, DNS and outbound HTTPS access, then run:" >&2
    echo "  sudo systemctl start ip-reporter.service" >&2
    echo "  journalctl -u ip-reporter.service -n 50 --no-pager" >&2
fi

echo "manual test:"
echo "  /usr/local/bin/ip-reporter --config $CONFIG --print-payload"
