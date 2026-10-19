#!/usr/bin/env python3
"""Report the internal IP address(es) of this Linux machine to a central server.

The client has no third-party dependencies and is designed to be run from a
systemd timer (or manually with --loop).  It detects the address used by the
default route, plus all non-loopback interface addresses, and POSTs them to the
server over HTTPS.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import logging
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Linux
    fcntl = None  # type: ignore[assignment]

VERSION = "1.0.1"
LOG = logging.getLogger("ip-reporter")

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAC_RE = re.compile(r"^[0-9A-Fa-f:.-]{0,32}$")
ROUTE_SRC_RE = re.compile(r"\bsrc\s+([0-9A-Fa-f:.%]+)")
ADDR_LINE_RE = re.compile(
    r"^\d+:\s+(\S+)\s+(inet6?)\s+(\S+)\s+.*?\bscope\s+(\S+)"
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "server_url": "",
    "report_token": "",
    "client_id": "",
    "state_file": "",
    "timeout_seconds": 10,
    "retries": 3,
    "verify_tls": True,
    "ca_file": "",
    "include_interfaces": [],
    "exclude_interfaces": ["lo", "docker*", "veth*", "br-*", "virbr*"],
    "include_loopback": False,
    "extra_tags": {},
    "user_agent": f"ip-reporter/{VERSION}",
}


class ConfigError(RuntimeError):
    pass


class ReportError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


# ---------------------------------------------------------------------------
# Configuration / state
# ---------------------------------------------------------------------------


def default_state_file() -> str:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "/var/lib/ip-reporter/state.json"
    return os.path.expanduser("~/.local/state/ip-reporter/state.json")


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config file must contain a JSON object")

    cfg = dict(DEFAULT_CONFIG)
    cfg.update(raw)
    cfg["_config_path"] = str(config_path)

    env_map = {
        "server_url": "IP_REPORTER_SERVER_URL",
        "report_token": "IP_REPORTER_TOKEN",
        "client_id": "IP_REPORTER_CLIENT_ID",
        "state_file": "IP_REPORTER_STATE_FILE",
    }
    for key, env_name in env_map.items():
        if os.environ.get(env_name):
            cfg[key] = os.environ[env_name]

    if os.environ.get("IP_REPORTER_INSECURE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        cfg["verify_tls"] = False

    server_url = str(cfg.get("server_url") or "").strip()
    if not server_url:
        raise ConfigError("server_url is required")
    cfg["server_url"] = normalize_server_url(server_url)

    token = str(cfg.get("report_token") or "").strip()
    if not token:
        raise ConfigError("report_token is required")
    cfg["report_token"] = token

    cfg["client_id"] = str(cfg.get("client_id") or "").strip()
    if cfg["client_id"] and not CLIENT_ID_RE.match(cfg["client_id"]):
        raise ConfigError(
            "client_id may only contain letters, digits, '.', '_', ':', '@' and '-'"
        )

    state_file = str(cfg.get("state_file") or "").strip()
    cfg["state_file"] = str(
        Path(state_file or default_state_file()).expanduser().resolve()
    )

    try:
        cfg["timeout_seconds"] = int(cfg.get("timeout_seconds", 10))
        cfg["retries"] = int(cfg.get("retries", 3))
    except (TypeError, ValueError) as exc:
        raise ConfigError("timeout_seconds and retries must be integers") from exc
    if not 1 <= cfg["timeout_seconds"] <= 120:
        raise ConfigError("timeout_seconds must be between 1 and 120")
    if not 0 <= cfg["retries"] <= 10:
        raise ConfigError("retries must be between 0 and 10")

    verify_tls = cfg.get("verify_tls", True)
    if isinstance(verify_tls, str):
        cfg["verify_tls"] = verify_tls.strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
    else:
        cfg["verify_tls"] = bool(verify_tls)

    for key in ("include_interfaces", "exclude_interfaces"):
        value = cfg.get(key)
        if value is None:
            cfg[key] = []
        elif not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise ConfigError(f"{key} must be an array of strings")

    if not isinstance(cfg.get("extra_tags"), dict):
        raise ConfigError("extra_tags must be an object")

    cfg["ca_file"] = str(cfg.get("ca_file") or "").strip()
    cfg["user_agent"] = str(cfg.get("user_agent") or f"ip-reporter/{VERSION}")
    return cfg


def normalize_server_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ConfigError("server_url must start with http:// or https://")
    if not parsed.netloc:
        raise ConfigError("server_url is missing a host")
    path = parsed.path.rstrip("/")
    if path.endswith("/api/v1/report"):
        pass
    elif path.endswith("/api/v1"):
        path += "/report"
    else:
        path += "/api/v1/report"
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, path, "", "", "")
    )


class State:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.data: Dict[str, Any] = {}
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                self.data = raw
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError) as exc:
            LOG.warning("could not read state file %s: %s", self.path, exc)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            fd = os.open(
                str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            LOG.warning("could not write state file %s: %s", self.path, exc)


def sanitize_client_id_part(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._@-]+", "-", text.strip())
    cleaned = cleaned.strip(".-")
    return cleaned[:48]


def read_machine_id() -> str:
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            value = Path(candidate).read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            continue
    return ""


def resolve_client_id(cfg: Dict[str, Any], state: State) -> str:
    if cfg["client_id"]:
        return cfg["client_id"]

    stored = str(state.get("client_id") or "").strip()
    if stored and CLIENT_ID_RE.match(stored):
        return stored

    machine_id = read_machine_id()
    if machine_id:
        digest = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:24]
        client_id = f"machine-{digest}"
    else:
        host = sanitize_client_id_part(socket.gethostname()) or "linux"
        client_id = f"{host}-{secrets.token_hex(4)}"

    state.set("client_id", client_id)
    state.save()
    return client_id


# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def run_command(args: List[str], timeout: float = 8.0) -> Optional[str]:
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def find_ip_binary() -> Optional[str]:
    found = shutil.which("ip")
    if found:
        return found
    for candidate in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"):
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def interface_allowed(
    name: str,
    flags: List[str],
    include: List[str],
    exclude: List[str],
    include_loopback: bool,
) -> bool:
    is_loopback = "LOOPBACK" in flags or name == "lo"
    if is_loopback:
        # include_loopback is an explicit override of the normal loopback
        # filter and of a broad exclude pattern such as "lo".
        if not include_loopback:
            return False
        return not include or any(
            fnmatch.fnmatch(name, pattern) for pattern in include
        )
    if include:
        return any(fnmatch.fnmatch(name, pattern) for pattern in include)
    if any(fnmatch.fnmatch(name, pattern) for pattern in exclude):
        return False
    return True


def read_mac(name: str) -> Optional[str]:
    try:
        value = Path(f"/sys/class/net/{name}/address").read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        return None
    if not value or value == "00:00:00:00:00:00" or not MAC_RE.match(value):
        return None
    return value.lower()


def make_address(
    family: str, address: str, prefixlen: int, scope: str
) -> Dict[str, Any]:
    return {
        "family": family,
        "address": address,
        "prefixlen": prefixlen,
        "scope": scope,
    }


def collect_interfaces_ip_json(
    ip_bin: str, cfg: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    output = run_command([ip_bin, "-j", "addr", "show"], timeout=10)
    if not output:
        return None
    try:
        raw = json.loads(output)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, list):
        return None

    include = cfg.get("include_interfaces") or []
    exclude = cfg.get("exclude_interfaces") or []
    include_loopback = bool(cfg.get("include_loopback"))
    interfaces: List[Dict[str, Any]] = []

    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("ifname")
        if not isinstance(name, str) or not name:
            continue
        flags = [str(flag) for flag in item.get("flags") or []]
        if not interface_allowed(name, flags, include, exclude, include_loopback):
            continue

        addresses: List[Dict[str, Any]] = []
        for addr in item.get("addr_info") or []:
            if not isinstance(addr, dict):
                continue
            family = addr.get("family")
            local = addr.get("local")
            if family not in ("inet", "inet6") or not isinstance(local, str):
                continue
            if local in ("127.0.0.1", "::1") and not include_loopback:
                continue
            scope = str(addr.get("scope") or "global")
            if scope == "host" and not include_loopback:
                continue
            try:
                prefixlen = int(
                    addr.get("prefixlen", 32 if family == "inet" else 128)
                )
            except (TypeError, ValueError):
                prefixlen = 32 if family == "inet" else 128
            addresses.append(make_address(family, local, prefixlen, scope))

        if not addresses:
            continue
        entry: Dict[str, Any] = {"name": name, "addresses": addresses}
        mac = read_mac(name)
        if mac:
            entry["mac"] = mac
        state = item.get("operstate")
        if isinstance(state, str) and state:
            entry["state"] = state
        interfaces.append(entry)

    interfaces.sort(key=lambda entry: entry["name"])
    return interfaces


def collect_interfaces_ip_output(
    ip_bin: str, cfg: Dict[str, Any]
) -> List[Dict[str, Any]]:
    output = run_command([ip_bin, "-o", "addr", "show"], timeout=10)
    if not output:
        return []

    include = cfg.get("include_interfaces") or []
    exclude = cfg.get("exclude_interfaces") or []
    include_loopback = bool(cfg.get("include_loopback"))
    by_name: Dict[str, Dict[str, Any]] = {}

    for line in output.splitlines():
        match = ADDR_LINE_RE.match(line)
        if not match:
            continue
        name, family, cidr, scope = match.groups()
        flags: List[str] = []
        if name == "lo":
            flags.append("LOOPBACK")
        if not interface_allowed(name, flags, include, exclude, include_loopback):
            continue
        if "/" in cidr:
            address, prefix_text = cidr.split("/", 1)
        else:
            address, prefix_text = cidr, ""
        try:
            prefixlen = int(prefix_text)
        except ValueError:
            prefixlen = 32 if family == "inet" else 128
        if address in ("127.0.0.1", "::1") and not include_loopback:
            continue
        if scope == "host" and not include_loopback:
            continue
        entry = by_name.setdefault(
            name, {"name": name, "addresses": []}
        )
        entry["addresses"].append(make_address(family, address, prefixlen, scope))

    interfaces = []
    for name in sorted(by_name):
        entry = by_name[name]
        if not entry["addresses"]:
            continue
        mac = read_mac(name)
        if mac:
            entry["mac"] = mac
        interfaces.append(entry)
    return interfaces


def collect_interfaces_fallback(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Last-resort fallback when the iproute2 binary is unavailable."""
    include_loopback = bool(cfg.get("include_loopback"))
    addresses: List[Dict[str, Any]] = []
    hostname_ip = run_command(["hostname", "-I"], timeout=3)
    if hostname_ip:
        for item in hostname_ip.split():
            try:
                family = "inet6" if ":" in item else "inet"
                addresses.append(
                    make_address(
                        family, item, 128 if family == "inet6" else 32, "global"
                    )
                )
            except Exception:
                continue
    if not addresses and not include_loopback:
        return []
    return [{"name": "default", "addresses": addresses}]


def collect_interfaces(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    ip_bin = find_ip_binary()
    if ip_bin:
        interfaces = collect_interfaces_ip_json(ip_bin, cfg)
        if interfaces is not None:
            return interfaces
        interfaces = collect_interfaces_ip_output(ip_bin, cfg)
        if interfaces:
            return interfaces
    return collect_interfaces_fallback(cfg)


def route_source(ip_bin: Optional[str], family: int) -> Optional[str]:
    if not ip_bin:
        return None
    if family == socket.AF_INET:
        args = [ip_bin, "-4", "route", "get", "1.1.1.1"]
    else:
        args = [ip_bin, "-6", "route", "get", "2001:4860:4860::8888"]
    output = run_command(args, timeout=5)
    if not output:
        return None
    match = ROUTE_SRC_RE.search(output)
    return match.group(1) if match else None


def socket_source(host: str, port: int, family: int) -> Optional[str]:
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(2)
        if family == socket.AF_INET6:
            sock.connect((host, port, 0, 0))
        else:
            sock.connect((host, port))
        address = sock.getsockname()[0]
        if address and address not in ("0.0.0.0", "::"):
            return address
    except OSError:
        return None
    finally:
        if sock is not None:
            sock.close()
    return None


def server_host_port(url: str) -> Tuple[str, int]:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "1.1.1.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def is_globalish(address: str) -> bool:
    """Cheap filter for addresses that make sense as the primary LAN address."""
    if not address:
        return False
    if address.startswith("127.") or address == "::1":
        return False
    if address.startswith("169.254.") or address.lower().startswith("fe80:"):
        return False
    return True


def choose_primary(
    interfaces: List[Dict[str, Any]],
    ip_bin: Optional[str],
    server_url: str,
) -> Tuple[Optional[str], Optional[str]]:
    forwarded4 = route_source(ip_bin, socket.AF_INET)
    forwarded6 = route_source(ip_bin, socket.AF_INET6)

    host, port = server_host_port(server_url)
    if not forwarded4:
        forwarded4 = socket_source(host, port, socket.AF_INET)
    if not forwarded6:
        forwarded6 = socket_source(host, port, socket.AF_INET6)

    all4: List[str] = []
    all6: List[str] = []
    for iface in interfaces:
        for addr in iface.get("addresses", []):
            if addr.get("family") == "inet":
                all4.append(addr["address"])
            elif addr.get("family") == "inet6":
                all6.append(addr["address"])

    primary4 = forwarded4 if forwarded4 and is_globalish(forwarded4) else None
    if not primary4:
        primary4 = next((addr for addr in all4 if is_globalish(addr)), None)
    if not primary4:
        primary4 = next((addr for addr in all4 if not addr.startswith("127.")), None)

    primary6 = forwarded6 if forwarded6 and is_globalish(forwarded6) else None
    if not primary6:
        primary6 = next((addr for addr in all6 if is_globalish(addr)), None)

    return primary4, primary6


def read_os_name() -> str:
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                value = line.split("=", 1)[1].strip()
                if value[:1] == value[-1:] and value[:1] in ("'", '"'):
                    value = value[1:-1]
                return value
    except OSError:
        pass
    return platform.platform()


def build_payload(cfg: Dict[str, Any], client_id: str) -> Dict[str, Any]:
    interfaces = collect_interfaces(cfg)
    ip_bin = find_ip_binary()
    primary4, primary6 = choose_primary(interfaces, ip_bin, cfg["server_url"])

    if not interfaces:
        addresses = []
        if primary4:
            addresses.append(make_address("inet", primary4, 32, "global"))
        if primary6:
            addresses.append(make_address("inet6", primary6, 128, "global"))
        if addresses:
            interfaces = [{"name": "default", "addresses": addresses}]

    if not primary4 and not primary6:
        raise RuntimeError(
            "could not determine any non-loopback IP address; check `ip addr`"
        )

    hostname = socket.gethostname() or "unknown"
    try:
        fqdn = socket.getfqdn()
    except OSError:
        fqdn = hostname

    tags = {}
    for key, value in (cfg.get("extra_tags") or {}).items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            tags[str(key)[:64]] = str(value)[:128]

    return {
        "client_id": client_id,
        "hostname": hostname[:255],
        "fqdn": fqdn[:255] if fqdn and fqdn != hostname else "",
        "primary_ip": primary4,
        "primary_ipv6": primary6,
        "interfaces": interfaces,
        "os": read_os_name()[:128],
        "kernel": platform.release()[:128],
        "agent_version": VERSION,
        "tags": tags,
        "client_time": utc_now_iso(),
    }


# ---------------------------------------------------------------------------
# HTTP upload
# ---------------------------------------------------------------------------


def post_report(
    url: str,
    payload: Dict[str, Any],
    token: str,
    timeout: float,
    verify_tls: bool,
    ca_file: str,
    user_agent: str,
) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": user_agent,
        },
    )

    context = None
    if url.lower().startswith("https://"):
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise ReportError(
                f"could not load CA file {ca_file}: {exc}", retryable=False
            ) from exc
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=context
        ) as response:
            raw = response.read(65536)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read(65536)
        except Exception:
            pass
        message = ""
        try:
            data = json.loads(raw.decode("utf-8"))
            if isinstance(data, dict) and data.get("error"):
                message = str(data["error"])
        except (UnicodeDecodeError, json.JSONDecodeError):
            message = raw.decode("utf-8", "replace").strip()
        if not message:
            message = f"HTTP {exc.code} {exc.reason}"
        retryable = exc.code in (408, 425, 429) or 500 <= exc.code <= 599
        raise ReportError(
            f"server rejected report: {message}", retryable=retryable
        ) from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            raise ReportError(
                f"TLS certificate verification failed: {reason}", retryable=False
            ) from exc
        raise ReportError(f"could not reach server: {exc}", retryable=True) from exc
    except (TimeoutError, socket.timeout, OSError) as exc:
        raise ReportError(f"could not reach server: {exc}", retryable=True) from exc

    if status < 200 or status >= 300:
        raise ReportError(f"unexpected HTTP status {status}", retryable=True)
    try:
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        data = {}
    return data if isinstance(data, dict) else {}


def report_once(
    cfg: Dict[str, Any], state: State, client_id: str, print_payload: bool = False
) -> int:
    payload = build_payload(cfg, client_id)
    if print_payload:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if not cfg["verify_tls"]:
        LOG.warning("TLS certificate verification is disabled (verify_tls=false)")

    attempts = int(cfg["retries"]) + 1
    for attempt in range(1, attempts + 1):
        try:
            result = post_report(
                cfg["server_url"],
                payload,
                cfg["report_token"],
                timeout=float(cfg["timeout_seconds"]),
                verify_tls=bool(cfg["verify_tls"]),
                ca_file=str(cfg.get("ca_file") or ""),
                user_agent=str(cfg["user_agent"]),
            )
            break
        except ReportError as exc:
            if not exc.retryable or attempt >= attempts:
                raise
            delay = min(2 ** (attempt - 1), 30)
            LOG.warning(
                "attempt %d/%d failed: %s; retrying in %ds",
                attempt,
                attempts,
                exc,
                delay,
            )
            time.sleep(delay)
    else:  # pragma: no cover - attempts is always >= 1
        raise ReportError("report failed", retryable=False)

    primary = payload.get("primary_ip") or payload.get("primary_ipv6") or "?"
    observed = result.get("observed_ip") or "?"
    LOG.info(
        "reported hostname=%s primary=%s public=%s server=%s",
        payload["hostname"],
        primary,
        observed,
        urllib.parse.urlparse(cfg["server_url"]).netloc,
    )

    state.set("last_report_at", utc_now_iso())
    state.set("last_primary_ip", payload.get("primary_ip"))
    state.set("last_primary_ipv6", payload.get("primary_ipv6"))
    state.set("last_observed_ip", result.get("observed_ip"))
    state.save()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class InstanceLock:
    def __init__(self, state_file: str) -> None:
        self.path = Path(state_file).with_name(Path(state_file).name + ".lock")
        self.handle: Optional[Any] = None

    def acquire(self) -> bool:
        if fcntl is None:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.handle = self.path.open("a+")
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            if self.handle is not None:
                try:
                    self.handle.close()
                except OSError:
                    pass
                self.handle = None
            return False

    def release(self) -> None:
        if self.handle is not None:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                self.handle.close()
            except OSError:
                pass
            self.handle = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report this Linux machine's internal IP address to a server"
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("IP_REPORTER_CONFIG", "/etc/ip-reporter/client.json"),
        help="path to client JSON config (default: %(default)s)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="keep running and report periodically instead of once",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="seconds between reports in --loop mode (default: 300)",
    )
    parser.add_argument(
        "--print-payload",
        action="store_true",
        help="print the detected payload as JSON without uploading",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="alias for --print-payload",
    )
    parser.add_argument("--quiet", action="store_true", help="only log warnings/errors")
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    if args.quiet:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        LOG.error("configuration error: %s", exc)
        return 2

    if args.interval < 30:
        LOG.error("--interval must be >= 30 seconds")
        return 2

    state = State(cfg["state_file"])
    try:
        client_id = resolve_client_id(cfg, state)
    except OSError as exc:
        LOG.error("could not determine client id: %s", exc)
        return 2

    lock = InstanceLock(cfg["state_file"])
    if not lock.acquire():
        LOG.warning("another ip-reporter instance is already running; exiting")
        return 0

    print_payload = bool(args.print_payload or args.dry_run)
    try:
        if args.loop:
            LOG.info(
                "starting loop: every %ds, state=%s", args.interval, cfg["state_file"]
            )
            while True:
                try:
                    report_once(cfg, state, client_id, print_payload=print_payload)
                except ReportError as exc:
                    LOG.error("report failed: %s", exc)
                except RuntimeError as exc:
                    LOG.error("detection failed: %s", exc)
                if print_payload:
                    return 0
                time.sleep(args.interval)
        try:
            return report_once(cfg, state, client_id, print_payload=print_payload)
        except ReportError as exc:
            LOG.error("report failed: %s", exc)
            return 1
        except RuntimeError as exc:
            LOG.error("detection failed: %s", exc)
            return 1
    except KeyboardInterrupt:
        return 130
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
