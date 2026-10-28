#!/usr/bin/env python3
"""Central server for the internal-IP reporter.

Only the Python standard library is required.  The server stores one JSON file
per client on the filesystem (plus per-report history snapshots) and exposes a
small JSON API plus a self-contained dashboard.  No database is required.

Typical deployment is behind nginx (HTTPS).  The server itself then listens on
127.0.0.1 only and trusts the X-Forwarded-For / X-Real-IP headers set by nginx.
"""

from __future__ import annotations

import argparse
import html as html_lib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

VERSION = "1.3.0"
LOG = logging.getLogger("ip-reporter-server")

MAX_LABEL_LENGTH = 64
MAX_BODY_BYTES = 64 * 1024
MAX_INTERFACES = 64
MAX_ADDRESSES_PER_INTERFACE = 64
MAX_TAGS = 32

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
MAC_RE = re.compile(r"^[0-9A-Fa-f:.-]{0,32}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
ZONE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

DEFAULT_CONFIG: Dict[str, Any] = {
    "listen_host": "127.0.0.1",
    "listen_port": 8765,
    "data_dir": "data",
    "report_token": "",
    "admin_token": "",
    "trust_proxy": False,
    "online_threshold_seconds": 600,
    "history_retention_days": 90,
    "history_max_per_client": 1000,
    "dashboard_title": "内网 IP 上报",
    "log_level": "INFO",
}


class ConfigError(RuntimeError):
    pass


class ValidationError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def clean_text(
    value: Any,
    name: str,
    max_length: int,
    *,
    required: bool = True,
    allow_empty: bool = False,
) -> Optional[str]:
    if value is None:
        if required:
            raise ValidationError(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a string")
    if CONTROL_RE.search(value):
        raise ValidationError(f"{name} contains control characters")
    text = value.strip()
    if not text and not allow_empty:
        if required:
            raise ValidationError(f"{name} must not be empty")
        return None
    if len(text) > max_length:
        raise ValidationError(f"{name} is too long (max {max_length})")
    return text


def validate_ip(value: Any, name: str) -> str:
    text = clean_text(value, name, 128)
    assert text is not None
    zone = ""
    base = text
    if "%" in text:
        base, zone = text.split("%", 1)
        if not ZONE_RE.match(zone):
            raise ValidationError(f"{name} has an invalid IPv6 zone")
    try:
        ipaddress.ip_address(base)
    except ValueError as exc:
        raise ValidationError(f"{name} is not a valid IP address") from exc
    return f"{base}%{zone}" if zone else base


def optional_ip(value: Any, name: str) -> Optional[str]:
    if value is None or value == "":
        return None
    return validate_ip(value, name)


def normalize_tags(value: Any) -> Dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError("tags must be an object")
    if len(value) > MAX_TAGS:
        raise ValidationError(f"too many tags (max {MAX_TAGS})")
    tags: Dict[str, str] = {}
    for key, val in value.items():
        if not isinstance(key, str):
            raise ValidationError("tag keys must be strings")
        key = key.strip()
        if not key or len(key) > 64 or CONTROL_RE.search(key):
            raise ValidationError("invalid tag key")
        if isinstance(val, (str, int, float, bool)):
            text = str(val)
        elif val is None:
            text = ""
        else:
            raise ValidationError("tag values must be scalar values")
        if len(text) > 128 or CONTROL_RE.search(text):
            raise ValidationError("invalid tag value")
        tags[key] = text
    return tags


def normalize_interfaces(value: Any) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("interfaces must be an array")
    if len(value) > MAX_INTERFACES:
        raise ValidationError(f"too many interfaces (max {MAX_INTERFACES})")

    interfaces: List[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValidationError("each interface must be an object")
        name = clean_text(item.get("name"), "interface name", 64)
        assert name is not None
        raw_addresses = item.get("addresses")
        if raw_addresses is None:
            raw_addresses = []
        if not isinstance(raw_addresses, list):
            raise ValidationError("interface addresses must be an array")
        if len(raw_addresses) > MAX_ADDRESSES_PER_INTERFACE:
            raise ValidationError("too many addresses on one interface")

        addresses: List[Dict[str, Any]] = []
        for addr in raw_addresses:
            if not isinstance(addr, dict):
                raise ValidationError("each address must be an object")
            family = addr.get("family")
            if family not in ("inet", "inet6"):
                raise ValidationError("address family must be inet or inet6")
            local = validate_ip(addr.get("address"), "interface address")
            max_prefix = 32 if family == "inet" else 128
            try:
                prefixlen = int(addr.get("prefixlen", max_prefix))
            except (TypeError, ValueError) as exc:
                raise ValidationError("invalid prefixlen") from exc
            if not 0 <= prefixlen <= max_prefix:
                raise ValidationError("prefixlen out of range")
            scope = clean_text(
                addr.get("scope", "global"),
                "address scope",
                16,
                required=False,
                allow_empty=True,
            ) or "global"
            addresses.append(
                {
                    "family": family,
                    "address": local,
                    "prefixlen": prefixlen,
                    "scope": scope,
                }
            )

        mac = clean_text(
            item.get("mac"), "interface mac", 32, required=False, allow_empty=True
        )
        if mac and not MAC_RE.match(mac):
            raise ValidationError("invalid interface mac")
        state = clean_text(
            item.get("state"), "interface state", 32, required=False, allow_empty=True
        )
        entry: Dict[str, Any] = {"name": name, "addresses": addresses}
        if mac:
            entry["mac"] = mac.lower()
        if state:
            entry["state"] = state
        interfaces.append(entry)
    return interfaces


def normalize_report(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationError("request body must be a JSON object")

    client_id = clean_text(data.get("client_id"), "client_id", 128)
    assert client_id is not None
    if not CLIENT_ID_RE.match(client_id):
        raise ValidationError(
            "client_id may only contain letters, digits, '.', '_', ':', '@' and '-'"
        )

    label = clean_text(data.get("label"), "label", MAX_LABEL_LENGTH)
    assert label is not None

    hostname = clean_text(data.get("hostname"), "hostname", 255)
    assert hostname is not None
    fqdn = clean_text(
        data.get("fqdn"), "fqdn", 255, required=False, allow_empty=True
    )
    interfaces = normalize_interfaces(data.get("interfaces"))
    primary_ip = optional_ip(data.get("primary_ip"), "primary_ip")
    primary_ipv6 = optional_ip(data.get("primary_ipv6"), "primary_ipv6")

    if primary_ip and ":" in primary_ip:
        primary_ip, primary_ipv6 = None, primary_ipv6 or primary_ip
    if primary_ipv6 and ":" not in primary_ipv6:
        primary_ipv6 = None

    if not primary_ip and not primary_ipv6:
        for iface in interfaces:
            for addr in iface["addresses"]:
                if addr["family"] == "inet" and addr["scope"] != "host":
                    primary_ip = addr["address"]
                    break
            if primary_ip:
                break

    if not primary_ip and not primary_ipv6:
        raise ValidationError("primary_ip or primary_ipv6 is required")

    return {
        "client_id": client_id,
        "label": label,
        "hostname": hostname,
        "fqdn": fqdn,
        "primary_ip": primary_ip,
        "primary_ipv6": primary_ipv6,
        "interfaces": interfaces,
        "os": clean_text(
            data.get("os"), "os", 128, required=False, allow_empty=True
        ),
        "kernel": clean_text(
            data.get("kernel"), "kernel", 128, required=False, allow_empty=True
        ),
        "agent_version": clean_text(
            data.get("agent_version"),
            "agent_version",
            32,
            required=False,
            allow_empty=True,
        ),
        "tags": normalize_tags(data.get("tags")),
        "client_time": clean_text(
            data.get("client_time"),
            "client_time",
            64,
            required=False,
            allow_empty=True,
        ),
    }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


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
    cfg["_config_dir"] = str(config_path.parent)

    env_map = {
        "listen_host": "IP_REPORTER_SERVER_LISTEN_HOST",
        "listen_port": "IP_REPORTER_SERVER_LISTEN_PORT",
        "data_dir": "IP_REPORTER_SERVER_DATA_DIR",
        "report_token": "IP_REPORTER_SERVER_REPORT_TOKEN",
        "admin_token": "IP_REPORTER_SERVER_ADMIN_TOKEN",
        "trust_proxy": "IP_REPORTER_SERVER_TRUST_PROXY",
        "log_level": "IP_REPORTER_SERVER_LOG_LEVEL",
    }
    for key, env_name in env_map.items():
        if env_name in os.environ and os.environ[env_name] != "":
            cfg[key] = os.environ[env_name]

    try:
        cfg["listen_port"] = int(cfg["listen_port"])
        cfg["online_threshold_seconds"] = int(cfg["online_threshold_seconds"])
        cfg["history_retention_days"] = int(cfg["history_retention_days"])
        cfg["history_max_per_client"] = int(cfg["history_max_per_client"])
    except (TypeError, ValueError) as exc:
        raise ConfigError("port and numeric settings must be integers") from exc

    if not 0 <= cfg["listen_port"] <= 65535:
        raise ConfigError("listen_port must be between 0 and 65535")
    if cfg["online_threshold_seconds"] < 30:
        raise ConfigError("online_threshold_seconds must be >= 30")
    if cfg["history_retention_days"] < 0:
        raise ConfigError("history_retention_days must be >= 0")
    if cfg["history_max_per_client"] < 1:
        raise ConfigError("history_max_per_client must be >= 1")

    trust_proxy = cfg.get("trust_proxy")
    if isinstance(trust_proxy, str):
        cfg["trust_proxy"] = trust_proxy.strip().lower() in ("1", "true", "yes", "on")
    else:
        cfg["trust_proxy"] = bool(trust_proxy)

    data_dir = Path(str(cfg.get("data_dir") or "data")).expanduser()
    if not data_dir.is_absolute():
        data_dir = config_path.parent / data_dir
    cfg["data_dir"] = str(data_dir.resolve())

    cfg["dashboard_title"] = str(cfg.get("dashboard_title") or "内网 IP 上报")
    return cfg


def init_config(path: str, force: bool = False) -> Dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    if config_path.exists() and not force:
        raise ConfigError(
            f"{config_path} already exists; use --force to overwrite it"
        )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = {
        "listen_host": "127.0.0.1",
        "listen_port": 8765,
        "data_dir": "../data",
        "report_token": secrets.token_urlsafe(32),
        "admin_token": secrets.token_urlsafe(32),
        "trust_proxy": True,
        "online_threshold_seconds": 600,
        "history_retention_days": 90,
        "history_max_per_client": 1000,
        "dashboard_title": "内网 IP 上报",
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(config_path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    try:
        os.chmod(config_path, 0o600)
    except OSError:
        pass
    return cfg


def collect_tokens(cfg: Dict[str, Any], kind: str) -> List[str]:
    values: List[str] = []
    for key in (f"{kind}_token", f"{kind}_tokens"):
        raw = cfg.get(key)
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, list):
            values.extend(item for item in raw if isinstance(item, str))
    return [item.strip() for item in values if item and item.strip()]


# ---------------------------------------------------------------------------
# Filesystem storage
# ---------------------------------------------------------------------------
#
# Layout:
#
#   <data_dir>/
#     clients/
#       <client_id>/
#         latest.json
#         history/
#           20261019T063925Z-<time_ns>.json
#
# Every JSON file is written to a temporary file in the same directory and then
# atomically replaced with os.replace().  Readers therefore never see a
# half-written file.  Writers are serialized with a process-local lock; the
# server is a single process, so no external lock service is needed.
#
# The format is intentionally human-readable so it can be inspected, backed up
# with tar, or edited by hand while the service is stopped.


class Store:
    def __init__(
        self,
        data_dir: str,
        retention_days: int = 90,
        max_history_per_client: int = 1000,
        online_threshold_seconds: int = 600,
    ) -> None:
        self.root = Path(data_dir).expanduser().resolve()
        self.clients_dir = self.root / "clients"
        self.retention_days = retention_days
        self.max_history_per_client = max_history_per_client
        self.online_threshold_seconds = online_threshold_seconds
        self._write_lock = threading.Lock()
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        for path in (self.root, self.clients_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass

    def _client_dir(self, client_id: str) -> Optional[Path]:
        if not isinstance(client_id, str) or not CLIENT_ID_RE.match(client_id):
            return None
        return self.clients_dir / client_id

    def _read_json(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            LOG.warning("could not read %s: %s", path, exc)
            return None
        return data if isinstance(data, dict) else None

    def _atomic_write_json(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.parent / (
            f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
        )
        try:
            fd = os.open(
                str(tmp),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(str(tmp), str(path))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            # Make the rename durable as well (best effort).
            try:
                dir_fd = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _client_record(self, data: Dict[str, Any]) -> Dict[str, Any]:
        last_seen = parse_iso(data.get("last_seen"))
        online = bool(
            last_seen
            and (utc_now() - last_seen).total_seconds()
            <= self.online_threshold_seconds
        )
        try:
            report_count = int(data.get("report_count") or 0)
        except (TypeError, ValueError):
            report_count = 0
        interfaces = data.get("interfaces")
        tags = data.get("tags")
        return {
            "client_id": data.get("client_id"),
            "label": data.get("label") or "",
            "hostname": data.get("hostname"),
            "fqdn": data.get("fqdn"),
            "primary_ip": data.get("primary_ip"),
            "primary_ipv6": data.get("primary_ipv6"),
            "public_ip": data.get("public_ip"),
            "interfaces": interfaces if isinstance(interfaces, list) else [],
            "os": data.get("os"),
            "kernel": data.get("kernel"),
            "agent_version": data.get("agent_version"),
            "tags": tags if isinstance(tags, dict) else {},
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "source_ip": data.get("source_ip"),
            "report_count": report_count,
            "online": online,
        }

    def _iter_latest(self):
        try:
            paths = sorted(self.clients_dir.glob("*/latest.json"))
        except OSError:
            return
        for path in paths:
            data = self._read_json(path)
            if data:
                yield data

    def check(self) -> bool:
        probe = self.root / (
            f".health-{os.getpid()}-{secrets.token_hex(4)}.probe"
        )
        try:
            self._ensure_dirs()
            self._atomic_write_json(probe, {"server_time": utc_now_iso()})
            return True
        except OSError:
            return False
        finally:
            try:
                probe.unlink()
            except OSError:
                pass

    def save_report(
        self,
        report: Dict[str, Any],
        source_ip: str,
        public_ip: str,
        received_at: str,
    ) -> None:
        client_dir = self._client_dir(report["client_id"])
        if client_dir is None:
            raise ValueError("invalid client_id")
        history_dir = client_dir / "history"

        with self._write_lock:
            client_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            history_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            for path in (client_dir, history_dir):
                try:
                    os.chmod(path, 0o700)
                except OSError:
                    pass

            existing = self._read_json(client_dir / "latest.json") or {}
            first_seen = existing.get("first_seen") or received_at
            try:
                previous_count = int(existing.get("report_count") or 0)
            except (TypeError, ValueError):
                previous_count = 0

            latest = {
                "schema_version": 1,
                "client_id": report["client_id"],
                "label": report["label"],
                "hostname": report["hostname"],
                "fqdn": report["fqdn"],
                "primary_ip": report["primary_ip"],
                "primary_ipv6": report["primary_ipv6"],
                "public_ip": public_ip,
                "interfaces": report["interfaces"],
                "os": report["os"],
                "kernel": report["kernel"],
                "agent_version": report["agent_version"],
                "tags": report["tags"],
                "first_seen": first_seen,
                "last_seen": received_at,
                "source_ip": source_ip,
                "report_count": previous_count + 1,
            }
            self._atomic_write_json(client_dir / "latest.json", latest)

            history_record = {
                "schema_version": 1,
                "client_id": report["client_id"],
                "label": report["label"],
                "hostname": report["hostname"],
                "fqdn": report["fqdn"],
                "primary_ip": report["primary_ip"],
                "primary_ipv6": report["primary_ipv6"],
                "public_ip": public_ip,
                "source_ip": source_ip,
                "interfaces": report["interfaces"],
                "os": report["os"],
                "kernel": report["kernel"],
                "agent_version": report["agent_version"],
                "tags": report["tags"],
                "client_time": report["client_time"],
                "received_at": received_at,
            }
            stamp = received_at.replace("-", "").replace(":", "")
            filename = f"{stamp}-{time.time_ns()}.json"
            try:
                self._atomic_write_json(history_dir / filename, history_record)
                self._prune_history(history_dir)
            except OSError:
                # The latest state is already safely written; history is
                # secondary, so do not fail the report because of it.
                LOG.exception("could not write history for %s", report["client_id"])

    def _prune_history(self, history_dir: Path) -> None:
        try:
            files = sorted(
                (
                    path
                    for path in history_dir.iterdir()
                    if path.is_file() and path.suffix == ".json"
                ),
                key=lambda path: path.name,
            )
        except OSError:
            return

        if self.retention_days > 0:
            cutoff = time.time() - self.retention_days * 86400
            kept = []
            for path in files:
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                        continue
                except OSError:
                    continue
                kept.append(path)
            files = kept

        excess = len(files) - self.max_history_per_client
        for path in files[: max(0, excess)]:
            try:
                path.unlink()
            except OSError:
                pass

    def list_clients(self, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        needle = search.strip().lower()
        clients: List[Dict[str, Any]] = []
        for data in self._iter_latest():
            client = self._client_record(data)
            if needle:
                values = [
                    client.get("client_id"),
                    client.get("label"),
                    client.get("hostname"),
                    client.get("fqdn"),
                    client.get("primary_ip"),
                    client.get("primary_ipv6"),
                    client.get("public_ip"),
                ]
                for iface in client["interfaces"]:
                    if not isinstance(iface, dict):
                        continue
                    values.append(iface.get("name"))
                    for addr in iface.get("addresses") or []:
                        if isinstance(addr, dict):
                            values.append(addr.get("address"))
                haystack = " ".join(
                    str(value) for value in values if value
                ).lower()
                if needle not in haystack:
                    continue
            clients.append(client)
        clients.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
        return clients[:limit]

    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        client_dir = self._client_dir(client_id)
        if client_dir is None:
            return None
        data = self._read_json(client_dir / "latest.json")
        return self._client_record(data) if data else None

    def lookup(
        self, hostname: str = "", client_id: str = "", label: str = ""
    ) -> Optional[Dict[str, Any]]:
        if client_id:
            return self.get_client(client_id)
        target = hostname.strip().lower()
        target_label = label.strip().lower()
        if not target and not target_label:
            return None
        matches: List[Dict[str, Any]] = []
        for data in self._iter_latest():
            if target_label and (data.get("label") or "").lower() != target_label:
                continue
            if target and not (
                (data.get("hostname") or "").lower() == target
                or (data.get("fqdn") or "").lower() == target
            ):
                continue
            matches.append(self._client_record(data))
        if not matches:
            return None
        matches.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
        return matches[0]

    def history(self, client_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        client_dir = self._client_dir(client_id)
        if client_dir is None:
            return []
        history_dir = client_dir / "history"
        try:
            paths = sorted(
                (
                    path
                    for path in history_dir.iterdir()
                    if path.is_file() and path.suffix == ".json"
                ),
                key=lambda path: path.name,
                reverse=True,
            )
        except OSError:
            return []

        result: List[Dict[str, Any]] = []
        for path in paths:
            if len(result) >= limit:
                break
            data = self._read_json(path)
            if not data:
                continue
            result.append(
                {
                    "id": path.stem,
                    "client_id": data.get("client_id"),
                    "label": data.get("label") or "",
                    "client_time": data.get("client_time"),
                    "received_at": data.get("received_at"),
                    "primary_ip": data.get("primary_ip"),
                    "primary_ipv6": data.get("primary_ipv6"),
                    "public_ip": data.get("public_ip"),
                    "source_ip": data.get("source_ip"),
                    "interfaces": (
                        data.get("interfaces")
                        if isinstance(data.get("interfaces"), list)
                        else []
                    ),
                }
            )
        return result

    def client_count(self) -> int:
        try:
            return sum(1 for _ in self._iter_latest())
        except OSError:
            return 0

    def delete_client(self, client_id: str) -> bool:
        client_dir = self._client_dir(client_id)
        if client_dir is None:
            return False
        with self._write_lock:
            if not client_dir.exists():
                return False
            try:
                shutil.rmtree(client_dir)
            except OSError:
                LOG.exception("could not delete client directory %s", client_dir)
                return False
            return True


# ---------------------------------------------------------------------------
# HTTP application
# ---------------------------------------------------------------------------


def _first_valid_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    for part in value.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        if "%" in candidate:
            candidate = candidate.split("%", 1)[0]
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


class App:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.store = Store(
            config["data_dir"],
            retention_days=int(config["history_retention_days"]),
            max_history_per_client=int(config["history_max_per_client"]),
            online_threshold_seconds=int(config["online_threshold_seconds"]),
        )
        self.report_tokens = collect_tokens(config, "report")
        self.admin_tokens = collect_tokens(config, "admin")
        self.started_at = utc_now_iso()
        self.started_monotonic = time.monotonic()
        self.dashboard_path = Path(__file__).with_name("dashboard.html")
        self.max_body_bytes = int(config.get("max_body_bytes", MAX_BODY_BYTES))

    def dashboard(self) -> bytes:
        try:
            body = self.dashboard_path.read_text(encoding="utf-8")
            title = html_lib.escape(
                str(self.config.get("dashboard_title") or "内网 IP 上报")
            )
            return body.replace("内网 IP 上报", title).encode("utf-8")
        except OSError:
            return (
                "<!doctype html><html><meta charset='utf-8'>"
                "<title>IP Reporter</title><body><h1>IP Reporter</h1>"
                "<p>dashboard.html is missing next to the server script.</p>"
                "</body></html>"
            ).encode("utf-8")

    def token_ok(self, supplied: str, kind: str) -> bool:
        tokens = self.report_tokens + self.admin_tokens if kind == "report" else self.admin_tokens
        if not supplied or not tokens:
            return False
        supplied_bytes = supplied.encode("utf-8", "replace")
        matched = False
        for token in tokens:
            if hmac.compare_digest(supplied_bytes, token.encode("utf-8")):
                matched = True
        return matched

    def has_tokens(self, kind: str) -> bool:
        if kind == "report":
            return bool(self.report_tokens or self.admin_tokens)
        return bool(self.admin_tokens)


class Handler(BaseHTTPRequestHandler):
    server_version = f"ip-reporter/{VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def version_string(self) -> str:
        return self.server_version

    # -- logging ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("%s - %s", self._peer_ip(), fmt % args)

    # -- low level responses --------------------------------------------

    def _common_headers(self, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: Optional[List[Tuple[str, str]]] = None,
        head_only: bool = False,
    ) -> None:
        try:
            self.send_response(status)
            self._common_headers(content_type, len(body))
            for key, value in extra_headers or []:
                self.send_header(key, value)
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(
        self,
        status: int,
        payload: Dict[str, Any],
        extra_headers: Optional[List[Tuple[str, str]]] = None,
        head_only: bool = False,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
            head_only=head_only,
        )

    def _error(
        self,
        status: int,
        message: str,
        *,
        head_only: bool = False,
        extra_headers: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        self._send_json(
            status,
            {"ok": False, "error": message},
            extra_headers=extra_headers,
            head_only=head_only,
        )

    def _method_not_allowed(self, allow: str) -> None:
        self._error(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method not allowed",
            extra_headers=[("Allow", allow)],
        )

    # -- request helpers -------------------------------------------------

    def _peer_ip(self) -> str:
        return self.client_address[0] if self.client_address else ""

    def _request_source_ip(self) -> str:
        peer = self._peer_ip()
        if not self.app.config.get("trust_proxy"):
            return peer
        forwarded = _first_valid_ip(self.headers.get("X-Forwarded-For"))
        if forwarded:
            return forwarded
        real_ip = _first_valid_ip(self.headers.get("X-Real-IP"))
        return real_ip or peer

    def _supplied_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return (
            self.headers.get("X-Auth-Token", "").strip()
            or self.headers.get("X-Admin-Token", "").strip()
        )

    def _authorize(self, kind: str) -> bool:
        if not self.app.has_tokens(kind):
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                f"{kind} token is not configured on the server",
            )
            return False
        if not self.app.token_ok(self._supplied_token(), kind):
            self._error(
                HTTPStatus.UNAUTHORIZED,
                "invalid or missing token",
                extra_headers=[("WWW-Authenticate", 'Bearer realm="ip-reporter"')],
            )
            return False
        return True

    def _read_json(self) -> Any:
        content_type = (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        )
        if content_type not in ("application/json", "text/json"):
            raise ValidationError("Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValidationError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValidationError("invalid Content-Length") from exc
        if length <= 0:
            raise ValidationError("request body is empty")
        if length > self.app.max_body_bytes:
            raise ValidationError(
                f"request body is too large (max {self.app.max_body_bytes} bytes)"
            )
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValidationError("incomplete request body")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("request body is not valid UTF-8 JSON") from exc

    @staticmethod
    def _int_param(value: Optional[str], default: int, minimum: int, maximum: int) -> int:
        if value is None or value == "":
            return default
        try:
            number = int(value)
        except ValueError:
            return default
        return max(minimum, min(maximum, number))

    # -- routing ---------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_bytes(
            HTTPStatus.NO_CONTENT,
            b"",
            "text/plain; charset=utf-8",
            extra_headers=[
                ("Allow", "GET, HEAD, POST, DELETE, OPTIONS"),
                ("Access-Control-Allow-Methods", "GET, HEAD, POST, DELETE, OPTIONS"),
                ("Access-Control-Allow-Headers", "Authorization, Content-Type"),
            ],
        )

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if len(path) > 1:
            path = path.rstrip("/")
        query = parse_qs(parsed.query, keep_blank_values=True)
        head_only = method == "HEAD"

        try:
            if path == "/healthz":
                if method not in ("GET", "HEAD"):
                    return self._method_not_allowed("GET, HEAD")
                return self._handle_health(head_only)

            if path in ("/", "/index.html", "/dashboard"):
                if method not in ("GET", "HEAD"):
                    return self._method_not_allowed("GET, HEAD")
                return self._handle_dashboard(head_only)

            if path == "/favicon.ico":
                return self._send_bytes(
                    HTTPStatus.NO_CONTENT, b"", "image/x-icon", head_only=head_only
                )

            if path == "/api/v1/report":
                if method != "POST":
                    return self._method_not_allowed("POST")
                return self._handle_report()

            if path == "/api/v1/clients":
                if method not in ("GET", "HEAD"):
                    return self._method_not_allowed("GET, HEAD")
                return self._handle_clients(query, head_only)

            if path == "/api/v1/lookup":
                if method not in ("GET", "HEAD"):
                    return self._method_not_allowed("GET, HEAD")
                return self._handle_lookup(query, head_only)

            match = re.match(r"^/api/v1/clients/([^/]+)$", path)
            if match:
                if method not in ("GET", "HEAD", "DELETE"):
                    return self._method_not_allowed("GET, HEAD, DELETE")
                client_id = unquote(match.group(1))
                if method == "DELETE":
                    return self._handle_delete_client(client_id)
                return self._handle_client(client_id, head_only)

            match = re.match(r"^/api/v1/clients/([^/]+)/history$", path)
            if match:
                if method not in ("GET", "HEAD"):
                    return self._method_not_allowed("GET, HEAD")
                return self._handle_history(
                    unquote(match.group(1)), query, head_only
                )

            if path.startswith("/api/"):
                return self._error(HTTPStatus.NOT_FOUND, "API endpoint not found")
            return self._send_bytes(
                HTTPStatus.NOT_FOUND,
                "<!doctype html><html><meta charset='utf-8'><title>404</title>"
                "<body><h1>404 Not Found</h1></body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
                head_only=head_only,
            )
        except ValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:  # pragma: no cover - last-resort guard
            LOG.exception("unhandled error while handling %s %s", method, path)
            try:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal server error")
            except Exception:
                pass

    # -- endpoint implementations ---------------------------------------

    def _handle_health(self, head_only: bool) -> None:
        try:
            storage_ok = bool(self.app.store.check())
        except Exception:
            storage_ok = False
        self._send_json(
            HTTPStatus.OK if storage_ok else HTTPStatus.SERVICE_UNAVAILABLE,
            {
                "ok": storage_ok,
                "version": VERSION,
                "server_time": utc_now_iso(),
                "started_at": self.app.started_at,
                "uptime_seconds": int(time.monotonic() - self.app.started_monotonic),
                "storage": "ok" if storage_ok else "error",
                "clients": self.app.store.client_count() if storage_ok else None,
            },
            head_only=head_only,
        )

    def _handle_dashboard(self, head_only: bool) -> None:
        body = self.app.dashboard()
        self._send_bytes(
            HTTPStatus.OK,
            body,
            "text/html; charset=utf-8",
            extra_headers=[
                (
                    "Content-Security-Policy",
                    "default-src 'self'; img-src 'self' data:; "
                    "style-src 'self' 'unsafe-inline'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                    "form-action 'self'",
                ),
                ("X-Frame-Options", "DENY"),
            ],
            head_only=head_only,
        )

    def _handle_report(self) -> None:
        if not self._authorize("report"):
            return
        data = self._read_json()
        report = normalize_report(data)
        received_at = utc_now_iso()
        source_ip = self._request_source_ip()
        self.app.store.save_report(
            report,
            source_ip=source_ip,
            public_ip=source_ip,
            received_at=received_at,
        )
        LOG.info(
            "report client=%s label=%s hostname=%s primary=%s public=%s",
            report["client_id"],
            report["label"] or "-",
            report["hostname"],
            report["primary_ip"] or report["primary_ipv6"],
            source_ip,
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "client_id": report["client_id"],
                "label": report["label"],
                "server_time": received_at,
                "observed_ip": source_ip,
                "primary_ip": report["primary_ip"],
                "primary_ipv6": report["primary_ipv6"],
            },
        )

    def _handle_clients(self, query: Dict[str, List[str]], head_only: bool) -> None:
        if not self._authorize("admin"):
            return
        search = (query.get("q") or [""])[0].strip()[:128]
        limit = self._int_param((query.get("limit") or [None])[0], 500, 1, 2000)
        clients = self.app.store.list_clients(search=search, limit=limit)
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "server_time": utc_now_iso(),
                "count": len(clients),
                "clients": clients,
            },
            head_only=head_only,
        )

    def _handle_client(self, client_id: str, head_only: bool) -> None:
        if not self._authorize("admin"):
            return
        client = self.app.store.get_client(client_id)
        if not client:
            return self._error(HTTPStatus.NOT_FOUND, "client not found", head_only=head_only)
        self._send_json(
            HTTPStatus.OK,
            {"ok": True, "server_time": utc_now_iso(), "client": client},
            head_only=head_only,
        )

    def _handle_delete_client(self, client_id: str) -> None:
        if not self._authorize("admin"):
            return
        if not self.app.store.delete_client(client_id):
            return self._error(HTTPStatus.NOT_FOUND, "client not found")
        LOG.info("deleted client=%s", client_id)
        self._send_json(
            HTTPStatus.OK,
            {"ok": True, "client_id": client_id, "deleted": True},
        )

    def _handle_history(
        self,
        client_id: str,
        query: Dict[str, List[str]],
        head_only: bool,
    ) -> None:
        if not self._authorize("admin"):
            return
        if not self.app.store.get_client(client_id):
            return self._error(HTTPStatus.NOT_FOUND, "client not found", head_only=head_only)
        limit = self._int_param((query.get("limit") or [None])[0], 50, 1, 500)
        reports = self.app.store.history(client_id, limit=limit)
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "client_id": client_id,
                "server_time": utc_now_iso(),
                "reports": reports,
            },
            head_only=head_only,
        )

    def _handle_lookup(self, query: Dict[str, List[str]], head_only: bool) -> None:
        # The client only needs to write reports.  Lookup is a read operation
        # and is therefore restricted to the admin token.
        if not self._authorize("admin"):
            return
        hostname = (query.get("hostname") or query.get("name") or [""])[0].strip()
        client_id = (query.get("client_id") or [""])[0].strip()
        label = (query.get("label") or [""])[0].strip()
        if not hostname and not client_id and not label:
            return self._error(
                HTTPStatus.BAD_REQUEST,
                "hostname, client_id or label query parameter is required",
                head_only=head_only,
            )
        client = self.app.store.lookup(
            hostname=hostname, client_id=client_id, label=label
        )
        if not client:
            return self._error(HTTPStatus.NOT_FOUND, "client not found", head_only=head_only)

        fmt = (query.get("format") or ["json"])[0].strip().lower()
        if fmt == "text":
            ip = client["primary_ip"] or client["primary_ipv6"] or ""
            self._send_bytes(
                HTTPStatus.OK,
                (ip + "\n").encode("utf-8"),
                "text/plain; charset=utf-8",
                head_only=head_only,
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "client_id": client["client_id"],
                "label": client["label"],
                "hostname": client["hostname"],
                "primary_ip": client["primary_ip"],
                "primary_ipv6": client["primary_ipv6"],
                "public_ip": client["public_ip"],
                "last_seen": client["last_seen"],
                "online": client["online"],
            },
            head_only=head_only,
        )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def create_server(
    config: Dict[str, Any],
    host: Optional[str] = None,
    port: Optional[int] = None,
) -> ThreadingHTTPServer:
    app = App(config)
    bind_host = host if host is not None else str(config["listen_host"])
    bind_port = int(port if port is not None else config["listen_port"])
    server = ThreadingHTTPServer((bind_host, bind_port), Handler)
    server.daemon_threads = True
    server.app = app  # type: ignore[attr-defined]
    return server


def serve(config: Dict[str, Any]) -> None:
    server = create_server(config)
    host, port = server.server_address[:2]
    LOG.info(
        "listening on %s:%s, data_dir=%s, report_tokens=%d, admin_tokens=%d",
        host,
        port,
        config["data_dir"],
        len(server.app.report_tokens),  # type: ignore[attr-defined]
        len(server.app.admin_tokens),  # type: ignore[attr-defined]
    )

    def stop(signum: int, _frame: Any) -> None:
        LOG.info("received signal %s, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        LOG.info("server stopped")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Internal IP reporter server (standard library only)"
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("IP_REPORTER_SERVER_CONFIG", ""),
        help="path to server JSON config",
    )
    parser.add_argument(
        "--init-config",
        metavar="PATH",
        help="create a new config with random tokens and exit",
    )
    parser.add_argument(
        "--force", action="store_true", help="overwrite an existing config"
    )
    parser.add_argument(
        "--show-tokens",
        action="store_true",
        help="print configured report/admin tokens and exit",
    )
    parser.add_argument(
        "--check", action="store_true", help="validate config and storage and exit"
    )
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.init_config:
        try:
            cfg = init_config(args.init_config, force=args.force)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        path = Path(args.init_config).expanduser().resolve()
        print(f"created config: {path} (mode 600)")
        print(f"report_token={cfg['report_token']}")
        print(f"admin_token={cfg['admin_token']}")
        print("Keep this file private and give report_token to clients.")
        return 0

    if not args.config:
        print(
            "error: --config is required (or use --init-config PATH first)",
            file=sys.stderr,
        )
        return 2

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    log_level = os.environ.get("IP_REPORTER_LOG_LEVEL", config.get("log_level", "INFO"))
    logging.basicConfig(
        level=getattr(logging, str(log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    if args.show_tokens:
        for kind in ("report", "admin"):
            for token in collect_tokens(config, kind):
                print(f"{kind}_token={token}")
        return 0

    if args.check:
        try:
            app = App(config)
            if not app.store.check():
                raise RuntimeError("data directory is not writable")
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"config: {config['_config_path']}")
        print(f"data_dir: {config['data_dir']}")
        print(f"report_tokens: {len(app.report_tokens)}, admin_tokens: {len(app.admin_tokens)}")
        print("ok")
        return 0

    try:
        serve(config)
    except OSError as exc:
        LOG.error("failed to start server: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
