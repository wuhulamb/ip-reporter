#!/usr/bin/env python3
"""Unit/integration tests for the server (stdlib unittest only)."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

import ip_reporter_server as server_mod  # noqa: E402


REPORT_TOKEN = "test-report-token"
ADMIN_TOKEN = "test-admin-token"


class ServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ip-reporter-test-"))
        self.config = dict(server_mod.DEFAULT_CONFIG)
        self.config.update(
            {
                "listen_host": "127.0.0.1",
                "listen_port": 0,
                "data_dir": str(self.tmp / "data"),
                "report_token": REPORT_TOKEN,
                "admin_token": ADMIN_TOKEN,
                "trust_proxy": False,
                "online_threshold_seconds": 600,
                "history_retention_days": 90,
                "history_max_per_client": 10,
            }
        )
        self.server = server_mod.create_server(self.config)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def request(
        self,
        method: str,
        path: str,
        payload=None,
        token: str = "",
        headers=None,
    ):
        data = None
        all_headers = dict(headers or {})
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            all_headers["Content-Type"] = "application/json"
        if token:
            all_headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            self.base + path, data=data, method=method, headers=all_headers
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read()
                return response.status, response.headers, body
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def json_request(self, *args, **kwargs):
        status, headers, body = self.request(*args, **kwargs)
        return status, headers, json.loads(body.decode("utf-8"))

    def report_payload(self, client_id="test-client", ip="192.168.1.50", label="guo"):
        return {
            "client_id": client_id,
            "label": label,
            "hostname": "test-laptop",
            "fqdn": "test-laptop.local",
            "primary_ip": ip,
            "primary_ipv6": None,
            "interfaces": [
                {
                    "name": "eth0",
                    "state": "UP",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "addresses": [
                        {
                            "family": "inet",
                            "address": ip,
                            "prefixlen": 24,
                            "scope": "global",
                        }
                    ],
                }
            ],
            "os": "Debian GNU/Linux 12",
            "kernel": "6.1.0",
            "agent_version": "1.0.0",
            "tags": {"env": "home"},
            "client_time": "2026-01-01T00:00:00Z",
        }

    def test_health(self):
        status, _, data = self.json_request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["version"], server_mod.VERSION)
        self.assertNotIn("token", json.dumps(data).lower())

    def test_dashboard_is_served(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"<!doctype html>", body.lower())
        self.assertIn("Content-Security-Policy", headers)

    def test_report_requires_token(self):
        status, _, data = self.json_request(
            "POST", "/api/v1/report", self.report_payload()
        )
        self.assertEqual(status, 401)
        self.assertFalse(data["ok"])

    def test_wrong_token_is_rejected(self):
        status, _, data = self.json_request(
            "POST",
            "/api/v1/report",
            self.report_payload(),
            token="wrong",
        )
        self.assertEqual(status, 401)
        self.assertFalse(data["ok"])

    def test_report_then_list_and_lookup(self):
        status, _, data = self.json_request(
            "POST",
            "/api/v1/report",
            self.report_payload(),
            token=REPORT_TOKEN,
        )
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertEqual(data["observed_ip"], "127.0.0.1")

        status, _, listing = self.json_request(
            "GET", "/api/v1/clients", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(listing["count"], 1)
        client = listing["clients"][0]
        self.assertEqual(client["client_id"], "test-client")
        self.assertEqual(client["label"], "guo")
        self.assertEqual(client["primary_ip"], "192.168.1.50")
        self.assertEqual(client["public_ip"], "127.0.0.1")
        self.assertEqual(client["report_count"], 1)
        self.assertTrue(client["online"])
        self.assertEqual(client["interfaces"][0]["name"], "eth0")
        self.assertEqual(client["tags"]["env"], "home")

        # Clients must not be able to read the lookup API.
        status, _, _ = self.json_request(
            "GET", "/api/v1/lookup?hostname=test-laptop", token=REPORT_TOKEN
        )
        self.assertEqual(status, 401)

        status, _, lookup = self.json_request(
            "GET", "/api/v1/lookup?hostname=test-laptop", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(lookup["primary_ip"], "192.168.1.50")

        status, _, body = self.request(
            "GET", "/api/v1/lookup?hostname=test-laptop&format=text", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"192.168.1.50\n")

    def test_filesystem_storage_layout(self):
        status, _, _ = self.json_request(
            "POST", "/api/v1/report", self.report_payload(), token=REPORT_TOKEN
        )
        self.assertEqual(status, 200)

        client_dir = self.tmp / "data" / "clients" / "test-client"
        latest_path = client_dir / "latest.json"
        self.assertTrue(latest_path.is_file())
        latest = json.loads(latest_path.read_text(encoding="utf-8"))
        self.assertEqual(latest["schema_version"], 1)
        self.assertEqual(latest["client_id"], "test-client")
        self.assertEqual(latest["label"], "guo")
        self.assertEqual(latest["primary_ip"], "192.168.1.50")
        self.assertEqual(latest["report_count"], 1)
        self.assertEqual(latest["first_seen"], latest["last_seen"])

        history_files = list((client_dir / "history").glob("*.json"))
        self.assertEqual(len(history_files), 1)
        history = json.loads(history_files[0].read_text(encoding="utf-8"))
        self.assertEqual(history["received_at"], latest["last_seen"])
        self.assertEqual(history["label"], "guo")
        self.assertEqual(history["primary_ip"], "192.168.1.50")

        # Atomic writes must not leave temporary files behind.
        self.assertEqual(list(self.tmp.glob("**/*.tmp")), [])

    def test_invalid_client_id_cannot_escape_data_dir(self):
        status, _, _ = self.json_request(
            "GET", "/api/v1/clients/..%2F..%2Fetc", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 404)
        status, _, _ = self.json_request(
            "DELETE", "/api/v1/clients/..%2F..%2Fetc", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 404)

    def test_report_updates_existing_client(self):
        for ip in ("192.168.1.50", "192.168.1.51", "192.168.1.52"):
            status, _, _ = self.json_request(
                "POST",
                "/api/v1/report",
                self.report_payload(ip=ip),
                token=REPORT_TOKEN,
            )
            self.assertEqual(status, 200)

        status, _, detail = self.json_request(
            "GET", "/api/v1/clients/test-client", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(detail["client"]["primary_ip"], "192.168.1.52")
        self.assertEqual(detail["client"]["report_count"], 3)

        status, _, history = self.json_request(
            "GET", "/api/v1/clients/test-client/history?limit=2", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(history["reports"]), 2)
        self.assertEqual(history["reports"][0]["primary_ip"], "192.168.1.52")

    def test_history_max_per_client(self):
        for index in range(15):
            status, _, _ = self.json_request(
                "POST",
                "/api/v1/report",
                self.report_payload(ip=f"10.0.0.{index + 1}"),
                token=REPORT_TOKEN,
            )
            self.assertEqual(status, 200)
        status, _, history = self.json_request(
            "GET", "/api/v1/clients/test-client/history?limit=100", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(history["reports"]), 10)

    def test_delete_client(self):
        status, _, _ = self.json_request(
            "POST", "/api/v1/report", self.report_payload(), token=REPORT_TOKEN
        )
        self.assertEqual(status, 200)

        # The report token must not be able to delete clients.
        status, _, _ = self.json_request(
            "DELETE", "/api/v1/clients/test-client", token=REPORT_TOKEN
        )
        self.assertEqual(status, 401)

        status, _, data = self.json_request(
            "DELETE", "/api/v1/clients/test-client", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["deleted"])
        self.assertFalse(
            (self.tmp / "data" / "clients" / "test-client").exists()
        )

        status, _, data = self.json_request(
            "GET", "/api/v1/clients", token=ADMIN_TOKEN
        )
        self.assertEqual(data["count"], 0)

        status, _, _ = self.json_request(
            "DELETE", "/api/v1/clients/test-client", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 404)

    def test_admin_endpoints_require_admin_token(self):
        status, _, _ = self.json_request("GET", "/api/v1/clients", token=REPORT_TOKEN)
        self.assertEqual(status, 401)
        status, _, _ = self.json_request("GET", "/api/v1/clients")
        self.assertEqual(status, 401)

    def test_invalid_payloads(self):
        cases = [
            {},
            {"client_id": "x", "hostname": "h", "primary_ip": "not-an-ip"},
            {
                "client_id": "bad id with spaces",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
                "interfaces": "not-a-list",
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
                "label": "",
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
                "label": "   ",
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
                "label": 123,
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
                "label": "line\nbreak",
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
                "label": "x" * 65,
            },
            {
                "client_id": "x",
                "hostname": "h",
                "primary_ip": "192.168.1.2",
                "interfaces": [
                    {
                        "name": "eth0",
                        "addresses": [
                            {"family": "inet", "address": "999.1.1.1", "prefixlen": 24}
                        ],
                    }
                ],
            },
        ]
        for payload in cases:
            status, _, data = self.json_request(
                "POST", "/api/v1/report", payload, token=REPORT_TOKEN
            )
            self.assertEqual(status, 400, payload)
            self.assertIn("error", data)

    def test_label_search_and_lookup(self):
        for client_id, label, ip in (
            ("laptop-a", "guo", "192.168.1.10"),
            ("laptop-b", "Guo-Backup", "192.168.1.11"),
        ):
            status, _, data = self.json_request(
                "POST",
                "/api/v1/report",
                self.report_payload(client_id=client_id, ip=ip, label=label),
                token=REPORT_TOKEN,
            )
            self.assertEqual(status, 200, data)

        status, _, listing = self.json_request(
            "GET", "/api/v1/clients?q=guo", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(listing["count"], 2)
        self.assertEqual(
            {client["label"] for client in listing["clients"]}, {"guo", "Guo-Backup"}
        )

        status, _, lookup = self.json_request(
            "GET", "/api/v1/lookup?label=guo", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(lookup["client_id"], "laptop-a")
        self.assertEqual(lookup["label"], "guo")

        status, _, lookup = self.json_request(
            "GET", "/api/v1/lookup?label=guo-backup", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(lookup["client_id"], "laptop-b")

        status, _, body = self.request(
            "GET", "/api/v1/lookup?label=GUO&format=text", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"192.168.1.10\n")

        status, _, lookup = self.json_request(
            "GET", "/api/v1/lookup?label=guo&hostname=test-laptop",
            token=ADMIN_TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertIn(lookup["client_id"], ("laptop-a", "laptop-b"))

        status, _, _ = self.json_request(
            "GET", "/api/v1/lookup?label=missing", token=ADMIN_TOKEN
        )
        self.assertEqual(status, 404)

    def test_unknown_api_route(self):
        status, _, data = self.json_request("GET", "/api/v1/nope", token=ADMIN_TOKEN)
        self.assertEqual(status, 404)
        self.assertFalse(data["ok"])

    def test_method_not_allowed(self):
        status, headers, _ = self.request(
            "GET", "/api/v1/report", token=REPORT_TOKEN
        )
        self.assertEqual(status, 405)
        self.assertIn("POST", headers.get("Allow", ""))

    def test_proxy_ip_parsing(self):
        self.assertEqual(
            server_mod._first_valid_ip("203.0.113.9, 10.0.0.1"), "203.0.113.9"
        )
        self.assertEqual(server_mod._first_valid_ip("garbage, 198.51.100.7"), "198.51.100.7")
        self.assertIsNone(server_mod._first_valid_ip("garbage"))

    def test_token_lists_support_rotation(self):
        cfg = dict(self.config)
        cfg["report_tokens"] = [REPORT_TOKEN, "second-token"]
        cfg["admin_tokens"] = [ADMIN_TOKEN, "second-admin"]
        app = server_mod.App(cfg)
        self.assertTrue(app.token_ok("second-token", "report"))
        self.assertTrue(app.token_ok("second-admin", "admin"))
        self.assertTrue(app.token_ok("second-admin", "report"))
        self.assertFalse(app.token_ok("second-token", "admin"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
