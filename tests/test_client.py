#!/usr/bin/env python3
"""Tests for client-side detection, config and upload."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "server"))

import ip_reporter as client_mod  # noqa: E402
import ip_reporter_server as server_mod  # noqa: E402


class ClientConfigTest(unittest.TestCase):
    def test_normalize_server_url(self):
        cases = {
            "https://ip.example.com": "https://ip.example.com/api/v1/report",
            "https://ip.example.com/": "https://ip.example.com/api/v1/report",
            "https://ip.example.com/ip-report": "https://ip.example.com/ip-report/api/v1/report",
            "https://ip.example.com/ip-report/": "https://ip.example.com/ip-report/api/v1/report",
            "https://ip.example.com/api/v1": "https://ip.example.com/api/v1/report",
            "https://ip.example.com/api/v1/report": "https://ip.example.com/api/v1/report",
            "http://127.0.0.1:8765/api/v1/report": "http://127.0.0.1:8765/api/v1/report",
        }
        for raw, expected in cases.items():
            self.assertEqual(client_mod.normalize_server_url(raw), expected)

    def test_invalid_server_url(self):
        for raw in ("", "ftp://example.com", "example.com", "https://"):
            with self.assertRaises(client_mod.ConfigError):
                client_mod.normalize_server_url(raw)

    def test_client_id_is_stable(self):
        tmp = Path(tempfile.mkdtemp(prefix="ip-reporter-client-test-"))
        try:
            state = client_mod.State(str(tmp / "state.json"))
            cfg = {"client_id": ""}
            first = client_mod.resolve_client_id(cfg, state)
            second = client_mod.resolve_client_id(cfg, client_mod.State(str(tmp / "state.json")))
            self.assertEqual(first, second)
            self.assertTrue(client_mod.CLIENT_ID_RE.match(first))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_payload_detection(self):
        cfg = {
            "server_url": "http://127.0.0.1:9/api/v1/report",
            "include_interfaces": [],
            "exclude_interfaces": ["lo"],
            "include_loopback": False,
            "extra_tags": {"env": "test"},
        }
        payload = client_mod.build_payload(cfg, "test-client")
        self.assertEqual(payload["client_id"], "test-client")
        self.assertTrue(payload["hostname"])
        self.assertTrue(payload["primary_ip"] or payload["primary_ipv6"])
        self.assertEqual(payload["tags"], {"env": "test"})
        self.assertEqual(payload["agent_version"], client_mod.VERSION)
        self.assertIsInstance(payload["interfaces"], list)

    def test_interface_filters(self):
        self.assertFalse(
            client_mod.interface_allowed("lo", ["LOOPBACK"], [], ["lo"], False)
        )
        self.assertTrue(
            client_mod.interface_allowed("lo", ["LOOPBACK"], [], ["lo"], True)
        )
        self.assertFalse(
            client_mod.interface_allowed("docker0", [], [], ["docker*"], False)
        )
        self.assertTrue(
            client_mod.interface_allowed("eth0", ["UP"], [], ["docker*"], False)
        )
        self.assertFalse(
            client_mod.interface_allowed("eth0", ["UP"], ["wlan*"], [], False)
        )
        self.assertTrue(
            client_mod.interface_allowed("wlan0", ["UP"], ["wlan*"], [], False)
        )


class ClientServerIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ip-reporter-e2e-"))
        self.report_token = "e2e-report-token"
        self.admin_token = "e2e-admin-token"
        config = dict(server_mod.DEFAULT_CONFIG)
        config.update(
            {
                "listen_host": "127.0.0.1",
                "listen_port": 0,
                "data_dir": str(self.tmp / "data"),
                "report_token": self.report_token,
                "admin_token": self.admin_token,
                "trust_proxy": False,
            }
        )
        self.server = server_mod.create_server(config)
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

    def test_client_payload_is_accepted(self):
        cfg = {
            "server_url": self.base + "/api/v1/report",
            "report_token": self.report_token,
            "include_interfaces": [],
            "exclude_interfaces": ["lo"],
            "include_loopback": False,
            "extra_tags": {"test": "e2e"},
        }
        payload = client_mod.build_payload(cfg, "e2e-client")
        result = client_mod.post_report(
            cfg["server_url"],
            payload,
            self.report_token,
            timeout=5,
            verify_tls=True,
            ca_file="",
            user_agent=client_mod.VERSION,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["client_id"], "e2e-client")

        import urllib.request

        req = urllib.request.Request(
            self.base + "/api/v1/clients",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["clients"][0]["client_id"], "e2e-client")
        self.assertEqual(data["clients"][0]["tags"], {"test": "e2e"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
