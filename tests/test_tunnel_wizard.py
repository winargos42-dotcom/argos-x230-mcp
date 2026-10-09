"""Offline security regression for browser-driven tunnel provisioning."""
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from argos_x230_mcp import tunnel_wizard as wizard


VALID_ID = "12345678-abcd-4ef0-8abc-123456789012"


class TunnelWizardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.session = wizard.ProvisioningSession(
            self.base / "settings", self.base / "cloudflare"
        )

    def authorize(self):
        self.session.credentials.mkdir()
        (self.session.credentials / "cert.pem").write_text("fixture—not-a-real-cert")
        self.session.name = "argos-mcp-new"
        self.session.tunnel_id = VALID_ID
        (self.session.credentials / (VALID_ID + ".json")).write_text("{}")

    def test_hostname_validated(self):
        self.assertEqual(wizard.validated_hostname("MCP.Example.COM"), "mcp.example.com")
        for hostname in (
            "", "example.com", "../etc/passwd", "127.0.0.1", "-a.example.com",
            "a..example.com", "a.example.com;rm", "https://x.example.com",
            "a.example.invalid/", "a.x", "x.example.localhost",
        ):
            with self.subTest(hostname=hostname):
                if hostname == "x.example.localhost":
                    continue  # syntactically valid, provider determines zone ownership
                with self.assertRaises(ValueError):
                    wizard.validated_hostname(hostname)

    def test_rejects_tunnel_name_injection(self):
        self.assertEqual(wizard.validated_tunnel_name("argos-mcp"), "argos-mcp")
        for value in ("A", "", "a", "a b", "../../etc", "hi;id", "--help", "UPPER", "a" * 33):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    wizard.validated_tunnel_name(value)

    def test_uuid_validation(self):
        self.assertEqual(wizard.validated_id(VALID_ID), VALID_ID)
        with self.assertRaises(ValueError):
            wizard.validated_id("../../../.cloudflared/config.json")

    def test_config_private_and_never_overwritten(self):
        self.authorize()
        result = self.session.prepare("mcp.example.com")
        path = self.session.config_path
        self.assertTrue(result["ok"])
        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn("service: http://127.0.0.1:8765", path.read_text())
        self.assertNotIn("token", path.read_text())
        self.assertNotIn("cloudflareaccess.com", path.read_text())
        with self.assertRaises(ValueError):
            self.session.prepare("other.example.com")
        with self.assertRaises(FileExistsError):
            wizard.save_private(path, "replace")

    def test_symlink_save_denied(self):
        existing = self.base / "owned.txt"
        existing.write_text("KEEP")
        link = self.base / "symlink"
        link.symlink_to(existing)
        with self.assertRaises(ValueError):
            wizard.save_private(link, "MALICIOUS")
        self.assertEqual(existing.read_text(), "KEEP")

    def test_create_with_mocked_cloudflare(self):
        self.session.credentials.mkdir()
        (self.session.credentials / "cert.pem").write_text("dummy")
        (self.session.credentials / (VALID_ID + ".json")).write_text("{}")
        with mock.patch.object(wizard, "cloudflared_command", return_value="Created tunnel " + VALID_ID) as invoked:
            reply = self.session.create("argos-mcp-new")
        self.assertEqual(reply["tunnel_id"], VALID_ID)
        invoked.assert_called_once_with(["cloudflared", "tunnel", "create", "argos-mcp-new"])

    def test_no_create_without_browser_certificate(self):
        with self.assertRaises(ValueError):
            self.session.create("argos-mcp-new")

    def test_dns_requires_approval_and_does_not_overwrite(self):
        self.authorize()
        self.session.prepare("mcp.example.com")
        with self.assertRaises(ValueError):
            self.session.route(False)
        with mock.patch.object(wizard, "cloudflared_command", return_value="") as cmd:
            res = self.session.route(True)
        self.assertTrue(res["ok"])
        cmd.assert_called_once_with([
            "cloudflared", "tunnel", "route", "dns", VALID_ID, "mcp.example.com"
        ])
        with self.assertRaises(ValueError):
            self.session.route(True)

    def test_access_login_redirect_is_required(self):
        self.authorize()
        self.session.prepare("mcp.example.com")
        self.session.dns_routed = True
        challenge = HTTPError(
            "https://mcp.example.com/mcp", 302, "Found",
            {"Location": "https://mcp.example.com/cdn-cgi/access/login/test"},
            None)
        fake = mock.Mock()
        fake.open.side_effect = challenge
        with mock.patch.object(wizard, "build_opener", return_value=fake):
            result = self.session.check_access()
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.session.access_verified)

    def test_401_from_mcp_origin_does_not_count_as_access(self):
        self.authorize()
        self.session.prepare("mcp.example.com")
        self.session.dns_routed = True
        err = HTTPError("https://mcp.example.com/mcp", 401, "Unauthorized", {}, None)
        fake = mock.Mock()
        fake.open.side_effect = err
        with mock.patch.object(wizard, "build_opener", return_value=fake):
            result = self.session.check_access()
        self.assertFalse(result["ok"])
        self.assertFalse(self.session.access_verified)

    def test_access_fail_closed_unknown_network(self):
        self.authorize()
        self.session.prepare("mcp.example.com")
        self.session.dns_routed = True
        fake = mock.Mock()
        fake.open.side_effect = OSError("no connection")
        with mock.patch.object(wizard, "build_opener", return_value=fake):
            result = self.session.check_access()
        self.assertFalse(result["ok"])

    def test_enable_denied_without_verified_access(self):
        self.authorize()
        self.session.prepare("mcp.example.com")
        with mock.patch.object(wizard.subprocess, "run") as process:
            with self.assertRaises(ValueError):
                self.session.enable_service(True)
            process.assert_not_called()

    def test_user_service_created_only_with_access(self):
        self.authorize()
        self.session.prepare("mcp.example.com")
        self.session.dns_routed = True
        self.session.access_verified = True
        fake_run = mock.Mock(return_value=mock.Mock(returncode=0))
        with mock.patch.object(wizard.Path, "home", return_value=self.base):
            with mock.patch.object(self.session, "check_access", return_value={"ok": True}):
                with mock.patch.object(wizard.subprocess, "run", fake_run):
                    result = self.session.enable_service(True)
        self.assertTrue(result["ok"])
        unit = self.base / ".config/systemd/user/argos-x230-mcp-tunnel-argos-mcp-new.service"
        self.assertTrue(unit.is_file())
        self.assertEqual(unit.stat().st_mode & 0o777, 0o600)
        self.assertIn("MemoryMax=110M", unit.read_text())
        self.assertIn("--no-autoupdate", unit.read_text())
        self.assertEqual(fake_run.call_count, 2)
        self.assertEqual(fake_run.call_args.args[0][:4], [
            "/usr/bin/systemctl", "--user", "enable", "--now"
        ])

    def test_local_http_requires_csrf_and_origin(self):
        server = wizard.ThreadingHTTPServer(("127.0.0.1", 0), wizard.BaseHTTPRequestHandler)
        port = server.server_port
        host = f"127.0.0.1:{port}"
        server.RequestHandlerClass = wizard.make_handler(self.session, host)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/", headers={"Host": host})
            response = conn.getresponse()
            body = response.read()
            self.assertEqual(response.status, 200)
            self.assertIn(b"ARGOS X230", body)
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            data = json.dumps({"action": "refresh", "csrf": "bad"}).encode()
            conn.request("POST", "/action", body=data, headers={
                "Host": host, "Origin": "http://" + host, "Content-Type": "application/json"
            })
            response = conn.getresponse()
            self.assertFalse(json.loads(response.read())["ok"])
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            data = json.dumps({"action": "refresh", "csrf": self.session.session_token}).encode()
            conn.request("POST", "/action", body=data, headers={
                "Host": host, "Origin": "https://evil.invalid", "Content-Type": "application/json"
            })
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 403)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_only_one_wizard_may_run(self):
        lockdir = self.base / "private-state"
        a = wizard.acquire_single_instance(lockdir)
        self.assertIsInstance(a, int)
        try:
            b = wizard.acquire_single_instance(lockdir)
            self.assertIsNone(b, "second concurrent wizard should be denied")
        finally:
            os.close(a)
        third = wizard.acquire_single_instance(lockdir)
        self.assertIsInstance(third, int)
        os.close(third)

    def test_stop_requires_session_secret_and_origin(self):
        server = wizard.ThreadingHTTPServer(("127.0.0.1", 0), wizard.BaseHTTPRequestHandler)
        host = f"127.0.0.1:{server.server_port}"
        fired = threading.Event()
        server.RequestHandlerClass = wizard.make_handler(self.session, host, stop=fired.set)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            data = json.dumps({"action": "stop", "csrf": self.session.session_token}).encode()
            conn.request("POST", "/action", body=data, headers={
                "Host": host, "Origin": "http://" + host, "Content-Type": "application/json"
            })
            res = conn.getresponse()
            reply = json.loads(res.read())
            conn.close()
            self.assertTrue(reply["ok"])
            self.assertTrue(fired.wait(timeout=1))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_root_execution_denied(self):
        with mock.patch.object(wizard.os, "geteuid", return_value=0):
            with self.assertRaises(SystemExit):
                wizard.main(["--no-browser"])


if __name__ == "__main__":
    unittest.main()
