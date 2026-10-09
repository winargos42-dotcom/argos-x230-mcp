"""Offline regression of project sandbox, bounded output and resource gate."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
from argos_x230_mcp import expanded_tools as tools


class FakeMCP:
    def __init__(self): self.registered = {}
    def tool(self):
        def decorator(func):
            self.registered[func.__name__] = func
            return func
        return decorator


class ExpandedToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="argos-project-tools-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.mcp = FakeMCP()
        tools.register_tools(self.mcp, self.root)

    def test_public_tools_present(self):
        expected = {
            "resource_status", "project_create", "project_list", "git_project",
            "python_project_test", "service_health", "service_logs"
        }
        self.assertEqual(set(self.mcp.registered), expected)

    def test_project_create_and_list(self):
        created = self.mcp.registered["project_create"]("sample-app")
        self.assertTrue(created["ok"])
        self.assertTrue((self.root / "projects/sample-app/tests/test_smoke.py").exists())
        self.assertIn("sample-app", str(self.mcp.registered["project_list"]()))

    def test_project_rejects_path_escape_and_existing_name(self):
        for value in ("..", "../etc", "/root", "a b", "a;rm -rf", "A", "x", "z"*40):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.mcp.registered["project_create"](value)
        self.mcp.registered["project_create"]("sample-app")
        with self.assertRaises(ValueError):
            self.mcp.registered["project_create"]("sample-app")

    def test_project_symlink_escape(self):
        base = self.root / "projects"
        base.mkdir(exist_ok=True)
        link = base / "evil-link"
        link.symlink_to(Path(self.tmp.name).parent)
        with self.assertRaises(ValueError):
            self.mcp.registered["git_project"]("evil-link", action="status")

    def test_git_rejects_network_actions(self):
        self.mcp.registered["project_create"]("sample-app")
        with self.assertRaises(ValueError):
            self.mcp.registered["git_project"]("sample-app", action="push")
        with self.assertRaises(ValueError):
            self.mcp.registered["git_project"]("sample-app", action="pull")
        with self.assertRaises(ValueError):
            self.mcp.registered["git_project"]("sample-app", action="add",
                                              relative_path="../../etc/passwd")

    def test_services_allowlist_denies_other_units(self):
        for action in ("service_health", "service_logs"):
            with self.subTest(action=action):
                with self.assertRaises(ValueError):
                    self.mcp.registered[action]("ssh.service")
        with self.assertRaises(ValueError):
            self.mcp.registered["service_logs"]("ollama.service", lines=999)

    def test_resource_guard_blocks_test_when_red(self):
        self.mcp.registered["project_create"]("sample-app")
        with mock.patch.object(tools, "resource_preflight", return_value={
            "level": "RED", "available_mib": 160, "swap_free_mib": 0,
            "cpu_celsius": 89, "heavy_allowed": False
        }):
            with mock.patch.object(tools, "_bwrap") as executor:
                report = self.mcp.registered["python_project_test"]("sample-app")
                executor.assert_not_called()
        self.assertEqual(report["exit_code"], 75)
        self.assertTrue(report["deferred"])

    def test_bwrap_called_for_python_tests_only_if_green(self):
        self.mcp.registered["project_create"]("sample-app")
        with mock.patch.object(tools, "resource_preflight", return_value={
            "level": "GREEN", "available_mib": 8000, "swap_free_mib": 1500,
            "cpu_celsius": 60, "heavy_allowed": True
        }):
            with mock.patch.object(tools, "_bwrap", return_value={
                "ok": True, "exit_code": 0, "stdout": "OK", "stderr": ""
            }) as executor:
                report = self.mcp.registered["python_project_test"]("sample-app")
                self.assertTrue(report["ok"])
                cmd = executor.call_args.args[1]
                self.assertIn("unittest", cmd)
                self.assertFalse(executor.call_args.kwargs["writable"])

    def test_bounded_subprocess_truncates_output_without_memory_capture(self):
        with mock.patch.object(tools.subprocess, "run", side_effect=AssertionError("No run() allowed")):
            result = tools._bounded(
                ["/usr/bin/python3", "-c", "print('A'*9000)"],
                cwd=self.root, timeout=5)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["stdout"]), tools.OUT_LIMIT)
        self.assertTrue(result["output_truncated"])

    def test_bounded_timeout_kills_process_group(self):
        started = time.monotonic()
        result = tools._bounded(
            ["/usr/bin/python3", "-c", "import time;time.sleep(3)"],
            cwd=self.root, timeout=1)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["exit_code"])
        self.assertLess(time.monotonic()-started, 2.9)
        self.assertIn("terminated", result["stderr"])

    def test_readonly_host_resources(self):
        result = self.mcp.registered["resource_status"]()
        self.assertIn(result["level"], ("RED", "GREEN", "UNKNOWN"))
        self.assertIn("heavy_allowed", result)
        self.assertNotIn("password", str(result).lower())

    def test_sandbox_argv_disables_network_and_mounts_workspace(self):
        p = self.root / "projects/demo"
        p.mkdir(parents=True)
        with mock.patch.object(tools, "_bounded", return_value={"ok":True}) as bounded:
            tools._bwrap(p, ["/usr/bin/python3", "-V"], writable=False)
        argv = bounded.call_args.args[0]
        self.assertIn("--unshare-net", argv)
        self.assertIn("--clearenv", argv)
        self.assertIn("--ro-bind", argv)
        self.assertNotIn("--share-net", argv)

    def test_service_status_only_fixed_systemctl(self):
        with mock.patch.object(tools, "_bounded", return_value={"ok":True,"stdout":"ActiveState=active"}) as bounded:
            self.mcp.registered["service_health"]("ollama.service")
        args = bounded.call_args.args[0]
        self.assertEqual(args[:2], ["/usr/bin/systemctl", "show"])
        self.assertNotIn("start", args)
        self.assertNotIn("restart", args)


if __name__ == "__main__":
    unittest.main()
