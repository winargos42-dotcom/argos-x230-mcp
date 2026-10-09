"""Safety regression for ARGOS X230's strictly allowlisted command tool.

Run as root for setup only, then run again under service identity if desired.
No network or subprocess shell, and no mutations outside temporary directories.
"""
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from argos_x230_mcp.safe_commands import run_safe_command, _audit_logger


class SafeCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="argos-mcp-safe-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "good.py").write_text("def add(a, b):\n    return a + b\n")
        (self.root / "broken.py").write_text("def bad(:\n    pass\n")

    def call(self, action, path=""):
        return run_safe_command(action, path, workspace=self.root)

    def test_identity_executes_real_fixed_command(self):
        res = self.call("identity")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["stdout"].strip(), os.getlogin() if False else __import__("pwd").getpwuid(os.geteuid()).pw_name)

    def test_uptime_memory_disk_execute(self):
        for action in ("uptime", "memory", "disk"):
            with self.subTest(action=action):
                res = self.call(action)
                self.assertTrue(res["ok"], res)
                self.assertIsInstance(res["stdout"], str)
                self.assertLessEqual(len(res["stdout"]), 4096)

    def test_good_source_parses_without_executing(self):
        bad_side_effect = self.root / "unexpected-created.txt"
        file = self.root / "good.py"
        file.write_text(
            "from pathlib import Path\n"
            f"Path({str(bad_side_effect)!r}).write_text('SIDE EFFECT')\n"
        )
        res = self.call("python_syntax", "good.py")
        self.assertTrue(res["ok"], res)
        self.assertIn("syntax OK", res["stdout"])
        self.assertFalse(bad_side_effect.exists(), "Source unexpectedly executed")

    def test_invalid_python_reports_syntax_error(self):
        res = self.call("python_syntax", "broken.py")
        self.assertFalse(res["ok"])
        self.assertIn("SyntaxError", res["stderr"])
        self.assertNotIn("def bad", res["stderr"])

    def test_forbid_command_injection_and_argv(self):
        for cmd in (
            "bash -c id",
            "id;touch /tmp/evil",
            "python_syntax;rm",
            "sudo", "", "git log", "ls", "/usr/bin/id", "identity ",
        ):
            with self.subTest(cmd=cmd):
                res = self.call(cmd)
                self.assertFalse(res["ok"], res)
                self.assertIn("Denied", res["stderr"])

    def test_scope_escape_and_symlink_escape_rejected(self):
        outside = Path(self.temp.name).parent / "argos-dont-read-outside.py"
        (self.root / "escape.py").symlink_to(outside)
        for name in ("../../etc/shadow", "/etc/shadow", "../outside.py", "escape.py", "good.py/../../something"):
            with self.subTest(name=name):
                self.assertFalse(self.call("python_syntax", name)["ok"])

    def test_limit_and_bad_suffix(self):
        (self.root / "huge.py").write_bytes(b"x" * 65537)
        self.assertFalse(self.call("python_syntax", "huge.py")["ok"])
        self.assertFalse(self.call("python_syntax", "good.txt")["ok"])
        self.assertFalse(self.call("python_syntax", "x" * 181)["ok"])
        self.assertFalse(self.call("python_syntax", "")["ok"])

    def test_extraneous_argument_denied(self):
        res = self.call("uptime", "--help")
        self.assertFalse(res["ok"])
        self.assertIn("Path is only supported", res["stderr"])

    def test_empty_workspace_git_status_fails_closed(self):
        res = self.call("git_status")
        self.assertFalse(res["ok"])
        self.assertIn("git", (res["stderr"] + res["stdout"]).lower())

    def test_git_diff_check_no_arbitrary_subprocess(self):
        res = self.call("git_diff_check")
        self.assertFalse(res["ok"])

    def test_subprocess_uses_static_argv_and_clean_env(self):
        import subprocess
        with patch.dict(os.environ, {"ARGOS_MCP_LEAK_CANARY": "secret"}):
            with patch("argos_x230_mcp.safe_commands.subprocess.run") as proc:
                proc.return_value = subprocess.CompletedProcess([], 0, "works", "")
                result = self.call("uptime")
                self.assertTrue(result["ok"])
                argv = proc.call_args.args[0]
                kwargs = proc.call_args.kwargs
                self.assertEqual(argv, ["/usr/bin/uptime"])
                self.assertIs(kwargs["shell"], False)
                self.assertNotIn("ARGOS_MCP_LEAK_CANARY", kwargs["env"])
                self.assertEqual(kwargs["cwd"], self.root)

    def test_timeout_is_bounded(self):
        import subprocess
        with patch("argos_x230_mcp.safe_commands.subprocess.run", side_effect=subprocess.TimeoutExpired("uptime", 3)):
            res = self.call("uptime")
            self.assertFalse(res["ok"])
            self.assertEqual(res["stderr"], "Command timed out")

    def test_audit_always_happens_on_denied_and_success(self):
        with patch.object(_audit_logger, "info") as audit:
            self.call("rm -rf /")
            self.call("identity")
            self.assertEqual(audit.call_count, 2)
            self.assertIn("DENIED", audit.call_args_list[0].args[0])
            self.assertIn('"outcome":"executed"', audit.call_args_list[1].args[0])

    def test_no_absolute_path_even_for_valid_suffix(self):
        self.assertFalse(self.call("python_syntax", str(self.root / "good.py"))["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
