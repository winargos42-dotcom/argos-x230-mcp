"""Allowlisted, read-only MCP commands for the ARGOS X230 workstation.

This is deliberately NOT a remote shell. Tool input selects a known operation,
and never becomes an executable, shell script, environment variable or argv
option. The service must continue running as argos-mcp, not root.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_OUTPUT = 4096
MAX_PY_BYTES = 65536
MAX_PATH_CHARS = 180
ALLOWED = frozenset({
    "identity",
    "uptime",
    "memory",
    "disk",
    "git_status",
    "git_diff_check",
    "python_syntax",
})

_audit_logger = logging.getLogger("argos_mcp.safe_command")
_audit_logger.setLevel(logging.INFO)
if not _audit_logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("ARGOS_MCP_SAFE_COMMAND_AUDIT %(message)s"))
    _audit_logger.addHandler(handler)
_audit_logger.propagate = False


def _validate_workspace(workspace: Path) -> Path:
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise ValueError("Workspace unavailable")
    return root


def _safe_python_path(root: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not (1 <= len(relative_path) <= MAX_PATH_CHARS):
        raise ValueError("Invalid relative path")
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".py":
        raise ValueError("Only relative .py files inside the workspace are allowed")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("Path leaves workspace or is not a file")
    if path.stat().st_size > MAX_PY_BYTES:
        raise ValueError("Python source exceeds 64 KiB")
    return path


def _run_fixed(argv: tuple[str, ...], root: Path, timeout: int, stdin: str | None = None) -> dict:
    """Spawn a single predefined process. No shell, stdin is only parsed as AST."""
    safe_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        proc = subprocess.run(
            list(argv), shell=False, cwd=root,
            env=safe_env, input=stdin, text=True,
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit_code": None, "stdout": "", "stderr": "Command timed out"}
    except OSError as exc:
        return {
            "ok": False, "exit_code": None, "stdout": "",
            "stderr": "Process unavailable: " + type(exc).__name__,
        }
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": (proc.stdout or "")[:MAX_OUTPUT],
        "stderr": (proc.stderr or "")[:MAX_OUTPUT],
    }


def run_safe_command(action: str, relative_path: str = "", *, workspace: Path) -> dict:
    """Execute a safe, fixed inspection action; always write a systemd journal record.

    Allowed action values: identity, uptime, memory, disk, git_status,
    git_diff_check, python_syntax. python_syntax reads a workspace .py file
    but never executes its source or imports from it.
    """
    start = time.monotonic()
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = {"ok": False, "exit_code": None, "stdout": "", "stderr": "Denied"}
    reason = "rejected"
    # Do not log user-controlled path strings, only a SHA256 digest for audit.
    # No secrets, tokens or source code are written to journald.
    try:
        if not isinstance(action, str) or action not in ALLOWED:
            raise ValueError("Action not on allowlist")
        root = _validate_workspace(workspace)
        if not isinstance(relative_path, str) or len(relative_path) > MAX_PATH_CHARS:
            raise ValueError("Invalid relative path")
        if action != "python_syntax" and relative_path not in ("", "."):
            raise ValueError("Path is only supported by python_syntax")

        if action == "identity":
            argv = ("/usr/bin/id", "-un")
            timeout = 3
            stdin = None
        elif action == "uptime":
            argv = ("/usr/bin/uptime",)
            timeout = 3
            stdin = None
        elif action == "memory":
            argv = ("/usr/bin/free", "-m")
            timeout = 3
            stdin = None
        elif action == "disk":
            argv = ("/usr/bin/df", "-h", "--", str(root))
            timeout = 3
            stdin = None
        elif action in ("git_status", "git_diff_check"):
            common = (
                "/usr/bin/git", "-c", "core.fsmonitor=false",
                "-c", "core.hooksPath=/dev/null",
                "-c", "diff.external=",
            )
            argv = common + (
                ("status", "--short", "--untracked-files=no")
                if action == "git_status"
                else ("diff", "--check", "--no-ext-diff", "--no-textconv")
            )
            timeout = 7
            stdin = None
        else:
            file_path = _safe_python_path(root, relative_path)
            # Read source as data only, AST parsing runs in isolated mode.
            source = file_path.read_text(encoding="utf-8")
            # Python -I -S removes site/user packages; code isn't executed.
            python_check = (
                "import ast,sys\n"
                "source = sys.stdin.read()\n"
                "try:\n"
                "    ast.parse(source, filename='<workspace-source>')\n"
                "except SyntaxError as e:\n"
                "    print('SyntaxError at line %s: %s' % (e.lineno, e.msg), file=sys.stderr)\n"
                "    raise SystemExit(1)\n"
                "print('Python syntax OK')\n"
            )
            argv = ("/usr/bin/python3", "-I", "-S", "-c", python_check)
            stdin = source
            timeout = 4
        result = _run_fixed(argv, root, timeout=timeout, stdin=stdin)
        reason = "executed" if result["ok"] else "command_failed"
    except (ValueError, UnicodeError, PermissionError, OSError) as exc:
        reason = "denied"
        result["stderr"] = "Denied: " + str(exc)[:160]
    finally:
        # journald owns the service stdout; cannot be overwritten via MCP write_text.
        entry = {
            "utc": timestamp,
            "action": action if isinstance(action, str) and action in ALLOWED else "DENIED",
            "outcome": reason,
            "ok": bool(result["ok"]),
            "exit_code": result["exit_code"],
            "elapsed_ms": round((time.monotonic() - start) * 1000),
            "service_uid": os.geteuid(),
        }
        _audit_logger.info(json.dumps(entry, ensure_ascii=True, separators=(",", ":")))
    return result
