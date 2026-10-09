"""ARGOS MCP project/Git/Python/service capabilities, v1.

The MCP user is unprivileged. Executable project content runs ONLY inside
bubblewrap with no network, no host-home mount and bounded resource limits.
No arbitrary shell or privileged systemctl mutations.
"""
from __future__ import annotations

import json
import logging
import os
import re
import resource
import signal
import tempfile
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
SERVICE_ALLOWLIST = frozenset({
    "argos-remote-mcp.service",
    "cloudflared.service",
    "argos-tun-coral.service",
    "ollama.service",
    "docker.service",
    "home-assistant.service",
})
PROJECT_LIMIT = 24
OUT_LIMIT = 7000
BWRAP = "/usr/bin/bwrap"
GIT = "/usr/bin/git"
PYTHON = "/usr/bin/python3"
AUDIT = logging.getLogger("argos_mcp.project_ops")
AUDIT.setLevel(logging.INFO)
if not AUDIT.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("ARGOS_MCP_PROJECT_AUDIT %(message)s"))
    AUDIT.addHandler(handler)
AUDIT.propagate = False


def _audit(operation: str, target: str, outcome: str, elapsed: float) -> None:
    AUDIT.info(json.dumps({
        "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operation": operation,
        "target": target[:80] if isinstance(target, str) else "invalid",
        "outcome": outcome,
        "elapsed_ms": round((time.monotonic() - elapsed) * 1000),
        "uid": os.geteuid(),
    }, separators=(",", ":")))


def _projects_dir(root: Path) -> Path:
    base = root / "projects"
    # Fail closed against redirected workspace paths.
    if base.is_symlink() or not base.resolve().is_relative_to(root.resolve()):
        raise ValueError("Unsafe projects directory")
    base.mkdir(mode=0o700, exist_ok=True)
    return base


def _project(root: Path, name: str, must_exist: bool = True) -> Path:
    if not isinstance(name, str) or not PROJECT_PATTERN.fullmatch(name):
        raise ValueError("Project name must be 2-32 characters: a-z, 0-9, _ or -")
    base = _projects_dir(root)
    p = base / name
    if p.is_symlink() or p.resolve() != p.absolute():
        raise ValueError("Project symlinks are prohibited")
    if must_exist and not p.is_dir():
        raise ValueError("Project not found")
    if not must_exist and p.exists():
        raise ValueError("Project already exists")
    return p


def _project_file(project_dir: Path, relative: str) -> str:
    if not isinstance(relative, str) or not relative or len(relative) > 180:
        raise ValueError("Invalid file path")
    p = Path(relative)
    if p.is_absolute() or ".." in p.parts or ".git" in p.parts:
        raise ValueError("Absolute, parent and .git paths are prohibited")
    target = (project_dir / p).resolve()
    if not target.is_relative_to(project_dir):
        raise ValueError("Path escapes project")
    if not target.is_file() or target.is_symlink():
        raise ValueError("Selected file must be a regular project file")
    return target.relative_to(project_dir).as_posix()


def _safe_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_PAGER": "cat",
    }


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (12, 13))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (48, 48))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _bounded(argv: list[str], *, cwd: Path, timeout: int = 15, env=None) -> dict:
    """Bound output on DISK, not RAM; kill entire process group on timeout.

    capture_output=True retains all stdout in memory before slicing and can
    itself trigger OOM on a small workstation. TemporaryFile avoids this.
    """
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(
                argv, cwd=cwd, env=env or _safe_env(), shell=False,
                stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                preexec_fn=_limits, start_new_session=True,
            )
            try:
                code = proc.wait(timeout=min(timeout, 20))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=3)
                return {"ok": False, "exit_code": None,
                        "stdout": "", "stderr": "Timed out; process group terminated"}
            out.seek(0)
            err.seek(0)
            stdout = out.read(OUT_LIMIT + 1).decode("utf-8", "replace")
            stderr = err.read(OUT_LIMIT + 1).decode("utf-8", "replace")
            truncated = len(stdout) > OUT_LIMIT or len(stderr) > OUT_LIMIT
            return {"ok": code == 0, "exit_code": code,
                    "stdout": stdout[:OUT_LIMIT], "stderr": stderr[:OUT_LIMIT],
                    "output_truncated": truncated}
    except (OSError, ValueError, subprocess.SubprocessError) as ex:
        return {"ok": False, "exit_code": None, "stdout": "",
                "stderr": "Execution unavailable: " + type(ex).__name__}


def _bwrap(project_dir: Path, command: list[str], writable: bool = False, timeout: int = 15) -> dict:
    # Neither host /etc nor user HOME nor token files are visible in the sandbox.
    # No network namespace access, even if test code spawns a subprocess.
    flags = [
        BWRAP, "--die-with-parent", "--new-session",
        "--unshare-net", "--unshare-pid", "--unshare-ipc",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--tmpfs", "/tmp",
        "--dev", "/dev",
        "--dir", "/workspace",
        "--bind" if writable else "--ro-bind", str(project_dir), "/workspace",
        "--chdir", "/workspace",
        "--clearenv",
    ]
    for name, value in _safe_env().items():
        flags.extend(["--setenv", name, value])
    flags += ["--"] + command
    return _bounded(flags, cwd=project_dir, timeout=timeout)


def resource_preflight() -> dict:
    """Read-only memory gate (Linux), not a substitute for cgroup resource caps."""
    result = {"level": "UNKNOWN", "available_mib": None,
              "swap_free_mib": None, "cpu_celsius": None, "heavy_allowed": False}
    try:
        values = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            if ":" in line:
                name, text = line.split(":", 1)
                if name in ("MemAvailable", "SwapFree"):
                    values[name] = int(text.split()[0]) / 1024
        avail = values.get("MemAvailable")
        swap = values.get("SwapFree")
        if avail is None or swap is None:
            return result
        result["available_mib"] = round(avail, 1)
        result["swap_free_mib"] = round(swap, 1)
        for zone in Path("/sys/class/thermal").glob("thermal_zone*"):
            if (zone / "type").read_text().strip() == "x86_pkg_temp":
                result["cpu_celsius"] = round(int((zone / "temp").read_text()) / 1000, 1)
                break
        temp = result["cpu_celsius"]
        blocked = avail < 2048 or (swap < 256 and avail < 3072)
        if temp is not None and temp >= 85:
            blocked = True
        result["level"] = "RED" if blocked else "GREEN"
        result["heavy_allowed"] = not blocked
    except (OSError, ValueError):
        pass
    return result


def register_tools(mcp, workspace: Path) -> None:
    """Register explicit MCP tools; workspace is the sole writable root."""
    root = Path(workspace).resolve()

    @mcp.tool()
    def resource_status() -> dict:
        """Read-only memory, zram and CPU temperature preflight on the host."""
        start = time.monotonic()
        status = resource_preflight()
        _audit("resource_status", "host", "ok" if status["level"] != "UNKNOWN" else "unknown", start)
        return status

    @mcp.tool()
    def project_create(name: str) -> dict:
        """Create a dedicated, writable project inside the ARGOS MCP workspace.

        No access to host project directories or arbitrary absolute paths.
        """
        start = time.monotonic()
        try:
            base = _projects_dir(root)
            if len(list(base.iterdir())) >= PROJECT_LIMIT:
                raise ValueError("Project limit reached")
            project = _project(root, name, must_exist=False)
            project.mkdir(mode=0o700)
            (project / "tests").mkdir(mode=0o700)
            (project / "tests" / "__init__.py").write_text("")
            (project / "README.md").write_text(f"# {name}\n\nARGOS MCP isolated project.\n")
            (project / "tests" / "test_smoke.py").write_text(
                "import unittest\n\n"
                "class SmokeTest(unittest.TestCase):\n"
                "    def test_basic_math(self):\n"
                "        self.assertEqual(2 + 2, 4)\n"
            )
            answer = {"ok": True, "project": name, "path": f"projects/{name}"}
            _audit("project_create", name, "ok", start)
            return answer
        except Exception:
            _audit("project_create", name, "denied", start)
            raise

    @mcp.tool()
    def project_list() -> list[dict]:
        """List ARGOS MCP isolated projects only, not other home directories."""
        start = time.monotonic()
        try:
            projects = [p.name for p in _projects_dir(root).iterdir()
                        if p.is_dir() and not p.is_symlink() and PROJECT_PATTERN.fullmatch(p.name)]
            _audit("project_list", ".", "ok", start)
            return [{"project": n} for n in sorted(projects)[:PROJECT_LIMIT]]
        except Exception:
            _audit("project_list", ".", "denied", start)
            raise

    @mcp.tool()
    def git_project(name: str, action: str = "status", relative_path: str = "", message: str = "") -> dict:
        """Git operations in one isolated project only.

        Actions: init, status, diff, diff_check, add, commit, log.
        'add' accepts one existing project-relative file. 'commit' needs a
        short message. No push/pull/network/remotes/host repo mutations.
        """
        start = time.monotonic()
        try:
            p = _project(root, name)
            allowed = {"init", "status", "diff", "diff_check", "add", "commit", "log"}
            if action not in allowed:
                raise ValueError("Unsupported Git operation")
            if relative_path and action != "add":
                raise ValueError("File argument supported only for add")
            if message and action != "commit":
                raise ValueError("Message supported only for commit")
            if action != "init" and not (p / ".git").is_dir():
                raise ValueError("Project is not initialized as a Git repository")
            common = [GIT, "-c", "core.hooksPath=/dev/null",
                      "-c", "core.fsmonitor=false",
                      "-c", "diff.external=",
                      "-c", "commit.gpgSign=false"]
            if action == "init":
                if (p / ".git").exists():
                    raise ValueError("Already initialized")
                args = ["init", "-q", "--initial-branch=main"]
            elif action == "status":
                args = ["status", "--short", "--untracked-files=normal"]
            elif action == "diff":
                args = ["diff", "--no-ext-diff", "--no-textconv", "--stat"]
            elif action == "diff_check":
                args = ["diff", "--check", "--no-ext-diff", "--no-textconv"]
            elif action == "add":
                file_path = _project_file(p, relative_path)
                args = ["add", "--", file_path]
            elif action == "commit":
                if not isinstance(message, str) or not (3 <= len(message) <= 100):
                    raise ValueError("Commit message length must be 3-100")
                if any(ord(c) < 32 for c in message):
                    raise ValueError("Commit message contains control characters")
                common += ["-c", "user.name=ARGOS MCP",
                           "-c", "user.email=argos-mcp@localhost"]
                args = ["commit", "-m", message, "--no-verify"]
            else:
                args = ["log", "-5", "--pretty=format:%h %s"]
            result = _bwrap(p, common + args, writable=action in {"init", "add", "commit"})
            result.update({"action": action, "project": name})
            _audit("git_" + action, name, "ok" if result["ok"] else "fail", start)
            return result
        except Exception:
            _audit("git_" + str(action)[:20], name, "denied", start)
            raise

    @mcp.tool()
    def python_project_test(name: str) -> dict:
        """Run unittest discovery INSIDE a no-network, read-only bubblewrap sandbox.

        Tests must be under projects/<name>/tests/test_*.py. Limit: 15 sec,
        768 MiB address space, CPU quota, 7 KiB output. No host credentials.
        """
        start = time.monotonic()
        try:
            project = _project(root, name)
            tests = project / "tests"
            if tests.is_symlink() or not tests.is_dir():
                raise ValueError("Project tests directory absent")
            files = list(tests.glob("test_*.py"))
            if not files or len(files) > 50:
                raise ValueError("Expected 1-50 unittest test_*.py files")
            for file in files:
                if file.is_symlink() or file.stat().st_size > 65536:
                    raise ValueError("Unsafe/oversized test")
            budget = resource_preflight()
            if not budget["heavy_allowed"]:
                _audit("python_project_test", name, "deferred_resource_pressure", start)
                return {"ok": False, "deferred": True,
                        "exit_code": 75, "stderr": "Resource Guardian deferred execution",
                        "resource_status": budget, "project": name}
            cmd = [PYTHON, "-I", "-B", "-m", "unittest", "discover",
                   "-s", "tests", "-t", ".", "-p", "test_*.py", "-v"]
            result = _bwrap(project, cmd, writable=False, timeout=15)
            result["project"] = name
            _audit("python_project_test", name, "ok" if result["ok"] else "fail", start)
            return result
        except Exception:
            _audit("python_project_test", name, "denied", start)
            raise

    @mcp.tool()
    def service_health(unit: str) -> dict:
        """Read-only systemd state for a small explicit ARGOS service allowlist.

        Does not start, stop, restart or enable services.
        """
        start = time.monotonic()
        try:
            if unit not in SERVICE_ALLOWLIST:
                raise ValueError("Service not allowlisted")
            cmd = ["/usr/bin/systemctl", "show", "--no-pager",
                   "-p", "Id", "-p", "LoadState", "-p", "ActiveState",
                   "-p", "SubState", "-p", "UnitFileState", "--", unit]
            result = _bounded(cmd, cwd=root, timeout=5)
            result["unit"] = unit
            _audit("service_health", unit, "ok" if result["ok"] else "fail", start)
            return result
        except Exception:
            _audit("service_health", str(unit), "denied", start)
            raise

    @mcp.tool()
    def service_logs(unit: str, lines: int = 10) -> dict:
        """Read a bounded number of journal lines for an allowlisted ARGOS service.

        Never exposes the full journal, and only returns what the unprivileged
        service account can access. Do not use for secrets.
        """
        start = time.monotonic()
        try:
            if unit not in SERVICE_ALLOWLIST:
                raise ValueError("Service not allowlisted")
            if not isinstance(lines, int) or not 1 <= lines <= 20:
                raise ValueError("lines must be 1-20")
            result = _bounded(["/usr/bin/journalctl", "--no-pager",
                               "--quiet", "--output=cat", "-n", str(lines),
                               "-u", unit], cwd=root, timeout=5)
            result["unit"] = unit
            _audit("service_logs", unit, "ok" if result["ok"] else "fail", start)
            return result
        except Exception:
            _audit("service_logs", str(unit), "denied", start)
            raise
