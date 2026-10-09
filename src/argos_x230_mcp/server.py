"""ARGOS Remote MCP - least-privilege local workstation bridge.

Transport: MCP Streamable HTTP, bound to 127.0.0.1.
All HTTP requests require a bearer token. This is NOT an OAuth server:
do not publish through Cloudflare before an OAuth/Access gateway is configured.
"""
import os
import secrets
import socket
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import jwt
from jwt import PyJWKClient
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from .safe_commands import run_safe_command as _run_safe_command
from .expanded_tools import register_tools

ROOT = Path(os.environ.get("ARGOS_MCP_WORKSPACE", str(Path.home() / "argos-mcp-workspace"))).resolve()
HOST = "127.0.0.1"
PORT = int(os.environ.get("ARGOS_MCP_PORT", "8765"))
TOKEN_FILE = Path(os.environ.get("ARGOS_MCP_TOKEN_FILE", str(Path.home() / ".config" / "argos-x230-mcp" / "token")))
PUBLIC_HOST = os.environ.get("ARGOS_MCP_PUBLIC_HOSTNAME", "").strip().lower()
if PUBLIC_HOST:
    import re
    if (len(PUBLIC_HOST) > 253 or not re.fullmatch(r"[a-z0-9.-]+", PUBLIC_HOST)
            or ".." in PUBLIC_HOST or PUBLIC_HOST.startswith(".") or PUBLIC_HOST.endswith(".")):
        raise ValueError("ARGOS_MCP_PUBLIC_HOSTNAME must be a valid DNS hostname")
PUBLIC_HOSTS = [PUBLIC_HOST, PUBLIC_HOST + ":*"] if PUBLIC_HOST else []
PUBLIC_ORIGINS = ["https://" + PUBLIC_HOST] if PUBLIC_HOST else []
# Cloudflare Access JWT verification requires all three trusted values.
CF_TEAM = os.environ.get("ARGOS_CF_ACCESS_TEAM", "").strip().lower()
CF_AUD = os.environ.get("ARGOS_CF_ACCESS_AUD", "").strip()
CF_EMAIL = os.environ.get("ARGOS_CF_ACCESS_EMAIL", "").strip().casefold()
if CF_TEAM and not CF_TEAM.endswith(".cloudflareaccess.com"):
    raise ValueError("ARGOS_CF_ACCESS_TEAM must be a Cloudflare Access team domain")
CF_JWKS = (PyJWKClient(f"https://{CF_TEAM}/cdn-cgi/access/certs",
                     cache_jwk_set=True, lifespan=300, timeout=5)
           if CF_TEAM and CF_AUD and CF_EMAIL else None)
MAX_TEXT_BYTES = 262144

mcp = FastMCP(
    "ARGOS Remote MCP",
    host=HOST,
    port=PORT,
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            *PUBLIC_HOSTS,
            "127.0.0.1", "127.0.0.1:*",
            "localhost", "localhost:*",
            "[::1]", "[::1]:*",
        ],
        allowed_origins=[
            *PUBLIC_ORIGINS,
            "https://chatgpt.com",
            "https://chat.openai.com",
            "http://127.0.0.1:*",
            "http://localhost:*",
        ],
    ),
)

def scoped(relative_path: str) -> Path:
    """Paths must stay within workspace, including after symlink resolution."""
    given = Path(relative_path)
    if given.is_absolute():
        raise ValueError("Absolute paths are forbidden")
    result = (ROOT / given).resolve()
    if not result.is_relative_to(ROOT):
        raise ValueError("Path escapes ARGOS workspace")
    return result

@mcp.tool()
def ping() -> dict:
    """Confirm ARGOS MCP is running, with host and current UTC time."""
    return {"ok": True, "node": socket.gethostname(), "service": "argos-remote-mcp",
            "utc": datetime.now(timezone.utc).isoformat()}

@mcp.tool()
def workstation_status() -> dict:
    """Get bounded local memory and uptime telemetry without arbitrary commands."""
    def meminfo():
        mem = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith(("MemTotal:", "MemAvailable:")):
                key, data = line.split(":", 1)
                mem[key] = int(data.strip().split()[0]) * 1024
        return mem
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    return {"host": socket.gethostname(), "uptime_seconds": round(uptime),
            "memory": meminfo(), "workspace": str(ROOT)}

@mcp.tool()
def list_files(relative_path: str = ".", limit: int = 100) -> list[dict]:
    """List files only inside the dedicated ARGOS workspace."""
    path = scoped(relative_path)
    if not path.is_dir():
        raise ValueError("Not a workspace directory")
    if not 1 <= limit <= 200:
        raise ValueError("limit must be 1..200")
    entries = sorted(path.iterdir(), key=lambda p: p.name)
    return [{"name": p.name, "type": "directory" if p.is_dir() else "file"}
            for p in entries[:limit]]

@mcp.tool()
def read_text(relative_path: str) -> str:
    """Read a UTF-8 text file in the dedicated workspace, max 256 KiB."""
    path = scoped(relative_path)
    if not path.is_file():
        raise ValueError("Not a workspace file")
    if path.stat().st_size > MAX_TEXT_BYTES:
        raise ValueError("File exceeds 256 KiB")
    return path.read_text(encoding="utf-8")

@mcp.tool()
def write_text(relative_path: str, content: str) -> dict:
    """Atomically create or replace a UTF-8 file inside the workspace."""
    path = scoped(relative_path)
    if path == ROOT or not path.parent.is_dir():
        raise ValueError("Parent workspace directory must exist")
    payload = content.encode("utf-8")
    if len(payload) > MAX_TEXT_BYTES:
        raise ValueError("File exceeds 256 KiB")
    if path.exists() and not path.is_file():
        raise ValueError("Target is not a file")
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".argos-mcp-",
                                         delete=False) as f:
            tmp = Path(f.name)
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp and tmp.exists():
            tmp.unlink()
    return {"ok": True, "path": str(path.relative_to(ROOT)), "bytes": len(payload)}

@mcp.tool()
def safe_patch(relative_path: str, old_text: str, new_text: str) -> dict:
    """Replace only a unique exact match; reject ambiguous edits."""
    path = scoped(relative_path)
    if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
        raise ValueError("Missing file or file too large")
    if not old_text:
        raise ValueError("old_text cannot be empty")
    original = path.read_text(encoding="utf-8")
    count = original.count(old_text)
    if count != 1:
        raise ValueError(f"Expected exactly one match; got {count}")
    updated = original.replace(old_text, new_text, 1)
    if len(updated.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError("Result too large")
    return write_text(relative_path, updated)

@mcp.tool()
def git_status() -> dict:
    """Run ONLY 'git status --short' in the workspace; never use a shell."""
    try:
        result = subprocess.run(
            ["git", "status", "--short"], cwd=ROOT, capture_output=True,
            text=True, timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": str(ROOT)},
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    return {"ok": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": result.stdout[:8000], "stderr": result.stderr[:1000]}


@mcp.tool()
def run_safe_command(
    action: str, relative_path: str = ""
) -> dict:
    """Read-only bounded command on X230. Never an arbitrary shell.

    Actions: identity, uptime, memory, disk, git_status, git_diff_check,
    python_syntax. Only python_syntax accepts a relative workspace .py path.
    No root elevation, scripts, shell metacharacters, outside paths, or
    network calls. All invocations, including denials, are journaled.
    """
    return _run_safe_command(action, relative_path, workspace=ROOT)

register_tools(mcp, ROOT)

class BearerGate:
    """Fail-closed auth for all HTTP requests; ASGI lifespan passes through."""
    def __init__(self, downstream):
        self.downstream = downstream

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.downstream(scope, receive, send)
        try:
            expected = TOKEN_FILE.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            expected = ""
        headers = dict(scope.get("headers", []))
        provided = headers.get(b"authorization", b"").decode("ascii", "ignore")
        valid = bool(expected) and secrets.compare_digest(provided, "Bearer " + expected)
        # Accept Cloudflare Access ONLY with verified RS256 signature, issuer,
        # audience and the explicitly allowlisted account email.
        if not valid and CF_JWKS is not None:
            assertion = headers.get(b"cf-access-jwt-assertion", b"").decode("ascii", "ignore")
            if assertion and len(assertion) <= 8192:
                try:
                    key = CF_JWKS.get_signing_key_from_jwt(assertion).key
                    claims = jwt.decode(
                        assertion, key, algorithms=["RS256"],
                        audience=CF_AUD, issuer=f"https://{CF_TEAM}",
                        options={"require": ["exp", "iat", "aud", "iss"]},
                    )
                    valid = secrets.compare_digest(
                        str(claims.get("email", "")).casefold(), CF_EMAIL
                    )
                except (jwt.PyJWTError, ValueError, TypeError, OSError):
                    valid = False
        if not valid:
            body = b'{"error":"unauthorized"}'
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"www-authenticate", b"Bearer")]})
            await send({"type": "http.response.body", "body": body})
            return
        return await self.downstream(scope, receive, send)

app = BearerGate(mcp.streamable_http_app())
