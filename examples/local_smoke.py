"""Read-only smoke tests of the local running MCP endpoint plus a canary patch."""
import json
import os
from pathlib import Path
import httpx

url = "http://127.0.0.1:8765/mcp"
token = Path(os.getenv("ARGOS_MCP_TOKEN_FILE",
                       str(Path.home() / ".config" / "argos-x230-mcp" / "token"))).read_text().strip()
headers = {"Authorization": f"Bearer {token}",
           "Accept": "application/json, text/event-stream"}
def rpc(method, params=None, authorize=True):
    request_headers = dict(headers)
    if not authorize:
        request_headers.pop("Authorization")
    response = httpx.post(url, headers=request_headers,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        timeout=8)
    return response.status_code, response.json()
def call(name, args=None):
    status, result = rpc("tools/call", {"name": name, "arguments": args or {}})
    assert status == 200 and not result["result"].get("isError"), result
    return result["result"]

status, result = rpc("tools/list", authorize=False)
assert status == 401
print("PASS: missing authorization rejected")

status, result = rpc("initialize", {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "argos-smoke", "version": "1"}})
assert status == 200 and "result" in result
print("PASS: initialize")

status, result = rpc("tools/list")
names = {t["name"] for t in result["result"]["tools"]}
assert {"ping", "list_files", "read_text", "write_text", "safe_patch"}.issubset(names)
print("PASS: tools/list")

assert call("ping")["content"]
print("PASS: ping")

call("write_text", {"relative_path": "mcp-smoke.txt", "content": "before"})
call("safe_patch", {"relative_path": "mcp-smoke.txt",
                    "old_text": "before", "new_text": "after"})
result = call("read_text", {"relative_path": "mcp-smoke.txt"})
assert any(t.get("text") == "after" for t in result["content"]), result
print("PASS: write -> unique patch -> read")

status, error = rpc("tools/call", {"name": "safe_patch",
    "arguments": {"relative_path": "mcp-smoke.txt",
                  "old_text": "missing", "new_text": "bad"}})
assert status == 200 and error["result"].get("isError")
print("PASS: ambiguous/missing match rejected")
print("ARGOS_REMOTE_MCP_SMOKE_PASS")
