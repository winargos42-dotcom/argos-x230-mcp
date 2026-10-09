"""Browser-assisted Cloudflare Tunnel provisioning, without privileged access.

Run locally: python -m argos_x230_mcp.tunnel_wizard
A real browser signs in via cloudflared tunnel login; after explicit approvals
the wizard creates a NEW tunnel, DNS route and a private config. It never
modifies /etc/cloudflared, reads keys into ChatGPT or restarts existing tunnels.

DO NOT expose the wizard on a public interface. Always 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import fcntl
import signal
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import HTTPRedirectHandler
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPHandler, HTTPSHandler
import uuid
import webbrowser

NAME = re.compile(r"^[a-z][a-z0-9-]{2,30}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")
LOGIN_PAGE = "https://dash.cloudflare.com/argotunnel"
ACCESS_PAGE = "https://one.dash.cloudflare.com/"
CONFIG_DIR = Path.home() / ".config" / "argos-x230-mcp"
CREDENTIAL_DIR = Path.home() / ".cloudflared"
WIZARD_TITLE = "ARGOS X230 · Cloudflare Tunnel"


def validated_hostname(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Hostname must be a string")
    name = value.strip().lower()
    if len(name) > 253 or name.count(".") < 2:
        raise ValueError("Use a real DNS hostname such as mcp.example.com")
    labels = name.split(".")
    if not (3 <= len(labels) <= 12) or any(not LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid DNS hostname")
    if not labels[-1].isalpha() or len(labels[-1]) < 2:
        raise ValueError("Invalid DNS suffix")
    return name


def validated_tunnel_name(value: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError("Tunnel name must be 3-31 chars: a-z, digits and -")
    return value


def validated_id(value: str) -> str:
    if not isinstance(value, str) or not UUID.fullmatch(value.lower()):
        raise ValueError("Invalid tunnel UUID")
    return value.lower()


def save_private(path: Path, payload: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing symlink destination")
    if path.exists():
        raise FileExistsError("File already exists; no overwrite: " + path.name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def acquire_single_instance(base: Path) -> int | None:
    """Linux advisory lock, one wizard instance per user."""
    base = Path(base)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(base / ".wizard.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        os.close(fd)
        return None
    return fd


def redacted_result(output: str) -> str:
    # Do not display the output from cloudflared, because it may include
    # credential paths or ephemeral authorization URLs/tokens.
    return "Cloudflare command completed" if output else "Cloudflare command completed"


def cloudflared_command(argv: list[str], timeout: int = 25) -> str:
    """Fixed CLI argument prefix, no shell/secret prints and bounded stdout."""
    if argv[:2] != ["cloudflared", "tunnel"]:
        raise ValueError("Unsupported cloudflared operation")
    binary = "/usr/bin/cloudflared"
    with subprocess.Popen(
        [binary] + argv[1:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, text=False, start_new_session=True,
        env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"},
    ) as child:
        try:
            out = child.communicate(timeout=timeout)[0] or b""
        except subprocess.TimeoutExpired:
            try:
                import signal
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=5)
            raise TimeoutError("Cloudflare command timed out")
        if child.returncode != 0:
            raise RuntimeError("cloudflared returned a failure; check login and DNS permissions")
        return out[:16384].decode("utf-8", "replace")


class ProvisioningSession:
    def __init__(self, base: Path = CONFIG_DIR, credentials: Path = CREDENTIAL_DIR):
        self.base = Path(base)
        self.credentials = Path(credentials)
        self.session_token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.tunnel_id: str | None = None
        self.name: str | None = None
        self.hostname: str | None = None
        self.config_path: Path | None = None
        self.dns_routed = False
        self.access_verified = False
        self.login_proc: subprocess.Popen | None = None
        self.login_log_path: Path | None = None

    def close(self) -> None:
        """Clean up temporary login process without stopping any tunnel."""
        with self.lock:
            if self.login_proc is not None and self.login_proc.poll() is None:
                try:
                    os.killpg(self.login_proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if self.login_log_path:
                self.login_log_path.unlink(missing_ok=True)

    def status(self) -> dict:
        return {
            "certificate_ready": (self.credentials / "cert.pem").is_file(),
            "login_started": self.login_proc is not None,
            "login_running": self.login_proc is not None and self.login_proc.poll() is None,
            "tunnel_created": self.tunnel_id is not None,
            "tunnel_id": self.tunnel_id,
            "hostname": self.hostname,
            "dns_routed": self.dns_routed,
            "access_verified": self.access_verified,
            "config_ready": self.config_path is not None,
            "next_step": (
                "Authorize Cloudflare in your browser" if not (self.credentials / "cert.pem").is_file()
                else "Create a new tunnel, configure Access, then route DNS"
            ),
        }

    def begin_login(self) -> dict:
        with self.lock:
            if (self.credentials / "cert.pem").exists():
                return {"ok": True, "message": "Cloudflare certificate already available"}
            if self.login_proc is not None and self.login_proc.poll() is None:
                return {"ok": True, "message": "Cloudflare login is waiting for browser authorization", "login_url": LOGIN_PAGE}
            self.credentials.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Capture the one-time authorization URL privately, never in journald.
            self.base.mkdir(mode=0o700, parents=True, exist_ok=True)
            log = self.base / ".cloudflare-login-once.log"
            if log.exists():
                log.unlink()
            fd = os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                self.login_proc = subprocess.Popen(
                    ["/usr/bin/cloudflared", "tunnel", "login"],
                    cwd=str(self.credentials),
                    stdin=subprocess.DEVNULL, stdout=fd, stderr=fd,
                    env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "BROWSER": "true"},
                    start_new_session=True,
                )
            finally:
                os.close(fd)
            self.login_log_path = log
            login_url = None
            for _ in range(12):
                time.sleep(.12)
                raw = log.read_text(errors="replace")[-8192:]
                links = re.findall(r"https://dash\.cloudflare\.com/argotunnel[^\s]*", raw)
                if links:
                    login_url = links[0].rstrip(").,")
                    break
                if self.login_proc.poll() is not None:
                    break
            return {
                "ok": True,
                "message": "Authorize Cloudflare in the browser, then click Refresh.",
                "login_url": login_url or LOGIN_PAGE,
            }

    def create(self, name: str) -> dict:
        with self.lock:
            name = validated_tunnel_name(name)
            if self.tunnel_id:
                raise ValueError("Tunnel already created in this session")
            if not (self.credentials / "cert.pem").is_file():
                raise ValueError("Browser login required first")
            result = cloudflared_command(["cloudflared", "tunnel", "create", name])
            ids = [m.lower() for m in re.findall(
                r"\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-8][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}\b",
                result)]
            if len(set(ids)) != 1:
                raise RuntimeError("Tunnel created but UUID was not unambiguously parsed; inspect cloudflared tunnel list manually")
            created = validated_id(ids[0])
            credential = self.credentials / (created + ".json")
            if not credential.is_file():
                raise RuntimeError("Credentials not found; aborting further provisioning")
            self.name = name
            self.tunnel_id = created
            return {"ok": True, "message": "New named tunnel created", "tunnel_id": created}

    def prepare(self, hostname: str) -> dict:
        with self.lock:
            name = validated_hostname(hostname)
            if not self.tunnel_id or not self.name:
                raise ValueError("Create the tunnel before generating config")
            if self.config_path:
                raise ValueError("Configuration already prepared for this session")
            credential = self.credentials / (self.tunnel_id + ".json")
            if not credential.is_file() or credential.is_symlink():
                raise ValueError("Tunnel credentials unavailable")
            config = self.base / "tunnels" / (self.name + ".yml")
            # Local-only origin, no wildcard bind, no other public services.
            payload = (
                f"tunnel: {self.tunnel_id}\n"
                f"credentials-file: {credential}\n"
                "ingress:\n"
                f"  - hostname: {name}\n"
                "    service: http://127.0.0.1:8765\n"
                "  - service: http_status:404\n"
            )
            save_private(config, payload)
            self.hostname = name
            self.config_path = config
            return {"ok": True, "message": "Private config saved. No DNS or service changes yet.",
                    "config_file": str(config)}

    def route(self, approved: bool) -> dict:
        with self.lock:
            if not approved:
                raise ValueError("Confirm Cloudflare Access policy has been created BEFORE DNS publication")
            if not self.tunnel_id or not self.hostname or not self.config_path:
                raise ValueError("Create the tunnel and config first")
            if self.dns_routed:
                raise ValueError("DNS was already routed in this session")
            cloudflared_command(["cloudflared", "tunnel", "route", "dns",
                                self.tunnel_id, self.hostname])
            self.dns_routed = True
            return {"ok": True, "message": "DNS CNAME created without overwrite. Origin is NOT started.",
                    "hostname": self.hostname}

    def enable_service(self, approved: bool) -> dict:
        """Start ONLY the newly created tunnel after live Access challenge."""
        with self.lock:
            if not approved or not self.access_verified:
                raise ValueError("Explicit approval and verified Cloudflare Access required")
            if not self.check_access().get("ok"):
                raise ValueError("Cloudflare Access login challenge no longer verified")
            if not self.tunnel_id or not self.config_path or not self.name:
                raise ValueError("Missing tunnel configuration")
            unit_name = "argos-x230-mcp-tunnel-" + self.name + ".service"
            path = Path.home() / ".config" / "systemd" / "user" / unit_name
            body = (
                "[Unit]\nDescription=ARGOS separate Cloudflare MCP tunnel\n"
                "After=network-online.target\nWants=network-online.target\n\n"
                "[Service]\nType=simple\n"
                "ExecStart=/usr/bin/cloudflared --no-autoupdate --config "
                f"{self.config_path} tunnel run {self.tunnel_id}\n"
                "Restart=on-failure\nRestartSec=10\n"
                "NoNewPrivileges=yes\nMemoryMax=110M\nCPUQuota=30%\n\n"
                "[Install]\nWantedBy=default.target\n"
            )
            save_private(path, body)
            reload = subprocess.run(
                ["/usr/bin/systemctl", "--user", "daemon-reload"],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=False)
            if reload.returncode != 0:
                return {"ok": False, "message": "Unit saved but systemd user daemon unavailable",
                        "unit": unit_name}
            start = subprocess.run(
                ["/usr/bin/systemctl", "--user", "enable", "--now", unit_name],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=12, check=False)
            return {"ok": start.returncode == 0,
                    "message": "New tunnel enabled" if start.returncode == 0 else "Unit saved; could not start automatically",
                    "unit": unit_name}

    def check_access(self) -> dict:
        with self.lock:
            if not self.dns_routed or not self.hostname:
                raise ValueError("Route DNS after creating Cloudflare Access application")
            request = Request(f"https://{self.hostname}/mcp", headers={
                "User-Agent": "ARGOS-X230-MCP-Tunnel-Wizard/1.0",
            })
            opener = build_opener(_NoRedirect())
            try:
                response = opener.open(request, timeout=8)
                status = response.status
                location = response.headers.get("Location", "")
                response.close()
            except Exception as err:
                # HTTPError exposes status+headers for redirects.
                if hasattr(err, "code"):
                    status = err.code
                    location = err.headers.get("Location", "")
                else:
                    self.access_verified = False
                    return {"ok": False, "message": "Access preflight could not reach the hostname"}
            domain = (urlsplit(location).hostname or "").lower()
            # A redirect to Cloudflare Access login confirms an interactive
            # identity gateway is enforcing authentication for this hostname.
            path = urlsplit(location).path
            self.access_verified = status in {302, 303, 307, 308} and (
                domain.endswith(".cloudflareaccess.com")
                or (domain == self.hostname and path.startswith("/cdn-cgi/access/login"))
            )
            if not self.access_verified:
                return {"ok": False, "message": "Access login was not verified; do not start the tunnel",
                        "http_status": status}
            return {"ok": True, "message": "Cloudflare Access login challenge verified. Configure explicit email policies before starting your tunnel."}


class _NoRedirect(HTTPRedirectHandler):
    """Stop urllib from following authentication redirects."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _ui_html(token: str) -> str:
    return """<!doctype html><html lang="ru"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-STYLE_N'; script-src 'nonce-SCRIPT_N'; connect-src 'self'; form-action 'none'; base-uri 'none'">
    <title>ARGOS MCP — настройка Cloudflare Tunnel</title>
    <style nonce="STYLE_N">:root{font-family:system-ui;color-scheme:dark}body{background:#101929;color:#e4f3fc;margin:0;padding:24px}main{max-width:720px;margin:auto}
    h1{color:#93e5ea}section{padding:18px;border:1px solid #395066;background:#1b2b3b;border-radius:12px;margin:16px 0}button,input{font:inherit;padding:10px;border-radius:8px}
    input{background:#121f30;color:white;border:1px solid #52697a;width:90%;margin:8px 0}button{background:#91e3e8;color:#092b34;border:0;font-weight:bold;margin:6px 0}
    button:disabled{opacity:.4}.muted{color:#aebfc9}a{color:#a5ecf0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#102133;padding:14px}
    </style></head><body><main><h1>✳ ARGOS X230 — мастер туннеля</h1>
    <p>Локальный мастер. Никаких токенов в браузер, ChatGPT или репозиторий не передаётся. Выполнение только после нажатия кнопок.</p>
    <section><h2>1. Авторизация Cloudflare</h2>
    <p>Выполните авторизацию в открывшейся вкладке Cloudflare. Доступ к домену подтверждает владелец.</p>
    <button id="login">Открыть вход через Cloudflare</button> <a href="https://dash.cloudflare.com/argotunnel" target="_blank" rel="noopener">Cloudflare Dashboard ↗</a></section>
    <section><h2>2. Новый отдельный туннель</h2>
    <label>Название (без пробелов)<input id="name" value="argos-mcp"></label>
    <button id="create">Создать named tunnel</button>
    <p class="muted">Существующие Home Assistant и другие туннели не изменяются.</p></section>
    <section><h2>3. Hostname и Cloudflare Access</h2>
    <label>Ваш DNS hostname<input id="hostname" placeholder="mcp.example.com"></label>
    <button id="prepare">Подготовить приватный конфиг</button>
    <p>Создайте Cloudflare Access → Applications → Self-hosted на этом hostname. Ограничьте доступ вашей учётной записью и включите аутентификацию.</p>
    <a href="https://one.dash.cloudflare.com/" target="_blank" rel="noopener">Настроить Access в браузере ↗</a>
    <p><label><input type="checkbox" id="approval" style="width:auto"> Я создал ограниченную Access-политику и разрешаю добавление DNS</label></p>
    <button id="route">Создать DNS запись</button>
    <button id="verify">Проверить Access без авторизации</button>
    <p><button id="enable">Запустить новый туннель (после проверки Access)</button></p>
    <p class="muted">Только отдельный туннель systemd --user. Существующий Cloudflare и HA не затрагиваются.</p></section>
    <section><h2>Состояние и инструкции</h2><button id="refresh">Обновить статус</button> <button id="stop">Закрыть мастер</button>
    <pre id="output">Ожидаю команду…</pre></section>
    <p class="muted">Мастер слушает только 127.0.0.1. Для закрытия нажмите «Закрыть мастер» или Ctrl+C в терминале.</p>
    </main><script nonce="SCRIPT_N">
    const csrf="TOKEN_VALUE";
    const out=document.getElementById("output");
    async function post(action,extra={}) {
      out.textContent="Выполняется "+action+"…";
      try{
        const r=await fetch("/action",{method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({csrf,action,...extra})});
        const data=await r.json();out.textContent=JSON.stringify(data,null,2);
        return data;
      }catch(e){out.textContent="Ошибка соединения с локальным мастером";return {ok:false};}
    }
    for(const action of ["login","create","prepare","route","verify","enable","refresh","stop"]){
      document.getElementById(action).onclick=async()=>{
        const popup=action==="login" ? window.open("about:blank","_blank") : null;
        const map={create:{name:document.getElementById("name").value},
          prepare:{hostname:document.getElementById("hostname").value},
          route:{approved:document.getElementById("approval").checked},
          enable:{approved:document.getElementById("approval").checked}};
        const response=await post(action,map[action]||{});
        if(popup) {
          const href=response && response.result && response.result.login_url;
          if(response.ok && href && href.startsWith("https://dash.cloudflare.com/"))
            popup.location.href=href;
          else popup.close();
        }
      }
    }
    post("refresh");
    </script></body></html>""".replace("TOKEN_VALUE", token).replace("STYLE_N", token[:16]).replace("SCRIPT_N", token[16:32])


def make_handler(session: ProvisioningSession, host: str, stop=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.headers.get("Host") != host:
                self.send_error(403)
                return
            if self.path != "/":
                self.send_error(404)
                return
            data = _ui_html(session.session_token).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != "/action" or self.headers.get("Host") != host:
                self.send_error(403)
                return
            origin = self.headers.get("Origin", "")
            if origin != "http://" + host:
                self.send_error(403)
                return
            if self.headers.get("Content-Type", "").split(";",1)[0] != "application/json":
                self.send_error(415)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 1 <= size <= 4096:
                    raise ValueError("Request size out of bounds")
                request = json.loads(self.rfile.read(size))
                if not secrets.compare_digest(str(request.get("csrf", "")), session.session_token):
                    raise ValueError("Bad CSRF token")
                operation = request.get("action")
                if operation == "refresh": answer = session.status()
                elif operation == "login": answer = session.begin_login()
                elif operation == "create": answer = session.create(request.get("name", ""))
                elif operation == "prepare": answer = session.prepare(request.get("hostname", ""))
                elif operation == "route": answer = session.route(request.get("approved") is True)
                elif operation == "verify": answer = session.check_access()
                elif operation == "enable": answer = session.enable_service(request.get("approved") is True)
                elif operation == "stop":
                    if stop is None:
                        raise ValueError("Stop button unavailable")
                    answer = {"ok": True, "message": "Local master is shutting down"}
                else: raise ValueError("Unsupported operation")
                response = {"ok": True, "result": answer}
            except (ValueError, OSError, RuntimeError, TimeoutError) as error:
                response = {"ok": False, "error": str(error)[:250]}
            payload = json.dumps(response, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            if (stop is not None and response.get("ok")
                    and response.get("result", {}).get("message") == "Local master is shutting down"):
                threading.Thread(target=stop, daemon=True).start()
    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local browser wizard for Cloudflare Tunnel + MCP")
    parser.add_argument("--no-browser", action="store_true", help="Display URL without opening a tab")
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        parser.error("Do not run tunnel wizard as root")
    lock_fd = acquire_single_instance(CONFIG_DIR)
    if lock_fd is None:
        print("ARGOS Cloudflare Tunnel Wizard is already running for this user")
        return 75
    session = ProvisioningSession()
    try:
        web = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        web.RequestHandlerClass = make_handler(
            session, f"127.0.0.1:{web.server_port}", stop=web.shutdown
        )
        url = f"http://127.0.0.1:{web.server_port}/"
        print("ARGOS Tunnel Wizard (local-only):", url, flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        try:
            web.serve_forever(poll_interval=.2)
        except KeyboardInterrupt:
            print("\nMaster stopped; existing tunnels unchanged")
        finally:
            web.server_close()
    finally:
        session.close()
        os.close(lock_fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
