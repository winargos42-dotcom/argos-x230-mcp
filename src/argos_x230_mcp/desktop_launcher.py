"""Add a local Linux desktop launcher for the Cloudflare Tunnel wizard.

Only creates files owned by the invoking user; no elevation or service changes.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


def desktop_contents(python: Path) -> str:
    path = str(python)
    if not python.is_absolute() or any(ch in path for ch in ("\n", "\r", '"', "%")):
        raise ValueError("Invalid Python interpreter path")
    # Freedesktop desktop-entry Exec syntax: quote args with spaces.
    quoted = '"' + path.replace("\\", "\\\\") + '"'
    return (
        "[Desktop Entry]\n"
        "Version=1.0\nType=Application\n"
        "Name=ARGOS — Создать Cloudflare Tunnel\n"
        "Comment=Open a local browser wizard for your own Cloudflare tunnel\n"
        f"Exec={quoted} -m argos_x230_mcp.tunnel_wizard\n"
        "Icon=network-server\n"
        "Terminal=true\nCategories=Network;\n"
    )


def install_desktop(home: Path, python: Path) -> list[str]:
    home = Path(home)
    if not home.is_absolute():
        raise ValueError("Home path must be absolute")
    entry = desktop_contents(Path(python))
    applications = home / ".local" / "share" / "applications"
    applications.mkdir(mode=0o700, parents=True, exist_ok=True)
    targets = [applications / "argos-x230-tunnel-wizard.desktop"]
    desktop = home / "Desktop"
    if desktop.is_dir():
        targets.append(desktop / "ARGOS-Создать-туннель.desktop")
    # Reject any existing unrelated launcher instead of silently overwriting.
    for target in targets:
        if target.is_symlink():
            raise ValueError("Refusing symlink launcher")
        if target.exists() and target.read_text(encoding="utf8") != entry:
            raise FileExistsError("Desktop launcher already exists with other settings: " + target.name)
    for target in targets:
        if not target.exists():
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, "w", encoding="utf8") as out:
                out.write(entry)
        target.chmod(0o700)
    return [str(path) for path in targets]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install ARGOS Cloudflare wizard desktop shortcut")
    args = parser.parse_args(argv)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        parser.error("Run as an ordinary Linux user, not root")
    for file in install_desktop(Path.home(), Path(sys.executable)):
        print("Launcher saved:", file)
    print("No tunnel was created or started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
