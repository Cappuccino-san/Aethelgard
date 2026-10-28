"""Linux and WSL2 systemd user service unit generator and manager (Phase 4).

Generates, installs, and manages `~/.config/systemd/user/aethelgard.service`
for persistent zero-friction passive capture.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

DEFAULT_SYSTEMD_USER_DIR = Path.home() / ".config" / "systemd" / "user"
SYSTEMD_SERVICE_NAME = "aethelgard.service"

SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=Project Aethelgard Passive Cognitive Daemon
Documentation=https://github.com/Cappuccino-san/Aethelgard
After=network.target

[Service]
Type=simple
ExecStart={exec_cmd}
Restart=on-failure
RestartSec=5s
Environment=PYTHONUNBUFFERED=1
Environment=AETHELGARD_DATA_DIR=%h/.local/share/aethelgard
WorkingDirectory=%h

[Install]
WantedBy=default.target
"""


def get_systemd_unit_content(
    exec_cmd: Optional[str] = None,
    python_path: Optional[str] = None,
    watch_dir: Optional[str] = None,
) -> str:
    """Generate the systemd user service unit content."""
    if exec_cmd is None:
        py_exe = python_path or sys.executable or "python3"
        args = [py_exe, "-m", "aethelgard.daemon", "start"]
        if watch_dir:
            args.extend(["--watch", watch_dir])
        exec_cmd = " ".join(f'"{a}"' if " " in a else a for a in args)

    return SYSTEMD_UNIT_TEMPLATE.format(exec_cmd=exec_cmd)


def install_systemd_unit(
    target_path: Optional[Path | str] = None,
    exec_cmd: Optional[str] = None,
    watch_dir: Optional[str] = None,
    enable: bool = False,
) -> Path:
    """Install the systemd user service unit file.

    Parameters:
        target_path: Destination path for the service unit (defaults to ~/.config/systemd/user/aethelgard.service).
        exec_cmd: Explicit ExecStart command.
        watch_dir: Directory to passively monitor.
        enable: If True and on Linux/WSL2, runs `systemctl --user daemon-reload` and `systemctl --user enable`.
    """
    if target_path:
        dest = Path(target_path)
    else:
        dest = DEFAULT_SYSTEMD_USER_DIR / SYSTEMD_SERVICE_NAME

    dest.parent.mkdir(parents=True, exist_ok=True)
    content = get_systemd_unit_content(exec_cmd=exec_cmd, watch_dir=watch_dir)
    dest.write_text(content, encoding="utf-8")

    if enable:
        try:
            subprocess.run(
                ["systemctl", "--user", "daemon-reload"],
                capture_output=True,
                check=False,
                timeout=5.0,
            )
            subprocess.run(
                ["systemctl", "--user", "enable", SYSTEMD_SERVICE_NAME],
                capture_output=True,
                check=False,
                timeout=5.0,
            )
        except Exception:
            pass

    return dest


def uninstall_systemd_unit(
    target_path: Optional[Path | str] = None, disable: bool = False
) -> bool:
    """Remove the systemd user service unit file."""
    if target_path:
        dest = Path(target_path)
    else:
        dest = DEFAULT_SYSTEMD_USER_DIR / SYSTEMD_SERVICE_NAME

    if disable:
        try:
            subprocess.run(
                ["systemctl", "--user", "disable", "--now", SYSTEMD_SERVICE_NAME],
                capture_output=True,
                check=False,
                timeout=5.0,
            )
        except Exception:
            pass

    if dest.exists():
        dest.unlink()
        return True
    return False
