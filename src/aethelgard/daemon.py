"""Subsystem Layer: Passive Daemon Process (Phase 4).

Coordinates the watchdog filesystem listener, handles OS lifecycle signals,
and manages background cognitive capture for Project Aethelgard.
"""

import argparse
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

from .listener import PassiveFSListener
from .systemd import get_systemd_unit_content, install_systemd_unit


def run_daemon(
    watch_paths: list[Path | str] | Path | str,
    db_path: Optional[Path | str] = None,
    debounce_seconds: float = 0.5,
) -> None:
    """Run the passive capture daemon until interrupted by SIGINT or SIGTERM."""
    listener = PassiveFSListener(
        watch_paths=watch_paths,
        db_path=db_path,
        debounce_seconds=debounce_seconds,
    )

    stop_requested = False

    def handle_signal(sig: int, frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    try:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
    except (ValueError, AttributeError):
        pass

    listener.start()
    try:
        while not stop_requested:
            time.sleep(0.5)
    finally:
        listener.stop()


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint for daemon management."""
    parser = argparse.ArgumentParser(
        prog="aethelgard-daemon",
        description="Project Aethelgard Passive Background Daemon",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # start
    start_p = subparsers.add_parser("start", help="Start the passive capture daemon")
    start_p.add_argument(
        "--watch",
        action="append",
        dest="watch_paths",
        default=[],
        help="Directories to monitor (defaults to cwd)",
    )
    start_p.add_argument("--db", type=Path, default=None, help="Path to ledger.db")
    start_p.add_argument(
        "--debounce", type=float, default=0.5, help="Debounce duration in seconds"
    )

    # service
    svc_p = subparsers.add_parser("service", help="Manage systemd user service")
    svc_p.add_argument(
        "--install", action="store_true", help="Install systemd user service"
    )
    svc_p.add_argument(
        "--print", action="store_true", help="Print systemd user service unit"
    )
    svc_p.add_argument(
        "--watch-dir", type=str, default=None, help="Directory to configure in service"
    )

    args = parser.parse_args(argv)

    if args.command == "start":
        watch_targets = args.watch_paths or [Path.cwd()]
        run_daemon(
            watch_paths=watch_targets,
            db_path=args.db,
            debounce_seconds=args.debounce,
        )
        return 0

    if args.command == "service":
        if args.print:
            print(get_systemd_unit_content(watch_dir=args.watch_dir))
            return 0
        if args.install:
            path = install_systemd_unit(watch_dir=args.watch_dir)
            print(f"Installed systemd user service to: {path}")
            return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
