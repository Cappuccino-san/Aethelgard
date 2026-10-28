"""Subsystem Layer: Non-blocking Git Post-Commit Ingestion Hook (Phase 4).

Captures git commits into the append-only ledger and synchronizes FTS5,
sqlite-vec, and KùzuDB graph views. Filters out lockfiles, .git internals,
and build artifacts.

Critical Invariant:
  A hook failure must NEVER block a commit. All hook scripts and CLI entrypoints
  strictly guarantee exit code 0 under all error conditions.
"""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from .filters import filter_file_paths, is_ignored_path
from .graph import GraphView
from .ledger import DEFAULT_DATA_DIR, Ledger
from .views import FTS5View, VectorView

DEFAULT_GLOBAL_HOOKS_DIR = (
    Path.home() / ".config" / "git" / "hooks"
    if (Path.home() / ".config").exists()
    else DEFAULT_DATA_DIR / "git-hooks"
)

POST_COMMIT_HOOK_SCRIPT = """#!/bin/sh
# Project Aethelgard Non-Blocking Git Post-Commit Hook
# Invariant: A hook failure must NEVER block a commit.
(
    python3 -m aethelgard.git_hook post-commit "$@" 2>/dev/null || \
    twin hook post-commit "$@" 2>/dev/null || \
    python -m aethelgard.git_hook post-commit "$@" 2>/dev/null || \
    true
) </dev/null >/dev/null 2>&1 &
exit 0
"""


def _run_git_cmd(args: list[str], cwd: Optional[Path | str] = None) -> Optional[str]:
    """Execute a git command safely, suppressing errors."""
    try:
        res = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return None


def capture_git_commit(
    repo_path: Optional[Path | str] = None,
    ledger: Optional[Ledger] = None,
    db_path: Optional[Path | str] = None,
    skip_if_all_filtered: bool = False,
) -> Optional[dict[str, Any]]:
    """Capture the most recent Git commit in `repo_path` into the append-only ledger.

    Filters out lockfiles, .git internals, and build artifacts.
    Guaranteed not to raise unhandled exceptions.
    """
    try:
        cwd = Path(repo_path) if repo_path else Path.cwd()

        # 1. Verify git repository status
        is_git = _run_git_cmd(["rev-parse", "--is-inside-work-tree"], cwd=cwd)
        if is_git != "true":
            return None

        # Verify HEAD exists (handle empty repos)
        head_commit = _run_git_cmd(["rev-parse", "HEAD"], cwd=cwd)
        if not head_commit:
            return None

        # 2. Extract commit metadata
        author = _run_git_cmd(["log", "-1", "--format=%an <%ae>"], cwd=cwd) or "Unknown"
        committer = _run_git_cmd(["log", "-1", "--format=%cn <%ce>"], cwd=cwd) or "Unknown"
        message = _run_git_cmd(["log", "-1", "--format=%B"], cwd=cwd) or ""
        raw_ts = _run_git_cmd(["log", "-1", "--format=%ct"], cwd=cwd)
        ts = int(raw_ts) if raw_ts and raw_ts.isdigit() else None
        branch = _run_git_cmd(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd) or "HEAD"

        # 3. Extract modified files list and apply ignore filters
        raw_files_output = _run_git_cmd(
            ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "HEAD"], cwd=cwd
        )
        raw_files = raw_files_output.splitlines() if raw_files_output else []

        # Filter out lockfiles, .git, and build artifacts
        filtered_files = filter_file_paths(raw_files)

        if skip_if_all_filtered and raw_files and not filtered_files:
            return None

        payload: dict[str, Any] = {
            "commit_hash": head_commit,
            "branch": branch,
            "author": author,
            "committer": committer,
            "message": message.strip(),
            "commit_timestamp": ts,
            "files": filtered_files,
            "total_files_changed": len(raw_files),
            "filtered_files_count": len(raw_files) - len(filtered_files),
            "repo_path": str(cwd.resolve()),
        }

        # 4. Ingest into ledger
        active_ledger = ledger or Ledger(db_path=db_path)
        event = active_ledger.append_event("git_commit", payload)

        # 5. Synchronize materialized views
        target_db = active_ledger.db_path
        fts_view = FTS5View(db_path=target_db)
        vec_view = VectorView(db_path=target_db)
        graph_view = GraphView(db_path=target_db)

        fts_view.index_event(event)
        vec_view.index_event(event)
        graph_view.index_event(event)

        # Connect entities in Kùzu graph (branch, author, and touched files)
        try:
            ev_id = event["event_id"]
            if branch and branch != "HEAD":
                graph_view.create_involves_edge(ev_id, branch, "branch")
            if author:
                graph_view.create_involves_edge(ev_id, author, "author")
            for f in filtered_files[:20]:
                graph_view.create_involves_edge(ev_id, f, "file")
        except Exception:
            pass

        return event

    except Exception:
        # Failure must never bubble up
        return None


def get_post_commit_hook_script() -> str:
    """Return the content of the non-blocking post-commit shell hook."""
    if sys.platform == "win32":
        project_root = Path(__file__).resolve().parents[2]
        twin_exe = project_root / ".venv" / "Scripts" / "twin.exe"
        if not twin_exe.exists():
            twin_exe = Path(sys.prefix) / "Scripts" / "twin.exe"
        twin_posix = twin_exe.as_posix()
        proj_posix = project_root.as_posix()
        return f"""#!/bin/sh
# Project Aethelgard Non-Blocking Git Post-Commit Hook
# Invariant: A hook failure must NEVER block a commit.
(
    REPO_DIR="$(pwd -W 2>/dev/null || pwd)"
    "{twin_posix}" hook post-commit --repo "$REPO_DIR" "$@" 2>/dev/null || \\
    (cd "{proj_posix}" && uv run twin hook post-commit --repo "$REPO_DIR" "$@" 2>/dev/null) || \\
    true
) </dev/null >/dev/null 2>&1 &
exit 0
"""
    return POST_COMMIT_HOOK_SCRIPT


def install_post_commit_hook(
    global_hook: bool = False,
    hooks_dir: Optional[Path | str] = None,
    target_repo: Optional[Path | str] = None,
) -> Path:
    """Install the non-blocking git post-commit hook.

    Parameters:
        global_hook: If True, configures git globally via `git config --global core.hooksPath`.
        hooks_dir: Specific directory to store the hook.
        target_repo: If global_hook is False, target repository directory to install `.git/hooks/post-commit`.
    """
    script_content = get_post_commit_hook_script()
    if global_hook:
        dest_dir = Path(hooks_dir) if hooks_dir else DEFAULT_GLOBAL_HOOKS_DIR
        dest_dir.mkdir(parents=True, exist_ok=True)
        hook_path = dest_dir / "post-commit"
        hook_path.write_text(script_content, encoding="utf-8")

        # Make executable on POSIX systems
        try:
            current_mode = hook_path.stat().st_mode
            hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass

        # Configure git global core.hooksPath
        _run_git_cmd(["config", "--global", "core.hooksPath", str(dest_dir.resolve())])
        return hook_path
    else:
        repo = Path(target_repo) if target_repo else Path.cwd()
        git_dir = repo / ".git"
        if not git_dir.exists():
            raise FileNotFoundError(f"Not a git repository: {repo}")

        hooks_target = git_dir / "hooks"
        hooks_target.mkdir(parents=True, exist_ok=True)
        hook_path = hooks_target / "post-commit"
        hook_path.write_text(script_content, encoding="utf-8")

        try:
            current_mode = hook_path.stat().st_mode
            hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass

        return hook_path


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint for git hook operations. Always returns 0 on post-commit."""
    try:
        import argparse

        parser = argparse.ArgumentParser(
            prog="aethelgard-hook",
            description="Project Aethelgard Git Hooks",
        )
        subparsers = parser.add_subparsers(dest="command")

        # post-commit
        pc_p = subparsers.add_parser("post-commit", help="Execute post-commit passive capture")
        pc_p.add_argument("--repo", type=Path, default=None, help="Repository path")
        pc_p.add_argument("--db", type=Path, default=None, help="Path to ledger.db")

        # install
        inst_p = subparsers.add_parser("install", help="Install non-blocking post-commit hook")
        inst_p.add_argument("--global", dest="global_hook", action="store_true", help="Install globally")
        inst_p.add_argument("--dir", type=Path, default=None, help="Custom hooks directory")
        inst_p.add_argument("--repo", type=Path, default=None, help="Target repository path")

        args = parser.parse_args(argv)

        if args.command == "post-commit":
            capture_git_commit(repo_path=args.repo, db_path=args.db)
            return 0

        if args.command == "install":
            path = install_post_commit_hook(
                global_hook=args.global_hook,
                hooks_dir=args.dir,
                target_repo=args.repo,
            )
            print(f"Installed non-blocking post-commit hook to: {path}")
            return 0

    except BaseException:
        # Crucial Invariant: A hook failure must NEVER block a commit
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
