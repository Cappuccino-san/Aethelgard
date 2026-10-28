"""Unit and integration tests for Phase 4: Passive Daemon, Watchdog Listener, and Git Hooks."""

import gc
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from aethelgard.filters import filter_file_paths, is_ignored_path
from aethelgard.git_hook import (
    capture_git_commit,
    get_post_commit_hook_script,
    install_post_commit_hook,
    main as hook_main,
)
from aethelgard.ledger import Ledger
from aethelgard.listener import PassiveFSListener
from aethelgard.systemd import (
    get_systemd_unit_content,
    install_systemd_unit,
    uninstall_systemd_unit,
)
from aethelgard.views import search_lexical


def test_path_filtering_rules() -> None:
    """Verify lockfiles, .git internals, and build artifacts are strictly filtered."""
    ignored = [
        # Lockfiles
        "uv.lock",
        "package-lock.json",
        "Cargo.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
        "sub/dir/poetry.lock",
        "custom.lock",
        "custom.lockb",
        # Git directory internals
        ".git",
        ".git/HEAD",
        ".git/COMMIT_EDITMSG",
        ".git/hooks/post-commit",
        "subproject/.git/config",
        # Build artifacts & caches
        "__pycache__/module.cpython-312.pyc",
        "script.pyc",
        "script.pyo",
        "lib.pyd",
        "dist/bundle.js",
        "build/temp.o",
        "target/release/binary",
        "node_modules/express/index.js",
        ".venv/lib/site-packages/pkg.py",
        "venv/bin/activate",
        ".pytest_cache/v/cache",
        ".mypy_cache/3.12/mod.data",
        "package.egg-info/PKG-INFO",
        "app.exe",
        "libtest.so",
        "libtest.dylib",
        "artifact.whl",
        # Temp and database files
        "ledger.db",
        "ledger.db-wal",
        "graph.kuzu",
        ".DS_Store",
        "file.tmp",
        "file.swp",
        "file~",
    ]

    for path in ignored:
        assert is_ignored_path(path) is True, f"Expected {path} to be ignored"

    not_ignored = [
        "src/aethelgard/ledger.py",
        "README.md",
        "pyproject.toml",
        "tests/test_phase4.py",
        "docs/spec.pdf",
        "frontend/App.tsx",
        "package.json",
        "Cargo.toml",
    ]

    for path in not_ignored:
        assert is_ignored_path(path) is False, f"Expected {path} NOT to be ignored"

    mixed = ["README.md", "uv.lock", "src/main.py", "__pycache__/main.cpython-312.pyc", "dist/bundle.js"]
    cleaned = filter_file_paths(mixed)
    assert cleaned == ["README.md", "src/main.py"]


def test_git_post_commit_hook_capture(tmp_path: Path) -> None:
    """Verify git commit is captured into ledger with lockfiles and build artifacts filtered."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    db_file = tmp_path / "ledger.db"

    # 1. Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "committer@example.com"], cwd=repo_dir, check=True, capture_output=True)

    # 2. Create commit with normal file + lockfile
    (repo_dir / "README.md").write_text("# Project Root\nArchitecture notes.", encoding="utf-8")
    (repo_dir / "uv.lock").write_text("lockfile binary data", encoding="utf-8")
    subprocess.run(["git", "add", "README.md", "uv.lock"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "feat: initial commit with lockfile"], cwd=repo_dir, check=True, capture_output=True)

    # 3. Execute hook capture
    event = capture_git_commit(repo_path=repo_dir, db_path=db_file)
    assert event is not None
    assert event["event_type"] == "git_commit"

    payload = json.loads(event["payload"])
    assert "README.md" in payload["files"]
    assert "uv.lock" not in payload["files"]  # Filtered out
    assert payload["filtered_files_count"] == 1
    assert "initial commit" in payload["message"]
    assert payload["author"] == "Test Committer <committer@example.com>"

    # 4. Verify cryptographic provenance
    ledger = Ledger(db_path=db_file)
    audit = ledger.verify_provenance()
    assert audit["valid"] is True
    assert audit["verified_count"] == 1

    # 5. Verify searchability in decoupled lexical view
    hits = search_lexical(db_file, "initial commit")
    assert len(hits) == 1
    assert hits[0]["event_id"] == event["event_id"]


def test_git_hook_failure_never_blocks_commit(tmp_path: Path) -> None:
    """Invariant: A hook failure must NEVER block a commit under any error condition."""
    # 1. Non-existent path returns None without exception
    res = capture_git_commit(repo_path=tmp_path / "non_existent_directory")
    assert res is None

    # 2. Non-git directory returns None without exception
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    res2 = capture_git_commit(repo_path=empty_dir)
    assert res2 is None

    # 3. CLI entrypoint exits with code 0 on invalid repository
    exit_code = hook_main(["post-commit", "--repo", str(empty_dir)])
    assert exit_code == 0

    # 4. CLI entrypoint exits with code 0 on nonexistent command or failure
    exit_code2 = hook_main(["invalid_command"])
    assert exit_code2 == 0


def test_post_commit_hook_installation(tmp_path: Path) -> None:
    """Verify local and global post-commit hook scripts are generated and installed."""
    script = get_post_commit_hook_script()
    assert "#!/bin/sh" in script
    assert "exit 0" in script
    assert "post-commit" in script

    # Local repo install
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    installed_local = install_post_commit_hook(global_hook=False, target_repo=repo_dir)
    assert installed_local.exists()
    assert (repo_dir / ".git" / "hooks" / "post-commit").exists()
    assert installed_local.read_text(encoding="utf-8") == script

    # Custom directory install (simulating global hooks directory)
    custom_hooks = tmp_path / "custom_hooks"
    from aethelgard.git_hook import _run_git_cmd

    orig_hooks = _run_git_cmd(["config", "--global", "--get", "core.hooksPath"])
    try:
        installed_global = install_post_commit_hook(global_hook=True, hooks_dir=custom_hooks)
        assert installed_global.exists()
        assert (custom_hooks / "post-commit").exists()
    finally:
        if orig_hooks:
            _run_git_cmd(["config", "--global", "core.hooksPath", orig_hooks])
        else:
            _run_git_cmd(["config", "--global", "--unset", "core.hooksPath"])


def test_watchdog_passive_filesystem_listener(tmp_path: Path) -> None:
    """Verify watchdog filesystem listener debounces, filters, and logs file changes."""
    watch_dir = tmp_path / "workspace"
    watch_dir.mkdir()
    db_file = tmp_path / "ledger.db"

    captured_events: list[dict] = []

    listener = PassiveFSListener(
        watch_paths=watch_dir,
        db_path=db_file,
        debounce_seconds=0.1,
        on_event=lambda ev: captured_events.append(ev),
    )

    with listener:
        # 1. Create a legitimate code file
        code_file = watch_dir / "algorithm.py"
        code_file.write_text("def solve(): return 42\n", encoding="utf-8")

        # 2. Create ignored files (lockfile, build artifact, git internal)
        lock_file = watch_dir / "uv.lock"
        lock_file.write_text("lockfile data", encoding="utf-8")

        dist_dir = watch_dir / "dist"
        dist_dir.mkdir()
        (dist_dir / "output.js").write_text("bundled code", encoding="utf-8")

        # Flush pending events
        events = listener.flush()

    assert len(events) >= 1
    file_paths = [json.loads(e["payload"])["file_path"] for e in events]

    # algorithm.py must be captured
    assert any("algorithm.py" in p for p in file_paths)

    # uv.lock and dist/output.js must NOT be captured
    assert not any("uv.lock" in p for p in file_paths)
    assert not any("output.js" in p for p in file_paths)

    # Check ledger provenance
    ledger = Ledger(db_path=db_file)
    audit = ledger.verify_provenance()
    assert audit["valid"] is True


def test_systemd_user_service_unit(tmp_path: Path) -> None:
    """Verify systemd user service unit generation, installation, and uninstallation."""
    unit_content = get_systemd_unit_content(watch_dir="/home/dev/workspace")
    assert "[Unit]" in unit_content
    assert "Description=Project Aethelgard Passive Cognitive Daemon" in unit_content
    assert "[Service]" in unit_content
    assert "ExecStart=" in unit_content
    assert "--watch /home/dev/workspace" in unit_content
    assert "AETHELGARD_DATA_DIR=" in unit_content
    assert "WantedBy=default.target" in unit_content

    # Install to custom path
    target_service = tmp_path / "systemd" / "user" / "aethelgard.service"
    installed = install_systemd_unit(target_path=target_service, watch_dir="/home/dev/workspace")
    assert installed.exists()
    assert target_service.exists()
    assert target_service.read_text(encoding="utf-8") == unit_content

    # Uninstall
    uninstalled = uninstall_systemd_unit(target_path=target_service)
    assert uninstalled is True
    assert not target_service.exists()
