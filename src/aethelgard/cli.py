"""CLI entrypoint (`twin commit`, `twin note`, `twin rebuild-views`, `twin verify`)."""

import argparse
import json
import sys
from pathlib import Path

from .graph import GraphView, commit_decision
from .ledger import DEFAULT_DATA_DIR, Ledger
from .views import FTS5View, VectorView, rebuild_views


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="twin", description="Project Aethelgard CLI")
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DATA_DIR / "ledger.db",
        help="Path to ledger.db",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # twin commit
    commit_p = subparsers.add_parser("commit", help="Commit an Architectural Decision Record")
    commit_p.add_argument("--title", required=True)
    commit_p.add_argument("--context", required=True)
    commit_p.add_argument("--rejected", nargs="*", default=[])
    commit_p.add_argument("--decision", required=True)
    commit_p.add_argument("--supersedes-id", default=None)

    # twin note
    note_p = subparsers.add_parser("note", help="Append a research or engineering note")
    note_p.add_argument("text", help="Note content")

    # twin rebuild-views
    subparsers.add_parser("rebuild-views", help="Drop and rebuild disposable FTS5, sqlite-vec, and KùzuDB views from ledger")

    # twin verify
    verify_p = subparsers.add_parser("verify", help="Verify BLAKE3 Merkle chain and Ed25519 signatures")
    verify_p.add_argument("--start-seq", type=int, default=None)
    verify_p.add_argument("--end-seq", type=int, default=None)

    # twin search
    search_p = subparsers.add_parser("search", help="Execute 3-way hybrid RRF search across lexical, vector, and graph views")
    search_p.add_argument("query", help="Query string")
    search_p.add_argument("--limit", type=int, default=10)
    search_p.add_argument("--k", type=int, default=60)
    search_p.add_argument("--lambda", dest="decay_lambda", type=float, default=0.0)
    search_p.add_argument("--no-superseded", action="store_true", help="Exclude superseded decisions")

    # twin mcp
    mcp_p = subparsers.add_parser("mcp", help="Run FastMCP bridge over stdio")
    mcp_p.add_argument("--graph", type=Path, default=None, help="Path to graph.kuzu")

    # twin serve (alias for mcp)
    serve_p = subparsers.add_parser("serve", help="Run FastMCP bridge over stdio (alias for twin mcp)")
    serve_p.add_argument("--graph", type=Path, default=None, help="Path to graph.kuzu")

    # twin hook
    hook_p = subparsers.add_parser("hook", help="Git hook management and execution")
    hook_sub = hook_p.add_subparsers(dest="hook_command", required=True)

    hook_pc = hook_sub.add_parser("post-commit", help="Execute post-commit hook capture")
    hook_pc.add_argument("--repo", type=Path, default=None, help="Repository path")

    hook_inst = hook_sub.add_parser("install", help="Install non-blocking post-commit hook")
    hook_inst.add_argument("--global", dest="global_hook", action="store_true", help="Install globally")
    hook_inst.add_argument("--dir", type=Path, default=None, help="Custom hooks directory")
    hook_inst.add_argument("--repo", type=Path, default=None, help="Target repository path")

    # twin daemon
    daemon_p = subparsers.add_parser("daemon", help="Passive background daemon and systemd management")
    daemon_sub = daemon_p.add_subparsers(dest="daemon_command", required=True)

    daemon_start = daemon_sub.add_parser("start", help="Start passive capture daemon")
    daemon_start.add_argument(
        "--watch", action="append", dest="watch_paths", default=[], help="Directories to monitor"
    )
    daemon_start.add_argument("--debounce", type=float, default=0.5, help="Debounce duration in seconds")

    daemon_svc = daemon_sub.add_parser("service", help="Manage systemd user service unit")
    daemon_svc.add_argument("--install", action="store_true", help="Install systemd user service")
    daemon_svc.add_argument("--print", action="store_true", help="Print systemd user service unit")
    daemon_svc.add_argument("--watch-dir", type=str, default=None, help="Directory to configure in service")

    args = parser.parse_args(argv)
    ledger = Ledger(db_path=args.db)
    view = FTS5View(db_path=args.db)
    vec_view = VectorView(db_path=args.db)
    graph_view = GraphView(db_path=args.db)

    if args.command == "commit":
        event = commit_decision(
            ledger=ledger,
            title=args.title,
            context=args.context,
            rejected=args.rejected,
            decision=args.decision,
            supersedes_id=args.supersedes_id,
            graph_view=graph_view,
        )
        view.index_event(event)
        vec_view.index_event(event)
        print(json.dumps(event))
        return 0

    if args.command == "note":
        event = ledger.append_event("note", {"text": args.text})
        view.index_event(event)
        vec_view.index_event(event)
        graph_view.index_event(event)
        print(json.dumps(event))
        return 0

    if args.command == "rebuild-views":
        count = rebuild_views(args.db)
        print(json.dumps({"rebuilt_events": count}))
        return 0

    if args.command == "verify":
        res = ledger.verify_provenance(start_seq=args.start_seq, end_seq=args.end_seq)
        print(json.dumps(res))
        return 0 if res["valid"] else 1

    if args.command == "search":
        from .ranker import HybridRRFRanker

        ranker = HybridRRFRanker(db_path=args.db)
        results = ranker.search(
            query=args.query,
            limit=args.limit,
            k=args.k,
            decay_lambda=args.decay_lambda,
            include_superseded=not args.no_superseded,
        )
        print(json.dumps(results, indent=2))
        return 0

    if args.command in ("mcp", "serve"):
        from .mcp import run_stdio

        run_stdio(db_path=args.db, graph_path=args.graph)
        return 0

    if args.command == "hook":
        from .git_hook import capture_git_commit, install_post_commit_hook

        if args.hook_command == "post-commit":
            capture_git_commit(repo_path=args.repo, db_path=args.db)
            return 0
        if args.hook_command == "install":
            installed_path = install_post_commit_hook(
                global_hook=args.global_hook,
                hooks_dir=args.dir,
                target_repo=args.repo,
            )
            print(json.dumps({"installed_hook": str(installed_path)}))
            return 0

    if args.command == "daemon":
        from .daemon import run_daemon
        from .systemd import get_systemd_unit_content, install_systemd_unit

        if args.daemon_command == "start":
            watch_targets = args.watch_paths or [Path.cwd()]
            run_daemon(
                watch_paths=watch_targets,
                db_path=args.db,
                debounce_seconds=args.debounce,
            )
            return 0
        if args.daemon_command == "service":
            if args.print:
                print(get_systemd_unit_content(watch_dir=args.watch_dir))
                return 0
            if args.install:
                path = install_systemd_unit(watch_dir=args.watch_dir)
                print(json.dumps({"installed_service": str(path)}))
                return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
