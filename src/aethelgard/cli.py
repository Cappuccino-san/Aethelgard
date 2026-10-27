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

    return 1


if __name__ == "__main__":
    sys.exit(main())
