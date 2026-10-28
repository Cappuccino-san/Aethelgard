"""Subsystem Layer: FastMCP Bridge (Exposing Cognitive State via Model Context Protocol).

Provides a standardized Model Context Protocol (MCP) server over stdio,
exposing Project Aethelgard's cryptographic ledger, disposable materialized
views (FTS5 BM25, sqlite-vec 768d), and KùzuDB episodic graph to IDEs and
autonomous agents.

Exposes the 5 canonical MCP tools defined in Specification Section 06:
  1. recall_context(query, domain?, include_superseded?)
  2. commit_decision(title, context, rejected[], decision, supersedes_id?)
  3. trace_entity_history(entity_name, max_depth?)
  4. log_execution_artifact(action_type, inputs, outputs, status)
  5. verify_provenance(start_seq?, end_seq?)
"""

import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

from mcp.server.fastmcp import FastMCP

from .graph import GraphView, close_kuzu_db
from .graph import commit_decision as graph_commit_decision
from .ledger import DEFAULT_DATA_DIR, Ledger
from .ledger import log_execution_artifact as ledger_log_artifact
from .ranker import HybridRRFRanker
from .views import FTS5View, VectorView


def create_mcp_server(
    db_path: Optional[Path | str] = None,
    graph_path: Optional[Path | str] = None,
    signing_key: Optional[Any] = None,
    embed_fn: Optional[Callable[[str], list[float]]] = None,
    server_name: str = "aethelgard",
) -> FastMCP:
    """Create and configure a FastMCP server instance exposing Aethelgard's 5 cognitive tools.

    Parameters:
        db_path: Path to the SQLite ledger database (defaults to AETHELGARD_DB or ~/.local/share/aethelgard/ledger.db).
        graph_path: Path to KùzuDB database directory (defaults to sibling graph.kuzu).
        signing_key: Optional Ed25519PrivateKey for signing ledger events.
        embed_fn: Optional custom embedding function for VectorView and ranker.
        server_name: Name of the FastMCP server instance (default: 'aethelgard').
    """
    resolved_db_path: Path | str
    if db_path is not None:
        resolved_db_path = Path(db_path) if str(db_path) != ":memory:" else db_path
    elif "AETHELGARD_DB" in os.environ:
        resolved_db_path = Path(os.environ["AETHELGARD_DB"])
    else:
        resolved_db_path = DEFAULT_DATA_DIR / "ledger.db"

    # Initialize subsystems
    ledger = Ledger(db_path=resolved_db_path, signing_key=signing_key)
    fts_view = FTS5View(db_path=resolved_db_path)
    vec_view = VectorView(db_path=resolved_db_path, embed_fn=embed_fn)
    graph_view = GraphView(db_path=resolved_db_path, graph_path=graph_path)
    ranker = HybridRRFRanker(
        db_path=resolved_db_path, graph_path=graph_path, embed_fn=embed_fn
    )

    # Ensure view tables exist
    fts_view.init_view()
    vec_view.init_view()
    graph_view.init_view()

    # Create FastMCP server
    server = FastMCP(
        server_name,
        instructions=(
            "Project Aethelgard: Sovereign Cognitive Twin & Cryptographic Provenance Engine. "
            "Exposes immutable ledger records, 3-way hybrid RRF retrieval, and episodic graph traversals."
        ),
    )

    # Attach subsystem references for testing and direct access
    server.ledger = ledger  # type: ignore[attr-defined]
    server.fts_view = fts_view  # type: ignore[attr-defined]
    server.vec_view = vec_view  # type: ignore[attr-defined]
    server.graph_view = graph_view  # type: ignore[attr-defined]
    server.ranker = ranker  # type: ignore[attr-defined]

    def close_all() -> None:
        """Close graph database and release file locks."""
        close_kuzu_db(graph_view.graph_path)

    server.close = close_all  # type: ignore[attr-defined]

    # Tool 1: recall_context
    @server.tool()
    def recall_context(
        query: str,
        domain: Optional[str] = None,
        include_superseded: bool = False,
        limit: int = 10,
        decay_lambda: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Execute 3-Way Hybrid RRF across FTS5, sqlite-vec, and KùzuDB; filters out obsolete patterns by default."""
        clean_query = query.strip()
        if not clean_query:
            return []

        effective_query = (
            f"{domain} {clean_query}"
            if domain and domain.lower() not in clean_query.lower()
            else clean_query
        )

        results = ranker.search(
            query=effective_query,
            limit=limit,
            decay_lambda=decay_lambda,
            include_superseded=include_superseded,
        )

        if domain:
            # If any results explicitly carry a domain attribute in their payload, filter to matching domain
            has_explicit_domain = any(
                isinstance(r.get("payload"), dict) and "domain" in r["payload"]
                for r in results
            )
            if has_explicit_domain:
                results = [
                    r
                    for r in results
                    if isinstance(r.get("payload"), dict)
                    and str(r["payload"].get("domain", "")).lower() == domain.lower()
                ]

        return results

    # Tool 2: commit_decision
    @server.tool()
    def commit_decision(
        title: str,
        context: str,
        rejected: list[str],
        decision: str,
        supersedes_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Hash an Architectural Decision Record (ADR) into the ledger and write SUPERSEDES edges into KùzuDB."""
        rej_list = list(rejected) if rejected is not None else []
        event = graph_commit_decision(
            ledger=ledger,
            title=title,
            context=context,
            rejected=rej_list,
            decision=decision,
            supersedes_id=supersedes_id,
            graph_view=graph_view,
        )
        fts_view.index_event(event)
        vec_view.index_event(event)
        return event

    # Tool 3: trace_entity_history
    @server.tool()
    def trace_entity_history(
        entity_name: str,
        max_depth: int = 2,
    ) -> list[dict[str, Any]]:
        """Traverse KùzuDB to return a chronological timeline of commits, bugs, and strategy shifts for a module or concept."""
        depth = max_depth if max_depth is not None else 2
        return graph_view.trace_entity_history(entity_name.strip(), max_depth=depth)

    # Tool 4: log_execution_artifact
    @server.tool()
    def log_execution_artifact(
        action_type: str,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
        status: str,
    ) -> dict[str, Any]:
        """Append autonomous agent executions into the Merkle chain for auditability."""
        event = ledger_log_artifact(
            ledger=ledger,
            action_type=action_type,
            inputs=inputs or {},
            outputs=outputs or {},
            status=status,
        )
        fts_view.index_event(event)
        vec_view.index_event(event)
        graph_view.index_event(event)
        return event

    # Tool 5: verify_provenance
    @server.tool()
    def verify_provenance(
        start_seq: Optional[int] = None,
        end_seq: Optional[int] = None,
    ) -> dict[str, Any]:
        """Recompute BLAKE3 hashes and Ed25519 signatures from Genesis to detect database tampering or corruption."""
        return ledger.verify_provenance(start_seq=start_seq, end_seq=end_seq)

    # Store tool functions on server for direct programmatic access
    server.recall_context = recall_context  # type: ignore[attr-defined]
    server.commit_decision = commit_decision  # type: ignore[attr-defined]
    server.trace_entity_history = trace_entity_history  # type: ignore[attr-defined]
    server.log_execution_artifact = log_execution_artifact  # type: ignore[attr-defined]
    server.verify_provenance = verify_provenance  # type: ignore[attr-defined]

    return server


# Module-level cached default server instance (lazy initialized)
_DEFAULT_SERVER: Optional[FastMCP] = None


def get_mcp_server(
    db_path: Optional[Path | str] = None,
    graph_path: Optional[Path | str] = None,
    **kwargs: Any,
) -> FastMCP:
    """Get or create a FastMCP server instance (lazy initialized)."""
    global _DEFAULT_SERVER
    if db_path is not None or graph_path is not None or kwargs:
        return create_mcp_server(db_path=db_path, graph_path=graph_path, **kwargs)
    if _DEFAULT_SERVER is None:
        _DEFAULT_SERVER = create_mcp_server()
    return _DEFAULT_SERVER


def __getattr__(name: str) -> Any:
    if name == "mcp":
        return get_mcp_server()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def run_stdio(
    db_path: Optional[Path | str] = None,
    graph_path: Optional[Path | str] = None,
    signing_key: Optional[Any] = None,
    embed_fn: Optional[Callable[[str], list[float]]] = None,
) -> None:
    """Run the FastMCP bridge server using the stdio transport."""
    server = create_mcp_server(
        db_path=db_path,
        graph_path=graph_path,
        signing_key=signing_key,
        embed_fn=embed_fn,
    )
    server.run(transport="stdio")


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint for running the FastMCP stdio server."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="aethelgard-mcp",
        description="Project Aethelgard FastMCP Stdio Bridge",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Path to ledger.db (defaults to ~/.local/share/aethelgard/ledger.db)",
    )
    parser.add_argument(
        "--graph",
        type=Path,
        default=None,
        help="Path to graph.kuzu (defaults to sibling of ledger.db)",
    )

    args = parser.parse_args(argv)
    run_stdio(db_path=args.db, graph_path=args.graph)
    return 0


if __name__ == "__main__":
    sys.exit(main())
