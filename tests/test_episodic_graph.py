"""Unit & verification tests for Phase 2 Episodic Graph (KùzuDB: Entity, Decision, Event, SUPERSEDES, CAUSED, INVOLVES)."""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aethelgard.graph import GraphView, close_kuzu_db, commit_decision
from aethelgard.ledger import (
    Ledger,
    log_execution_artifact,
    verify_provenance,
)
from aethelgard.views import rebuild_views, search_lexical, search_semantic


def test_kuzu_schema_initialization(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    graph_view = GraphView(db_path=db_file)
    graph_view.init_view()

    # Query schema to verify node tables exist
    conn = graph_view._get_connection()
    res = conn.execute("MATCH (d:Decision) RETURN count(d);")
    assert res.has_next()
    assert res.get_next()[0] == 0

    res_ent = conn.execute("MATCH (e:Entity) RETURN count(e);")
    assert res_ent.has_next()
    assert res_ent.get_next()[0] == 0

    res_ev = conn.execute("MATCH (ev:Event) RETURN count(ev);")
    assert res_ev.has_next()
    assert res_ev.get_next()[0] == 0

    close_kuzu_db(graph_view.graph_path)


def test_commit_decision_creates_supersedes_edge(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    ledger = Ledger(db_path=db_file)
    graph_view = GraphView(db_path=db_file)

    # 1. First decision
    d1 = commit_decision(
        ledger=ledger,
        title="Initial Storage Architecture",
        context="Evaluation of embedded database options",
        rejected=["PostgreSQL", "DynamoDB"],
        decision="Use DuckDB for both storage and analytics",
        graph_view=graph_view,
    )
    d1_id = d1["event_id"]

    assert graph_view.is_superseded(d1_id) is False
    assert graph_view.get_superseded_by(d1_id) == []

    # 2. Second decision superseding d1
    d2 = commit_decision(
        ledger=ledger,
        title="Decoupled SQLite WAL Architecture",
        context="10-year durability and append-only cryptographic invariants",
        rejected=["DuckDB monolith"],
        decision="Use SQLite 3 WAL for immutable ledger and KùzuDB for episodic graph",
        supersedes_id=d1_id,
        graph_view=graph_view,
    )
    d2_id = d2["event_id"]

    # Invariants verification
    assert graph_view.is_superseded(d1_id) is True
    assert graph_view.is_superseded(d2_id) is False
    assert graph_view.get_superseded_by(d1_id) == [d2_id]
    assert graph_view.get_supersedes(d2_id) == [d1_id]

    close_kuzu_db(graph_view.graph_path)


def test_caused_and_involves_edges_and_trace(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    ledger = Ledger(db_path=db_file)
    graph_view = GraphView(db_path=db_file)

    d1 = commit_decision(
        ledger=ledger,
        title="Adopt BLAKE3 Provenance Chain",
        context="Cryptographic non-repudiation INV-03",
        rejected=["SHA256", "MD5"],
        decision="Use BLAKE3 Merkle chain linking each row to prev_hash",
        graph_view=graph_view,
    )

    art = log_execution_artifact(
        ledger,
        action_type="provenance_audit",
        inputs={"module": "BLAKE3", "algo": "XOF"},
        outputs={"status": "PASSED"},
        status="SUCCESS",
    )
    graph_view.index_event(art)
    graph_view.create_caused_edge(d1["event_id"], art["event_id"])

    # Trace history for BLAKE3
    history = graph_view.trace_entity_history("BLAKE3")
    assert len(history) >= 1
    event_ids = [h["id"] for h in history]
    assert art["event_id"] in event_ids

    close_kuzu_db(graph_view.graph_path)


def test_decoupled_graph_drop_and_rebuild_from_ledger(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    priv_key = Ed25519PrivateKey.generate()
    ledger = Ledger(db_path=db_file, signing_key=priv_key)
    graph_view = GraphView(db_path=db_file)

    # 1. Commit initial decision
    d1 = commit_decision(
        ledger=ledger,
        title="Old Graph Engine",
        context="Explore graph databases",
        rejected=["Neo4j"],
        decision="Use in-memory adjacency list",
        graph_view=graph_view,
    )
    d1_id = d1["event_id"]

    # 2. Commit superseding decision
    d2 = commit_decision(
        ledger=ledger,
        title="Adopt KùzuDB Embedded Graph",
        context="Sub-millisecond Cypher traversals on disk",
        rejected=["Networked Neo4j"],
        decision="Use embedded KùzuDB for episodic memory",
        supersedes_id=d1_id,
        graph_view=graph_view,
    )
    d2_id = d2["event_id"]

    # 3. Add a note and an execution artifact
    n1 = ledger.append_event("note", {"text": "Tested KùzuDB SUPERSEDES edge"})
    graph_view.index_event(n1)

    # Verify initial state
    assert graph_view.is_superseded(d1_id) is True
    assert graph_view.get_superseded_by(d1_id) == [d2_id]

    # 4. Drop the graph view completely (INV-01 Disposable Materialized Views)
    graph_view.drop_view()

    # Verify ledger integrity is 100% intact after dropping view
    audit_pre = verify_provenance(ledger)
    assert audit_pre["valid"] is True
    assert audit_pre["verified_count"] == 3

    # 5. Rebuild ALL views (FTS5 + sqlite-vec + KùzuDB) strictly from ledger
    rebuilt_count = rebuild_views(db_file)
    assert rebuilt_count == 3

    # 6. Verify KùzuDB was completely reconstructed from raw ledger events
    assert graph_view.is_superseded(d1_id) is True
    assert graph_view.is_superseded(d2_id) is False
    assert graph_view.get_superseded_by(d1_id) == [d2_id]
    assert graph_view.get_supersedes(d2_id) == [d1_id]

    # 7. Verify lexical and semantic views also pass after rebuild
    assert len(search_lexical(db_file, "KùzuDB")) >= 1
    assert len(search_semantic(db_file, "Adopt KùzuDB Embedded Graph")) >= 1

    # 8. Cryptographic provenance remains intact
    audit_post = verify_provenance(ledger)
    assert audit_post["valid"] is True
    assert audit_post["verified_count"] == 3

    close_kuzu_db(graph_view.graph_path)
