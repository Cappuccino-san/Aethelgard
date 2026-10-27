import json
import math
import sqlite3
import time
from pathlib import Path

import pytest

from aethelgard import (
    DEFAULT_K,
    PSI_ACTIVE,
    PSI_SUPERSEDED,
    FTS5View,
    GraphView,
    HybridRRFRanker,
    Ledger,
    VectorView,
    close_kuzu_db,
    commit_decision,
    hybrid_rrf_search,
)
from aethelgard.cli import main as cli_main


@pytest.fixture(autouse=True)
def cleanup_kuzu():
    """Ensure Kuzu database singletons are cleaned up between tests."""
    yield
    close_kuzu_db()


def test_3way_hybrid_rrf_exact_scoring_and_formula(tmp_path: Path):
    """Verify that Score = sum[ wm / (k + rank_m) ] * Psi * e^(-lambda * delta_t) with k=60."""
    db_path = tmp_path / "ledger.db"
    graph_path = tmp_path / "graph.kuzu"

    ledger = Ledger(db_path=db_path)
    fts_view = FTS5View(db_path)
    vec_view = VectorView(db_path)
    graph_view = GraphView(db_path, graph_path=graph_path)

    # 1. Commit decisions with known timestamps
    t_ref = 10000.0
    t1 = 9000.0  # delta_t = 1000
    t2 = 9500.0  # delta_t = 500

    ev1 = ledger.append_event(
        "decision",
        {
            "title": "Use SQLite WAL for durability",
            "context": "High concurrency storage",
            "rejected": ["RocksDB", "PostgreSQL"],
            "decision": "Adopt SQLite WAL mode as append-only engine",
        },
    )
    # Manually backdate timestamp in DB for deterministic temporal testing
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE events SET timestamp = ? WHERE event_id = ?;", (t1, ev1["event_id"]))
        conn.commit()

    ev2 = ledger.append_event(
        "decision",
        {
            "title": "Use KuzuDB for graph memory",
            "context": "Complex relationship querying",
            "rejected": ["Neo4j", "Memgraph"],
            "decision": "Embed KuzuDB for episodic graph persistence",
        },
    )
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE events SET timestamp = ? WHERE event_id = ?;", (t2, ev2["event_id"]))
        conn.commit()

    # Index into all 3 views
    for ev in [ev1, ev2]:
        fts_view.index_event(ev)
        vec_view.index_event(ev)
        graph_view.index_event(ev)

    # Query for "SQLite WAL durability"
    ranker = HybridRRFRanker(db_path=db_path, graph_path=graph_path)
    decay_lambda = 0.0005
    results = ranker.search(
        query="SQLite WAL durability",
        k=DEFAULT_K,
        decay_lambda=decay_lambda,
        reference_time=t_ref,
    )

    assert len(results) > 0
    top_hit = results[0]
    assert top_hit["event_id"] == ev1["event_id"]
    assert top_hit["is_superseded"] is False
    assert top_hit["psi"] == PSI_ACTIVE == 1.0

    # Verify RRF and exact math
    ranks = top_hit["ranks"]
    expected_rrf = 0.0
    for mod, rank in ranks.items():
        if rank is not None:
            expected_rrf += 1.0 / (DEFAULT_K + rank)

    assert top_hit["rrf_score"] == pytest.approx(round(expected_rrf, 8), abs=1e-6)

    # delta_t = 10000 - 9000 = 1000
    expected_delta_t = t_ref - t1
    assert top_hit["delta_t"] == pytest.approx(expected_delta_t, abs=1e-4)

    expected_decay = math.exp(-decay_lambda * expected_delta_t)
    assert top_hit["decay"] == pytest.approx(round(expected_decay, 8), abs=1e-6)

    expected_score = expected_rrf * PSI_ACTIVE * expected_decay
    assert top_hit["score"] == pytest.approx(round(expected_score, 8), abs=1e-6)


def test_supersession_penalty_psi_and_filtering(tmp_path: Path):
    """Verify Psi = 0.15 for superseded decisions and Psi = 1.0 for active decisions."""
    db_path = tmp_path / "ledger.db"
    graph_path = tmp_path / "graph.kuzu"

    ledger = Ledger(db_path=db_path)
    fts_view = FTS5View(db_path)
    vec_view = VectorView(db_path)
    graph_view = GraphView(db_path, graph_path=graph_path)

    # Commit initial decision D1
    d1 = commit_decision(
        ledger=ledger,
        title="Cache Architecture v1",
        context="In-memory cache for speed",
        rejected=["Disk cache"],
        decision="Use simple in-memory Redis cache for speed",
        graph_view=graph_view,
    )
    fts_view.index_event(d1)
    vec_view.index_event(d1)

    # Commit superseding decision D2 pointing to D1
    d2 = commit_decision(
        ledger=ledger,
        title="Cache Architecture v2",
        context="Redis OOM under high load",
        rejected=["Redis Cluster"],
        decision="Replace Redis with local Moka in-memory cache and LMDB overflow",
        supersedes_id=d1["event_id"],
        graph_view=graph_view,
    )
    fts_view.index_event(d2)
    vec_view.index_event(d2)

    ranker = HybridRRFRanker(db_path=db_path, graph_path=graph_path)

    # 1. Search including superseded items
    results = ranker.search("Cache Architecture", decay_lambda=0.0, include_superseded=True)
    res_map = {r["event_id"]: r for r in results}

    assert d1["event_id"] in res_map
    assert d2["event_id"] in res_map

    # Check Psi values
    assert res_map[d1["event_id"]]["is_superseded"] is True
    assert res_map[d1["event_id"]]["psi"] == PSI_SUPERSEDED == 0.15

    assert res_map[d2["event_id"]]["is_superseded"] is False
    assert res_map[d2["event_id"]]["psi"] == PSI_ACTIVE == 1.0

    # D2 should easily outrank D1 because of the 85% penalty on D1
    assert res_map[d2["event_id"]]["score"] > res_map[d1["event_id"]]["score"]

    # 2. Search excluding superseded items
    results_active_only = ranker.search(
        "Cache Architecture", decay_lambda=0.0, include_superseded=False
    )
    active_ids = [r["event_id"] for r in results_active_only]
    assert d2["event_id"] in active_ids
    assert d1["event_id"] not in active_ids


def test_explicit_named_lambda_parameter_support(tmp_path: Path):
    """Verify that lambda can be passed as explicit named parameters: decay_lambda, lambda_param, lambda_."""
    db_path = tmp_path / "ledger.db"
    graph_path = tmp_path / "graph.kuzu"

    ledger = Ledger(db_path=db_path)
    ev = ledger.append_event("note", {"text": "Authentication JWT rotated to Ed25519 tokens"})
    FTS5View(db_path).index_event(ev)
    VectorView(db_path).index_event(ev)
    GraphView(db_path, graph_path=graph_path).index_event(ev)

    # Test via functional wrapper with decay_lambda
    fixed_ref_time = 10000.0
    res_decay = hybrid_rrf_search(
        db_path=db_path,
        graph_path=graph_path,
        query="JWT Ed25519 tokens",
        decay_lambda=0.05,
        reference_time=fixed_ref_time,
    )
    assert len(res_decay) == 1

    # Test via functional wrapper with lambda_param
    res_param = hybrid_rrf_search(
        db_path=db_path,
        graph_path=graph_path,
        query="JWT Ed25519 tokens",
        lambda_param=0.05,
        reference_time=fixed_ref_time,
    )
    assert len(res_param) == 1
    assert res_param[0]["score"] == res_decay[0]["score"]

    # Test via functional wrapper with lambda_ (PEP 8 trailing underscore for keywords)
    res_kw = hybrid_rrf_search(
        db_path=db_path,
        graph_path=graph_path,
        query="JWT Ed25519 tokens",
        lambda_=0.05,
        reference_time=fixed_ref_time,
    )
    assert len(res_kw) == 1
    assert res_kw[0]["score"] == res_decay[0]["score"]

    # Test via kwargs dict {"lambda": 0.05}
    res_dict = hybrid_rrf_search(
        db_path=db_path,
        graph_path=graph_path,
        query="JWT Ed25519 tokens",
        reference_time=fixed_ref_time,
        **{"lambda": 0.05},
    )
    assert len(res_dict) == 1
    assert res_dict[0]["score"] == res_decay[0]["score"]


def test_cli_search_command_output(tmp_path: Path, capsys):
    """Verify CLI `twin search` runs end-to-end and outputs formatted JSON."""
    db_path = tmp_path / "ledger.db"
    ledger = Ledger(db_path=db_path)
    fts = FTS5View(db_path)
    vec = VectorView(db_path)
    graph = GraphView(db_path)

    ev = commit_decision(
        ledger=ledger,
        title="Microservice Decomposition",
        context="Monolith scaling issues",
        rejected=["Stay on monolith"],
        decision="Decompose services into bounded contexts",
        graph_view=graph,
    )
    fts.index_event(ev)
    vec.index_event(ev)

    code = cli_main(["--db", str(db_path), "search", "Microservice", "--k", "60", "--lambda", "0.0"])
    assert code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["event_id"] == ev["event_id"]
    assert "score" in data[0]
    assert "ranks" in data[0]
