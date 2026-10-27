"""Unit & verification tests for Phase 2 Semantic View (sqlite-vec vec0 [768d] + nomic-embed-text)."""

import math
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aethelgard.embeddings import (
    EMBEDDING_DIM,
    OllamaEmbeddingClient,
    generate_mock_embedding,
    get_embedding,
)
from aethelgard.ledger import Ledger, commit_decision, verify_provenance
from aethelgard.views import (
    FTS5View,
    VectorView,
    load_sqlite_vec,
    rebuild_views,
    search_lexical,
    search_semantic,
)


def test_mock_embedding_determinism_and_normalization() -> None:
    text_a = "Sovereign Cognitive Twin & Cryptographic Provenance Engine"
    text_b = "Disposable materialized views over append-only SQLite WAL"

    vec_a1 = generate_mock_embedding(text_a, dim=EMBEDDING_DIM)
    vec_a2 = generate_mock_embedding(text_a, dim=EMBEDDING_DIM)
    vec_b = generate_mock_embedding(text_b, dim=EMBEDDING_DIM)

    # 1. Dimension invariant
    assert len(vec_a1) == 768
    assert len(vec_b) == 768

    # 2. Strict determinism
    assert vec_a1 == vec_a2

    # 3. Distinction
    assert vec_a1 != vec_b

    # 4. Unit norm
    norm_a = math.sqrt(sum(x * x for x in vec_a1))
    norm_b = math.sqrt(sum(x * x for x in vec_b))
    assert abs(norm_a - 1.0) < 1e-6
    assert abs(norm_b - 1.0) < 1e-6


def test_ollama_fallback_when_offline() -> None:
    # Point client to a port that is not hosting Ollama
    client = OllamaEmbeddingClient(
        host="http://127.0.0.1:59123",
        timeout=0.1,
        cooldown_seconds=5.0,
    )
    assert client.is_available() is False

    vec = client.embed("Test fallback behavior")
    assert len(vec) == 768
    norm = math.sqrt(sum(x * x for x in vec))
    assert abs(norm - 1.0) < 1e-6

    # Verify cached cooldown doesn't re-trigger slow timeouts
    vec2 = client.embed("Second call in cooldown")
    assert len(vec2) == 768


def test_vector_view_sqlite_vec_loading_and_table_init(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    conn = sqlite3.connect(str(db_file))
    load_sqlite_vec(conn)
    vec_ver = conn.execute("SELECT vec_version();").fetchone()[0]
    conn.close()
    assert vec_ver is not None
    assert "v" in vec_ver

    view = VectorView(db_path=db_file)
    view.init_view()

    conn2 = sqlite3.connect(str(db_file))
    load_sqlite_vec(conn2)
    tbl = conn2.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events_vec';"
    ).fetchone()
    conn2.close()
    assert tbl is not None


def test_vector_view_indexing_and_semantic_search(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    ledger = Ledger(db_path=db_file)
    vec_view = VectorView(db_path=db_file)

    ev1 = commit_decision(
        ledger,
        title="SQLite WAL Event Ledger",
        context="Durability and Zero-Cloud Sovereignty",
        rejected=["PostgreSQL", "DynamoDB"],
        decision="Use embedded SQLite 3 WAL mode with BLAKE3 Merkle chain",
    )
    vec_view.index_event(ev1)

    ev2 = ledger.append_event(
        "note",
        {"text": "Quant trading model deployed for 0DTE volatility arbitrage"},
    )
    vec_view.index_event(ev2)

    # 1. Search for keyword query matching ev1
    results = vec_view.search("SQLite WAL Event Ledger", limit=5)
    assert len(results) == 2
    top_hit = results[0]
    assert top_hit["seq"] == 1
    assert top_hit["event_id"] == ev1["event_id"]
    assert top_hit["event_type"] == "decision"
    # Relevant decision is significantly closer than unrelated trading note
    assert top_hit["distance"] < results[1]["distance"]
    assert top_hit["score"] > results[1]["score"]
    assert top_hit["payload"]["title"] == "SQLite WAL Event Ledger"

    # 2. Search for exact note text of ev2
    exact_results = vec_view.search("Quant trading model deployed for 0DTE volatility arbitrage", limit=5)
    assert len(exact_results) == 2
    top_hit_exact = exact_results[0]
    assert top_hit_exact["seq"] == 2
    assert top_hit_exact["event_id"] == ev2["event_id"]
    # Exact text match gives near-zero cosine distance and near-1.0 score
    assert top_hit_exact["distance"] < 0.05
    assert top_hit_exact["score"] > 0.95


def test_decoupled_vector_drop_rebuild_from_ledger_and_integrity(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    priv_key = Ed25519PrivateKey.generate()
    ledger = Ledger(db_path=db_file, signing_key=priv_key)
    fts_view = FTS5View(db_path=db_file)
    vec_view = VectorView(db_path=db_file)

    e1 = commit_decision(
        ledger,
        title="Vector Search Engine",
        context="Model Context Protocol semantic lookup",
        rejected=["Pinecone", "Milvus", "Qdrant"],
        decision="sqlite-vec vec0 extension embedded directly inside SQLite",
    )
    fts_view.index_event(e1)
    vec_view.index_event(e1)

    e2 = ledger.append_event(
        "note",
        {"text": "Testing decoupled disposable materialized view rebuild"},
    )
    fts_view.index_event(e2)
    vec_view.index_event(e2)

    # Capture initial semantic search result
    query = "Vector Search Engine"
    initial_results = search_semantic(db_file, query)
    assert len(initial_results) >= 1

    # 1. Drop the vector view completely (INV-01 Disposable Materialized Views)
    vec_view.drop_view()

    # Verify events_vec table is dropped
    conn = sqlite3.connect(str(db_file))
    load_sqlite_vec(conn)
    vec_exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events_vec';"
    ).fetchone()
    conn.close()
    assert vec_exists is None

    # Verify ledger cryptographic provenance is untouched
    assert verify_provenance(ledger)["valid"] is True

    # 2. Rebuild both FTS5 and Vector views strictly from the raw ledger
    rebuilt_count = rebuild_views(db_file)
    assert rebuilt_count == 2

    # 3. Verify semantic results after rebuild match initial results exactly
    rebuilt_results = search_semantic(db_file, query)
    assert len(rebuilt_results) == len(initial_results)
    assert rebuilt_results[0]["seq"] == initial_results[0]["seq"]
    assert rebuilt_results[0]["event_id"] == initial_results[0]["event_id"]
    assert rebuilt_results[0]["distance"] == initial_results[0]["distance"]

    # 4. Verify lexical search also works after unified rebuild
    lex_results = search_lexical(db_file, "sqlite-vec")
    assert len(lex_results) >= 1

    # 5. Verify cryptographic provenance remains 100% valid
    final_audit = verify_provenance(ledger)
    assert final_audit["valid"] is True
    assert final_audit["verified_count"] == 2


def test_custom_embed_fn_injection(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    ledger = Ledger(db_path=db_file)

    ev = ledger.append_event("note", {"text": "Custom embedding injection"})

    # Injected custom mock embedding
    def custom_embedder(text: str) -> list[float]:
        # Return a simple deterministic 768d one-hot vector
        vec = [0.0] * 768
        vec[0] = 1.0
        return vec

    vec_view = VectorView(db_path=db_file, embed_fn=custom_embedder)
    vec_view.index_event(ev)

    results = vec_view.search("Anything", limit=1)
    assert len(results) == 1
    assert results[0]["distance"] == 0.0
    assert results[0]["score"] == 1.0
