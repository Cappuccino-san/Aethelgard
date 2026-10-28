"""Unit & verification tests for Phase 1 Cryptographic Core, Airlock, and Decoupled FTS5 View."""

import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aethelgard.airlock import scrub_payload
from aethelgard.canonical import canonicalize_json
from aethelgard.ledger import (
    GENESIS_HASH,
    Ledger,
    commit_decision,
    compute_merkle_hash,
    log_execution_artifact,
    verify_provenance,
)
from aethelgard.views import FTS5View, rebuild_views, search_lexical


def test_privacy_airlock_regex_and_entropy() -> None:
    raw = {
        "note": "Configured OpenAI key sk-proj1234567890abcdefABCDEF and AWS key AKIAIOSFODNN7EXAMPLE",
        "nested": {
            "high_entropy_secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IHRva2VuIDEyMzQ1Njc4OTA=",
            "normal_identifier": "verify_provenance_merkle_chain",
        },
    }
    scrubbed = scrub_payload(raw)
    assert "sk-proj1234567890abcdefABCDEF" not in scrubbed["note"]
    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed["note"]
    assert "[REDACTED]" in scrubbed["note"]
    assert scrubbed["nested"]["high_entropy_secret"] == "[REDACTED]"
    assert scrubbed["nested"]["normal_identifier"] == "verify_provenance_merkle_chain"


def test_rfc8785_canonical_json_determinism() -> None:
    payload_a = {"b": [3, 2, 1], "a": {"z": True, "alpha": None, "num": 10.0}}
    payload_b = {"a": {"num": 10, "alpha": None, "z": True}, "b": [3, 2, 1]}
    canon_a = canonicalize_json(payload_a)
    canon_b = canonicalize_json(payload_b)
    assert canon_a == canon_b
    assert canon_a == '{"a":{"alpha":null,"num":10,"z":true},"b":[3,2,1]}'


def test_blake3_merkle_chain_and_ed25519_verification(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    priv_key = Ed25519PrivateKey.generate()
    ledger = Ledger(db_path=db_file, signing_key=priv_key)

    ev1 = commit_decision(
        ledger,
        title="Use SQLite WAL for Event Ledger",
        context="Need 10-year durability and zero-cloud sovereignty",
        rejected=["PostgreSQL container", "Cloud DynamoDB"],
        decision="SQLite 3 in WAL mode storing RFC 8785 canonical JSON",
    )
    assert ev1["prev_hash"] == GENESIS_HASH
    assert ev1["curr_hash"] == compute_merkle_hash(GENESIS_HASH, ev1["payload"])
    assert ev1["signature"] is not None

    ev2 = log_execution_artifact(
        ledger,
        action_type="backtest_run",
        inputs={"ticker": "$SPX", "strategy": "0DTE_GEX"},
        outputs={"sharpe": 2.41, "error_code": "ERR_NONE"},
        status="SUCCESS",
    )
    assert ev2["prev_hash"] == ev1["curr_hash"]
    assert ev2["curr_hash"] == compute_merkle_hash(ev1["curr_hash"], ev2["payload"])

    verification = verify_provenance(ledger)
    assert verification == {
        "valid": True,
        "verified_count": 2,
        "failed_seq": None,
        "reason": None,
    }


def test_tamper_detection_payload_and_signature(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    priv_key = Ed25519PrivateKey.generate()
    ledger = Ledger(db_path=db_file, signing_key=priv_key)

    commit_decision(
        ledger,
        title="Initial Architecture",
        context="Phase 1 setup",
        rejected=["None"],
        decision="Use BLAKE3",
    )
    commit_decision(
        ledger,
        title="Second Decision",
        context="Add signing",
        rejected=["RSA"],
        decision="Use Ed25519",
    )

    # Tamper with payload of seq 1 directly in SQLite
    conn = sqlite3.connect(str(db_file))
    orig_payload = conn.execute("SELECT payload FROM events WHERE seq = 1;").fetchone()[0]
    tampered_payload = orig_payload.replace("BLAKE3", "MD5")
    conn.execute("UPDATE events SET payload = ? WHERE seq = 1;", (tampered_payload,))
    conn.commit()

    res = verify_provenance(ledger)
    assert res["valid"] is False
    assert res["failed_seq"] == 1
    assert "BLAKE3 hash mismatch" in res["reason"]

    # Restore payload, then tamper with Ed25519 signature on seq 2
    conn.execute("UPDATE events SET payload = ? WHERE seq = 1;", (orig_payload,))
    bad_sig = "00" * 64
    conn.execute("UPDATE events SET signature = ? WHERE seq = 2;", (bad_sig,))
    conn.commit()
    conn.close()

    res2 = verify_provenance(ledger)
    assert res2["valid"] is False
    assert res2["failed_seq"] == 2
    assert "Invalid Ed25519 signature" in res2["reason"]


def test_decoupled_fts5_drop_rebuild_identical_and_ledger_intact(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger.db"
    priv_key = Ed25519PrivateKey.generate()
    ledger = Ledger(db_path=db_file, signing_key=priv_key)
    view = FTS5View(db_path=db_file)

    e1 = commit_decision(
        ledger,
        title="Adopt BLAKE3 Merkle Chain",
        context="Cryptographic provenance invariant INV-03",
        rejected=["SHA256"],
        decision="compute_merkle_hash with BLAKE3 and Ed25519",
    )
    view.index_event(e1)

    e2 = log_execution_artifact(
        ledger,
        action_type="quant_pipeline",
        inputs={"symbol": "$QQQ", "fn": "calculate_vanna_exposure"},
        outputs={"code": "E_TIMEOUT_408"},
        status="RETRY",
    )
    view.index_event(e2)

    e3 = commit_decision(
        ledger,
        title="Lexical Index Selection",
        context="Capture exact identifier tokens, function signatures, error codes, and financial tickers",
        rejected=["External Elasticsearch"],
        decision="SQLite FTS5 BM25 disposable materialized view",
        supersedes_id=e1["event_id"],
    )
    view.index_event(e3)

    # 1. Capture initial search results across identifier tokens, tickers, and error codes
    queries = ["compute_merkle_hash", "$QQQ", "E_TIMEOUT_408", "BM25"]
    initial_results = {q: search_lexical(db_file, q) for q in queries}
    for q in queries:
        assert len(initial_results[q]) >= 1

    # 2. Drop the FTS5 view completely
    view.drop_view()

    # Verify the FTS5 table is gone while the ledger remains intact
    conn = sqlite3.connect(str(db_file))
    fts_exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events_fts';"
    ).fetchone()
    conn.close()
    assert fts_exists is None
    assert verify_provenance(ledger)["valid"] is True

    # 3. Rebuild the FTS5 view strictly from the immutable ledger
    rebuilt_count = rebuild_views(db_file)
    assert rebuilt_count == 3

    # 4. Verify search results after rebuild are 100% identical to pre-drop results
    rebuilt_results = {q: search_lexical(db_file, q) for q in queries}
    assert rebuilt_results == initial_results

    # 5. Verify ledger cryptographic provenance still passes
    final_verification = verify_provenance(ledger)
    assert final_verification == {
        "valid": True,
        "verified_count": 3,
        "failed_seq": None,
        "reason": None,
    }


def test_persistent_signing_key_lifecycle(tmp_path: Path) -> None:
    """Verify Ed25519 signing key persistence across startups without regeneration."""
    from aethelgard.ledger import load_or_create_signing_key

    key_path = tmp_path / "ed25519.pem"
    db_file = tmp_path / "ledger.db"

    # 1. First startup: generates key once and persists
    k1 = load_or_create_signing_key(key_path)
    assert key_path.exists()
    pub1 = k1.public_key().public_bytes_raw().hex()

    # 2. Second startup: loads identical key from disk without regenerating
    k2 = load_or_create_signing_key(key_path)
    pub2 = k2.public_key().public_bytes_raw().hex()
    assert pub1 == pub2

    # 3. Commit event using loaded key
    ledger = Ledger(db_path=db_file, signing_key=k2)
    ev = commit_decision(
        ledger=ledger,
        title="ADR-Persistent-Key",
        context="Testing key persistence",
        rejected=[],
        decision="Use persistent Ed25519 key",
    )
    assert ev["signature"] is not None
    assert ev["pub_key"] == pub1

    # 4. Verify provenance succeeds with signature check
    audit = ledger.verify_provenance()
    assert audit["valid"] is True
    assert audit["verified_count"] == 1

