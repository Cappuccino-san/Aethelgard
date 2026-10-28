"""Subsystem Layer 2 & 3: Immutable SQLite WAL Ledger & BLAKE3 + Ed25519 Provenance Chain."""

import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .airlock import scrub_payload
from .canonical import canonicalize_json

DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "aethelgard"
DEFAULT_KEY_PATH = DEFAULT_DATA_DIR / "ed25519.pem"
GENESIS_HASH = "0" * 64


def load_or_create_signing_key(
    key_path: Optional[Path | str] = None,
) -> Ed25519PrivateKey:
    """Load persistent Ed25519 signing key or generate once outside Git and ledger.

    Loads the same key on every startup to ensure signing persistence across runs
    without regenerating keys.
    """
    if key_path is not None:
        target_path = Path(key_path)
    elif "AETHELGARD_KEY_PATH" in os.environ:
        target_path = Path(os.environ["AETHELGARD_KEY_PATH"])
    elif "AETHELGARD_SIGNING_KEY" in os.environ:
        target_path = Path(os.environ["AETHELGARD_SIGNING_KEY"])
    else:
        target_path = DEFAULT_KEY_PATH

    if target_path.exists():
        pem_bytes = target_path.read_bytes()
        return serialization.load_pem_private_key(pem_bytes, password=None)  # type: ignore[return-value]

    target_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    target_path.write_bytes(pem_bytes)
    try:
        target_path.chmod(0o600)
    except OSError:
        pass
    return key



def compute_merkle_hash(prev_hash: str, canonical_payload: str) -> str:
    """Compute H_n = BLAKE3(H_{n-1} || Payload)."""
    hasher = blake3()
    hasher.update(prev_hash.encode("utf-8"))
    hasher.update(canonical_payload.encode("utf-8"))
    return hasher.hexdigest()


class Ledger:
    """Append-only SQLite WAL Event Ledger with BLAKE3 Merkle Chain and Ed25519 signing."""

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        signing_key: Optional[Ed25519PrivateKey] = None,
    ) -> None:
        if db_path is None:
            DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
            self.db_path = DEFAULT_DATA_DIR / "ledger.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.signing_key = signing_key
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    payload TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    curr_hash TEXT NOT NULL,
                    signature TEXT,
                    pub_key TEXT
                );
                """
            )
            conn.commit()

    def append_event(
        self,
        event_type: str,
        raw_payload: dict[str, Any],
        event_id: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> dict[str, Any]:
        """Scrub via Privacy Airlock, canonicalize (RFC 8785), chain BLAKE3, sign Ed25519, and append."""
        scrubbed = scrub_payload(raw_payload)
        canonical_payload = canonicalize_json(scrubbed)
        ev_id = event_id or str(uuid.uuid4())
        ts = timestamp if timestamp is not None else time.time()

        with self._connect() as conn:
            row = conn.execute(
                "SELECT curr_hash FROM events ORDER BY seq DESC LIMIT 1;"
            ).fetchone()
            prev_hash = row["curr_hash"] if row else GENESIS_HASH
            curr_hash = compute_merkle_hash(prev_hash, canonical_payload)

            signature_hex: Optional[str] = None
            pub_key_hex: Optional[str] = None
            if self.signing_key is not None:
                sig_bytes = self.signing_key.sign(curr_hash.encode("utf-8"))
                signature_hex = sig_bytes.hex()
                pub_key_hex = self.signing_key.public_key().public_bytes_raw().hex()

            cursor = conn.execute(
                """
                INSERT INTO events (
                    event_id, event_type, timestamp, payload, prev_hash, curr_hash, signature, pub_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    ev_id,
                    event_type,
                    ts,
                    canonical_payload,
                    prev_hash,
                    curr_hash,
                    signature_hex,
                    pub_key_hex,
                ),
            )
            seq = cursor.lastrowid
            conn.commit()

        return {
            "seq": seq,
            "event_id": ev_id,
            "event_type": event_type,
            "timestamp": ts,
            "payload": canonical_payload,
            "prev_hash": prev_hash,
            "curr_hash": curr_hash,
            "signature": signature_hex,
            "pub_key": pub_key_hex,
        }

    def commit_decision(
        self,
        title: str,
        context: str,
        rejected: list[str],
        decision: str,
        supersedes_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """MCP Tool Contract: commit_decision(title, context, rejected[], decision, supersedes_id?)."""
        payload: dict[str, Any] = {
            "title": title,
            "context": context,
            "rejected": list(rejected),
            "decision": decision,
            "supersedes_id": supersedes_id,
        }
        return self.append_event("decision", payload)

    def log_execution_artifact(
        self,
        action_type: str,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
        status: str,
    ) -> dict[str, Any]:
        """MCP Tool Contract: log_execution_artifact(action_type, inputs, outputs, status)."""
        payload: dict[str, Any] = {
            "action_type": action_type,
            "inputs": inputs,
            "outputs": outputs,
            "status": status,
        }
        return self.append_event("execution_artifact", payload)

    def verify_provenance(
        self,
        start_seq: Optional[int] = None,
        end_seq: Optional[int] = None,
    ) -> dict[str, Any]:
        """MCP Tool Contract: verify_provenance(start_seq?, end_seq?).

        Recomputes BLAKE3 hashes and Ed25519 signatures from Genesis to detect
        database tampering or corruption.
        """
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY seq ASC;").fetchall()

        expected_prev_hash = GENESIS_HASH
        verified_count = 0

        for idx, row in enumerate(rows, start=1):
            seq = row["seq"]
            in_range = (start_seq is None or seq >= start_seq) and (
                end_seq is None or seq <= end_seq
            )

            # Check sequence gap / row deletion
            if seq != idx:
                if in_range:
                    return {
                        "valid": False,
                        "verified_count": verified_count,
                        "failed_seq": seq,
                        "reason": f"Sequence gap detected: expected seq {idx}, found {seq}",
                    }

            # Check prev_hash linkage
            if row["prev_hash"] != expected_prev_hash:
                if in_range:
                    return {
                        "valid": False,
                        "verified_count": verified_count,
                        "failed_seq": seq,
                        "reason": f"Broken prev_hash link at seq {seq}",
                    }

            # Verify RFC 8785 canonical invariant and recompute BLAKE3(H_{n-1} || Payload)
            recomputed_hash = compute_merkle_hash(row["prev_hash"], row["payload"])
            if recomputed_hash != row["curr_hash"]:
                if in_range:
                    return {
                        "valid": False,
                        "verified_count": verified_count,
                        "failed_seq": seq,
                        "reason": f"BLAKE3 hash mismatch at seq {seq}",
                    }

            # Verify Ed25519 signature if present
            if row["signature"] is not None or row["pub_key"] is not None:
                if not row["signature"] or not row["pub_key"]:
                    if in_range:
                        return {
                            "valid": False,
                            "verified_count": verified_count,
                            "failed_seq": seq,
                            "reason": f"Incomplete Ed25519 signature metadata at seq {seq}",
                        }
                try:
                    pub = Ed25519PublicKey.from_public_bytes(
                        bytes.fromhex(row["pub_key"])
                    )
                    pub.verify(
                        bytes.fromhex(row["signature"]),
                        row["curr_hash"].encode("utf-8"),
                    )
                except (ValueError, InvalidSignature):
                    if in_range:
                        return {
                            "valid": False,
                            "verified_count": verified_count,
                            "failed_seq": seq,
                            "reason": f"Invalid Ed25519 signature at seq {seq}",
                        }

            expected_prev_hash = row["curr_hash"]
            if in_range:
                verified_count += 1

        return {
            "valid": True,
            "verified_count": verified_count,
            "failed_seq": None,
            "reason": None,
        }


# Top-level MCP contract functions operating on a Ledger instance
def commit_decision(
    ledger: Ledger,
    title: str,
    context: str,
    rejected: list[str],
    decision: str,
    supersedes_id: Optional[str] = None,
) -> dict[str, Any]:
    return ledger.commit_decision(title, context, rejected, decision, supersedes_id)


def log_execution_artifact(
    ledger: Ledger,
    action_type: str,
    inputs: dict[str, Any],
    outputs: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    return ledger.log_execution_artifact(action_type, inputs, outputs, status)


def verify_provenance(
    ledger: Ledger,
    start_seq: Optional[int] = None,
    end_seq: Optional[int] = None,
) -> dict[str, Any]:
    return ledger.verify_provenance(start_seq, end_seq)
