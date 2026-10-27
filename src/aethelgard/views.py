"""Subsystem Layer 4 & 5: Disposable Materialized Views (SQLite FTS5 BM25 & sqlite-vec 768d vec0).

INV-01 Event-Sourced Truth: Raw events are stored in an append-only SQLite ledger.
Materialized views (lexical and semantic vector indexes) are disposable and can be
wiped and rebuilt anytime without compromising ledger integrity.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Callable, Optional

import sqlite_vec

from .embeddings import EMBEDDING_DIM, get_embedding
from .graph import GraphView


def load_sqlite_vec(conn: sqlite3.Connection) -> None:
    """Load the sqlite-vec extension into a connection."""
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)


def _flatten_json_text(obj: Any) -> str:
    """Extract searchable lexical text from canonical JSON payloads."""
    parts: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                parts.append(str(k))
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)
        elif node is not None:
            parts.append(str(node))

    _walk(obj)
    return " ".join(parts)


def _format_event_text(event_type: str, payload_obj: Any) -> str:
    """Format event payload into text for semantic embedding."""
    if isinstance(payload_obj, dict):
        if event_type == "decision":
            title = payload_obj.get("title", "")
            context = payload_obj.get("context", "")
            decision = payload_obj.get("decision", "")
            rejected = payload_obj.get("rejected", [])
            rej_str = ", ".join(rejected) if isinstance(rejected, list) else str(rejected)
            return f"Decision: {title}\nContext: {context}\nDecision: {decision}\nRejected alternatives: {rej_str}"
        if event_type == "note":
            return str(payload_obj.get("text", ""))
        if event_type == "execution_artifact":
            action = payload_obj.get("action_type", "")
            status = payload_obj.get("status", "")
            inputs = payload_obj.get("inputs", {})
            outputs = payload_obj.get("outputs", {})
            return f"Execution: {action} [{status}]\nInputs: {inputs}\nOutputs: {outputs}"
    return _flatten_json_text(payload_obj)


class FTS5View:
    """Decoupled, disposable SQLite FTS5 BM25 lexical materialized view."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def init_view(self) -> None:
        """Create the decoupled FTS5 virtual table without attaching triggers to the immutable ledger."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    event_id UNINDEXED,
                    event_type,
                    content,
                    tokenize='unicode61 tokenchars ''_-$.:'''
                );
                """
            )
            conn.commit()

    def drop_view(self) -> None:
        """Completely drop the disposable FTS5 view without touching the events ledger."""
        with self._connect() as conn:
            conn.execute("DROP TABLE IF EXISTS events_fts;")
            conn.commit()

    def index_event(self, event: dict[str, Any]) -> None:
        """Index a single ledger event into the decoupled FTS5 view."""
        self.init_view()
        payload_obj = (
            json.loads(event["payload"])
            if isinstance(event["payload"], str)
            else event["payload"]
        )
        content = _flatten_json_text(payload_obj)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events_fts (rowid, event_id, event_type, content) VALUES (?, ?, ?, ?);",
                (event["seq"], event["event_id"], event["event_type"], content),
            )
            conn.commit()

    def rebuild(self) -> int:
        """Wipe and rebuild the FTS5 lexical index strictly from the append-only events table."""
        self.drop_view()
        self.init_view()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, event_id, event_type, payload FROM events ORDER BY seq ASC;"
            ).fetchall()
            batch = []
            for row in rows:
                payload_obj = json.loads(row["payload"])
                content = _flatten_json_text(payload_obj)
                batch.append((row["seq"], row["event_id"], row["event_type"], content))
            conn.executemany(
                "INSERT INTO events_fts (rowid, event_id, event_type, content) VALUES (?, ?, ?, ?);",
                batch,
            )
            conn.commit()
            return len(batch)

    def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Execute BM25 lexical search over the FTS5 view."""
        self.init_view()
        clean_query = query.replace('"', '').strip()
        if not clean_query:
            return []
        quoted_query = f'"{clean_query}"'
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT
                        rowid AS seq,
                        event_id,
                        event_type,
                        content,
                        bm25(events_fts) AS bm25_score
                    FROM events_fts
                    WHERE events_fts MATCH ?
                    ORDER BY bm25(events_fts) ASC, rowid ASC
                    LIMIT ?;
                    """,
                    (quoted_query, limit),
                ).fetchall()
                return [
                    {
                        "seq": r["seq"],
                        "event_id": r["event_id"],
                        "event_type": r["event_type"],
                        "content": r["content"],
                        "bm25_score": round(float(r["bm25_score"]), 8),
                    }
                    for r in rows
                ]
        except sqlite3.OperationalError:
            return []


class VectorView:
    """Decoupled, disposable SQLite sqlite-vec (vec0) 768d semantic materialized view."""

    def __init__(
        self,
        db_path: Path | str,
        embed_fn: Optional[Callable[[str], list[float]]] = None,
        ollama_url: Optional[str] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.embed_fn = embed_fn
        self.ollama_url = ollama_url

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        load_sqlite_vec(conn)
        return conn

    def init_view(self) -> None:
        """Create the decoupled vec0 virtual table for 768d cosine vector search."""
        with self._connect() as conn:
            conn.execute(
                f"""
                CREATE VIRTUAL TABLE IF NOT EXISTS events_vec USING vec0(
                    event_id text,
                    event_type text,
                    embedding float[{EMBEDDING_DIM}] distance_metric=cosine
                );
                """
            )
            conn.commit()

    def drop_view(self) -> None:
        """Drop the disposable vec0 view without touching the events ledger."""
        with self._connect() as conn:
            conn.execute("DROP TABLE IF EXISTS events_vec;")
            conn.commit()

    def get_embedding(self, text: str) -> list[float]:
        """Generate or retrieve 768d embedding vector."""
        return get_embedding(text, host=self.ollama_url, embed_fn=self.embed_fn)

    def index_event(self, event: dict[str, Any]) -> None:
        """Index a single ledger event into the vec0 semantic view."""
        self.init_view()
        payload_obj = (
            json.loads(event["payload"])
            if isinstance(event["payload"], str)
            else event["payload"]
        )
        text = _format_event_text(event["event_type"], payload_obj)
        emb = self.get_embedding(text)
        serialized_emb = sqlite_vec.serialize_float32(emb)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events_vec (rowid, event_id, event_type, embedding) VALUES (?, ?, ?, ?);",
                (event["seq"], event["event_id"], event["event_type"], serialized_emb),
            )
            conn.commit()

    def rebuild(self) -> int:
        """Wipe and rebuild the vec0 semantic index strictly from the append-only events table."""
        self.drop_view()
        self.init_view()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, event_id, event_type, payload FROM events ORDER BY seq ASC;"
            ).fetchall()
            batch = []
            for row in rows:
                payload_obj = json.loads(row["payload"])
                text = _format_event_text(row["event_type"], payload_obj)
                emb = self.get_embedding(text)
                batch.append(
                    (row["seq"], row["event_id"], row["event_type"], sqlite_vec.serialize_float32(emb))
                )
            conn.executemany(
                "INSERT INTO events_vec (rowid, event_id, event_type, embedding) VALUES (?, ?, ?, ?);",
                batch,
            )
            conn.commit()
            return len(batch)

    def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Execute cosine kNN semantic vector search over the vec0 view."""
        self.init_view()
        query_emb = self.get_embedding(query)
        serialized_query = sqlite_vec.serialize_float32(query_emb)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    v.rowid AS seq,
                    v.event_id,
                    v.event_type,
                    v.distance,
                    e.payload
                FROM events_vec v
                LEFT JOIN events e ON e.seq = v.rowid
                WHERE v.embedding MATCH ? AND k = ?
                ORDER BY v.distance ASC;
                """,
                (serialized_query, limit),
            ).fetchall()
            return [
                {
                    "seq": r["seq"],
                    "event_id": r["event_id"],
                    "event_type": r["event_type"],
                    "distance": round(float(r["distance"]), 8),
                    "score": round(max(0.0, 1.0 - float(r["distance"])), 8),
                    "payload": json.loads(r["payload"]) if r["payload"] else None,
                }
                for r in rows
            ]


def rebuild_views(
    db_path: Path | str,
    embed_fn: Optional[Callable[[str], list[float]]] = None,
    graph_path: Optional[Path | str] = None,
) -> int:
    """Implements `twin rebuild-views` for all decoupled materialized views (FTS5 lexical, sqlite-vec semantic, and KùzuDB episodic graph)."""
    fts_view = FTS5View(db_path)
    fts_count = fts_view.rebuild()

    vec_view = VectorView(db_path, embed_fn=embed_fn)
    vec_view.rebuild()

    graph_view = GraphView(db_path, graph_path=graph_path)
    graph_view.rebuild()

    return fts_count


def search_lexical(db_path: Path | str, query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Query the FTS5 BM25 view."""
    view = FTS5View(db_path)
    return view.search(query, limit=limit)


def search_semantic(
    db_path: Path | str,
    query: str,
    limit: int = 20,
    embed_fn: Optional[Callable[[str], list[float]]] = None,
) -> list[dict[str, Any]]:
    """Query the sqlite-vec semantic view."""
    view = VectorView(db_path, embed_fn=embed_fn)
    return view.search(query, limit=limit)
