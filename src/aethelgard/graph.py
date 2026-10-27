"""Subsystem Layer 6: Episodic Graph (Embedded KùzuDB Cypher Engine).

Maintains temporal edges (SUPERSEDES, CAUSED, INVOLVES) over Entity, Decision,
and Event nodes. Treated as a disposable materialized view (INV-01) rebuildable
from the append-only SQLite ledger at any time.
"""

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Optional

import kuzu

from .ledger import Ledger

_KUZU_DATABASES: dict[str, kuzu.Database] = {}


def get_kuzu_db(graph_path: str | Path) -> kuzu.Database:
    """Retrieve or initialize a cached Kùzu database instance for a given path."""
    p = str(graph_path)
    if p in (":memory:", ""):
        return kuzu.Database(":memory:")
    abs_p = os.path.abspath(p)
    if abs_p in _KUZU_DATABASES:
        db = _KUZU_DATABASES[abs_p]
        if not getattr(db, "is_closed", False):
            return db
    db = kuzu.Database(abs_p)
    _KUZU_DATABASES[abs_p] = db
    return db


def close_kuzu_db(graph_path: Optional[str | Path] = None) -> None:
    """Close and release file lock on a Kùzu database (or all cached databases if graph_path is None)."""
    if graph_path is None:
        for abs_p, db in list(_KUZU_DATABASES.items()):
            try:
                db.close()
            except Exception:
                pass
        _KUZU_DATABASES.clear()
        return

    p = str(graph_path)
    if p not in (":memory:", ""):
        abs_p = os.path.abspath(p)
        if abs_p in _KUZU_DATABASES:
            db = _KUZU_DATABASES.pop(abs_p)
            try:
                db.close()
            except Exception:
                pass


class GraphView:
    """Decoupled, disposable KùzuDB episodic graph materialized view."""

    def __init__(
        self,
        db_path: Path | str,
        graph_path: Optional[Path | str] = None,
    ) -> None:
        self.db_path = Path(db_path) if str(db_path) != ":memory:" else db_path
        if graph_path is not None:
            self.graph_path = Path(graph_path) if str(graph_path) != ":memory:" else graph_path
        elif str(db_path) == ":memory:":
            self.graph_path = ":memory:"
        else:
            self.graph_path = Path(db_path).parent / "graph.kuzu"

    def _get_connection(self) -> kuzu.Connection:
        db = get_kuzu_db(self.graph_path)
        return kuzu.Connection(db)

    def init_view(self) -> None:
        """Create the episodic graph schema (Entity, Decision, Event nodes; SUPERSEDES, CAUSED, INVOLVES edges)."""
        conn = self._get_connection()
        conn.execute(
            "CREATE NODE TABLE IF NOT EXISTS Entity(name STRING, type STRING, PRIMARY KEY(name));"
        )
        conn.execute(
            "CREATE NODE TABLE IF NOT EXISTS Decision(id STRING, title STRING, context STRING, decision STRING, timestamp DOUBLE, PRIMARY KEY(id));"
        )
        conn.execute(
            "CREATE NODE TABLE IF NOT EXISTS Event(id STRING, event_type STRING, timestamp DOUBLE, PRIMARY KEY(id));"
        )

        conn.execute(
            "CREATE REL TABLE IF NOT EXISTS SUPERSEDES(FROM Decision TO Decision);"
        )
        conn.execute(
            "CREATE REL TABLE IF NOT EXISTS CAUSED(FROM Event TO Event, FROM Decision TO Event, FROM Event TO Decision);"
        )
        conn.execute(
            "CREATE REL TABLE IF NOT EXISTS INVOLVES(FROM Event TO Entity, FROM Decision TO Entity);"
        )

    def drop_view(self) -> None:
        """Completely drop all graph tables without touching the immutable ledger."""
        conn = self._get_connection()
        conn.execute("DROP TABLE IF EXISTS SUPERSEDES;")
        conn.execute("DROP TABLE IF EXISTS CAUSED;")
        conn.execute("DROP TABLE IF EXISTS INVOLVES;")
        conn.execute("DROP TABLE IF EXISTS Decision;")
        conn.execute("DROP TABLE IF EXISTS Event;")
        conn.execute("DROP TABLE IF EXISTS Entity;")

    def create_supersedes_edge(self, decision_id: str, supersedes_id: str) -> None:
        """Create a direct SUPERSEDES edge from decision_id to supersedes_id."""
        self.init_view()
        conn = self._get_connection()
        conn.execute(
            """
            MERGE (d_new:Decision {id: $d_new_id})
            MERGE (d_old:Decision {id: $d_old_id})
            MERGE (d_new)-[:SUPERSEDES]->(d_old);
            """,
            {"d_new_id": decision_id, "d_old_id": supersedes_id},
        )

    def create_caused_edge(self, from_id: str, to_id: str) -> None:
        """Create a CAUSED edge between events/decisions."""
        self.init_view()
        conn = self._get_connection()
        conn.execute(
            """
            MERGE (a:Event {id: $from_id})
            MERGE (b:Event {id: $to_id})
            MERGE (a)-[:CAUSED]->(b);
            """,
            {"from_id": from_id, "to_id": to_id},
        )

    def create_involves_edge(
        self, from_id: str, entity_name: str, entity_type: str = "concept"
    ) -> None:
        """Create an INVOLVES edge from an event/decision to an entity."""
        self.init_view()
        conn = self._get_connection()
        conn.execute(
            """
            MERGE (ent:Entity {name: $name}) ON CREATE SET ent.type = $type
            WITH ent
            MERGE (ev:Event {id: $from_id})
            MERGE (ev)-[:INVOLVES]->(ent);
            """,
            {"from_id": from_id, "name": entity_name, "type": entity_type},
        )

    def index_event(self, event: dict[str, Any]) -> None:
        """Index a single ledger event into KùzuDB, materializing nodes and temporal edges."""
        self.init_view()
        conn = self._get_connection()

        ev_id = str(event["event_id"])
        ev_type = str(event["event_type"])
        ts = float(event["timestamp"])
        payload_obj = (
            json.loads(event["payload"])
            if isinstance(event["payload"], str)
            else event["payload"]
        )

        # 1. Base Event node
        conn.execute(
            """
            MERGE (ev:Event {id: $id})
            ON CREATE SET ev.event_type = $event_type, ev.timestamp = $timestamp;
            """,
            {"id": ev_id, "event_type": ev_type, "timestamp": ts},
        )

        # 2. Decision node & SUPERSEDES edge
        if ev_type == "decision" and isinstance(payload_obj, dict):
            title = str(payload_obj.get("title", ""))
            context = str(payload_obj.get("context", ""))
            decision = str(payload_obj.get("decision", ""))
            supersedes_id = payload_obj.get("supersedes_id")
            rejected = payload_obj.get("rejected", [])

            conn.execute(
                """
                MERGE (d:Decision {id: $id})
                ON CREATE SET d.title = $title, d.context = $context, d.decision = $decision, d.timestamp = $timestamp;
                """,
                {
                    "id": ev_id,
                    "title": title,
                    "context": context,
                    "decision": decision,
                    "timestamp": ts,
                },
            )

            # Create SUPERSEDES edge when supersedes_id is given
            if supersedes_id:
                self.create_supersedes_edge(ev_id, str(supersedes_id))

            # Connect rejected alternatives
            if isinstance(rejected, (list, tuple)):
                for rej in rejected:
                    if rej:
                        conn.execute(
                            """
                            MERGE (ent:Entity {name: $rej}) ON CREATE SET ent.type = 'rejected_alternative'
                            WITH ent
                            MATCH (d:Decision {id: $id})
                            MERGE (d)-[:INVOLVES]->(ent);
                            """,
                            {"id": ev_id, "rej": str(rej)},
                        )

        # 3. Execution artifact node & entities
        elif ev_type == "execution_artifact" and isinstance(payload_obj, dict):
            action_type = payload_obj.get("action_type")
            if action_type:
                self.create_involves_edge(ev_id, str(action_type), "action_type")

            for section in ("inputs", "outputs"):
                sec_dict = payload_obj.get(section, {})
                if isinstance(sec_dict, dict):
                    for k, v in sec_dict.items():
                        if isinstance(v, str) and (
                            v.startswith("$") or v.startswith("ERR_") or v.isupper()
                        ):
                            self.create_involves_edge(ev_id, str(v), str(k))

            caused_by = payload_obj.get("caused_by_id")
            if caused_by:
                self.create_caused_edge(str(caused_by), ev_id)

        # 4. Note events
        elif ev_type == "note" and isinstance(payload_obj, dict):
            text = str(payload_obj.get("text", ""))
            tokens = re.findall(r"\$[A-Za-z0-9_]+|\b[A-Z]{3,}\b", text)
            for tok in set(tokens):
                self.create_involves_edge(ev_id, tok, "concept")

    def rebuild(self) -> int:
        """Wipe and rebuild the episodic graph strictly from the append-only SQLite events table."""
        self.drop_view()
        self.init_view()
        conn_sql = sqlite3.connect(str(self.db_path))
        conn_sql.row_factory = sqlite3.Row
        rows = conn_sql.execute(
            "SELECT seq, event_id, event_type, timestamp, payload FROM events ORDER BY seq ASC;"
        ).fetchall()
        conn_sql.close()

        count = 0
        for r in rows:
            event = {
                "seq": r["seq"],
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "timestamp": r["timestamp"],
                "payload": r["payload"],
            }
            self.index_event(event)
            count += 1
        return count

    def is_superseded(self, decision_id: str) -> bool:
        """Check if a decision is superseded by any newer decision."""
        self.init_view()
        conn = self._get_connection()
        res = conn.execute(
            """
            MATCH (newer:Decision)-[:SUPERSEDES]->(target:Decision {id: $id})
            RETURN newer.id LIMIT 1;
            """,
            {"id": decision_id},
        )
        return res.has_next()

    def get_superseded_set(self, decision_ids: list[str]) -> set[str]:
        """Batch query to find which decision IDs in the provided list have been superseded."""
        if not decision_ids:
            return set()
        self.init_view()
        conn = self._get_connection()
        res = conn.execute(
            """
            MATCH (newer:Decision)-[:SUPERSEDES]->(target:Decision)
            WHERE target.id IN $ids
            RETURN DISTINCT target.id;
            """,
            {"ids": list(decision_ids)},
        )
        superseded: set[str] = set()
        while res.has_next():
            superseded.add(res.get_next()[0])
        return superseded

    def get_superseded_by(self, decision_id: str) -> list[str]:
        """Return IDs of decisions that supersede this decision."""
        self.init_view()
        conn = self._get_connection()
        res = conn.execute(
            """
            MATCH (newer:Decision)-[:SUPERSEDES]->(target:Decision {id: $id})
            RETURN newer.id;
            """,
            {"id": decision_id},
        )
        out = []
        while res.has_next():
            out.append(res.get_next()[0])
        return out

    def get_supersedes(self, decision_id: str) -> list[str]:
        """Return IDs of decisions that this decision supersedes."""
        self.init_view()
        conn = self._get_connection()
        res = conn.execute(
            """
            MATCH (current:Decision {id: $id})-[:SUPERSEDES]->(older:Decision)
            RETURN older.id;
            """,
            {"id": decision_id},
        )
        out = []
        while res.has_next():
            out.append(res.get_next()[0])
        return out

    def trace_entity_history(
        self, entity_name: str, max_depth: int = 2
    ) -> list[dict[str, Any]]:
        """Traverse KùzuDB to return a chronological timeline of decisions and events for an entity."""
        self.init_view()
        conn = self._get_connection()
        res = conn.execute(
            """
            MATCH (ev:Event)-[:INVOLVES]->(ent:Entity {name: $name})
            OPTIONAL MATCH (d:Decision {id: ev.id})
            RETURN ev.id, ev.event_type, ev.timestamp, d.title
            ORDER BY ev.timestamp ASC;
            """,
            {"name": entity_name},
        )
        out = []
        while res.has_next():
            row = res.get_next()
            out.append(
                {
                    "id": row[0],
                    "event_type": row[1],
                    "timestamp": row[2],
                    "title": row[3],
                }
            )
        return out

    def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Search the episodic graph for events and decisions matching entities or keywords."""
        self.init_view()
        conn = self._get_connection()
        tokens = [t.lower() for t in re.findall(r"[A-Za-z0-9_$-]{2,}", query)]
        if not tokens:
            return []

        candidates: dict[str, dict[str, Any]] = {}

        # 1. Match events connected to entities matching query tokens
        try:
            res = conn.execute(
                """
                MATCH (ev:Event)-[:INVOLVES]->(ent:Entity)
                WHERE lower(ent.name) IN $tokens
                RETURN ev.id, ev.event_type, ev.timestamp, count(ent) AS rel
                ORDER BY rel DESC, ev.timestamp DESC
                LIMIT $limit;
                """,
                {"tokens": tokens, "limit": limit},
            )
            while res.has_next():
                row = res.get_next()
                ev_id, ev_type, ts, rel = row[0], row[1], row[2], row[3]
                candidates[ev_id] = {
                    "event_id": ev_id,
                    "event_type": ev_type,
                    "timestamp": ts,
                    "graph_score": float(rel),
                }
        except Exception:
            pass

        # 2. Match decisions whose title, context, or decision text contains tokens
        try:
            for tok in tokens[:5]:
                res_d = conn.execute(
                    """
                    MATCH (d:Decision)
                    MATCH (ev:Event {id: d.id})
                    WHERE lower(d.title) CONTAINS $tok OR lower(d.decision) CONTAINS $tok
                    RETURN ev.id, ev.event_type, ev.timestamp
                    LIMIT $limit;
                    """,
                    {"tok": tok, "limit": limit},
                )
                while res_d.has_next():
                    row = res_d.get_next()
                    d_id, ev_type, ts = row[0], row[1], row[2]
                    if d_id in candidates:
                        candidates[d_id]["graph_score"] += 1.0
                    else:
                        candidates[d_id] = {
                            "event_id": d_id,
                            "event_type": ev_type,
                            "timestamp": ts,
                            "graph_score": 1.0,
                        }
        except Exception:
            pass

        sorted_candidates = sorted(
            candidates.values(), key=lambda x: x["graph_score"], reverse=True
        )
        return sorted_candidates[:limit]


def commit_decision(
    ledger: Ledger,
    title: str,
    context: str,
    rejected: list[str],
    decision: str,
    supersedes_id: Optional[str] = None,
    graph_view: Optional[GraphView] = None,
) -> dict[str, Any]:
    """MCP Tool Contract: commit_decision(title, context, rejected[], decision, supersedes_id?).

    Hashes an Architectural Decision Record (ADR) into the ledger and writes
    SUPERSEDES edges into KùzuDB when supersedes_id is given.
    """
    event = ledger.commit_decision(
        title=title,
        context=context,
        rejected=rejected,
        decision=decision,
        supersedes_id=supersedes_id,
    )
    gv = graph_view
    if gv is None and hasattr(ledger, "graph_view"):
        gv = ledger.graph_view
    if gv is None and ledger.db_path:
        gv = GraphView(ledger.db_path)
    if gv is not None:
        gv.index_event(event)
    return event
