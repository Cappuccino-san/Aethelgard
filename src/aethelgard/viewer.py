"""Local read-only web viewer for Project Aethelgard.

Strictly bound to 127.0.0.1 (local loopback only). Provides 5 core capabilities:
  1. Hybrid RRF Search (/search): Reciprocal Rank Fusion with BM25, Vec, Graph ranks, supersession & filters
  2. Timeline (/timeline): Chronological recent events with seq, type, title/message, signed status & filters
  3. Decision & Event Detail View (/event/<seq>): Full payload, hash prefixes only, and related events
  4. Verify (/verify): Provenance verification status (BLAKE3 Merkle chain & Ed25519 signatures)
  5. Graph (/graph): Mermaid diagram from KùzuDB episodic decision nodes and edges
"""

import html
import http.server
import json
import sqlite3
import sys
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .graph import GraphView
from .ledger import DEFAULT_DATA_DIR, Ledger
from .ranker import HybridRRFRanker


def extract_title_or_message(event_type: str, payload: dict[str, Any]) -> str:
    """Extract a concise title or message from an event payload based on event_type."""
    if event_type == "decision":
        return str(payload.get("title", "Untitled Decision"))
    elif event_type == "git_commit":
        msg = str(payload.get("message", "Git commit")).strip()
        commit_hash = payload.get("commit_hash")
        short_hash = f"[{commit_hash[:7]}] " if commit_hash else ""
        branch = f" ({payload.get('branch')})" if payload.get("branch") else ""
        return f"{short_hash}{msg}{branch}"
    elif event_type == "file_change":
        change = payload.get("change_type", "change")
        path = payload.get("file_path") or payload.get("absolute_path") or ""
        return f"{change}: {path}"
    elif event_type == "note":
        text = str(payload.get("text", "")).strip()
        return text if len(text) <= 120 else text[:117] + "..."
    elif event_type == "execution_artifact":
        action = payload.get("action_type", "artifact")
        status = payload.get("status", "")
        return f"{action} ({status})" if status else str(action)
    else:
        for k in ("title", "message", "text", "description", "name"):
            if k in payload:
                return str(payload[k])
        return str(payload)[:100]


def get_available_event_types(db_path: Path | str) -> list[str]:
    """Retrieve distinct event types recorded in the ledger, with standard fallback types."""
    default_types = [
        "decision",
        "git_commit",
        "file_change",
        "note",
        "execution_artifact",
    ]
    db_file = Path(db_path)
    if not db_file.exists():
        return default_types

    discovered: set[str] = set(default_types)
    try:
        with sqlite3.connect(str(db_file)) as conn:
            rows = conn.execute("SELECT DISTINCT event_type FROM events;").fetchall()
            for r in rows:
                if r[0]:
                    discovered.add(str(r[0]))
    except Exception:
        pass
    return sorted(list(discovered))


def get_timeline_events(
    db_path: Path | str,
    limit: int = 100,
    event_type: Optional[str] = None,
    signed: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Retrieve recent events from SQLite ledger ordered by seq DESC, with optional filtering.

    Parameters:
      event_type: Specific event_type to filter (or None / "all" for all types).
      signed: "yes" for signed events only, "no" for unsigned only, or "all" / None for both.

    Security Guarantee: Never outputs raw private keys, public keys, or full signature hexes.
    Only computes and returns `signed: True/False`.
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return []

    where_clauses = ["1=1"]
    query_params: list[Any] = []

    if event_type and event_type.strip().lower() not in ("all", ""):
        where_clauses.append("event_type = ?")
        query_params.append(event_type.strip())

    if signed:
        s_val = signed.strip().lower()
        if s_val in ("yes", "true", "1"):
            where_clauses.append(
                "(signature IS NOT NULL AND length(signature) > 0 AND pub_key IS NOT NULL AND length(pub_key) > 0)"
            )
        elif s_val in ("no", "false", "0"):
            where_clauses.append(
                "(signature IS NULL OR length(signature) = 0 OR pub_key IS NULL OR length(pub_key) = 0)"
            )

    where_sql = " AND ".join(where_clauses)
    query_params.append(limit)

    events: list[dict[str, Any]] = []
    with sqlite3.connect(str(db_file)) as conn:
        conn.row_factory = sqlite3.Row
        sql = f"""
            SELECT seq, event_id, event_type, timestamp, payload,
                   (signature IS NOT NULL AND length(signature) > 0 AND pub_key IS NOT NULL AND length(pub_key) > 0) AS is_signed
            FROM events
            WHERE {where_sql}
            ORDER BY seq DESC
            LIMIT ?;
        """
        rows = conn.execute(sql, query_params).fetchall()

        for r in rows:
            raw_payload = r["payload"]
            payload_obj = (
                json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            )
            title = extract_title_or_message(r["event_type"], payload_obj)
            ts = float(r["timestamp"])
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            events.append(
                {
                    "seq": r["seq"],
                    "event_id": r["event_id"],
                    "event_type": r["event_type"],
                    "timestamp": ts,
                    "datetime": dt,
                    "title": title,
                    "signed": bool(r["is_signed"]),
                    "payload": payload_obj,
                }
            )
    return events


def get_event_detail(db_path: Path | str, seq: int) -> Optional[dict[str, Any]]:
    """Retrieve full event detail by sequence number.

    Security Guarantee: Never outputs raw private keys, public keys, or full signature hexes.
    Only exposes BLAKE3 hash prefixes (prev_hash[:12]..., curr_hash[:12]...) and boolean signed status.
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return None

    with sqlite3.connect(str(db_file)) as conn:
        conn.row_factory = sqlite3.Row
        r = conn.execute(
            """
            SELECT seq, event_id, event_type, timestamp, payload, prev_hash, curr_hash,
                   (signature IS NOT NULL AND length(signature) > 0 AND pub_key IS NOT NULL AND length(pub_key) > 0) AS is_signed
            FROM events
            WHERE seq = ?;
            """,
            (seq,),
        ).fetchone()

        if not r:
            return None

        raw_payload = r["payload"]
        payload_obj = (
            json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        )
        ts = float(r["timestamp"])
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        prev_h = r["prev_hash"]
        curr_h = r["curr_hash"]
        ev_id = str(r["event_id"])

        return {
            "seq": r["seq"],
            "event_id": ev_id,
            "event_id_prefix": ev_id[:12] + "...",
            "event_type": r["event_type"],
            "timestamp": ts,
            "datetime": dt,
            "prev_hash_prefix": (prev_h[:12] + "...") if prev_h else "N/A",
            "curr_hash_prefix": (curr_h[:12] + "...") if curr_h else "N/A",
            "signed": bool(r["is_signed"]),
            "title": extract_title_or_message(r["event_type"], payload_obj),
            "payload": payload_obj,
        }


def get_related_events(
    db_path: Path | str, event: dict[str, Any], graph_path: Optional[Path | str] = None
) -> dict[str, Any]:
    """Retrieve related events: supersession chain, events involving same entities, and git_commit repo/files."""
    db_file = Path(db_path)
    if not db_file.exists():
        return {
            "supersession_chain": [],
            "entity_events": [],
            "commit_details": {},
        }

    ev_id = str(event["event_id"])
    ev_type = str(event["event_type"])
    seq = event.get("seq")
    payload = event.get("payload", {})

    supersession_chain: list[dict[str, Any]] = []
    entity_events: list[dict[str, Any]] = []
    commit_details: dict[str, Any] = {}

    with sqlite3.connect(str(db_file)) as conn:
        conn.row_factory = sqlite3.Row

        # 1. Supersession chain (for decisions)
        if ev_type == "decision":
            supersedes_id = payload.get("supersedes_id")
            if supersedes_id:
                old_row = conn.execute(
                    "SELECT seq, event_id, event_type, timestamp, payload FROM events WHERE event_id = ?;",
                    (str(supersedes_id),),
                ).fetchone()
                if old_row:
                    old_p = (
                        json.loads(old_row["payload"])
                        if isinstance(old_row["payload"], str)
                        else old_row["payload"]
                    )
                    old_ts = float(old_row["timestamp"])
                    old_dt = datetime.fromtimestamp(old_ts, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
                    supersession_chain.append(
                        {
                            "relationship": "SUPERSEDES (Older Decision)",
                            "seq": old_row["seq"],
                            "event_id_prefix": old_row["event_id"][:12] + "...",
                            "title": old_p.get("title", "Untitled"),
                            "datetime": old_dt,
                        }
                    )

            # Query KùzuDB for decisions superseding this one
            try:
                g = GraphView(db_path, graph_path=graph_path)
                conn_k = g._get_connection()
                res_sup = conn_k.execute(
                    "MATCH (newer:Decision)-[:SUPERSEDES]->(target:Decision {id: $id}) RETURN newer.id;",
                    {"id": ev_id},
                )
                while res_sup.has_next():
                    nid = str(res_sup.get_next()[0])
                    nrow = conn.execute(
                        "SELECT seq, event_id, event_type, timestamp, payload FROM events WHERE event_id = ?;",
                        (nid,),
                    ).fetchone()
                    if nrow:
                        np = (
                            json.loads(nrow["payload"])
                            if isinstance(nrow["payload"], str)
                            else nrow["payload"]
                        )
                        nts = float(nrow["timestamp"])
                        ndt = datetime.fromtimestamp(nts, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        )
                        supersession_chain.append(
                            {
                                "relationship": "SUPERSEDED BY (Newer Decision)",
                                "seq": nrow["seq"],
                                "event_id_prefix": nrow["event_id"][:12] + "...",
                                "title": np.get("title", "Untitled"),
                                "datetime": ndt,
                            }
                        )
            except Exception:
                pass

            # SQLite fallback for supersession check
            if not any(
                "SUPERSEDED BY" in item["relationship"] for item in supersession_chain
            ):
                newer_rows = conn.execute(
                    "SELECT seq, event_id, event_type, timestamp, payload FROM events WHERE event_type = 'decision' AND (payload LIKE ? OR payload LIKE ?);",
                    (f'%"supersedes_id":"{ev_id}"%', f'%"supersedes_id": "{ev_id}"%'),
                ).fetchall()
                for nr in newer_rows:
                    np = (
                        json.loads(nr["payload"])
                        if isinstance(nr["payload"], str)
                        else nr["payload"]
                    )
                    nts = float(nr["timestamp"])
                    ndt = datetime.fromtimestamp(nts, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
                    supersession_chain.append(
                        {
                            "relationship": "SUPERSEDED BY (Newer Decision)",
                            "seq": nr["seq"],
                            "event_id_prefix": nr["event_id"][:12] + "...",
                            "title": np.get("title", "Untitled"),
                            "datetime": ndt,
                        }
                    )

        # 2. Events involving the same entities
        entity_names: list[tuple[str, str]] = []

        try:
            g = GraphView(db_path, graph_path=graph_path)
            conn_k = g._get_connection()
            res_ent = conn_k.execute(
                "MATCH (ev:Event {id: $id})-[:INVOLVES]->(ent:Entity) RETURN ent.name, ent.type;",
                {"id": ev_id},
            )
            while res_ent.has_next():
                r_e = res_ent.get_next()
                entity_names.append((str(r_e[0]), str(r_e[1])))
        except Exception:
            pass

        if ev_type == "decision":
            for rej in payload.get("rejected", []):
                if rej and (rej, "rejected_alternative") not in entity_names:
                    entity_names.append((str(rej), "rejected_alternative"))
        elif ev_type == "git_commit":
            if payload.get("branch"):
                entity_names.append((str(payload.get("branch")), "branch"))
            for f in payload.get("files", []):
                entity_names.append((str(f), "file"))
        elif ev_type == "file_change":
            if payload.get("file_path"):
                entity_names.append((str(payload.get("file_path")), "file"))

        seen_seqs: set[int] = {seq} if seq is not None else set()

        try:
            g = GraphView(db_path, graph_path=graph_path)
            conn_k = g._get_connection()
            res_other = conn_k.execute(
                """
                MATCH (ev:Event {id: $id})-[:INVOLVES]->(ent:Entity)<-[:INVOLVES]-(other:Event)
                WHERE other.id != $id
                RETURN DISTINCT other.id, ent.name, ent.type LIMIT 25;
                """,
                {"id": ev_id},
            )
            while res_other.has_next():
                row_o = res_other.get_next()
                other_id = str(row_o[0])
                ent_name = str(row_o[1])
                ent_type_str = str(row_o[2])
                erow = conn.execute(
                    "SELECT seq, event_id, event_type, timestamp, payload FROM events WHERE event_id = ?;",
                    (other_id,),
                ).fetchone()
                if erow and erow["seq"] not in seen_seqs:
                    seen_seqs.add(erow["seq"])
                    ep = (
                        json.loads(erow["payload"])
                        if isinstance(erow["payload"], str)
                        else erow["payload"]
                    )
                    ets = float(erow["timestamp"])
                    edt = datetime.fromtimestamp(ets, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
                    entity_events.append(
                        {
                            "seq": erow["seq"],
                            "event_id_prefix": erow["event_id"][:12] + "...",
                            "event_type": erow["event_type"],
                            "title": extract_title_or_message(erow["event_type"], ep),
                            "entity_name": ent_name,
                            "entity_type": ent_type_str,
                            "datetime": edt,
                        }
                    )
        except Exception:
            pass

        if len(entity_events) < 5 and entity_names:
            for ent_name, ent_type_str in entity_names[:10]:
                matches = conn.execute(
                    "SELECT seq, event_id, event_type, timestamp, payload FROM events WHERE seq != ? AND payload LIKE ? LIMIT 5;",
                    (seq or -1, f"%{ent_name}%"),
                ).fetchall()
                for mr in matches:
                    if mr["seq"] not in seen_seqs:
                        seen_seqs.add(mr["seq"])
                        mp = (
                            json.loads(mr["payload"])
                            if isinstance(mr["payload"], str)
                            else mr["payload"]
                        )
                        mts = float(mr["timestamp"])
                        mdt = datetime.fromtimestamp(mts, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        )
                        entity_events.append(
                            {
                                "seq": mr["seq"],
                                "event_id_prefix": mr["event_id"][:12] + "...",
                                "event_type": mr["event_type"],
                                "title": extract_title_or_message(mr["event_type"], mp),
                                "entity_name": ent_name,
                                "entity_type": ent_type_str,
                                "datetime": mdt,
                            }
                        )

        # 3. For a git_commit: its files and repo
        if ev_type == "git_commit":
            repo_path = str(payload.get("repo_path", ""))
            branch = str(payload.get("branch", ""))
            files = list(payload.get("files", []))
            chash = payload.get("commit_hash")
            short_chash = (str(chash)[:10] + "...") if chash else "N/A"
            filtered_cnt = payload.get("filtered_files_count", 0)
            total_cnt = payload.get("total_files_changed", len(files))

            related_files: list[dict[str, Any]] = []
            file_seen_seqs: set[int] = {seq} if seq is not None else set()

            for f in files[:10]:
                fname = Path(f).name
                f_matches = conn.execute(
                    "SELECT seq, event_id, event_type, timestamp, payload FROM events WHERE seq != ? AND (payload LIKE ? OR payload LIKE ?) LIMIT 5;",
                    (seq or -1, f"%{f}%", f"%{fname}%"),
                ).fetchall()
                for fm in f_matches:
                    if fm["seq"] not in file_seen_seqs:
                        file_seen_seqs.add(fm["seq"])
                        fmp = (
                            json.loads(fm["payload"])
                            if isinstance(fm["payload"], str)
                            else fm["payload"]
                        )
                        fmts = float(fm["timestamp"])
                        fmdt = datetime.fromtimestamp(fmts, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        )
                        related_files.append(
                            {
                                "file": f,
                                "seq": fm["seq"],
                                "event_id_prefix": fm["event_id"][:12] + "...",
                                "event_type": fm["event_type"],
                                "title": extract_title_or_message(
                                    fm["event_type"], fmp
                                ),
                                "datetime": fmdt,
                            }
                        )

            commit_details = {
                "repo_path": repo_path,
                "branch": branch,
                "commit_hash_prefix": short_chash,
                "files": files,
                "filtered_files_count": filtered_cnt,
                "total_files_changed": total_cnt,
                "related_file_events": related_files,
            }

    return {
        "supersession_chain": supersession_chain,
        "entity_events": entity_events,
        "commit_details": commit_details,
    }


def get_verify_status(db_path: Path | str) -> dict[str, Any]:
    """Execute twin verify and return sanitized verification dictionary."""
    db_file = Path(db_path)
    if not db_file.exists():
        return {
            "valid": False,
            "verified_count": 0,
            "failed_seq": None,
            "reason": f"Database file does not exist: {db_file}",
        }
    ledger = Ledger(db_path=db_file)
    return ledger.verify_provenance()


def generate_mermaid_graph(
    db_path: Path | str, graph_path: Optional[Path | str] = None
) -> str:
    """Generate Mermaid flowchart TD from KùzuDB decision nodes and edges (with SQLite fallback)."""
    decisions: list[tuple[str, str]] = []
    supersedes: list[tuple[str, str]] = []

    kuzu_success = False
    try:
        g = GraphView(db_path, graph_path=graph_path)
        conn = g._get_connection()
        res = conn.execute("MATCH (d:Decision) RETURN d.id, d.title;")
        while res.has_next():
            row = res.get_next()
            decisions.append((str(row[0]), str(row[1])))

        res_sup = conn.execute(
            "MATCH (d1:Decision)-[:SUPERSEDES]->(d2:Decision) RETURN d1.id, d2.id;"
        )
        while res_sup.has_next():
            row = res_sup.get_next()
            supersedes.append((str(row[0]), str(row[1])))
        kuzu_success = True
    except Exception:
        kuzu_success = False

    if not kuzu_success or not decisions:
        try:
            with sqlite3.connect(str(db_path)) as sconn:
                sconn.row_factory = sqlite3.Row
                rows = sconn.execute(
                    "SELECT event_id, payload FROM events WHERE event_type='decision' ORDER BY seq ASC;"
                ).fetchall()
                decisions.clear()
                supersedes.clear()
                for r in rows:
                    p = (
                        json.loads(r["payload"])
                        if isinstance(r["payload"], str)
                        else r["payload"]
                    )
                    ev_id = str(r["event_id"])
                    title = str(p.get("title", "Untitled Decision"))
                    decisions.append((ev_id, title))
                    sup_id = p.get("supersedes_id")
                    if sup_id:
                        supersedes.append((ev_id, str(sup_id)))
        except Exception:
            pass

    lines = ["flowchart TD"]
    if not decisions:
        lines.append('    Empty["No architectural decisions recorded in ledger"]')
        return "\n".join(lines)

    lines.append('    subgraph Decisions ["Architectural Decisions"]')
    for dev_id, title in decisions:
        nid = "d_" + dev_id.replace("-", "_")
        safe_title = title.replace('"', "'").replace("\n", " ")
        lines.append(f'        {nid}["{safe_title}"]')
    lines.append("    end")

    for s_new, s_old in supersedes:
        n_new = "d_" + s_new.replace("-", "_")
        n_old = "d_" + s_old.replace("-", "_")
        lines.append(f"    {n_new} -->|SUPERSEDES| {n_old}")

    lines.append(
        "    classDef decision fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#f8fafc;"
    )
    for dev_id, _ in decisions:
        nid = "d_" + dev_id.replace("-", "_")
        lines.append(f"    class {nid} decision;")

    return "\n".join(lines)


# --- HTML Page Renderers ---

BASE_CSS = """
:root {
  --bg: #0f172a;
  --surface: #1e293b;
  --surface-hover: #334155;
  --border: #334155;
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --primary: #3b82f6;
  --primary-hover: #2563eb;
  --success: #10b981;
  --danger: #ef4444;
  --warning: #f59e0b;
  --info: #06b6d4;
  --purple: #a855f7;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding: 0;
  margin: 0;
}
header {
  background-color: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 1rem 2rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  z-index: 100;
}
.brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--text);
  text-decoration: none;
}
.brand-pill {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  background: rgba(59, 130, 246, 0.2);
  color: #60a5fa;
  padding: 0.2rem 0.5rem;
  border-radius: 9999px;
  border: 1px solid rgba(59, 130, 246, 0.4);
}
nav {
  display: flex;
  gap: 0.5rem;
}
nav a {
  padding: 0.5rem 1rem;
  border-radius: 0.375rem;
  text-decoration: none;
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--text-muted);
  transition: all 0.15s ease-in-out;
}
nav a:hover {
  background-color: var(--surface-hover);
  color: var(--text);
}
nav a.active {
  background-color: var(--primary);
  color: #ffffff;
}
.security-badge {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.75rem;
  background: rgba(16, 185, 129, 0.15);
  color: #34d399;
  border: 1px solid rgba(16, 185, 129, 0.3);
  padding: 0.3rem 0.6rem;
  border-radius: 9999px;
}
.security-dot {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background-color: var(--success);
}
main {
  max-width: 1100px;
  margin: 2rem auto;
  padding: 0 1.5rem;
}
.card {
  background-color: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}
.card-title {
  font-size: 1.15rem;
  font-weight: 600;
}
.card-title a {
  color: inherit;
  text-decoration: none;
}
.card-title a:hover {
  color: var(--primary);
  text-decoration: underline;
}
.badge {
  display: inline-flex;
  align-items: center;
  padding: 0.2rem 0.5rem;
  font-size: 0.75rem;
  font-weight: 600;
  border-radius: 0.25rem;
}
.badge-active { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
.badge-superseded { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
.badge-signed { background: rgba(16, 185, 129, 0.2); color: #34d399; }
.badge-unsigned { background: rgba(148, 163, 184, 0.2); color: #94a3b8; }
.badge-decision { background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
.badge-commit { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
.badge-file { background: rgba(20, 184, 166, 0.2); color: #2dd4bf; border: 1px solid rgba(20, 184, 166, 0.4); }
.badge-note { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
.badge-artifact { background: rgba(6, 182, 212, 0.2); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4); }

.search-form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-bottom: 2rem;
}
.search-input {
  flex: 1;
  background-color: #0b1120;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 0.75rem 1rem;
  border-radius: 0.375rem;
  font-size: 1rem;
}
.search-input:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3);
}

.filter-bar {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
  background-color: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 0.75rem 1rem;
  margin-bottom: 1.5rem;
}
.filter-group {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}
.filter-label {
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-muted);
}
.filter-select {
  background-color: #0b1120;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 0.4rem 0.75rem;
  border-radius: 0.375rem;
  font-size: 0.85rem;
}
.filter-select:focus {
  outline: none;
  border-color: var(--primary);
}

.btn {
  background-color: var(--primary);
  color: #fff;
  border: none;
  padding: 0.75rem 1.5rem;
  border-radius: 0.375rem;
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  transition: background-color 0.15s ease-in-out;
}
.btn:hover { background-color: var(--primary-hover); }
.btn-sm {
  padding: 0.35rem 0.75rem;
  font-size: 0.8rem;
  background-color: var(--surface-hover);
  color: var(--text);
}
.btn-sm:hover { background-color: #475569; }

.rank-capsule {
  display: inline-flex;
  gap: 0.5rem;
  background-color: #0b1120;
  border: 1px solid var(--border);
  padding: 0.25rem 0.6rem;
  border-radius: 0.375rem;
  font-size: 0.8rem;
  font-family: monospace;
}
.rank-item { color: var(--text-muted); }
.rank-val { color: var(--text); font-weight: 600; }
.score-pill {
  background: rgba(59, 130, 246, 0.2);
  color: #93c5fd;
  padding: 0.25rem 0.5rem;
  border-radius: 0.375rem;
  font-weight: 600;
  font-family: monospace;
  font-size: 0.85rem;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.5rem;
}
th {
  text-align: left;
  padding: 0.75rem 1rem;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}
td {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid rgba(51, 65, 85, 0.5);
  font-size: 0.9rem;
}
tr:hover td { background-color: rgba(51, 65, 85, 0.3); }

.pre-box {
  background-color: #0b1120;
  border: 1px solid var(--border);
  border-radius: 0.375rem;
  padding: 1rem;
  font-family: monospace;
  font-size: 0.85rem;
  color: #e2e8f0;
  overflow-x: auto;
  white-space: pre-wrap;
}

/* Metadata Grid */
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.meta-box {
  background: #0b1120;
  border: 1px solid var(--border);
  border-radius: 0.375rem;
  padding: 0.75rem 1rem;
}
.meta-label {
  font-size: 0.75rem;
  text-transform: uppercase;
  color: var(--text-muted);
  font-weight: 600;
  margin-bottom: 0.25rem;
}
.meta-val {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text);
  font-family: monospace;
  word-break: break-all;
}

/* Related Items */
.related-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.related-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1rem;
  background: #0b1120;
  border: 1px solid var(--border);
  border-radius: 0.375rem;
  text-decoration: none;
  color: inherit;
  transition: all 0.15s ease-in-out;
}
.related-card:hover {
  border-color: var(--primary);
  background: #131d33;
}

footer {
  text-align: center;
  padding: 2rem;
  font-size: 0.8rem;
  color: var(--text-muted);
  border-top: 1px solid var(--border);
  margin-top: 4rem;
}
"""


def render_page(title: str, active_tab: str, content_html: str) -> str:
    """Wrap content in base HTML skeleton with header navigation."""
    nav_tabs = [
        ("search", "Search", "/search"),
        ("timeline", "Timeline", "/timeline"),
        ("verify", "Verify", "/verify"),
        ("graph", "Graph", "/graph"),
    ]
    nav_links_html = "".join(
        f'<a href="{path}" class="{"active" if key == active_tab else ""}">{name}</a>'
        for key, name, path in nav_tabs
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)} - Aethelgard Viewer</title>
  <style>{BASE_CSS}</style>
</head>
<body>
  <header>
    <a href="/search" class="brand">
      <span>🛡️ Aethelgard</span>
      <span class="brand-pill">Viewer</span>
    </a>
    <nav>{nav_links_html}</nav>
    <div class="security-badge" title="Strictly bound to local loopback 127.0.0.1 (Read-Only)">
      <span class="security-dot"></span>
      <span>127.0.0.1 (Read-Only)</span>
    </div>
  </header>
  <main>
    {content_html}
  </main>
  <footer>
    Project Aethelgard &bull; Sovereign Cognitive Twin &bull; Cryptographic Provenance Ledger
  </footer>
</body>
</html>
"""


def render_search_page(
    db_path: Path | str,
    query: str = "",
    event_type: Optional[str] = None,
    signed: Optional[str] = None,
) -> str:
    """Render Search View: input form, type & signed filters, and 3-way hybrid RRF ranking results."""
    clean_q = query.strip()
    curr_type = (event_type or "").strip()
    curr_signed = (signed or "all").strip().lower()

    available_types = get_available_event_types(db_path)

    # Options for Type filter
    type_options = [
        '<option value="all"'
        + (" selected" if not curr_type or curr_type.lower() == "all" else "")
        + ">All Event Types</option>"
    ]
    for t in available_types:
        sel = " selected" if curr_type.lower() == t.lower() else ""
        type_options.append(
            f'<option value="{html.escape(t)}"{sel}>{html.escape(t)}</option>'
        )
    type_select_html = "".join(type_options)

    # Options for Signed filter
    signed_options = [
        f'<option value="all"{" selected" if curr_signed == "all" else ""}>All (Signed & Unsigned)</option>',
        f'<option value="yes"{" selected" if curr_signed == "yes" else ""}>Signed (Yes)</option>',
        f'<option value="no"{" selected" if curr_signed == "no" else ""}>Unsigned (No)</option>',
    ]
    signed_select_html = "".join(signed_options)

    results_html = ""

    if clean_q:
        try:
            ranker = HybridRRFRanker(db_path=db_path)
            raw_hits = ranker.search(query=clean_q, limit=50)

            # Retrieve signed status for candidate hits from SQLite
            hit_seqs = [h["seq"] for h in raw_hits if "seq" in h]
            signed_map: dict[int, bool] = {}
            if hit_seqs:
                with sqlite3.connect(str(db_path)) as conn:
                    conn.row_factory = sqlite3.Row
                    placeholders = ",".join("?" for _ in hit_seqs)
                    rows = conn.execute(
                        f"""SELECT seq,
                                  (signature IS NOT NULL AND length(signature) > 0 AND pub_key IS NOT NULL AND length(pub_key) > 0) AS is_signed
                           FROM events
                           WHERE seq IN ({placeholders});""",
                        hit_seqs,
                    ).fetchall()
                    signed_map = {r["seq"]: bool(r["is_signed"]) for r in rows}

            # Filter hits by event_type
            filtered_hits = raw_hits
            if curr_type and curr_type.lower() not in ("all", ""):
                filtered_hits = [
                    h
                    for h in filtered_hits
                    if str(h.get("event_type", "")).lower() == curr_type.lower()
                ]

            # Filter hits by signed status
            if curr_signed in ("yes", "true", "1"):
                filtered_hits = [
                    h
                    for h in filtered_hits
                    if signed_map.get(h.get("seq"), False) is True
                ]
            elif curr_signed in ("no", "false", "0"):
                filtered_hits = [
                    h
                    for h in filtered_hits
                    if signed_map.get(h.get("seq"), False) is False
                ]

            if filtered_hits:
                filter_desc = []
                if curr_type and curr_type.lower() != "all":
                    filter_desc.append(f"Type: {html.escape(curr_type)}")
                if curr_signed != "all":
                    filter_desc.append(
                        f"Signed: {'Yes' if curr_signed == 'yes' else 'No'}"
                    )
                filter_suffix = (
                    f" (Filters: {', '.join(filter_desc)})" if filter_desc else ""
                )

                results_html += (
                    f'<p style="margin-bottom:1rem; color:var(--text-muted);">'
                    f'Found <strong>{len(filtered_hits)}</strong> results for "<strong>{html.escape(clean_q)}</strong>"{filter_suffix}:</p>'
                )
                for h in filtered_hits:
                    ev_type = h.get("event_type", "unknown")
                    payload = h.get("payload", {})
                    title = extract_title_or_message(ev_type, payload)
                    is_sup = h.get("is_superseded", False)
                    ranks = h.get("ranks", {})
                    score = h.get("score", 0.0)
                    seq = h.get("seq", "?")
                    ts = h.get("timestamp", 0)
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
                    is_hit_signed = signed_map.get(seq, False)

                    bm25_str = (
                        f"#{ranks.get('BM25')}"
                        if ranks.get("BM25") is not None
                        else "&mdash;"
                    )
                    vec_str = (
                        f"#{ranks.get('Vec')}"
                        if ranks.get("Vec") is not None
                        else "&mdash;"
                    )
                    graph_str = (
                        f"#{ranks.get('Graph')}"
                        if ranks.get("Graph") is not None
                        else "&mdash;"
                    )

                    type_badge_cls = (
                        f"badge-{ev_type}"
                        if ev_type in ("decision", "commit", "file", "note", "artifact")
                        else "badge-commit"
                    )
                    if ev_type == "git_commit":
                        type_badge_cls = "badge-commit"
                    elif ev_type == "file_change":
                        type_badge_cls = "badge-file"

                    sup_badge = (
                        '<span class="badge badge-superseded">Superseded</span>'
                        if is_sup
                        else '<span class="badge badge-active">Active</span>'
                    )
                    hit_signed_badge = (
                        '<span class="badge badge-signed">&#10003; Yes</span>'
                        if is_hit_signed
                        else '<span class="badge badge-unsigned">&#10007; No</span>'
                    )

                    details_block = ""
                    if ev_type == "decision":
                        ctx = payload.get("context", "")
                        dec = payload.get("decision", "")
                        rej = payload.get("rejected", [])
                        details_block = f"""
                        <div style="margin-top:0.5rem; font-size:0.9rem; color:#cbd5e1;">
                          <p><strong>Decision:</strong> {html.escape(dec)}</p>
                          <p style="margin-top:0.25rem;"><strong>Context:</strong> {html.escape(ctx)}</p>
                          {'<p style="margin-top:0.25rem; color:#94a3b8;"><strong>Rejected:</strong> ' + html.escape(", ".join(rej)) + '</p>' if rej else ''}
                        </div>
                        """
                    elif ev_type == "git_commit":
                        files = payload.get("files", [])
                        author = payload.get("author", "")
                        details_block = f"""
                        <div style="margin-top:0.5rem; font-size:0.85rem; color:#94a3b8;">
                          <span>Author: {html.escape(author)}</span> &bull; <span>Files: {html.escape(', '.join(files[:5]))}{' (+' + str(len(files)-5) + ' more)' if len(files) > 5 else ''}</span>
                        </div>
                        """
                    elif ev_type == "file_change":
                        snippet = payload.get("snippet", "")
                        if snippet:
                            details_block = f'<div class="pre-box" style="margin-top:0.5rem; padding:0.5rem;">{html.escape(snippet)}</div>'

                    results_html += f"""
                    <div class="card">
                      <div class="card-header">
                        <div style="display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
                          <a href="/event/{seq}" style="color:var(--text-muted); font-size:0.85rem; font-family:monospace; text-decoration:none;">#{seq}</a>
                          <span class="badge {type_badge_cls}">{html.escape(ev_type)}</span>
                          <h3 class="card-title"><a href="/event/{seq}">{html.escape(title)}</a></h3>
                          {sup_badge}
                          {hit_signed_badge}
                        </div>
                        <div style="display:flex; align-items:center; gap:0.5rem;">
                          <span class="score-pill">Score: {score:.8f}</span>
                          <a href="/event/{seq}" class="btn btn-sm" style="text-decoration:none;">Details &rarr;</a>
                        </div>
                      </div>
                      <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap; margin-bottom:0.5rem;">
                        <span class="rank-capsule">
                          <span class="rank-item">BM25: <span class="rank-val">{bm25_str}</span></span>
                          <span class="rank-item">|</span>
                          <span class="rank-item">Vec: <span class="rank-val">{vec_str}</span></span>
                          <span class="rank-item">|</span>
                          <span class="rank-item">Graph: <span class="rank-val">{graph_str}</span></span>
                        </span>
                        <span style="font-size:0.8rem; color:var(--text-muted);">{dt}</span>
                      </div>
                      {details_block}
                    </div>
                    """
            else:
                results_html = f"""
                <div class="card" style="text-align:center; padding:3rem 1rem;">
                  <p style="color:var(--text-muted); font-size:1.1rem;">No matching events found for "<strong>{html.escape(clean_q)}</strong>"</p>
                  <p style="color:#64748b; font-size:0.9rem; margin-top:0.5rem;">Try adjusting your query or resetting event type / signed filters.</p>
                </div>
                """
        except Exception as e:
            results_html = f"""
            <div class="card" style="border-color:var(--danger); padding:1.5rem;">
              <h3 style="color:var(--danger); margin-bottom:0.5rem;">Search Execution Error</h3>
              <p style="color:var(--text-muted); font-family:monospace;">{html.escape(str(e))}</p>
            </div>
            """
    else:
        results_html = """
        <div class="card" style="text-align:center; padding:3rem 1rem;">
          <p style="color:var(--text-muted); font-size:1.1rem;">Enter a query above to execute 3-Way Reciprocal Rank Fusion.</p>
          <p style="color:#64748b; font-size:0.9rem; margin-top:0.5rem;">Fuses lexical BM25 (FTS5), 768d semantic vectors (sqlite-vec), and episodic graph nodes (KùzuDB) with supersession and signed filters.</p>
        </div>
        """

    content = f"""
    <div style="margin-bottom:1.5rem;">
      <h1 style="font-size:1.75rem; font-weight:700; margin-bottom:0.5rem;">Hybrid RRF Recall</h1>
      <p style="color:var(--text-muted);">Unified 3-Way Reciprocal Rank Fusion search across lexical, semantic vector, and episodic graph views.</p>
    </div>
    <form class="search-form" method="get" action="/search">
      <div style="display:flex; gap:0.5rem;">
        <input type="text" name="q" class="search-input" value="{html.escape(clean_q)}" placeholder="Search decisions, commits, notes, artifacts (e.g. SQLite, ADR-001, signing)..." autofocus>
        <button type="submit" class="btn">Search</button>
      </div>
      <div class="filter-bar" style="margin-bottom:0; padding:0.5rem 0.75rem;">
        <div class="filter-group">
          <label class="filter-label" for="srch-type">Filter Type:</label>
          <select id="srch-type" name="type" class="filter-select">
            {type_select_html}
          </select>
        </div>
        <div class="filter-group">
          <label class="filter-label" for="srch-signed">Signed Status:</label>
          <select id="srch-signed" name="signed" class="filter-select">
            {signed_select_html}
          </select>
        </div>
        <button type="submit" class="btn btn-sm">Apply Filters</button>
        <a href="/search" class="btn btn-sm" style="background:#334155;">Reset</a>
      </div>
    </form>
    {results_html}
    """
    return render_page("Hybrid RRF Search", "search", content)


def render_timeline_page(
    db_path: Path | str,
    event_type: Optional[str] = None,
    signed: Optional[str] = None,
) -> str:
    """Render Timeline View: chronological events by seq with type, title/message, signed (Yes/No), and filters."""
    curr_type = (event_type or "").strip()
    curr_signed = (signed or "all").strip().lower()

    events = get_timeline_events(
        db_path, limit=100, event_type=curr_type, signed=curr_signed
    )
    available_types = get_available_event_types(db_path)

    # Build options for Type select
    type_options = [
        '<option value="all"'
        + (" selected" if not curr_type or curr_type.lower() == "all" else "")
        + ">All Event Types</option>"
    ]
    for t in available_types:
        sel = " selected" if curr_type.lower() == t.lower() else ""
        type_options.append(
            f'<option value="{html.escape(t)}"{sel}>{html.escape(t)}</option>'
        )
    type_select_html = "".join(type_options)

    # Build options for Signed select
    signed_options = [
        f'<option value="all"{" selected" if curr_signed == "all" else ""}>All (Signed & Unsigned)</option>',
        f'<option value="yes"{" selected" if curr_signed == "yes" else ""}>Signed (Yes)</option>',
        f'<option value="no"{" selected" if curr_signed == "no" else ""}>Unsigned (No)</option>',
    ]
    signed_select_html = "".join(signed_options)

    active_filters = []
    if curr_type and curr_type.lower() != "all":
        active_filters.append(f"Type: {html.escape(curr_type)}")
    if curr_signed in ("yes", "no"):
        active_filters.append(f"Signed: {'Yes' if curr_signed == 'yes' else 'No'}")
    active_filter_html = ""
    if active_filters:
        active_filter_html = f'<div style="margin-bottom:0.75rem; font-size:0.85rem; color:var(--text-muted);">Active Filter: <strong>{", ".join(active_filters)}</strong></div>'

    rows_html = ""
    for ev in events:
        seq = ev["seq"]
        ev_type = ev["event_type"]
        title = ev["title"]
        dt = ev["datetime"]
        ev_signed = ev["signed"]

        type_badge_cls = (
            f"badge-{ev_type}"
            if ev_type in ("decision", "commit", "file", "note", "artifact")
            else "badge-commit"
        )
        if ev_type == "git_commit":
            type_badge_cls = "badge-commit"
        elif ev_type == "file_change":
            type_badge_cls = "badge-file"

        signed_badge = (
            '<span class="badge badge-signed">&#10003; Yes</span>'
            if ev_signed
            else '<span class="badge badge-unsigned">&#10007; No</span>'
        )

        rows_html += f"""
        <tr>
          <td style="font-family:monospace; font-weight:600;"><a href="/event/{seq}" style="color:var(--primary); text-decoration:none;">#{seq}</a></td>
          <td><span class="badge {type_badge_cls}">{html.escape(ev_type)}</span></td>
          <td style="font-weight:500;"><a href="/event/{seq}" style="color:inherit; text-decoration:none;">{html.escape(title)}</a></td>
          <td style="color:var(--text-muted); font-size:0.85rem; white-space:nowrap;">{dt}</td>
          <td>{signed_badge}</td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="5" style="text-align:center; padding:2rem; color:var(--text-muted);">No matching events found. Try adjusting your filters.</td></tr>'

    content = f"""
    <div style="margin-bottom:1.5rem;">
      <h1 style="font-size:1.75rem; font-weight:700; margin-bottom:0.5rem;">Event Timeline</h1>
      <p style="color:var(--text-muted);">Immutable audit trail of recent events by sequence number with cryptographic signature status.</p>
    </div>

    <!-- Timeline Filters Bar -->
    <form class="filter-bar" method="get" action="/timeline">
      <div class="filter-group">
        <label class="filter-label" for="tl-type">Event Type:</label>
        <select id="tl-type" name="type" class="filter-select">
          {type_select_html}
        </select>
      </div>
      <div class="filter-group">
        <label class="filter-label" for="tl-signed">Signed Status:</label>
        <select id="tl-signed" name="signed" class="filter-select">
          {signed_select_html}
        </select>
      </div>
      <button type="submit" class="btn btn-sm">Filter</button>
      <a href="/timeline" class="btn btn-sm" style="background:#334155;">Reset</a>
      <span style="font-size:0.85rem; color:var(--text-muted); margin-left:auto;">
        Showing <strong>{len(events)}</strong> event(s)
      </span>
    </form>
    {active_filter_html}

    <div class="card" style="padding:0; overflow:hidden;">
      <table>
        <thead>
          <tr>
            <th style="width:60px;">Seq</th>
            <th style="width:120px;">Type</th>
            <th>Title / Message</th>
            <th style="width:180px;">Timestamp</th>
            <th style="width:100px;">Signed</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
    """
    return render_page("Event Timeline", "timeline", content)


def render_event_detail_page(
    db_path: Path | str, seq: int, graph_path: Optional[Path | str] = None
) -> Optional[str]:
    """Render Decision and Event Detail View: full payload, hash prefixes only, and related events."""
    event = get_event_detail(db_path, seq)
    if not event:
        return None

    related = get_related_events(db_path, event, graph_path=graph_path)

    ev_id = event["event_id"]
    ev_type = event["event_type"]
    title = event["title"]
    dt = event["datetime"]
    is_signed = event["signed"]
    prev_h_prefix = event["prev_hash_prefix"]
    curr_h_prefix = event["curr_hash_prefix"]
    ev_id_prefix = event["event_id_prefix"]
    payload = event["payload"]

    type_badge_cls = (
        f"badge-{ev_type}"
        if ev_type in ("decision", "commit", "file", "note", "artifact")
        else "badge-commit"
    )
    if ev_type == "git_commit":
        type_badge_cls = "badge-commit"
    elif ev_type == "file_change":
        type_badge_cls = "badge-file"

    signed_badge = (
        '<span class="badge badge-signed">&#10003; Signed: Yes</span>'
        if is_signed
        else '<span class="badge badge-unsigned">&#10007; Signed: No</span>'
    )

    # 1. Payload Section Construction
    payload_html = ""
    if ev_type == "decision":
        dec_title = payload.get("title", "")
        dec_context = payload.get("context", "")
        dec_choice = payload.get("decision", "")
        rejected_list = payload.get("rejected", [])
        sup_id = payload.get("supersedes_id")

        superseded_by_list = [
            item
            for item in related["supersession_chain"]
            if "SUPERSEDED BY" in item["relationship"]
        ]
        supersedes_older_list = [
            item
            for item in related["supersession_chain"]
            if "SUPERSEDES" in item["relationship"]
        ]

        decision_status_badge = (
            '<span class="badge badge-superseded">Superseded</span>'
            if superseded_by_list
            else '<span class="badge badge-active">Active</span>'
        )

        rej_html = ""
        if rejected_list:
            rej_html = "".join(
                f'<li style="margin-left:1.25rem; margin-top:0.25rem;">{html.escape(r)}</li>'
                for r in rejected_list
            )
        else:
            rej_html = '<span style="color:var(--text-muted);">None specified</span>'

        sup_link_html = (
            '<span style="color:var(--text-muted);">None (Root decision)</span>'
        )
        if supersedes_older_list:
            older = supersedes_older_list[0]
            sup_link_html = f'<a href="/event/{older["seq"]}" style="color:var(--primary); font-weight:600;">#{older["seq"]} &mdash; {html.escape(older["title"])}</a>'
        elif sup_id:
            sup_link_html = f'<span style="font-family:monospace; color:var(--text-muted);">{html.escape(str(sup_id)[:12])}...</span>'

        superseded_by_html = (
            '<span style="color:#34d399; font-weight:600;">None (Current & Active)</span>'
        )
        if superseded_by_list:
            newer = superseded_by_list[0]
            superseded_by_html = f'<a href="/event/{newer["seq"]}" style="color:#f87171; font-weight:600;">Superseded by #{newer["seq"]} &mdash; {html.escape(newer["title"])}</a>'

        payload_html = f"""
        <div class="card">
          <div class="card-header">
            <h2 style="font-size:1.2rem; font-weight:700;">Architectural Decision Record</h2>
            {decision_status_badge}
          </div>
          <div style="display:flex; flex-direction:column; gap:1rem;">
            <div>
              <div class="meta-label">Title</div>
              <div style="font-size:1.1rem; font-weight:600; color:var(--text);">{html.escape(dec_title)}</div>
            </div>
            <div>
              <div class="meta-label">Decision</div>
              <div style="font-size:0.95rem; line-height:1.6; color:#e2e8f0; background:#0b1120; border:1px solid var(--border); border-radius:0.375rem; padding:1rem;">
                {html.escape(dec_choice)}
              </div>
            </div>
            <div>
              <div class="meta-label">Context & Rationale</div>
              <div style="font-size:0.95rem; line-height:1.6; color:#cbd5e1;">{html.escape(dec_context)}</div>
            </div>
            <div>
              <div class="meta-label">Rejected Alternatives</div>
              <ul style="color:#cbd5e1; font-size:0.95rem;">{rej_html}</ul>
            </div>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:1rem; border-top:1px solid var(--border); padding-top:1rem;">
              <div>
                <div class="meta-label">Supersedes ID</div>
                <div>{sup_link_html}</div>
              </div>
              <div>
                <div class="meta-label">What Superseded It</div>
                <div>{superseded_by_html}</div>
              </div>
            </div>
          </div>
        </div>
        """

    elif ev_type == "git_commit":
        commit_msg = payload.get("message", "")
        author = payload.get("author", "")
        branch = payload.get("branch", "")
        repo_path = payload.get("repo_path", "")
        files = payload.get("files", [])
        chash = (payload.get("commit_hash") or "")[:10]
        short_chash = (chash + "...") if chash else "N/A"
        filtered_cnt = payload.get("filtered_files_count", 0)
        total_cnt = payload.get("total_files_changed", len(files))

        files_list_html = "".join(
            f'<li style="margin-left:1.25rem; font-family:monospace; font-size:0.85rem; margin-top:0.25rem;">{html.escape(f)}</li>'
            for f in files
        ) or '<li style="color:var(--text-muted);">None</li>'

        payload_html = f"""
        <div class="card">
          <div class="card-header">
            <h2 style="font-size:1.2rem; font-weight:700;">Git Commit Payload</h2>
            <span class="badge badge-commit">{html.escape(branch or "commit")}</span>
          </div>
          <div style="display:flex; flex-direction:column; gap:1rem;">
            <div>
              <div class="meta-label">Commit Message</div>
              <div style="font-size:1.05rem; font-weight:600; color:var(--text);">{html.escape(commit_msg)}</div>
            </div>
            <div class="meta-grid" style="margin-bottom:0;">
              <div class="meta-box">
                <div class="meta-label">Commit Hash (Prefix)</div>
                <div class="meta-val">{html.escape(short_chash)}</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">Author</div>
                <div class="meta-val" style="font-family:inherit; font-size:0.9rem;">{html.escape(author)}</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">Branch</div>
                <div class="meta-val">{html.escape(branch or "N/A")}</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">Total / Filtered Files</div>
                <div class="meta-val">{total_cnt} total / {filtered_cnt} filtered</div>
              </div>
            </div>
            <div>
              <div class="meta-label">Repository Path</div>
              <div class="pre-box" style="padding:0.5rem 0.75rem;">{html.escape(repo_path or "N/A")}</div>
            </div>
            <div>
              <div class="meta-label">Changed Files ({len(files)})</div>
              <ul style="color:#cbd5e1; max-height:200px; overflow-y:auto; background:#0b1120; border:1px solid var(--border); border-radius:0.375rem; padding:0.75rem 1rem;">
                {files_list_html}
              </ul>
            </div>
          </div>
        </div>
        """

    elif ev_type == "file_change":
        fpath = payload.get("file_path", "")
        abspath = payload.get("absolute_path", "")
        change_t = payload.get("change_type", "")
        size_b = payload.get("size_bytes", 0)
        snippet = payload.get("snippet", "")
        chash = payload.get("content_hash", "")
        chash_prefix = (chash[:12] + "...") if chash else "N/A"

        payload_html = f"""
        <div class="card">
          <div class="card-header">
            <h2 style="font-size:1.2rem; font-weight:700;">File Change Event</h2>
            <span class="badge badge-file">{html.escape(change_t)}</span>
          </div>
          <div style="display:flex; flex-direction:column; gap:1rem;">
            <div class="meta-grid" style="margin-bottom:0;">
              <div class="meta-box">
                <div class="meta-label">Relative File Path</div>
                <div class="meta-val">{html.escape(fpath)}</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">Change Type</div>
                <div class="meta-val">{html.escape(change_t)}</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">File Size</div>
                <div class="meta-val">{size_b} bytes</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">Content Hash Prefix</div>
                <div class="meta-val">{html.escape(chash_prefix)}</div>
              </div>
            </div>
            <div>
              <div class="meta-label">Absolute Path</div>
              <div class="pre-box" style="padding:0.5rem 0.75rem;">{html.escape(abspath)}</div>
            </div>
            {'<div><div class="meta-label">Snippet</div><div class="pre-box">' + html.escape(snippet) + '</div></div>' if snippet else ''}
          </div>
        </div>
        """

    elif ev_type == "note":
        text_content = payload.get("text", "")
        payload_html = f"""
        <div class="card">
          <div class="card-header">
            <h2 style="font-size:1.2rem; font-weight:700;">Research / Engineering Note</h2>
            <span class="badge badge-note">note</span>
          </div>
          <div>
            <div class="meta-label">Note Content</div>
            <div class="pre-box">{html.escape(text_content)}</div>
          </div>
        </div>
        """

    elif ev_type == "execution_artifact":
        action_t = payload.get("action_type", "")
        status_val = payload.get("status", "")
        caused_by = payload.get("caused_by_id", "")
        inputs = payload.get("inputs", {})
        outputs = payload.get("outputs", {})

        payload_html = f"""
        <div class="card">
          <div class="card-header">
            <h2 style="font-size:1.2rem; font-weight:700;">Execution Artifact</h2>
            <span class="badge badge-artifact">{html.escape(status_val or "artifact")}</span>
          </div>
          <div style="display:flex; flex-direction:column; gap:1rem;">
            <div class="meta-grid" style="margin-bottom:0;">
              <div class="meta-box">
                <div class="meta-label">Action Type</div>
                <div class="meta-val">{html.escape(action_t)}</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">Status</div>
                <div class="meta-val">{html.escape(status_val)}</div>
              </div>
              <div class="meta-box">
                <div class="meta-label">Caused By ID (Prefix)</div>
                <div class="meta-val">{html.escape((caused_by[:12] + '...') if caused_by else 'None')}</div>
              </div>
            </div>
            <div>
              <div class="meta-label">Inputs</div>
              <div class="pre-box">{html.escape(json.dumps(inputs, indent=2))}</div>
            </div>
            <div>
              <div class="meta-label">Outputs</div>
              <div class="pre-box">{html.escape(json.dumps(outputs, indent=2))}</div>
            </div>
          </div>
        </div>
        """

    else:
        payload_html = f"""
        <div class="card">
          <div class="card-header">
            <h2 style="font-size:1.2rem; font-weight:700;">Event Payload</h2>
            <span class="badge badge-commit">{html.escape(ev_type)}</span>
          </div>
          <div class="pre-box">{html.escape(json.dumps(payload, indent=2))}</div>
        </div>
        """

    # 2. Related Events Section
    supersession_html = ""
    if related["supersession_chain"]:
        chain_cards = []
        for sitem in related["supersession_chain"]:
            rel_label = sitem["relationship"]
            is_newer = "NEWER" in rel_label or "SUPERSEDED BY" in rel_label
            badge_cls = "badge-superseded" if is_newer else "badge-active"
            chain_cards.append(
                f"""
                <a href="/event/{sitem['seq']}" class="related-card">
                  <div style="display:flex; align-items:center; gap:0.75rem;">
                    <span class="badge {badge_cls}">{html.escape(rel_label)}</span>
                    <span style="font-weight:600; color:var(--text);">#{sitem['seq']} &mdash; {html.escape(sitem['title'])}</span>
                  </div>
                  <span style="font-size:0.8rem; color:var(--text-muted);">{sitem['datetime']}</span>
                </a>
                """
            )
        supersession_html = "".join(chain_cards)
    elif ev_type == "decision":
        supersession_html = '<p style="color:var(--text-muted); font-size:0.9rem;">No supersession relationships recorded (Root decision).</p>'

    entity_events_html = ""
    if related["entity_events"]:
        ent_cards = []
        for eitem in related["entity_events"]:
            ent_type_badge = (
                f"badge-{eitem['event_type']}"
                if eitem["event_type"] in ("decision", "commit", "file", "note", "artifact")
                else "badge-commit"
            )
            if eitem["event_type"] == "git_commit":
                ent_type_badge = "badge-commit"
            elif eitem["event_type"] == "file_change":
                ent_type_badge = "badge-file"

            ent_cards.append(
                f"""
                <a href="/event/{eitem['seq']}" class="related-card">
                  <div style="display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
                    <span style="font-family:monospace; color:var(--text-muted); font-size:0.85rem;">#{eitem['seq']}</span>
                    <span class="badge {ent_type_badge}">{html.escape(eitem['event_type'])}</span>
                    <span style="font-weight:500; color:var(--text);">{html.escape(eitem['title'])}</span>
                    <span style="font-size:0.75rem; color:#60a5fa; background:rgba(59, 130, 246, 0.15); padding:0.15rem 0.4rem; border-radius:0.25rem;">
                      via {html.escape(eitem['entity_type'])}: {html.escape(eitem['entity_name'][:30])}
                    </span>
                  </div>
                  <span style="font-size:0.8rem; color:var(--text-muted); white-space:nowrap;">{eitem['datetime']}</span>
                </a>
                """
            )
        entity_events_html = "".join(ent_cards)
    else:
        entity_events_html = '<p style="color:var(--text-muted); font-size:0.9rem;">No other events currently share entities with this event.</p>'

    commit_rel_html = ""
    if ev_type == "git_commit" and related.get("commit_details"):
        cd = related["commit_details"]
        rel_files = cd.get("related_file_events", [])
        if rel_files:
            file_cards = []
            for rf in rel_files:
                fbadge_cls = (
                    "badge-file" if rf["event_type"] == "file_change" else "badge-commit"
                )
                file_cards.append(
                    f"""
                    <a href="/event/{rf['seq']}" class="related-card">
                      <div style="display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
                        <span style="font-family:monospace; color:var(--text-muted); font-size:0.85rem;">#{rf['seq']}</span>
                        <span class="badge {fbadge_cls}">{html.escape(rf['event_type'])}</span>
                        <span style="font-weight:500; color:var(--text);">{html.escape(rf['title'])}</span>
                        <span style="font-size:0.75rem; color:#2dd4bf; background:rgba(20, 184, 166, 0.15); padding:0.15rem 0.4rem; border-radius:0.25rem;">
                          file: {html.escape(Path(rf['file']).name)}
                        </span>
                      </div>
                      <span style="font-size:0.8rem; color:var(--text-muted); white-space:nowrap;">{rf['datetime']}</span>
                    </a>
                    """
                )
            commit_rel_html = f"""
            <div style="margin-top:1.5rem;">
              <h3 style="font-size:1rem; font-weight:600; margin-bottom:0.75rem; color:var(--text);">Events Involving Changed Files</h3>
              <div class="related-list">{ "".join(file_cards) }</div>
            </div>
            """

    content = f"""
    <div style="margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
      <div style="display:flex; gap:0.5rem;">
        <a href="/timeline" class="btn btn-sm">&larr; Timeline</a>
        <a href="/search" class="btn btn-sm">&larr; Search</a>
      </div>
      <div style="display:flex; gap:0.5rem; align-items:center;">
        <span class="badge {type_badge_cls}">{html.escape(ev_type)}</span>
        {signed_badge}
      </div>
    </div>

    <!-- Header Section -->
    <div style="margin-bottom:1.5rem;">
      <div style="display:flex; align-items:baseline; gap:0.75rem; flex-wrap:wrap;">
        <span style="color:var(--text-muted); font-size:1.25rem; font-family:monospace; font-weight:700;">#{seq}</span>
        <h1 style="font-size:1.75rem; font-weight:700; color:var(--text);">{html.escape(title)}</h1>
      </div>
      <p style="color:var(--text-muted); font-size:0.9rem; margin-top:0.25rem;">Recorded at {dt}</p>
    </div>

    <!-- Provenance & Hash Prefixes -->
    <div class="card">
      <div class="card-header">
        <h2 style="font-size:1.1rem; font-weight:600;">Cryptographic Provenance (BLAKE3 & Ed25519)</h2>
        <span style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">Privacy-Preserving Prefixes</span>
      </div>
      <div class="meta-grid">
        <div class="meta-box">
          <div class="meta-label">Sequence Number</div>
          <div class="meta-val">#{seq}</div>
        </div>
        <div class="meta-box">
          <div class="meta-label">Event ID Prefix</div>
          <div class="meta-val">{html.escape(ev_id_prefix)}</div>
        </div>
        <div class="meta-box">
          <div class="meta-label">BLAKE3 Current Hash (Prefix)</div>
          <div class="meta-val">{html.escape(curr_h_prefix)}</div>
        </div>
        <div class="meta-box">
          <div class="meta-label">BLAKE3 Previous Hash (Prefix)</div>
          <div class="meta-val">{html.escape(prev_h_prefix)}</div>
        </div>
      </div>
      <div style="font-size:0.8rem; color:var(--text-muted); border-top:1px solid var(--border); padding-top:0.75rem; display:flex; justify-content:space-between; align-items:center;">
        <span>Ed25519 Digital Signature: <strong>{'Verified Intact' if is_signed else 'Unsigned Event'}</strong></span>
        <span>Full signatures and private keys withheld by privacy policy.</span>
      </div>
    </div>

    <!-- Payload Details -->
    {payload_html}

    <!-- Related Events -->
    <div class="card">
      <div class="card-header">
        <h2 style="font-size:1.2rem; font-weight:700;">Related Events (Episodic Graph & Ledger)</h2>
      </div>

      <!-- Supersession Chain Section -->
      { '<div style="margin-bottom:1.5rem;"><h3 style="font-size:1rem; font-weight:600; margin-bottom:0.75rem; color:var(--text);">Supersession Chain</h3><div class="related-list">' + supersession_html + '</div></div>' if supersession_html else '' }

      <!-- Entity Sharing Events -->
      <div>
        <h3 style="font-size:1rem; font-weight:600; margin-bottom:0.75rem; color:var(--text);">Events Involving Common Entities</h3>
        <div class="related-list">
          {entity_events_html}
        </div>
      </div>

      <!-- Git Commit File Relations -->
      {commit_rel_html}
    </div>
    """
    return render_page(f"Event #{seq}: {title}", "timeline", content)


def render_verify_page(db_path: Path | str) -> str:
    """Render Verify Status Page: displays twin verify results for BLAKE3 hash chain and Ed25519 signatures."""
    res = get_verify_status(db_path)
    is_valid = res.get("valid", False)
    count = res.get("verified_count", 0)
    failed_seq = res.get("failed_seq")
    reason = res.get("reason")
    verified_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if is_valid:
        status_box = f"""
        <div style="display:flex; align-items:center; gap:1.25rem; background:rgba(16, 185, 129, 0.1); border:1px solid rgba(16, 185, 129, 0.3); border-radius:0.5rem; padding:1.5rem;">
          <div style="font-size:2.5rem; color:#34d399;">🛡️</div>
          <div>
            <h2 style="font-size:1.25rem; font-weight:700; color:#34d399;">PROVENANCE INTEGRITY VERIFIED</h2>
            <p style="color:#cbd5e1; font-size:0.95rem; margin-top:0.25rem;">
              Successfully verified cryptographic integrity across <strong>{count}</strong> events from Genesis.
            </p>
          </div>
        </div>
        """
    else:
        status_box = f"""
        <div style="display:flex; align-items:center; gap:1.25rem; background:rgba(239, 68, 68, 0.1); border:1px solid rgba(239, 68, 68, 0.3); border-radius:0.5rem; padding:1.5rem;">
          <div style="font-size:2.5rem; color:#f87171;">⚠️</div>
          <div>
            <h2 style="font-size:1.25rem; font-weight:700; color:#f87171;">PROVENANCE TAMPER DETECTED</h2>
            <p style="color:#cbd5e1; font-size:0.95rem; margin-top:0.25rem;">
              Failed at sequence <strong>#{failed_seq}</strong>: {html.escape(str(reason))}
            </p>
          </div>
        </div>
        """

    content = f"""
    <div style="margin-bottom:1.5rem;">
      <h1 style="font-size:1.75rem; font-weight:700; margin-bottom:0.5rem;">Ledger Provenance Verification</h1>
      <p style="color:var(--text-muted);">Real-time cryptographic audit of the BLAKE3 Merkle chain and persistent Ed25519 digital signatures.</p>
    </div>
    <div class="card">
      {status_box}
      <div style="margin-top:1.5rem; display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:1rem;">
        <div style="background:#0b1120; border:1px solid var(--border); border-radius:0.375rem; padding:1rem;">
          <div style="font-size:0.8rem; color:var(--text-muted); text-transform:uppercase;">Verified Events</div>
          <div style="font-size:1.5rem; font-weight:700; color:var(--text); margin-top:0.25rem;">{count}</div>
        </div>
        <div style="background:#0b1120; border:1px solid var(--border); border-radius:0.375rem; padding:1rem;">
          <div style="font-size:0.8rem; color:var(--text-muted); text-transform:uppercase;">BLAKE3 Hash Chain</div>
          <div style="font-size:1.1rem; font-weight:600; color:{'#34d399' if is_valid else '#f87171'}; margin-top:0.25rem;">
            {'✓ Intact & Continuous' if is_valid else '✗ Chain Broken'}
          </div>
        </div>
        <div style="background:#0b1120; border:1px solid var(--border); border-radius:0.375rem; padding:1rem;">
          <div style="font-size:0.8rem; color:var(--text-muted); text-transform:uppercase;">Ed25519 Signatures</div>
          <div style="font-size:1.1rem; font-weight:600; color:{'#34d399' if is_valid else '#f87171'}; margin-top:0.25rem;">
            {'✓ Valid Signatures' if is_valid else '✗ Signature Mismatch'}
          </div>
        </div>
        <div style="background:#0b1120; border:1px solid var(--border); border-radius:0.375rem; padding:1rem;">
          <div style="font-size:0.8rem; color:var(--text-muted); text-transform:uppercase;">Audited At</div>
          <div style="font-size:0.95rem; font-weight:500; color:var(--text-muted); margin-top:0.35rem;">{verified_at}</div>
        </div>
      </div>
    </div>
    """
    return render_page("Verify Status", "verify", content)


def render_graph_page(
    db_path: Path | str, graph_path: Optional[Path | str] = None
) -> str:
    """Render Mermaid Graph View: KùzuDB episodic decision nodes and edges."""
    mermaid_code = generate_mermaid_graph(db_path, graph_path=graph_path)

    content = f"""
    <div style="margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:flex-end;">
      <div>
        <h1 style="font-size:1.75rem; font-weight:700; margin-bottom:0.5rem;">Episodic Decision Graph</h1>
        <p style="color:var(--text-muted);">KùzuDB graph representation showing architectural decisions and temporal SUPERSEDES relationships.</p>
      </div>
      <button class="btn btn-sm" onclick="toggleRawMermaid()">Toggle Raw Mermaid</button>
    </div>
    <div class="card" style="padding:1.5rem; background:#0b1120; overflow:hidden;">
      <pre class="mermaid" style="display:flex; justify-content:center;">
{html.escape(mermaid_code)}
      </pre>
      <div id="raw-mermaid-container" style="display:none; margin-top:1.5rem; border-top:1px solid var(--border); padding-top:1rem;">
        <h4 style="color:var(--text-muted); margin-bottom:0.5rem; font-size:0.85rem; text-transform:uppercase;">Raw Mermaid Flowchart Syntax</h4>
        <div class="pre-box">{html.escape(mermaid_code)}</div>
      </div>
    </div>
    <script type="module">
      import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
      mermaid.initialize({{
        startOnLoad: true,
        theme: 'dark',
        flowchart: {{ useMaxWidth: true, htmlLabels: true, curve: 'basis' }}
      }});
    </script>
    <script>
      function toggleRawMermaid() {{
        var el = document.getElementById('raw-mermaid-container');
        if (el.style.display === 'none') {{
          el.style.display = 'block';
        }} else {{
          el.style.display = 'none';
        }}
      }}
    </script>
    """
    return render_page("Episodic Graph", "graph", content)


# --- HTTP Server & Request Handler ---


class ViewerHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Read-only request handler bound strictly to loopback."""

    server: "AethelgardViewerServer"

    def send_html(self, content: str, status_code: int = 200) -> None:
        payload_bytes = content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Cache-Control", "no-cache, no-store, must-revalidate, private"
        )
        self.end_headers()
        self.wfile.write(payload_bytes)

    def send_json(self, data: Any, status_code: int = 200) -> None:
        payload_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Cache-Control", "no-cache, no-store, must-revalidate, private"
        )
        self.end_headers()
        self.wfile.write(payload_bytes)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 1. HTML Pages
        if path in ("/", "/search"):
            q = params.get("q", [""])[0]
            t = params.get("type", [""])[0]
            s = params.get("signed", [""])[0]
            self.send_html(
                render_search_page(
                    self.server.db_path, query=q, event_type=t, signed=s
                )
            )
            return

        if path == "/timeline":
            t = params.get("type", [""])[0]
            s = params.get("signed", [""])[0]
            self.send_html(
                render_timeline_page(
                    self.server.db_path, event_type=t, signed=s
                )
            )
            return

        if path == "/verify":
            self.send_html(render_verify_page(self.server.db_path))
            return

        if path == "/graph":
            self.send_html(
                render_graph_page(
                    self.server.db_path, graph_path=self.server.graph_path
                )
            )
            return

        # Detail View: /event/<seq> or /event?seq=<seq>
        if path.startswith("/event/") or path == "/event":
            seq_val: Optional[int] = None
            if path.startswith("/event/"):
                parts = path.split("/event/")[1].strip("/").split("/")
                if parts and parts[0].isdigit():
                    seq_val = int(parts[0])
            elif "seq" in params and params["seq"][0].isdigit():
                seq_val = int(params["seq"][0])

            if seq_val is not None:
                html_detail = render_event_detail_page(
                    self.server.db_path, seq_val, graph_path=self.server.graph_path
                )
                if html_detail is not None:
                    self.send_html(html_detail)
                    return
                else:
                    self.send_html(
                        render_page(
                            "Event Not Found",
                            "",
                            f"""
                            <div class="card" style="text-align:center; padding:3rem 1rem;">
                              <h2 style="color:var(--danger); font-size:1.5rem;">Event #{seq_val} Not Found</h2>
                              <p style="color:var(--text-muted); margin-top:0.5rem;">The requested sequence number does not exist in the ledger.</p>
                              <a href="/timeline" class="btn" style="margin-top:1rem; display:inline-block;">Return to Timeline</a>
                            </div>
                            """,
                        ),
                        status_code=404,
                    )
                    return

        # 2. JSON APIs (strictly sanitized; no keys, signatures, or downloads)
        if path == "/api/search":
            q = params.get("q", [""])[0]
            t = params.get("type", [""])[0]
            s = params.get("signed", [""])[0]
            if not q:
                self.send_json([])
                return
            ranker = HybridRRFRanker(db_path=self.server.db_path)
            raw_hits = ranker.search(query=q, limit=50)

            # Check signed status
            hit_seqs = [h["seq"] for h in raw_hits if "seq" in h]
            signed_map: dict[int, bool] = {}
            if hit_seqs:
                with sqlite3.connect(str(self.server.db_path)) as conn:
                    conn.row_factory = sqlite3.Row
                    placeholders = ",".join("?" for _ in hit_seqs)
                    rows = conn.execute(
                        f"""SELECT seq,
                                  (signature IS NOT NULL AND length(signature) > 0 AND pub_key IS NOT NULL AND length(pub_key) > 0) AS is_signed
                           FROM events WHERE seq IN ({placeholders});""",
                        hit_seqs,
                    ).fetchall()
                    signed_map = {r["seq"]: bool(r["is_signed"]) for r in rows}

            filtered = raw_hits
            if t and t.lower() not in ("all", ""):
                filtered = [
                    h
                    for h in filtered
                    if str(h.get("event_type", "")).lower() == t.lower()
                ]
            if s in ("yes", "true", "1"):
                filtered = [
                    h
                    for h in filtered
                    if signed_map.get(h.get("seq"), False) is True
                ]
            elif s in ("no", "false", "0"):
                filtered = [
                    h
                    for h in filtered
                    if signed_map.get(h.get("seq"), False) is False
                ]

            self.send_json(filtered)
            return

        if path == "/api/timeline":
            t = params.get("type", [""])[0]
            s = params.get("signed", [""])[0]
            events = get_timeline_events(
                self.server.db_path, limit=100, event_type=t, signed=s
            )
            self.send_json(events)
            return

        if path.startswith("/api/event/") or path == "/api/event":
            seq_val = None
            if path.startswith("/api/event/"):
                parts = path.split("/api/event/")[1].strip("/").split("/")
                if parts and parts[0].isdigit():
                    seq_val = int(parts[0])
            elif "seq" in params and params["seq"][0].isdigit():
                seq_val = int(params["seq"][0])

            if seq_val is not None:
                detail = get_event_detail(self.server.db_path, seq_val)
                if detail is not None:
                    rel = get_related_events(
                        self.server.db_path, detail, graph_path=self.server.graph_path
                    )
                    self.send_json({"event": detail, "related": rel})
                    return
                else:
                    self.send_json(
                        {"error": f"Event #{seq_val} not found"}, status_code=404
                    )
                    return

        if path == "/api/verify":
            status = get_verify_status(self.server.db_path)
            self.send_json(status)
            return

        if path == "/api/graph":
            mermaid = generate_mermaid_graph(
                self.server.db_path, graph_path=self.server.graph_path
            )
            self.send_json({"mermaid": mermaid})
            return

        # 3. 404 Not Found
        self.send_html(
            render_page(
                "404 Not Found",
                "",
                """
            <div class="card" style="text-align:center; padding:3rem 1rem;">
              <h2 style="color:var(--danger); font-size:1.5rem;">404 Page Not Found</h2>
              <p style="color:var(--text-muted); margin-top:0.5rem;">The requested endpoint does not exist.</p>
              <a href="/search" class="btn" style="margin-top:1rem; display:inline-block;">Return to Search</a>
            </div>
            """,
            ),
            status_code=404,
        )

    # Strictly reject any state-modifying HTTP methods (Read-Only invariant)
    def do_POST(self) -> None:
        self.send_json(
            {"error": "Method Not Allowed. Aethelgard viewer is strictly read-only."},
            status_code=405,
        )

    def do_PUT(self) -> None:
        self.send_json(
            {"error": "Method Not Allowed. Aethelgard viewer is strictly read-only."},
            status_code=405,
        )

    def do_DELETE(self) -> None:
        self.send_json(
            {"error": "Method Not Allowed. Aethelgard viewer is strictly read-only."},
            status_code=405,
        )

    def log_message(self, format: str, *args: Any) -> None:
        return


class AethelgardViewerServer(http.server.ThreadingHTTPServer):
    """Threading HTTP Server bound strictly to 127.0.0.1 with ledger context."""

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[http.server.BaseHTTPRequestHandler],
        db_path: Path | str,
        graph_path: Optional[Path | str] = None,
    ) -> None:
        host, _ = server_address
        if host not in ("127.0.0.1", "localhost"):
            raise ValueError(
                f"Security Violation: Aethelgard viewer must bind to 127.0.0.1 (got '{host}')"
            )
        super().__init__(server_address, RequestHandlerClass)
        self.db_path = Path(db_path)
        self.graph_path = Path(graph_path) if graph_path else None


def run_viewer(
    host: str = "127.0.0.1",
    port: int = 8080,
    db_path: Optional[Path | str] = None,
    graph_path: Optional[Path | str] = None,
    open_browser: bool = False,
) -> None:
    """Start local read-only web viewer on 127.0.0.1."""
    if host not in ("127.0.0.1", "localhost"):
        print(
            f"Error: Aethelgard viewer is strictly restricted to 127.0.0.1 loopback. Host '{host}' is forbidden.",
            file=sys.stderr,
        )
        sys.exit(1)

    target_db = Path(db_path) if db_path is not None else DEFAULT_DATA_DIR / "ledger.db"
    server_address = (host, port)

    try:
        httpd = AethelgardViewerServer(
            server_address,
            ViewerHTTPRequestHandler,
            db_path=target_db,
            graph_path=graph_path,
        )
    except OSError as e:
        print(f"Error binding to {host}:{port}: {e}", file=sys.stderr)
        sys.exit(1)

    url = f"http://{host}:{port}/"
    print("=" * 64)
    print(" Project Aethelgard - Local Read-Only Web Viewer")
    print(f" Loopback Address:  {url}")
    print(f" Database:          {target_db}")
    print(f" Network Scope:     Strictly bound to 127.0.0.1 (No external access)")
    print("=" * 64)
    print("Press Ctrl+C to stop.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Aethelgard viewer...")
    finally:
        httpd.server_close()
