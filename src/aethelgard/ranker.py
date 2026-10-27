"""Subsystem Layer 7: Hybrid Retrieval & Temporal Supersession (3-Way Reciprocal Rank Fusion).

Combines:
  1. SQLite FTS5 BM25 Lexical Ranking
  2. sqlite-vec 768d Dense Vector Semantic Ranking
  3. KùzuDB Episodic Graph Structural Ranking

Formula (Specification Section 05):
  Score(d) = ∑_{m ∈ {BM25, Vec, Graph}} [ w_m / (k + rank_m(d)) ] × Ψ_supersede(d) × e^(-lambda * Δt)

Parameters:
  - k: RRF constant (default = 60)
  - Ψ (Psi): 0.15 if superseded else 1.0
  - lambda: decay rate (explicit named parameter `decay_lambda` / `lambda_param`)
  - Δt: elapsed time since event creation (t_ref - t_event)
"""

import json
import math
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .graph import GraphView
from .views import FTS5View, VectorView

DEFAULT_K = 60
PSI_ACTIVE = 1.0
PSI_SUPERSEDED = 0.15


class HybridRRFRanker:
    """3-Way Reciprocal Rank Fusion ranker combining lexical, semantic, and graph views with supersession penalties and temporal decay."""

    def __init__(
        self,
        db_path: Path | str,
        graph_path: Optional[Path | str] = None,
        embed_fn: Optional[Callable[[str], list[float]]] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.fts_view = FTS5View(db_path)
        self.vec_view = VectorView(db_path, embed_fn=embed_fn)
        self.graph_view = GraphView(db_path, graph_path=graph_path)

    def search(
        self,
        query: str,
        limit: int = 20,
        k: int = DEFAULT_K,
        decay_lambda: float = 0.0,
        lambda_param: Optional[float] = None,
        lambda_: Optional[float] = None,
        weights: Optional[dict[str, float]] = None,
        psi_superseded: float = PSI_SUPERSEDED,
        reference_time: Optional[float] = None,
        include_superseded: bool = True,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Execute 3-Way Hybrid RRF across FTS5, sqlite-vec, and KùzuDB.

        Score(d) = sum[ w_m / (k + rank_m(d)) ] * Psi(d) * exp(-lambda * delta_t)

        Parameters:
            query: The search query string.
            limit: Maximum number of fused results to return.
            k: RRF constant (default = 60).
            decay_lambda: Explicit named parameter for temporal decay rate.
            lambda_param: Explicit named alias for temporal decay rate.
            lambda_: Explicit named alias for temporal decay rate.
            weights: Modality weights dict: {"BM25": 1.0, "Vec": 1.0, "Graph": 1.0}.
            psi_superseded: Supersession multiplier (default = 0.15).
            reference_time: Base epoch timestamp for delta_t (defaults to now).
            include_superseded: Whether to include superseded items in results (default = True).
        """
        # Explicit named lambda parameter support across all common naming patterns
        if lambda_ is not None:
            actual_lambda = lambda_
        elif lambda_param is not None:
            actual_lambda = lambda_param
        elif "lambda" in kwargs:
            actual_lambda = kwargs["lambda"]
        elif "lambda_decay" in kwargs:
            actual_lambda = kwargs["lambda_decay"]
        else:
            actual_lambda = decay_lambda

        w = {
            "BM25": 1.0,
            "Vec": 1.0,
            "Graph": 1.0,
        }
        if weights:
            w.update(weights)

        ref_time = reference_time if reference_time is not None else time.time()
        fetch_limit = limit * 3  # Fetch a broader candidate pool for fusion

        # 1. Fetch rankings from all 3 modalities
        fts_hits = self.fts_view.search(query, limit=fetch_limit)
        vec_hits = self.vec_view.search(query, limit=fetch_limit)
        graph_hits = self.graph_view.search(query, limit=fetch_limit)

        # 2. Build 1-based rank maps
        fts_ranks: dict[str, int] = {
            hit["event_id"]: idx + 1 for idx, hit in enumerate(fts_hits)
        }
        vec_ranks: dict[str, int] = {
            hit["event_id"]: idx + 1 for idx, hit in enumerate(vec_hits)
        }
        graph_ranks: dict[str, int] = {
            hit["event_id"]: idx + 1 for idx, hit in enumerate(graph_hits)
        }

        all_event_ids = set(fts_ranks) | set(vec_ranks) | set(graph_ranks)
        if not all_event_ids:
            return []

        # 3. Retrieve ground-truth events metadata from SQLite ledger for canonical timestamps and payloads
        events_meta: dict[str, dict[str, Any]] = {}
        all_ids_list = list(all_event_ids)
        chunk_size = 500
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            for i in range(0, len(all_ids_list), chunk_size):
                chunk = all_ids_list[i : i + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT seq, event_id, event_type, timestamp, payload FROM events WHERE event_id IN ({placeholders});",
                    chunk,
                ).fetchall()
                for r in rows:
                    events_meta[r["event_id"]] = {
                        "seq": r["seq"],
                        "event_type": r["event_type"],
                        "timestamp": float(r["timestamp"]),
                        "payload": (
                            json.loads(r["payload"])
                            if isinstance(r["payload"], str)
                            else r["payload"]
                        ),
                    }

        # 4. Batch check superseded status in KùzuDB
        superseded_set = self.graph_view.get_superseded_set(all_ids_list)

        # 5. Compute 3-Way RRF score with supersession and temporal decay
        scored_results: list[dict[str, Any]] = []

        for ev_id in all_event_ids:
            meta = events_meta.get(ev_id)
            if not meta:
                continue

            # Compute sum[ w_m / (k + rank_m) ]
            rrf_sum = 0.0
            ranks: dict[str, Optional[int]] = {
                "BM25": fts_ranks.get(ev_id),
                "Vec": vec_ranks.get(ev_id),
                "Graph": graph_ranks.get(ev_id),
            }

            if ranks["BM25"] is not None:
                rrf_sum += w["BM25"] / (k + ranks["BM25"])
            if ranks["Vec"] is not None:
                rrf_sum += w["Vec"] / (k + ranks["Vec"])
            if ranks["Graph"] is not None:
                rrf_sum += w["Graph"] / (k + ranks["Graph"])

            # Psi_supersede(d): 0.15 if superseded else 1.0
            is_sup = ev_id in superseded_set
            psi = psi_superseded if is_sup else PSI_ACTIVE

            # If user explicitly requests to exclude superseded items, filter them
            if is_sup and not include_superseded:
                continue

            # Temporal decay: exp(-lambda * delta_t)
            ts = meta["timestamp"]
            delta_t = max(0.0, ref_time - ts)
            decay = math.exp(-actual_lambda * delta_t)

            final_score = rrf_sum * psi * decay

            scored_results.append(
                {
                    "event_id": ev_id,
                    "seq": meta["seq"],
                    "event_type": meta["event_type"],
                    "timestamp": ts,
                    "score": round(final_score, 8),
                    "rrf_score": round(rrf_sum, 8),
                    "psi": psi,
                    "decay": round(decay, 8),
                    "delta_t": round(delta_t, 4),
                    "is_superseded": is_sup,
                    "ranks": ranks,
                    "payload": meta["payload"],
                }
            )

        # 6. Order by final score descending
        scored_results.sort(key=lambda x: x["score"], reverse=True)
        return scored_results[:limit]


def hybrid_rrf_search(
    db_path: Path | str,
    query: str,
    limit: int = 20,
    k: int = DEFAULT_K,
    decay_lambda: float = 0.0,
    lambda_param: Optional[float] = None,
    lambda_: Optional[float] = None,
    weights: Optional[dict[str, float]] = None,
    psi_superseded: float = PSI_SUPERSEDED,
    reference_time: Optional[float] = None,
    include_superseded: bool = True,
    graph_path: Optional[Path | str] = None,
    embed_fn: Optional[Callable[[str], list[float]]] = None,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Convenience functional wrapper for 3-Way Hybrid RRF search."""
    ranker = HybridRRFRanker(
        db_path=db_path, graph_path=graph_path, embed_fn=embed_fn
    )
    return ranker.search(
        query=query,
        limit=limit,
        k=k,
        decay_lambda=decay_lambda,
        lambda_param=lambda_param,
        lambda_=lambda_,
        weights=weights,
        psi_superseded=psi_superseded,
        reference_time=reference_time,
        include_superseded=include_superseded,
        **kwargs,
    )
