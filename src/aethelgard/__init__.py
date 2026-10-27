"""Project Aethelgard: Sovereign Cognitive Twin & Cryptographic Provenance Engine."""

from .airlock import scrub_payload, shannon_entropy
from .canonical import canonicalize_json
from .embeddings import generate_mock_embedding, get_embedding
from .graph import GraphView, close_kuzu_db, commit_decision, get_kuzu_db
from .ledger import (
    GENESIS_HASH,
    Ledger,
    log_execution_artifact,
    verify_provenance,
)
from .ranker import (
    DEFAULT_K,
    PSI_ACTIVE,
    PSI_SUPERSEDED,
    HybridRRFRanker,
    hybrid_rrf_search,
)
from .views import (
    FTS5View,
    VectorView,
    rebuild_views,
    search_lexical,
    search_semantic,
)

__all__ = [
    "GENESIS_HASH",
    "Ledger",
    "FTS5View",
    "VectorView",
    "GraphView",
    "HybridRRFRanker",
    "hybrid_rrf_search",
    "DEFAULT_K",
    "PSI_ACTIVE",
    "PSI_SUPERSEDED",
    "scrub_payload",
    "shannon_entropy",
    "canonicalize_json",
    "commit_decision",
    "log_execution_artifact",
    "verify_provenance",
    "rebuild_views",
    "search_lexical",
    "search_semantic",
    "get_embedding",
    "generate_mock_embedding",
    "get_kuzu_db",
    "close_kuzu_db",
]
