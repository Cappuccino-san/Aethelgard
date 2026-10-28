"""Project Aethelgard: Sovereign Cognitive Twin & Cryptographic Provenance Engine."""

from .airlock import scrub_payload, shannon_entropy
from .canonical import canonicalize_json
from .embeddings import generate_mock_embedding, get_embedding
from .graph import GraphView, close_kuzu_db, commit_decision, get_kuzu_db
from .ledger import (
    DEFAULT_KEY_PATH,
    GENESIS_HASH,
    Ledger,
    load_or_create_signing_key,
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
from .daemon import run_daemon
from .filters import filter_file_paths, is_ignored_path
from .git_hook import (
    capture_git_commit,
    get_post_commit_hook_script,
    install_post_commit_hook,
)
from .listener import PassiveFSListener
from .mcp import create_mcp_server, get_mcp_server, run_stdio
from .systemd import (
    get_systemd_unit_content,
    install_systemd_unit,
    uninstall_systemd_unit,
)
from .viewer import run_viewer
from .views import (
    FTS5View,
    VectorView,
    rebuild_views,
    search_lexical,
    search_semantic,
)

__all__ = [
    "GENESIS_HASH",
    "DEFAULT_KEY_PATH",
    "load_or_create_signing_key",
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
    "create_mcp_server",
    "get_mcp_server",
    "mcp",
    "run_stdio",
    "is_ignored_path",
    "filter_file_paths",
    "capture_git_commit",
    "install_post_commit_hook",
    "get_post_commit_hook_script",
    "PassiveFSListener",
    "run_daemon",
    "get_systemd_unit_content",
    "install_systemd_unit",
    "uninstall_systemd_unit",
    "run_viewer",
]


def __getattr__(name: str):
    if name == "mcp":
        return get_mcp_server()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

