"""Subsystem Layer: Watchdog Filesystem Listener for Passive Capture (Phase 4).

Monitors workspaces and directories for file modifications, creations, and deletions.
Appends events to the append-only ledger and updates materialized views.
Filters out lockfiles, .git internals, and build artifacts using `is_ignored_path`.
"""

import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from blake3 import blake3
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .filters import is_ignored_path
from .graph import GraphView
from .ledger import DEFAULT_DATA_DIR, Ledger
from .views import FTS5View, VectorView

MAX_SNIPPET_BYTES = 2048
MAX_HASH_BYTES = 10 * 1024 * 1024  # 10 MB


class _AethelgardEventHandler(FileSystemEventHandler):
    """Internal Watchdog event handler with path filtering and debounce dispatching."""

    def __init__(self, listener: "PassiveFSListener") -> None:
        super().__init__()
        self.listener = listener

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        src_path = str(event.src_path)
        if is_ignored_path(src_path):
            return

        self.listener.queue_event(src_path, event.event_type)


class PassiveFSListener:
    """Passive filesystem listener capturing debounced changes into Aethelgard's ledger."""

    def __init__(
        self,
        watch_paths: list[Path | str] | Path | str,
        ledger: Optional[Ledger] = None,
        db_path: Optional[Path | str] = None,
        debounce_seconds: float = 0.5,
        recursive: bool = True,
        on_event: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        if isinstance(watch_paths, (str, Path)):
            self.watch_paths = [Path(watch_paths).resolve()]
        else:
            self.watch_paths = [Path(p).resolve() for p in watch_paths]

        self.ledger = ledger or Ledger(db_path=db_path)
        self.db_path = self.ledger.db_path
        self.debounce_seconds = max(0.05, debounce_seconds)
        self.recursive = recursive
        self.on_event = on_event

        self._pending_lock = threading.Lock()
        self._pending: dict[str, tuple[float, str]] = {}
        self._running = False
        self._stop_event = threading.Event()
        self._debounce_thread: Optional[threading.Thread] = None
        self._observer: Optional[Observer] = None

    def queue_event(self, file_path: str, event_type: str) -> None:
        """Enqueue an event with a refreshed timestamp for debouncing."""
        with self._pending_lock:
            self._pending[file_path] = (time.time(), event_type)

    def _debounce_loop(self) -> None:
        """Background thread worker to flush events that have settled past debounce_seconds."""
        while not self._stop_event.is_set():
            time.sleep(0.1)
            self._flush_settled()

    def _flush_settled(self, force: bool = False) -> list[dict[str, Any]]:
        """Flush and process events that have settled."""
        now = time.time()
        to_process: list[tuple[str, str]] = []

        with self._pending_lock:
            for path, (ts, evt_type) in list(self._pending.items()):
                if force or (now - ts >= self.debounce_seconds):
                    to_process.append((path, evt_type))
                    del self._pending[path]

        processed_events: list[dict[str, Any]] = []
        for path_str, evt_type in to_process:
            ev = self._process_single_event(path_str, evt_type)
            if ev:
                processed_events.append(ev)
        return processed_events

    def flush(self) -> list[dict[str, Any]]:
        """Force flush all pending debounced events immediately (useful in tests)."""
        return self._flush_settled(force=True)

    def _process_single_event(
        self, file_path_str: str, event_type: str
    ) -> Optional[dict[str, Any]]:
        """Ingest a single file change into the ledger and update views."""
        try:
            p = Path(file_path_str)
            if is_ignored_path(p):
                return None

            exists = p.exists() and p.is_file()
            size_bytes = 0
            content_hash = None
            snippet = None

            if exists:
                try:
                    size_bytes = p.stat().st_size
                    # Read up to MAX_HASH_BYTES for BLAKE3 hash
                    with p.open("rb") as f:
                        data = f.read(MAX_HASH_BYTES)
                    content_hash = blake3(data).hexdigest()

                    # Try text snippet if small
                    if size_bytes <= 128 * 1024:
                        try:
                            text = data[:MAX_SNIPPET_BYTES].decode("utf-8", errors="replace")
                            snippet = text.strip()
                        except Exception:
                            pass
                except (OSError, PermissionError):
                    pass

            # Find matching root to compute relative path
            display_path = file_path_str
            for root in self.watch_paths:
                try:
                    display_path = str(p.relative_to(root))
                    break
                except ValueError:
                    pass

            payload: dict[str, Any] = {
                "file_path": display_path,
                "absolute_path": str(p),
                "change_type": event_type,
                "exists": exists,
                "size_bytes": size_bytes,
                "content_hash": content_hash,
                "snippet": snippet,
                "timestamp": time.time(),
            }

            event = self.ledger.append_event("file_change", payload)

            # Update views
            target_db = self.db_path
            fts_view = FTS5View(db_path=target_db)
            vec_view = VectorView(db_path=target_db)
            graph_view = GraphView(db_path=target_db)

            fts_view.index_event(event)
            vec_view.index_event(event)
            graph_view.index_event(event)

            # Involve file entity in graph
            try:
                graph_view.create_involves_edge(event["event_id"], display_path, "file")
            except Exception:
                pass

            if self.on_event:
                try:
                    self.on_event(event)
                except Exception:
                    pass

            return event

        except Exception:
            return None

    def start(self) -> None:
        """Start the watchdog filesystem observer and debounce processing thread."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()

        # Start debounce loop thread
        self._debounce_thread = threading.Thread(
            target=self._debounce_loop, daemon=True, name="AethelgardDebounceThread"
        )
        self._debounce_thread.start()

        # Start Watchdog observer
        handler = _AethelgardEventHandler(self)
        self._observer = Observer()
        for root in self.watch_paths:
            if root.exists():
                self._observer.schedule(handler, str(root), recursive=self.recursive)
        self._observer.start()

    def stop(self) -> None:
        """Stop the watchdog observer and flush remaining events."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2.0)
            except Exception:
                pass
            self._observer = None

        if self._debounce_thread:
            try:
                self._debounce_thread.join(timeout=2.0)
            except Exception:
                pass
            self._debounce_thread = None

        # Flush any remaining items
        self._flush_settled(force=True)

    def is_alive(self) -> bool:
        """Check if the filesystem listener is actively running."""
        return self._running and (self._observer is not None and self._observer.is_alive())

    def __enter__(self) -> "PassiveFSListener":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
