"""Tests for Project Aethelgard local read-only web viewer."""

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aethelgard.ledger import Ledger
from aethelgard.views import rebuild_views
from aethelgard.viewer import (
    AethelgardViewerServer,
    ViewerHTTPRequestHandler,
    generate_mermaid_graph,
    get_available_event_types,
    get_event_detail,
    get_related_events,
    get_timeline_events,
    get_verify_status,
)


@pytest.fixture
def viewer_test_env(tmp_path: Path):
    """Fixture providing a test database with decisions and signed events."""
    db_path = tmp_path / "test_ledger.db"
    ledger = Ledger(db_path=db_path)

    # 1. Commit decisions (unsigned)
    d1 = ledger.commit_decision(
        title="ADR-001: Isolated Loopback Viewer",
        context="Ensuring zero remote surface area",
        rejected=["0.0.0.0 binding", "Cloud deployment"],
        decision="Bind strictly to 127.0.0.1",
    )
    d2 = ledger.commit_decision(
        title="ADR-002: Mermaid Graph Rendering",
        context="Visualizing episodic decisions",
        rejected=["Static PNG", "Graphviz server"],
        decision="Render client-side Mermaid from KùzuDB/SQLite",
        supersedes_id=d1["event_id"],
    )

    # 2. Append note & git_commit (unsigned)
    ledger.append_event("note", {"text": "Verified loopback invariant for viewer"})
    ledger.append_event(
        "git_commit",
        {
            "commit_hash": "abcdef1234567890",
            "message": "feat: add local web viewer",
            "branch": "main",
            "author": "Test Author <author@example.com>",
            "repo_path": str(tmp_path / "repo"),
            "files": ["src/aethelgard/viewer.py", "tests/test_viewer.py"],
            "total_files_changed": 2,
            "filtered_files_count": 0,
        },
    )

    # 3. Append signed decision
    signed_ledger = Ledger(db_path=db_path, signing_key=Ed25519PrivateKey.generate())
    d3 = signed_ledger.commit_decision(
        title="ADR-003: Signed Event Test",
        context="Testing signed detail view",
        rejected=[],
        decision="Sign with Ed25519 key",
    )

    rebuild_views(db_path)

    return db_path, d1, d2, d3


def test_timeline_extraction(viewer_test_env):
    db_path, *_ = viewer_test_env
    events = get_timeline_events(db_path)

    assert len(events) == 5
    # Check descending order by seq
    assert events[0]["seq"] == 5
    assert events[-1]["seq"] == 1

    # Check signed status
    assert events[0]["signed"] is True  # seq 5 was signed
    assert events[-1]["signed"] is False  # seq 1 was unsigned

    for ev in events:
        assert "seq" in ev
        assert "event_type" in ev
        assert "title" in ev
        assert "signed" in ev
        assert "datetime" in ev
        # Security invariant: NO raw signatures or public/private keys in timeline response
        assert "signature" not in ev
        assert "pub_key" not in ev


def test_timeline_filtering(viewer_test_env):
    db_path, *_ = viewer_test_env

    # 1. Available types
    types = get_available_event_types(db_path)
    assert "decision" in types
    assert "git_commit" in types
    assert "note" in types

    # 2. Filter by event_type
    decisions = get_timeline_events(db_path, event_type="decision")
    assert len(decisions) == 3
    assert all(e["event_type"] == "decision" for e in decisions)
    assert [e["seq"] for e in decisions] == [5, 2, 1]

    commits = get_timeline_events(db_path, event_type="git_commit")
    assert len(commits) == 1
    assert commits[0]["seq"] == 4

    empty = get_timeline_events(db_path, event_type="file_change")
    assert len(empty) == 0

    # 3. Filter by signed status
    signed_events = get_timeline_events(db_path, signed="yes")
    assert len(signed_events) == 1
    assert signed_events[0]["seq"] == 5
    assert signed_events[0]["signed"] is True

    unsigned_events = get_timeline_events(db_path, signed="no")
    assert len(unsigned_events) == 4
    assert all(e["signed"] is False for e in unsigned_events)

    # 4. Filter by both event_type and signed
    signed_decisions = get_timeline_events(db_path, event_type="decision", signed="yes")
    assert len(signed_decisions) == 1
    assert signed_decisions[0]["seq"] == 5

    unsigned_decisions = get_timeline_events(db_path, event_type="decision", signed="no")
    assert len(unsigned_decisions) == 2
    assert [e["seq"] for e in unsigned_decisions] == [2, 1]


def test_event_detail_extraction(viewer_test_env):
    db_path, *_ = viewer_test_env

    # 1. Check ADR-001 (seq 1, unsigned)
    ev1 = get_event_detail(db_path, 1)
    assert ev1 is not None
    assert ev1["seq"] == 1
    assert ev1["event_type"] == "decision"
    assert ev1["title"] == "ADR-001: Isolated Loopback Viewer"
    assert ev1["signed"] is False
    assert ev1["prev_hash_prefix"].endswith("...")
    assert ev1["curr_hash_prefix"].endswith("...")
    assert "signature" not in ev1
    assert "pub_key" not in ev1
    assert ev1["payload"]["decision"] == "Bind strictly to 127.0.0.1"
    assert ev1["payload"]["rejected"] == ["0.0.0.0 binding", "Cloud deployment"]

    # 2. Check ADR-003 (seq 5, signed)
    ev5 = get_event_detail(db_path, 5)
    assert ev5 is not None
    assert ev5["seq"] == 5
    assert ev5["event_type"] == "decision"
    assert ev5["title"] == "ADR-003: Signed Event Test"
    assert ev5["signed"] is True
    assert "signature" not in ev5
    assert "pub_key" not in ev5

    # 3. Check git_commit (seq 4)
    ev4 = get_event_detail(db_path, 4)
    assert ev4 is not None
    assert ev4["seq"] == 4
    assert ev4["event_type"] == "git_commit"
    assert "feat: add local web viewer" in ev4["title"]
    assert "src/aethelgard/viewer.py" in ev4["payload"]["files"]

    # 4. Nonexistent event
    assert get_event_detail(db_path, 999) is None


def test_related_events_discovery(viewer_test_env):
    db_path, *_ = viewer_test_env

    # 1. Related events for d1 (seq 1)
    ev1 = get_event_detail(db_path, 1)
    rel1 = get_related_events(db_path, ev1)
    # d1 was superseded by d2
    superseded_by = [
        item for item in rel1["supersession_chain"] if "SUPERSEDED BY" in item["relationship"]
    ]
    assert len(superseded_by) == 1
    assert superseded_by[0]["seq"] == 2
    assert "ADR-002" in superseded_by[0]["title"]

    # 2. Related events for d2 (seq 2)
    ev2 = get_event_detail(db_path, 2)
    rel2 = get_related_events(db_path, ev2)
    # d2 supersedes d1
    supersedes = [
        item for item in rel2["supersession_chain"] if "SUPERSEDES" in item["relationship"]
    ]
    assert len(supersedes) == 1
    assert supersedes[0]["seq"] == 1
    assert "ADR-001" in supersedes[0]["title"]

    # 3. Related events for git_commit (seq 4)
    ev4 = get_event_detail(db_path, 4)
    rel4 = get_related_events(db_path, ev4)
    cd = rel4["commit_details"]
    assert "src/aethelgard/viewer.py" in cd["files"]
    assert "repo" in cd["repo_path"]


def test_verify_status(viewer_test_env):
    db_path, *_ = viewer_test_env
    status = get_verify_status(db_path)

    assert status["valid"] is True
    assert status["verified_count"] == 5
    assert status["failed_seq"] is None
    assert status["reason"] is None


def test_mermaid_graph_generation(viewer_test_env):
    db_path, *_ = viewer_test_env
    mermaid = generate_mermaid_graph(db_path)

    assert "flowchart TD" in mermaid
    assert "ADR-001: Isolated Loopback Viewer" in mermaid
    assert "ADR-002: Mermaid Graph Rendering" in mermaid
    assert "SUPERSEDES" in mermaid


def test_loopback_security_invariant(viewer_test_env):
    db_path, *_ = viewer_test_env
    # Must reject non-loopback host
    with pytest.raises(ValueError, match="Security Violation"):
        AethelgardViewerServer(
            ("0.0.0.0", 8999), ViewerHTTPRequestHandler, db_path=db_path
        )


def test_viewer_http_endpoints(viewer_test_env):
    db_path, *_ = viewer_test_env

    # Bind to ephemeral port on 127.0.0.1
    server = AethelgardViewerServer(
        ("127.0.0.1", 0), ViewerHTTPRequestHandler, db_path=db_path
    )
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # 1. GET / and /search
        req = urllib.request.Request(f"{base_url}/search")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            assert "text/html" in resp.headers["Content-Type"]
            body = resp.read().decode("utf-8")
            assert "Hybrid RRF Recall" in body
            assert "127.0.0.1 (Read-Only)" in body

        # 2. GET /search?q=Loopback (verify links to /event/<seq>)
        req_q = urllib.request.Request(f"{base_url}/search?q=Loopback")
        with urllib.request.urlopen(req_q) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "ADR-001" in body
            assert "BM25" in body
            assert "Vec" in body
            assert "Graph" in body
            assert 'href="/event/1"' in body

        # 3. GET /timeline (verify links to /event/<seq>)
        req_tl = urllib.request.Request(f"{base_url}/timeline")
        with urllib.request.urlopen(req_tl) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "Event Timeline" in body
            assert 'href="/event/1"' in body
            assert 'href="/event/4"' in body

        # 3b. GET /timeline with filters
        req_tl_filtered = urllib.request.Request(f"{base_url}/timeline?type=decision&signed=yes")
        with urllib.request.urlopen(req_tl_filtered) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "ADR-003: Signed Event Test" in body
            assert "ADR-001" not in body
            assert "Active Filter:" in body

        # 3c. GET /search with filters
        req_s_filtered = urllib.request.Request(f"{base_url}/search?q=Loopback&type=decision&signed=no")
        with urllib.request.urlopen(req_s_filtered) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "ADR-001" in body

        req_s_nomatch = urllib.request.Request(f"{base_url}/search?q=Loopback&type=file_change")
        with urllib.request.urlopen(req_s_nomatch) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "No matching events found" in body

        # 4. GET /event/1 (ADR-001 Decision Detail View - Unsigned)
        req_d1 = urllib.request.Request(f"{base_url}/event/1")
        with urllib.request.urlopen(req_d1) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "ADR-001: Isolated Loopback Viewer" in body
            assert "Architectural Decision Record" in body
            assert "0.0.0.0 binding" in body
            assert "Cloud deployment" in body
            assert "Bind strictly to 127.0.0.1" in body
            assert "BLAKE3 Current Hash (Prefix)" in body
            assert "Signed: No" in body
            assert "Unsigned Event" in body
            assert "Related Events" in body
            assert "Superseded by #2" in body
            assert 'href="/event/2"' in body

        # 5. GET /event/5 (ADR-003 Decision Detail View - Signed)
        req_d5 = urllib.request.Request(f"{base_url}/event/5")
        with urllib.request.urlopen(req_d5) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "ADR-003: Signed Event Test" in body
            assert "Signed: Yes" in body
            assert "Verified Intact" in body

        # 6. GET /event/4 (Git Commit Detail View)
        req_c4 = urllib.request.Request(f"{base_url}/event/4")
        with urllib.request.urlopen(req_c4) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "feat: add local web viewer" in body
            assert "Git Commit Payload" in body
            assert "Repository Path" in body
            assert "src/aethelgard/viewer.py" in body
            assert "Related Events" in body

        # 7. GET /event/999 (404 Not Found)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/event/999")
        assert exc_info.value.code == 404

        # 8. GET /verify
        req_v = urllib.request.Request(f"{base_url}/verify")
        with urllib.request.urlopen(req_v) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "PROVENANCE INTEGRITY VERIFIED" in body
            assert "5" in body

        # 9. GET /graph
        req_g = urllib.request.Request(f"{base_url}/graph")
        with urllib.request.urlopen(req_g) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "mermaid" in body
            assert "ADR-001" in body

        # 10. JSON APIs: /api/timeline, /api/event/1, /api/event/5, /api/verify, /api/graph
        with urllib.request.urlopen(f"{base_url}/api/timeline") as resp:
            assert resp.status == 200
            assert "application/json" in resp.headers["Content-Type"]
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 5
            assert "signature" not in data[0]
            assert "pub_key" not in data[0]

        with urllib.request.urlopen(f"{base_url}/api/event/1") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            ev = data["event"]
            rel = data["related"]
            assert ev["seq"] == 1
            assert ev["event_type"] == "decision"
            assert ev["signed"] is False
            assert "signature" not in ev
            assert "pub_key" not in ev
            assert ev["curr_hash_prefix"].endswith("...")
            assert "supersession_chain" in rel

        with urllib.request.urlopen(f"{base_url}/api/event/5") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            ev = data["event"]
            assert ev["seq"] == 5
            assert ev["signed"] is True

        with urllib.request.urlopen(f"{base_url}/api/verify") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["valid"] is True
            assert data["verified_count"] == 5

        with urllib.request.urlopen(f"{base_url}/api/graph") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "flowchart TD" in data["mermaid"]

        # 10b. API filtering: /api/timeline and /api/search with query params
        with urllib.request.urlopen(f"{base_url}/api/timeline?type=decision") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 3
            assert all(e["event_type"] == "decision" for e in data)

        with urllib.request.urlopen(f"{base_url}/api/timeline?signed=yes") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 1
            assert data[0]["seq"] == 5

        with urllib.request.urlopen(f"{base_url}/api/timeline?signed=no") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 4

        with urllib.request.urlopen(f"{base_url}/api/search?q=Loopback&type=decision") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) > 0
            assert any(h["seq"] == 1 for h in data)

        with urllib.request.urlopen(f"{base_url}/api/search?q=Loopback&type=file_change") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 0

        with urllib.request.urlopen(f"{base_url}/api/search?q=Loopback&signed=no") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) > 0
            assert all(h["seq"] != 5 for h in data)
            assert any(h["seq"] == 1 for h in data)

        with urllib.request.urlopen(f"{base_url}/api/search?q=Loopback&signed=yes") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) > 0
            assert all(h["seq"] == 5 for h in data)

        with urllib.request.urlopen(f"{base_url}/api/search?q=") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 0

        # 11. Security: Reject POST requests with 405 Method Not Allowed
        post_req = urllib.request.Request(
            f"{base_url}/api/timeline", data=b"{}", method="POST"
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(post_req)
        assert exc_info.value.code == 405

        # 12. 404 for unknown endpoints
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/does_not_exist")
        assert exc_info.value.code == 404

    finally:
        server.shutdown()
        server.server_close()
