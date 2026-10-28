"""Unit and integration tests for the FastMCP Bridge over stdio (Specification Section 06)."""

import gc
import json
import sqlite3
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aethelgard.mcp import create_mcp_server


def _extract_tool_result(res):
    """Extract raw Python result from FastMCP call_tool return value."""
    if isinstance(res, tuple):
        val = res[1]
        if isinstance(val, dict) and "result" in val and len(val) == 1:
            return val["result"]
        return val
    if isinstance(res, list) and len(res) == 1 and hasattr(res[0], "text"):
        parsed = json.loads(res[0].text)
        if isinstance(parsed, dict) and "result" in parsed and len(parsed) == 1:
            return parsed["result"]
        return parsed
    if isinstance(res, list) and all(hasattr(x, "text") for x in res):
        return [json.loads(x.text) for x in res]
    return res


@pytest.fixture
def clean_server(tmp_path: Path):
    """Create an isolated FastMCP server and clean up locks on teardown."""
    db_file = tmp_path / "ledger.db"
    graph_path = tmp_path / "graph.kuzu"
    signing_key = Ed25519PrivateKey.generate()
    server = create_mcp_server(
        db_path=db_file,
        graph_path=graph_path,
        signing_key=signing_key,
    )
    yield server
    server.close()
    gc.collect()


@pytest.mark.anyio
async def test_fastmcp_tool_registration_and_schemas(clean_server):
    """Verify that all 5 canonical MCP tools are registered with valid input schemas."""
    tools = await clean_server.list_tools()
    tool_map = {t.name: t for t in tools}

    expected_tools = {
        "recall_context",
        "commit_decision",
        "trace_entity_history",
        "log_execution_artifact",
        "verify_provenance",
    }
    assert expected_tools.issubset(set(tool_map.keys()))

    # Verify commit_decision schema
    cd_schema = tool_map["commit_decision"].inputSchema
    assert "title" in cd_schema.get("properties", {})
    assert "context" in cd_schema.get("properties", {})
    assert "decision" in cd_schema.get("properties", {})
    assert "rejected" in cd_schema.get("properties", {})
    assert "supersedes_id" in cd_schema.get("properties", {})

    # Verify recall_context schema
    rc_schema = tool_map["recall_context"].inputSchema
    assert "query" in rc_schema.get("properties", {})
    assert "domain" in rc_schema.get("properties", {})
    assert "include_superseded" in rc_schema.get("properties", {})

    # Verify trace_entity_history schema
    te_schema = tool_map["trace_entity_history"].inputSchema
    assert "entity_name" in te_schema.get("properties", {})

    # Verify log_execution_artifact schema
    le_schema = tool_map["log_execution_artifact"].inputSchema
    assert "action_type" in le_schema.get("properties", {})
    assert "inputs" in le_schema.get("properties", {})
    assert "outputs" in le_schema.get("properties", {})
    assert "status" in le_schema.get("properties", {})

    # Verify verify_provenance schema
    vp_schema = tool_map["verify_provenance"].inputSchema
    assert "start_seq" in vp_schema.get("properties", {})
    assert "end_seq" in vp_schema.get("properties", {})


@pytest.mark.anyio
async def test_fastmcp_commit_decision_and_views_sync(clean_server):
    """Verify commit_decision writes to ledger and synchronizes FTS5, Vector, and Kùzu views."""
    res = await clean_server.call_tool(
        "commit_decision",
        {
            "title": "Adopt SQLite WAL",
            "context": "Need 10-year durability and single-file portability",
            "rejected": ["MongoDB", "PostgreSQL Docker"],
            "decision": "Use SQLite 3 in WAL mode with BLAKE3 chain",
        },
    )
    event_data = _extract_tool_result(res)
    assert event_data["event_type"] == "decision"
    assert event_data["seq"] == 1
    assert event_data["signature"] is not None

    # 1. Check ledger
    with sqlite3.connect(str(clean_server.ledger.db_path)) as conn:
        row = conn.execute("SELECT * FROM events WHERE seq = 1;").fetchone()
        assert row is not None

    # 2. Check FTS5 lexical search
    fts_hits = clean_server.fts_view.search("SQLite WAL")
    assert len(fts_hits) == 1
    assert fts_hits[0]["event_id"] == event_data["event_id"]

    # 3. Check Vector search
    vec_hits = clean_server.vec_view.search("durability single-file")
    assert len(vec_hits) == 1
    assert vec_hits[0]["event_id"] == event_data["event_id"]

    # 4. Verify provenance
    v_res = await clean_server.call_tool("verify_provenance", {})
    audit = _extract_tool_result(v_res)
    assert audit["valid"] is True
    assert audit["verified_count"] == 1


@pytest.mark.anyio
async def test_fastmcp_log_execution_artifact_and_tracing(clean_server):
    """Verify log_execution_artifact appends to Merkle chain and links entities in Kùzu."""
    res = await clean_server.call_tool(
        "log_execution_artifact",
        {
            "action_type": "security_audit",
            "inputs": {"module": "BLAKE3", "algo": "XOF"},
            "outputs": {"status": "PASSED", "error_code": "ERR_NONE"},
            "status": "SUCCESS",
        },
    )
    artifact_event = _extract_tool_result(res)
    assert artifact_event["event_type"] == "execution_artifact"
    assert artifact_event["seq"] == 1

    # Trace entity history for BLAKE3
    t_res = await clean_server.call_tool(
        "trace_entity_history", {"entity_name": "BLAKE3"}
    )
    history = _extract_tool_result(t_res)
    assert len(history) >= 1
    ids = [h["id"] for h in history]
    assert artifact_event["event_id"] in ids


@pytest.mark.anyio
async def test_fastmcp_recall_context_with_supersession_filtering(clean_server):
    """Verify recall_context executes 3-way RRF and filters superseded decisions by default."""
    # Commit Initial Decision D1
    res1 = await clean_server.call_tool(
        "commit_decision",
        {
            "title": "Auth Token Format v1",
            "context": "Stateless authentication",
            "rejected": ["Cookies"],
            "decision": "Use standard HS256 JWT tokens for auth",
        },
    )
    d1 = _extract_tool_result(res1)

    # Commit Superseding Decision D2
    res2 = await clean_server.call_tool(
        "commit_decision",
        {
            "title": "Auth Token Format v2",
            "context": "Cryptographic non-repudiation",
            "rejected": ["HS256 JWT"],
            "decision": "Replace HS256 JWT with Ed25519 asymmetric auth tokens",
            "supersedes_id": d1["event_id"],
        },
    )
    d2 = _extract_tool_result(res2)

    # 1. Default recall_context (include_superseded=False): Only active D2 returned
    rc1_res = await clean_server.call_tool(
        "recall_context",
        {"query": "Auth Token Format", "include_superseded": False},
    )
    results_active = _extract_tool_result(rc1_res)
    result_ids = [r["event_id"] for r in results_active]
    assert d2["event_id"] in result_ids
    assert d1["event_id"] not in result_ids

    # 2. recall_context with include_superseded=True: Both returned, D2 outranks D1
    rc2_res = await clean_server.call_tool(
        "recall_context",
        {"query": "Auth Token Format", "include_superseded": True},
    )
    results_all = _extract_tool_result(rc2_res)
    res_map = {r["event_id"]: r for r in results_all}
    assert d1["event_id"] in res_map
    assert d2["event_id"] in res_map
    assert res_map[d1["event_id"]]["is_superseded"] is True
    assert res_map[d2["event_id"]]["is_superseded"] is False
    assert res_map[d2["event_id"]]["score"] > res_map[d1["event_id"]]["score"]


@pytest.mark.anyio
async def test_fastmcp_tamper_detection(clean_server):
    """Verify verify_provenance detects tampering in the SQLite ledger."""
    # Commit two events
    await clean_server.call_tool(
        "commit_decision",
        {
            "title": "Decision 1",
            "context": "Test context",
            "rejected": [],
            "decision": "Decision text",
        },
    )
    await clean_server.call_tool(
        "commit_decision",
        {
            "title": "Decision 2",
            "context": "Test context",
            "rejected": [],
            "decision": "Decision text 2",
        },
    )

    # Initial provenance is valid
    audit_init_res = await clean_server.call_tool("verify_provenance", {})
    audit_init = _extract_tool_result(audit_init_res)
    assert audit_init["valid"] is True

    # Tamper with row 1 payload directly in SQLite
    db_path = clean_server.ledger.db_path
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("UPDATE events SET payload = '{\"tampered\": true}' WHERE seq = 1;")
        conn.commit()

    # Provenance audit should now fail
    audit_tampered_res = await clean_server.call_tool("verify_provenance", {})
    audit_tampered = _extract_tool_result(audit_tampered_res)
    assert audit_tampered["valid"] is False
    assert audit_tampered["failed_seq"] == 1


@pytest.mark.anyio
async def test_fastmcp_stdio_end_to_end(tmp_path: Path):
    """End-to-end test verifying the FastMCP server over actual stdio subprocess transport."""
    db_file = tmp_path / "stdio_ledger.db"
    graph_path = tmp_path / "stdio_graph.kuzu"

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "aethelgard.mcp",
            "--db",
            str(db_file),
            "--graph",
            str(graph_path),
        ],
        env=None,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List tools
            tools_result = await session.list_tools()
            tool_names = [t.name for t in tools_result.tools]
            assert "commit_decision" in tool_names
            assert "recall_context" in tool_names
            assert "trace_entity_history" in tool_names
            assert "log_execution_artifact" in tool_names
            assert "verify_provenance" in tool_names

            # 2. Call commit_decision over stdio
            c_res = await session.call_tool(
                "commit_decision",
                {
                    "title": "Stdio Protocol ADR",
                    "context": "Testing stdio transport bridge",
                    "rejected": ["Raw Sockets"],
                    "decision": "FastMCP stdio bridge for IDE and agents",
                },
            )
            assert c_res.content is not None
            c_text = c_res.content[0].text
            c_json = json.loads(c_text)
            assert c_json["event_type"] == "decision"
            assert c_json["seq"] == 1

            # 3. Call recall_context over stdio
            r_res = await session.call_tool(
                "recall_context",
                {"query": "Stdio Protocol"},
            )
            assert r_res.content is not None
            r_items = [json.loads(c.text) for c in r_res.content]
            assert len(r_items) == 1
            assert r_items[0]["event_id"] == c_json["event_id"]

            # 4. Call verify_provenance over stdio
            v_res = await session.call_tool("verify_provenance", {})
            assert v_res.content is not None
            v_text = v_res.content[0].text
            v_json = json.loads(v_text)
            assert v_json["valid"] is True
            assert v_json["verified_count"] == 1
