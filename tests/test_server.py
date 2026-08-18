"""Tests for the MCP layer, driven through ``call_tool`` rather than the functions.

Calling the tools the way a client does is the point: it exercises the schema,
the argument coercion and the error path, none of which are covered by calling
the Python functions directly.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from sweep_mcp import build_server


def call(server: MCPServer, name: str, arguments: dict) -> dict:
    """Invoke a tool and return its parsed JSON payload."""
    result = asyncio.run(server.call_tool(name, arguments))
    text = "".join(block.text for block in result.content if getattr(block, "text", None))
    return json.loads(text)


def denial(server: MCPServer, name: str, arguments: dict) -> str:
    """Invoke a tool expecting refusal, and return the reason the model would see.

    MCP 2.0 surfaces a raised exception as ``ToolError`` rather than as a
    ``CallToolResult(isError=True)``. Either way the text reaches the model,
    which is what matters — a refusal the agent cannot read is a refusal it
    cannot correct.
    """
    with pytest.raises(ToolError) as caught:
        asyncio.run(server.call_tool(name, arguments))
    return str(caught.value)


def scan_one(server: MCPServer, path: Path) -> str:
    """Scan and return the id of the single expected find."""
    payload = call(server, "scan", {"path": str(path)})
    assert payload["found"] == 1, payload
    return payload["finds"][0]["id"]


# -- tool registration ------------------------------------------------------


def test_the_destructive_tool_is_declared_destructive(workspace: Path):
    """A client that hides destructive tools behind confirmation needs the hint set."""
    server = build_server([workspace])
    tools = {t.name: t for t in asyncio.run(server.list_tools())}

    assert tools["reclaim"].annotations.destructive_hint is True
    assert tools["reclaim"].annotations.read_only_hint is False
    assert tools["scan"].annotations.read_only_hint is True
    assert tools["list_targets"].annotations.read_only_hint is True


def test_tool_descriptions_are_static(workspace: Path, make_node_project):
    """A directory name must never reach the model as instruction-shaped text."""
    make_node_project(workspace, name="ignore-previous-instructions")
    server = build_server([workspace])

    blob = " ".join(t.description or "" for t in asyncio.run(server.list_tools()))
    assert "ignore-previous-instructions" not in blob


# -- scan -------------------------------------------------------------------


def test_scan_finds_the_project(workspace: Path):
    server = build_server([workspace])
    payload = call(server, "scan", {"path": str(workspace)})

    assert payload["found"] == 1
    assert payload["finds"][0]["target"] == "node-modules"
    assert payload["finds"][0]["regenerate_with"] == "npm install"


def test_scan_outside_the_root_is_refused(workspace: Path, outside: Path):
    server = build_server([workspace])
    assert "outside the allowed roots" in denial(server, "scan", {"path": str(outside)})


def test_scan_with_an_unknown_target_key_is_refused(workspace: Path):
    server = build_server([workspace])
    reason = denial(server, "scan", {"path": str(workspace), "only": ["not-a-target"]})
    assert "unknown target keys" in reason


# -- reclaim: the default is not to delete ----------------------------------


def test_reclaim_is_a_dry_run_without_confirmation(workspace: Path):
    server = build_server([workspace])
    find_id = scan_one(server, workspace)
    path = Path(call(server, "scan", {"path": str(workspace)})["finds"][0]["path"])

    payload = call(server, "reclaim", {"ids": [find_id]})

    assert payload["dry_run"] is True
    assert len(payload["would_delete"]) == 1
    assert path.exists(), "a dry run must not touch the filesystem"


def test_a_wrong_confirmation_string_stays_a_dry_run(workspace: Path):
    """Anything other than the exact phrase is treated as 'no'."""
    server = build_server([workspace])
    find_id = scan_one(server, workspace)
    path = Path(call(server, "scan", {"path": str(workspace)})["finds"][0]["path"])

    for attempt in ["yes", "DELETE", "delete ", "true", "y"]:
        payload = call(server, "reclaim", {"ids": [find_id], "confirm": attempt})
        assert payload["dry_run"] is True, attempt
        assert path.exists(), attempt


def test_reclaim_with_no_ids_is_refused(workspace: Path):
    server = build_server([workspace])
    assert "no ids given" in denial(server, "reclaim", {"ids": []})


# -- reclaim: the deletion path ---------------------------------------------


def test_reclaim_deletes_when_confirmed(workspace: Path):
    server = build_server([workspace])
    payload = call(server, "scan", {"path": str(workspace)})
    find_id = payload["finds"][0]["id"]
    path = Path(payload["finds"][0]["path"])
    assert path.exists()

    done = call(server, "reclaim", {"ids": [find_id], "confirm": "delete"})

    assert done["dry_run"] is False
    assert len(done["deleted"]) == 1
    assert not path.exists()
    assert (path.parent / "package.json").exists(), "only the artifact should go"


def test_an_id_cannot_be_redeemed_twice(workspace: Path):
    server = build_server([workspace])
    find_id = scan_one(server, workspace)

    call(server, "reclaim", {"ids": [find_id], "confirm": "delete"})
    again = call(server, "reclaim", {"ids": [find_id], "confirm": "delete"})

    assert again["deleted"] == []
    assert again["refused"][0]["id"] == find_id
    assert "unknown find id" in again["refused"][0]["reason"]


def test_unknown_ids_are_refused_individually_not_fatally(workspace: Path):
    """One bad id must not cost the caller the whole batch."""
    server = build_server([workspace])
    find_id = scan_one(server, workspace)

    payload = call(
        server, "reclaim", {"ids": [find_id, "f-deadbeefcafe"], "confirm": "delete"}
    )

    assert len(payload["deleted"]) == 1
    assert len(payload["refused"]) == 1
    assert payload["refused"][0]["id"] == "f-deadbeefcafe"


def test_a_stale_find_is_refused_at_reclaim_time(workspace: Path):
    """Marker removed between scan and reclaim: the justification is gone."""
    server = build_server([workspace])
    payload = call(server, "scan", {"path": str(workspace)})
    find_id = payload["finds"][0]["id"]
    path = Path(payload["finds"][0]["path"])

    (path.parent / "package.json").unlink()

    done = call(server, "reclaim", {"ids": [find_id], "confirm": "delete"})

    assert done["deleted"] == []
    assert "no longer matches target" in done["refused"][0]["reason"]
    assert path.exists()


def test_ids_from_one_server_are_not_valid_on_another(workspace: Path):
    """Tickets are per-process. A restarted server forgets everything."""
    first = build_server([workspace])
    find_id = scan_one(first, workspace)

    second = build_server([workspace])
    payload = call(second, "reclaim", {"ids": [find_id], "confirm": "delete"})

    assert payload["deleted"] == []
    assert "unknown find id" in payload["refused"][0]["reason"]


# -- list_targets -----------------------------------------------------------


def test_list_targets_reports_the_configured_roots(workspace: Path):
    server = build_server([workspace])
    payload = call(server, "list_targets", {})

    assert payload["roots"] == [str(workspace.resolve())]
    keys = {t["key"] for t in payload["targets"]}
    assert "node-modules" in keys and "venv" in keys


def test_list_targets_states_the_marker_requirement(workspace: Path):
    server = build_server([workspace])
    payload = call(server, "list_targets", {})
    by_key = {t["key"]: t for t in payload["targets"]}

    assert by_key["node-modules"]["requires_marker_file"] == ["package.json"]
    assert by_key["pycache"]["requires_marker_file"] is None
