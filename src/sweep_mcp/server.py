"""The MCP surface: three tools over sweep, and nothing clever.

This layer translates and nothing else. Every decision that could lose someone
their data is made in :mod:`sweep_mcp.guard`, which knows nothing about MCP and
can be tested without it. If a rule appears to be enforced here, it is a bug —
it belongs one layer down where the tests can reach it directly.

Tool descriptions are string literals defined at import time. They are never
built from anything read off the filesystem, because a tool description is
instruction-shaped text that reaches the model, and a directory named
``ignore-previous-instructions`` should be inert data, not a sentence the model
reads as guidance.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from sweep import scan as sweep_scan
from sweep.targets import TARGETS, TARGETS_BY_KEY, resolve

from .guard import Denied, Guard

__all__ = ["build_server", "main"]

CONFIRM_PHRASE = "delete"


@dataclass
class State:
    """Server-wide state. One guard, for the life of the process."""

    guard: Guard


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def build_server(roots: Sequence[Path | str], *, version: str = "0.1.0") -> MCPServer:
    """Wire the tools onto a guard built from ``roots``.

    Exposed separately from :func:`main` so tests can drive the tools without a
    transport.
    """
    state = State(guard=Guard(roots))

    server = MCPServer(
        name="sweep",
        version=version,
        instructions=(
            "Finds regenerable build artifacts (node_modules, .venv, target, __pycache__ "
            "and similar) and reclaims the space. Deletion is limited to directories this "
            "server itself located inside its configured roots, and every deletion is "
            "re-checked against the filesystem before it happens."
        ),
    )

    # ---------------------------------------------------------------- targets

    @server.tool(
        name="list_targets",
        description=(
            "List the kinds of directory this server knows how to reclaim, with the "
            "command that regenerates each one. Read-only; touches no files."
        ),
        annotations=ToolAnnotations(
            title="List reclaimable target types",
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def list_targets() -> dict[str, Any]:
        return {
            "roots": [str(root) for root in state.guard.roots],
            "targets": [
                {
                    "key": target.key,
                    "ecosystem": target.ecosystem,
                    "matches": list(target.patterns),
                    "requires_marker_file": list(target.markers) or None,
                    "regenerate_with": target.regenerate,
                }
                for target in TARGETS
            ],
        }

    # ------------------------------------------------------------------ scan

    @server.tool(
        name="scan",
        description=(
            "Scan for reclaimable directories under a path inside the configured roots. "
            "Returns each find with an id, its size, and the command that regenerates it. "
            "Read-only: this never deletes anything. The ids it returns are the only "
            "things 'reclaim' will accept."
        ),
        annotations=ToolAnnotations(
            title="Scan for reclaimable directories",
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def scan(
        path: str,
        only: list[str] | None = None,
        min_size_mb: float = 0.0,
        older_than_days: float | None = None,
        max_depth: int | None = None,
    ) -> dict[str, Any]:
        root = state.guard.contain(path)

        targets = TARGETS
        if only:
            unknown = [key for key in only if key not in TARGETS_BY_KEY]
            if unknown:
                raise Denied(
                    f"unknown target keys {unknown}; call list_targets for the valid set"
                )
            targets = resolve(only)

        result = sweep_scan(
            [root],
            targets=targets,
            min_size=int(min_size_mb * 1024 * 1024),
            older_than=older_than_days,
            max_depth=max_depth,
        )

        tickets = state.guard.issue(result.finds)

        return {
            "scanned": str(root),
            "found": len(tickets),
            "total_size": _human(sum(t.find.size for t in tickets)),
            "total_bytes": sum(t.find.size for t in tickets),
            "duration_seconds": round(result.duration, 2),
            "finds": [
                {
                    "id": t.id,
                    "path": str(t.find.path),
                    "target": t.find.target.key,
                    "size": _human(t.find.size),
                    "size_bytes": t.find.size,
                    "files": t.find.files,
                    "age_days": round(t.find.age_days, 1),
                    "regenerate_with": t.find.target.regenerate,
                }
                for t in tickets
            ],
        }

    # --------------------------------------------------------------- reclaim

    @server.tool(
        name="reclaim",
        description=(
            "Delete directories previously located by 'scan', identified by the ids it "
            "returned. Paths are not accepted — only ids. Runs as a dry run unless "
            f"confirm is set to the exact string {CONFIRM_PHRASE!r}. Every id is "
            "re-checked against the filesystem before deletion, and ids that no longer "
            "match are refused individually rather than failing the whole call."
        ),
        annotations=ToolAnnotations(
            title="Delete scanned directories",
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    def reclaim(ids: list[str], confirm: str = "") -> dict[str, Any]:
        if not ids:
            raise Denied("no ids given; call scan first and pass the ids it returns")

        dry_run = confirm != CONFIRM_PHRASE

        planned: list[dict[str, Any]] = []
        refused: list[dict[str, Any]] = []
        deleted: list[dict[str, Any]] = []

        for ticket_id in ids:
            try:
                ticket = state.guard.redeem(ticket_id)
                state.guard.revalidate(ticket)
            except Denied as exc:
                refused.append({"id": ticket_id, "reason": str(exc)})
                continue

            entry = {
                "id": ticket_id,
                "path": str(ticket.path),
                "size": _human(ticket.find.size),
                "size_bytes": ticket.find.size,
                "regenerate_with": ticket.find.target.regenerate,
            }

            if dry_run:
                planned.append(entry)
                continue

            try:
                from sweep import delete as sweep_delete

                sweep_delete(ticket.find)
            except OSError as exc:
                refused.append({"id": ticket_id, "reason": f"delete failed: {exc}"})
                continue

            state.guard.forget(ticket_id)
            deleted.append(entry)

        if dry_run:
            return {
                "dry_run": True,
                "would_delete": planned,
                "would_reclaim": _human(sum(e["size_bytes"] for e in planned)),
                "refused": refused,
                "note": (
                    f"Nothing was deleted. Call again with confirm={CONFIRM_PHRASE!r} "
                    "to carry this out."
                ),
            }

        return {
            "dry_run": False,
            "deleted": deleted,
            "reclaimed": _human(sum(e["size_bytes"] for e in deleted)),
            "refused": refused,
        }

    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sweep-mcp",
        description="MCP server exposing sweep, confined to an explicit set of roots.",
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        help=(
            "A directory the server is allowed to scan and delete inside. "
            "Repeatable. Required: with no roots the server refuses every request."
        ),
    )
    args = parser.parse_args(argv)

    if not args.root:
        parser.error(
            "at least one --root is required. This server will not default to the "
            "whole filesystem."
        )

    try:
        server = build_server(args.root)
    except Denied as exc:
        parser.error(str(exc))
        return 2

    server.run(transport="stdio")
    return 0
