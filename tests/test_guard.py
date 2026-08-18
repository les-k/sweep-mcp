"""Tests for the rules that decide whether a directory may be deleted.

Each test names the attack it is standing in for. A control with no test that
makes it fire is a control nobody has checked.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from sweep import scan

from sweep_mcp.guard import Denied, Guard, is_link

# -- construction -----------------------------------------------------------


def test_empty_allowlist_denies_every_path(tmp_path: Path):
    """A server started with no roots must be useless, not unbounded."""
    guard = Guard([])
    assert guard.roots == ()
    with pytest.raises(Denied, match="no roots are configured"):
        guard.contain(tmp_path)


def test_nonexistent_root_is_refused_at_construction(tmp_path: Path):
    with pytest.raises(Denied, match="does not exist"):
        Guard([tmp_path / "nowhere"])


def test_file_as_root_is_refused(tmp_path: Path):
    target = tmp_path / "a-file.txt"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(Denied, match="not a directory"):
        Guard([target])


def test_symlinked_root_is_refused(tmp_path: Path, symlinks_allowed: bool):
    """A symlinked root points somewhere other than it appears to."""
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(real, link, target_is_directory=True)

    with pytest.raises(Denied, match="root is a link"):
        Guard([link])


# -- containment ------------------------------------------------------------


def test_path_inside_root_is_allowed(workspace: Path):
    guard = Guard([workspace])
    assert guard.contain(workspace / "app") == (workspace / "app").resolve()


def test_root_itself_is_allowed(workspace: Path):
    guard = Guard([workspace])
    assert guard.contain(workspace) == workspace.resolve()


def test_sibling_directory_is_denied(workspace: Path, outside: Path):
    guard = Guard([workspace])
    with pytest.raises(Denied, match="outside the allowed roots"):
        guard.contain(outside)


def test_dotdot_traversal_is_denied(workspace: Path, outside: Path):
    """The classic: spell the forbidden path relative to an allowed one."""
    guard = Guard([workspace])
    escape = workspace / ".." / "not-yours"
    with pytest.raises(Denied, match="outside the allowed roots"):
        guard.contain(escape)


def test_traversal_is_judged_after_resolution_not_before(workspace: Path, outside: Path):
    """``workspace/../not-yours`` must be reported as its real location."""
    guard = Guard([workspace])
    try:
        guard.contain(workspace / ".." / "not-yours" / "thesis.txt")
    except Denied as exc:
        assert "not-yours" in str(exc)
        assert ".." not in str(exc)
    else:  # pragma: no cover
        pytest.fail("traversal was not denied")


def test_symlink_pointing_outside_root_is_denied(
    workspace: Path, outside: Path, symlinks_allowed: bool
):
    """A link inside the root aimed at a path outside it."""
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")
    guard = Guard([workspace])
    bridge = workspace / "bridge"
    os.symlink(outside, bridge, target_is_directory=True)

    with pytest.raises(Denied, match="outside the allowed roots"):
        guard.contain(bridge / "thesis.txt")


# -- tickets ----------------------------------------------------------------


def test_issue_returns_a_ticket_per_find(workspace: Path):
    guard = Guard([workspace])
    result = scan([workspace])
    tickets = guard.issue(result.finds)
    assert len(tickets) == len(result.finds) == 1
    assert tickets[0].path.name == "node_modules"


def test_issue_silently_drops_finds_outside_the_allowlist(
    workspace: Path, outside: Path, make_node_project
):
    """A find from somewhere unauthorised must not become deletable."""
    make_node_project(outside, name="sneaky")
    guard = Guard([workspace])

    stray = scan([outside])
    assert stray.finds, "fixture should have produced a find"

    assert guard.issue(stray.finds) == []


def test_ticket_ids_are_not_guessable(workspace: Path, make_node_project):
    """Sequential ids invite an agent to iterate until something deletes."""
    make_node_project(workspace, name="second")
    guard = Guard([workspace])
    tickets = guard.issue(scan([workspace]).finds)

    ids = [t.id for t in tickets]
    assert len(set(ids)) == len(ids)
    for tid in ids:
        assert tid.startswith("f-")
        assert len(tid) == 14  # "f-" plus 12 hex characters
        assert tid[2:] != "0" * 12


def test_redeeming_an_unknown_id_is_denied(workspace: Path):
    guard = Guard([workspace])
    with pytest.raises(Denied, match="unknown find id"):
        guard.redeem("f-000000000000")


def test_there_is_no_way_to_delete_by_path(workspace: Path):
    """The guard exposes no path-accepting redemption route at all."""
    guard = Guard([workspace])
    assert not hasattr(guard, "redeem_path")
    with pytest.raises(Denied, match="unknown find id"):
        guard.redeem(str(workspace / "app" / "node_modules"))


def test_forget_makes_an_id_unusable(workspace: Path):
    guard = Guard([workspace])
    ticket = guard.issue(scan([workspace]).finds)[0]
    guard.forget(ticket.id)
    with pytest.raises(Denied, match="unknown find id"):
        guard.redeem(ticket.id)


# -- revalidation: the gap between scan and delete --------------------------


def test_revalidate_passes_for_an_untouched_find(workspace: Path):
    guard = Guard([workspace])
    ticket = guard.issue(scan([workspace]).finds)[0]
    guard.revalidate(ticket)  # must not raise


def test_revalidate_refuses_a_vanished_directory(workspace: Path):
    guard = Guard([workspace])
    ticket = guard.issue(scan([workspace]).finds)[0]
    shutil.rmtree(ticket.path)

    with pytest.raises(Denied, match="no longer exists"):
        guard.revalidate(ticket)


def test_revalidate_refuses_when_the_marker_file_is_gone(workspace: Path):
    """node_modules is only safe to delete because a package.json sits beside it."""
    guard = Guard([workspace])
    ticket = guard.issue(scan([workspace]).finds)[0]
    (ticket.path.parent / "package.json").unlink()

    with pytest.raises(Denied, match="no longer matches target"):
        guard.revalidate(ticket)


def test_revalidate_refuses_a_directory_swapped_for_a_symlink(
    workspace: Path, outside: Path, symlinks_allowed: bool
):
    """The attack the re-check exists for.

    Scan sees a real node_modules. Between the scan and the delete it is
    replaced by a link to something that matters. A server trusting its own
    stale scan would follow it.
    """
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")

    guard = Guard([workspace])
    ticket = guard.issue(scan([workspace]).finds)[0]

    shutil.rmtree(ticket.path)
    os.symlink(outside, ticket.path, target_is_directory=True)

    with pytest.raises(Denied, match="is now a link"):
        guard.revalidate(ticket)

    assert (outside / "thesis.txt").exists(), "the guard must not have followed the link"


def test_revalidate_refuses_a_swap_aimed_inside_the_root(
    workspace: Path, symlinks_allowed: bool, make_node_project
):
    """The swap the previous test does not cover.

    The first swap test aims the replacement symlink *outside* the root, where
    contain() denies it before is_link() is ever reached - the right outcome,
    reached because resolve() happens to land somewhere already forbidden.

    Here the replacement is aimed at a second, real node_modules that also
    lives inside the same allowed root. contain() resolves the link, finds the
    destination is legitimately in-bounds, and returns *that* path - so a
    link check running after containment would inspect the target, not the
    link, and the marker check downstream would find real markers and approve
    the delete. This is the case that forces is_link() to run on the ticket's
    own path before contain() ever resolves through it.
    """
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")

    guard = Guard([workspace])
    ticket = guard.issue(scan([workspace]).finds)[0]

    decoy = make_node_project(workspace, name="decoy")
    assert decoy != ticket.path

    shutil.rmtree(ticket.path)
    os.symlink(decoy, ticket.path, target_is_directory=True)

    with pytest.raises(Denied, match="is now a link"):
        guard.revalidate(ticket)

    assert decoy.exists(), "the guard must not have deleted the decoy it was swapped for"


def test_revalidate_refuses_a_target_not_enabled_on_this_server(workspace: Path):
    guard = Guard([workspace])
    ticket = guard.issue(scan([workspace]).finds)[0]

    with pytest.raises(Denied, match="not enabled on this server"):
        guard.revalidate(ticket, targets=())


# -- link detection ---------------------------------------------------------


def test_is_link_is_false_for_a_plain_directory(tmp_path: Path):
    assert is_link(tmp_path) is False


def test_is_link_is_true_for_a_symlink(tmp_path: Path, symlinks_allowed: bool):
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")
    target = tmp_path / "t"
    target.mkdir()
    link = tmp_path / "l"
    os.symlink(target, link, target_is_directory=True)
    assert is_link(link) is True
