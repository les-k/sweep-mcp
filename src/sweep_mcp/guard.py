"""The part that says no.

Everything dangerous about this server lives here, and none of it imports MCP.
That separation is deliberate: the protocol layer is a thin translation, and the
rules that decide whether a directory may be deleted can be tested directly,
without a client, a transport or an agent in the loop.

The design rests on three refusals:

1. **The agent never chooses the roots.** They are fixed when the server starts.
   An empty allowlist denies everything rather than defaulting to the whole
   filesystem, because a misconfigured server should be useless, not dangerous.

2. **The agent never names a path to delete.** It may only redeem an identifier
   that this process issued from its own scan. A path that was never scanned
   cannot be deleted, however it is spelled.

3. **A find is re-checked at the moment of deletion**, not trusted from when it
   was scanned. The gap between the two is where a directory can be swapped for
   a symlink pointing somewhere that matters.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from sweep import Find
from sweep.targets import TARGETS, Target

__all__ = ["Denied", "Guard", "Ticket", "is_link"]


class Denied(Exception):
    """A request was refused.

    Carries the reason as prose because the caller is a language model, and
    "denied" alone gives it nothing to correct. Every raise site states which
    rule fired and what the offending value was.
    """


# ``os.path.isjunction`` arrived in 3.12. Below that a Windows junction is not
# distinguishable from a directory without ctypes, so the check degrades to
# symlinks only — the same compromise sweep itself makes, and worth stating
# rather than hiding, since it is a real hole on older interpreters.
_isjunction = getattr(os.path, "isjunction", None)


def is_link(path: Path) -> bool:
    """True for a symlink or a Windows junction.

    Anything that raises while being inspected counts as a link. Refusing to
    touch a path we could not classify is the safe way to be wrong.
    """
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    if _isjunction is not None:
        try:
            return bool(_isjunction(path))
        except OSError:
            return True
    return False


@dataclass(frozen=True)
class Ticket:
    """One deletable find, and the identifier the agent must quote to delete it.

    The identifier is random rather than an index. A sequential id invites an
    agent to iterate — ``delete("1")``, ``delete("2")`` — and hitting a valid
    target by counting is exactly the behaviour this is meant to prevent.
    """

    id: str
    find: Find

    @property
    def path(self) -> Path:
        return self.find.path


class Guard:
    """Holds the allowlist, issues tickets, and re-checks them on redemption."""

    def __init__(self, roots: Sequence[Path | str]) -> None:
        resolved: list[Path] = []
        for root in roots:
            path = Path(root).expanduser()
            if is_link(path):
                # A symlinked root would let the allowlist point somewhere it
                # does not appear to point, which defeats the purpose of having
                # one. Refuse at configuration time, loudly.
                raise Denied(f"root is a link, refusing to use it as an allowlist entry: {path}")
            path = path.resolve(strict=False)
            if not path.is_dir():
                raise Denied(f"root does not exist or is not a directory: {path}")
            resolved.append(path)

        self._roots: tuple[Path, ...] = tuple(resolved)
        self._tickets: dict[str, Ticket] = {}

    @property
    def roots(self) -> tuple[Path, ...]:
        return self._roots

    # -- containment -------------------------------------------------------

    def contain(self, path: Path | str) -> Path:
        """Resolve ``path`` and confirm it sits inside an allowed root.

        Resolution happens *before* the comparison, so ``root/../etc`` and a
        symlink aimed outside both collapse to their real location and are
        judged on that rather than on how they were written.
        """
        if not self._roots:
            raise Denied(
                "no roots are configured, so every path is outside the allowlist; "
                "start the server with at least one --root"
            )

        candidate = Path(path).expanduser().resolve(strict=False)
        for root in self._roots:
            if candidate == root or candidate.is_relative_to(root):
                return candidate

        allowed = ", ".join(str(root) for root in self._roots)
        raise Denied(f"{candidate} is outside the allowed roots ({allowed})")

    # -- ticket issue and redemption --------------------------------------

    def issue(self, finds: Iterable[Find]) -> list[Ticket]:
        """Register finds and hand back tickets.

        Finds outside the allowlist are dropped rather than rejected: a scan
        that wandered is a bug in the caller, and the useful behaviour is to
        return the safe subset instead of failing the whole request.
        """
        tickets: list[Ticket] = []
        for find in finds:
            try:
                self.contain(find.path)
            except Denied:
                continue
            ticket = Ticket(id=f"f-{secrets.token_hex(6)}", find=find)
            self._tickets[ticket.id] = ticket
            tickets.append(ticket)
        return tickets

    def redeem(self, ticket_id: str) -> Ticket:
        """Look up a ticket, or refuse.

        This is the only route to a deletable path. There is deliberately no
        overload that accepts a path.
        """
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise Denied(
                f"unknown find id {ticket_id!r}; ids come from scan() and are valid "
                "only for the life of this server process"
            )
        return ticket

    def forget(self, ticket_id: str) -> None:
        """Drop a ticket so a deleted path cannot be redeemed twice."""
        self._tickets.pop(ticket_id, None)

    # -- the check that runs at deletion time ------------------------------

    def revalidate(self, ticket: Ticket, targets: Sequence[Target] = TARGETS) -> None:
        """Confirm the find is still what it was when it was scanned.

        Scanning and deleting are separate calls with an agent thinking in
        between, and that gap is attackable: replace ``node_modules`` with a
        symlink to somewhere that matters and a server which trusted its own
        stale scan would follow it. Every property is therefore checked again
        here, against the filesystem as it is now.
        """
        # is_link runs on the ticket's own path, before containment resolves
        # anything. contain() calls Path.resolve(), which follows a symlink to
        # its destination and returns *that* — so checking is_link afterwards
        # inspects wherever the link points, not the link itself. A swap aimed
        # at another real target inside an allowed root would resolve cleanly,
        # pass containment, and reach the marker check as if it were the
        # original find. Checking here, on the unresolved path, is what makes
        # a swap a link no matter where it leads.
        if is_link(ticket.path):
            raise Denied(f"{ticket.path} is now a link; it was a directory when scanned")

        path = self.contain(ticket.path)

        if not path.exists():
            raise Denied(f"{path} no longer exists")

        if not path.is_dir():
            raise Denied(f"{path} is no longer a directory")

        parent = path.parent
        try:
            siblings = frozenset(entry.name for entry in os.scandir(parent))
        except OSError as exc:
            raise Denied(f"cannot read {parent} to re-check the marker files: {exc}") from exc

        if not ticket.find.target.matches(path.name, siblings):
            raise Denied(
                f"{path} no longer matches target {ticket.find.target.key!r} — "
                "the marker file that justified deleting it is gone"
            )

        # A find whose target is not in the catalogue we were handed cannot be
        # trusted either; it would mean the ticket outlived the configuration
        # that produced it.
        if ticket.find.target not in targets:
            raise Denied(f"target {ticket.find.target.key!r} is not enabled on this server")
