"""sweep-mcp - sweep, exposed to an agent, with the guard rails that requires.

The public surface is the guard and the server builder:

    >>> from sweep_mcp import Guard
    >>> Guard([]).roots
    ()
"""

from __future__ import annotations

__version__ = "0.1.0"

from .guard import Denied, Guard, Ticket  # noqa: E402
from .server import build_server, main  # noqa: E402

__all__ = [
    "__version__",
    "Denied",
    "Guard",
    "Ticket",
    "build_server",
    "main",
]
