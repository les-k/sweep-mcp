"""Fixtures that build real directory trees on disk.

Nothing here is mocked. The whole point of the guard is what it does against a
filesystem, and a mocked ``Path`` would pass every test in this suite while the
server still deleted the wrong directory.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest


def _make_node_project(root: Path, name: str = "app", files: int = 3) -> Path:
    """A directory sweep will match: node_modules beside a package.json."""
    project = root / name
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text(f'{{"name": "{name}"}}', encoding="utf-8")

    modules = project / "node_modules"
    (modules / "left-pad").mkdir(parents=True, exist_ok=True)
    for i in range(files):
        (modules / "left-pad" / f"chunk{i}.js").write_text("x" * 512, encoding="utf-8")
    return modules


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """An allowed root containing one matchable node_modules."""
    root = tmp_path / "workspace"
    root.mkdir()
    _make_node_project(root)
    return root


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A directory deliberately outside the allowlist, holding something precious."""
    other = tmp_path / "not-yours"
    other.mkdir()
    (other / "thesis.txt").write_text("years of work", encoding="utf-8")
    return other


@pytest.fixture
def make_node_project():
    return _make_node_project


def can_symlink(tmp_path: Path) -> bool:
    """Whether this process may create symlinks.

    On Windows this needs developer mode or admin, and CI often has neither.
    Tests that need one skip rather than silently passing, because a symlink
    test that quietly does nothing is worse than no symlink test.
    """
    probe = tmp_path / "_probe"
    target = tmp_path / "_probe_target"
    target.mkdir(exist_ok=True)
    try:
        os.symlink(target, probe, target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        return False
    finally:
        if probe.is_symlink() or probe.exists():
            with contextlib.suppress(OSError):
                probe.unlink()
    return True


@pytest.fixture
def symlinks_allowed(tmp_path: Path) -> bool:
    return can_symlink(tmp_path)
