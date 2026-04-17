"""Shared pytest fixtures for the fly test suite.

These fixtures keep per-test setup boilerplate small so new tests can be
written cheaply, and every test stays well under the 1s budget from TODO.md.
"""

from dataclasses import dataclass
from pathlib import Path

import pytest

from fly import FileWrapper, Fly


@dataclass
class FakeArgs:
    fname: Path
    mountpoint: str = ''
    ttl: int = 300
    debug: bool = False


@pytest.fixture
def backing_file(tmp_path):
    """A backing file seeded with a known 22-byte payload."""

    def _make(name: str = 'backing', content: bytes = b'this_is_sample_content') -> Path:
        path = tmp_path / name
        path.write_bytes(content)
        return path

    return _make


@pytest.fixture
def file_wrapper(backing_file):
    """A fresh FileWrapper bound to a seeded backing file."""
    return FileWrapper(backing_file())


@pytest.fixture
def make_fly(backing_file):
    """Build a Fly instance wired to a fresh backing file.

    Returns the Fly, and the Path of the backing file, so tests can
    reopen the same storage (e.g. to assert persistence) via `reopen`.
    """

    def _make(name: str = 'fly_file', content: bytes = b'this_is_sample_content'):
        path = backing_file(name=name, content=content)
        fly = Fly()
        fly.add_args(FakeArgs(fname=path))

        def reopen() -> Fly:
            new_fly = Fly()
            new_fly.add_args(FakeArgs(fname=path))
            return new_fly

        return fly, path, reopen

    return _make


@pytest.fixture
def fly(make_fly):
    """A ready-to-use Fly instance for the common single-file test case."""
    instance, _path, _reopen = make_fly()
    return instance
