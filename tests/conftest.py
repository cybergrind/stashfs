"""Shared pytest fixtures for the fly test suite.

Keeps per-test setup boilerplate small so new tests can be written
cheaply, and every test stays well under the 1s budget from TODO.md.

Fly is now backed by the encrypted ``Volume`` stack, so the fixture
supplies the test-grade ``KDFParams.fast()`` preset and a chosen
``password`` (empty by default -> slot 0).
"""

from dataclasses import dataclass
from pathlib import Path

import pytest

from fly import KDF, FileWrapper, Fly, KDFParams


@dataclass
class FakeArgs:
    fname: Path
    mountpoint: str = ''
    ttl: int = 300
    debug: bool = False


@pytest.fixture
def fast_kdf() -> KDF:
    """Shared ``KDF`` tuned to stay under the per-test time budget."""
    return KDF(KDFParams.fast())


@pytest.fixture
def backing_file(tmp_path):
    """Return a factory that creates an empty backing file for a container."""

    def _make(name: str = 'backing') -> Path:
        path = tmp_path / name
        path.write_bytes(b'')
        return path

    return _make


@pytest.fixture
def file_wrapper(backing_file):
    """A fresh FileWrapper bound to an empty backing file."""
    return FileWrapper(backing_file())


@pytest.fixture(params=['', 'hunter2'])
def password(request) -> str:
    """Parametrize every test that takes ``password`` over empty + real."""
    return request.param


@pytest.fixture
def make_fly(backing_file, fast_kdf):
    """Build a Fly instance over a fresh encrypted container.

    Returns the Fly, the backing file path, and a ``reopen`` callable that
    remounts with the same (or a different) password so tests can assert
    persistence.
    """

    def _make(name: str = 'fly_file', pw: str = ''):
        path = backing_file(name=name)
        fly = Fly()
        fly.add_args(FakeArgs(fname=path), password=pw, kdf=fast_kdf)

        def reopen(new_password: str | None = None) -> Fly:
            new_fly = Fly()
            new_fly.add_args(
                FakeArgs(fname=path),
                password=pw if new_password is None else new_password,
                kdf=fast_kdf,
            )
            return new_fly

        return fly, path, reopen

    return _make


@pytest.fixture
def fly(make_fly, password):
    """A ready-to-use Fly for the common single-volume test case.

    Parametrised over an empty password (slot 0) and a real password
    (slot 1) so every test using this fixture runs twice.
    """
    instance, _path, _reopen = make_fly(pw=password)
    return instance
