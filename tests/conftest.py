"""Shared pytest fixtures for the stashfs test suite.

Keeps per-test setup boilerplate small so new tests can be written
cheaply, and every test stays well under the 1s budget from TODO.md.

Stash is now backed by the encrypted ``Volume`` stack, so the fixture
supplies the test-grade ``KDFParams.fast()`` preset and a chosen
``password`` (empty by default -> slot 0).
"""

import gc
from dataclasses import dataclass
from pathlib import Path

import pytest

from stashfs import KDF, FileWrapper, KDFParams, Stash


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
def make_stash(backing_file, fast_kdf):
    """Build a Stash instance over a fresh encrypted container.

    Returns the Stash, the backing file path, and a ``reopen`` callable that
    remounts with the same (or a different) password so tests can assert
    persistence.
    """

    def _make(name: str = 'fly_file', pw: str = ''):
        path = backing_file(name=name)
        stash = Stash()
        stash.add_args(FakeArgs(fname=path), password=pw, kdf=fast_kdf)

        def reopen(new_password: str | None = None) -> Stash:
            # Mirror what real FUSE close(2) -> flush would do for a
            # userland writer. Without this, every test that wrote
            # through the first Stash and then re-opens to assert
            # persistence would see the deferred index commit
            # disappear.
            stash.volume.flush()
            new_fly = Stash()
            new_fly.add_args(
                FakeArgs(fname=path),
                password=pw if new_password is None else new_password,
                kdf=fast_kdf,
            )
            return new_fly

        return stash, path, reopen

    return _make


class MultiStash:
    """Test helper for driving several passwords against one backing file.

    Hides the boilerplate of constructing ``Stash`` / ``FakeArgs`` / ``KDF``
    and provides an honest ``unmount_all`` that actually releases the
    Python-side file handles. Stash participates in a reference cycle
    (via ``fuse.Fuse``) so ``del`` alone does not drop the object; we
    close the ``FileWrapper`` read handle explicitly and then force
    cyclic GC so a subsequent ``mount`` opens an independent view of
    the on-disk container.
    """

    def __init__(self, path: Path, kdf: KDF) -> None:
        self.path = path
        self.kdf = kdf
        self._live: list[Stash] = []

    def mount(self, password: str = '') -> Stash:
        # Flush every volume that's already live so their deferred
        # index commits land on disk before a new volume opens its
        # own (read-only-at-construction) view of the allocation
        # chain. Without this, a later flush from a stale-view volume
        # would write allocation entries based on outdated state and
        # collide with appends from sibling volumes.
        for live in self._live:
            live.volume.flush()
        stash = Stash()
        stash.add_args(FakeArgs(fname=self.path), password=password, kdf=self.kdf)
        self._live.append(stash)
        return stash

    def unmount_all(self) -> None:
        for stash in self._live:
            # Flush any deferred index commit before tearing down the
            # underlying file handles. Without this, writes that the
            # test made without going through Stash's FUSE-level
            # flush/release callbacks would be silently dropped at
            # remount time.
            stash.volume.flush()
            handle = getattr(stash.storage, 'read_handle', None)
            if handle is not None and not handle.closed:
                handle.close()
        self._live.clear()
        gc.collect()

    def remount(self, password: str = '') -> Stash:
        """Unmount every live Stash and return a fresh mount for ``password``."""
        self.unmount_all()
        return self.mount(password)


@pytest.fixture
def multi_stash(backing_file, fast_kdf):
    """Drive several passwords against one backing file via ``MultiStash``.

    The fixture yields a ``MultiStash`` whose ``mount(password)`` opens a
    fresh ``Stash`` over the shared backing file. ``unmount_all`` and
    ``remount`` release handles cleanly so tests can assert
    persistence without leaking low-level cleanup into the test body.
    The fixture also unmounts anything still live at teardown.
    """
    path = backing_file(name='multi_stash_file')
    mfly = MultiStash(path, fast_kdf)
    try:
        yield mfly
    finally:
        mfly.unmount_all()


@pytest.fixture
def stash(make_stash, password):
    """A ready-to-use Stash for the common single-volume test case.

    Parametrised over an empty password (slot 0) and a real password
    (slot 1) so every test using this fixture runs twice.
    """
    instance, _path, _reopen = make_stash(pw=password)
    return instance
