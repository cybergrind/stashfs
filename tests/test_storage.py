"""Contract tests for the ``Storage`` protocol.

Every Storage implementation must pass every test in this module. For
Phase 0 the only implementation is ``FileWrapper``; later phases can
parametrize the same tests over encrypted storage or in-memory mocks.
"""

from __future__ import annotations

import pytest

from fly.storage import CoverStorage, FileWrapper, Storage


def _make_filewrapper(tmp_path, name='backing', content=b''):
    path = tmp_path / name
    path.write_bytes(content)
    return FileWrapper(path)


def _make_cover_storage(tmp_path, name='backing', content=b''):
    """CoverStorage on top of an *empty* FileWrapper - no cover bytes."""
    inner = _make_filewrapper(tmp_path, name=name, content=content)
    return CoverStorage.attach(inner)


def _make_cover_storage_over_cover(tmp_path, name='backing'):
    """CoverStorage on top of a FileWrapper that has pre-existing cover."""
    path = tmp_path / name
    path.write_bytes(b'pretend-this-is-a-png-\x89PNG' * 10)
    inner = FileWrapper(path)
    return CoverStorage.attach(inner)


STORAGE_FACTORIES = [
    pytest.param(_make_filewrapper, id='FileWrapper'),
    pytest.param(_make_cover_storage, id='CoverStorage-no-cover'),
    pytest.param(_make_cover_storage_over_cover, id='CoverStorage-with-cover'),
]


@pytest.fixture(params=STORAGE_FACTORIES)
def storage(request, tmp_path) -> Storage:
    factory = request.param
    return factory(tmp_path)


class TestStorageContract:
    def test_satisfies_protocol(self, storage):
        assert isinstance(storage, Storage)

    def test_empty_size_is_zero(self, storage):
        assert storage.size() == 0

    def test_write_end_grows_file(self, storage):
        storage.write_end(b'abc')
        assert storage.size() == 3
        assert storage.read(3, 0) == b'abc'

    def test_write_end_appends(self, storage):
        storage.write_end(b'abc')
        storage.write_end(b'def')
        assert storage.read(6, 0) == b'abcdef'

    def test_write_at_offset_replaces_bytes(self, storage):
        storage.write_end(b'hello world')
        storage.write(6, b'fly!!')
        assert storage.read(11, 0) == b'hello fly!!'

    def test_read_past_eof_returns_short(self, storage):
        storage.write_end(b'short')
        assert storage.read(100, 0) == b'short'

    def test_read_at_eof_returns_empty(self, storage):
        storage.write_end(b'x')
        assert storage.read(5, 10) == b''

    def test_truncate_shrinks(self, storage):
        storage.write_end(b'abcdefgh')
        storage.truncate(3)
        assert storage.size() == 3
        assert storage.read(3, 0) == b'abc'

    def test_truncate_grows_with_zero_fill(self, storage):
        storage.write_end(b'abc')
        storage.truncate(6)
        assert storage.size() == 6
        assert storage.read(6, 0) == b'abc\x00\x00\x00'

    def test_write_then_read_round_trip(self, storage):
        storage.write_end(b'\x00' * 16)
        storage.write(4, b'payload')
        assert storage.read(7, 4) == b'payload'
        assert storage.read(16, 0)[:4] == b'\x00\x00\x00\x00'


class TestCoverStorageSpecifics:
    """Behaviour that is CoverStorage-specific."""

    def _file_bytes(self, inner: FileWrapper) -> bytes:
        return inner.read(inner.size(), 0)

    def test_fresh_empty_file_gets_footer_only(self, tmp_path):
        inner = FileWrapper(tmp_path / 'b')
        view = CoverStorage.attach(inner)
        assert view.cover_length == 0
        assert view.size() == 0
        on_disk = self._file_bytes(inner)
        assert on_disk[: len(CoverStorage.FOOTER_MAGIC)] == CoverStorage.FOOTER_MAGIC

    def test_existing_bytes_become_cover(self, tmp_path):
        path = tmp_path / 'b'
        path.write_bytes(b'this-is-cover')
        inner = FileWrapper(path)
        view = CoverStorage.attach(inner)
        assert view.cover_length == len(b'this-is-cover')
        assert view.size() == 0
        assert path.read_bytes().startswith(b'this-is-cover')

    def test_cover_bytes_never_overwritten_by_writes(self, tmp_path):
        path = tmp_path / 'b'
        path.write_bytes(b'COVER-PAYLOAD')
        inner = FileWrapper(path)
        view = CoverStorage.attach(inner)
        view.write_end(b'hello')
        view.write(0, b'WORLD')
        assert path.read_bytes().startswith(b'COVER-PAYLOAD')
        assert view.read(5, 0) == b'WORLD'

    def test_reattach_reads_existing_cover(self, tmp_path):
        path = tmp_path / 'b'
        path.write_bytes(b'COVER')
        view_a = CoverStorage.attach(FileWrapper(path))
        view_a.write_end(b'\x00' * 64)
        view_a.write(0, b'inside')

        view_b = CoverStorage.attach(FileWrapper(path))
        assert view_b.cover_length == len(b'COVER')
        assert view_b.read(6, 0) == b'inside'

    def test_read_does_not_leak_footer(self, tmp_path):
        inner = FileWrapper(tmp_path / 'b')
        view = CoverStorage.attach(inner)
        view.write_end(b'payload')
        # Read beyond end returns only the logical bytes, never the
        # FOOTER_MAGIC.
        assert CoverStorage.FOOTER_MAGIC not in view.read(1024, 0)

    def test_truncate_keeps_footer(self, tmp_path):
        inner = FileWrapper(tmp_path / 'b')
        view = CoverStorage.attach(inner)
        view.write_end(b'payload-more-data')
        view.truncate(4)
        assert view.size() == 4
        assert self._file_bytes(inner).endswith(CoverStorage.FOOTER_MAGIC + b'\x00' * 8)

    def test_corrupt_footer_length_raises(self, tmp_path):
        path = tmp_path / 'b'
        # Magic present, but cover_length claims a larger file than exists.
        path.write_bytes(b'x' * 10 + CoverStorage.FOOTER_MAGIC + (10**9).to_bytes(8, 'big'))
        with pytest.raises(ValueError, match='cover_length'):
            CoverStorage.attach(FileWrapper(path))
