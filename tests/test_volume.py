"""Unit tests for ``fyl.volume.Volume``.

Two volumes on the same container must not interfere. The slot table
and file index rewrites are exercised end-to-end without FUSE.
"""

from __future__ import annotations

import pytest

from fyl.container import CHUNK_PAYLOAD_SIZE, N_SLOTS, Container
from fyl.crypto import KDF, KDFParams
from fyl.file_index import VolumeFile, parse, serialize
from fyl.slot_table import PasswordDoesNotMatch
from fyl.storage import FileWrapper
from fyl.volume import Volume


@pytest.fixture
def kdf() -> KDF:
    return KDF(KDFParams.fast())


@pytest.fixture
def container(tmp_path) -> Container:
    return Container(FileWrapper(tmp_path / 'backing'))


class TestFileIndexSerialization:
    def test_round_trip_empty(self):
        assert parse(serialize({})) == {}

    def test_round_trip_with_files(self):
        files = {
            'a.txt': VolumeFile(name='a.txt', size=10, chunk_ids=[0, 1, 2]),
            'b.txt': VolumeFile(name='b.txt', size=4096, chunk_ids=[3]),
            'unicode-\u00e9.txt': VolumeFile(name='unicode-\u00e9.txt', size=1, chunk_ids=[]),
        }
        reparsed = parse(serialize(files))
        assert set(reparsed) == set(files)
        for name, vf in files.items():
            assert reparsed[name].size == vf.size
            assert reparsed[name].chunk_ids == vf.chunk_ids


class TestVolumeBasic:
    def test_empty_password_volume_starts_unassociated(self, container, kdf):
        v = Volume(container, kdf, '')
        assert v.slot_index == 0
        assert v.is_associated is False
        assert v.list() == []

    def test_write_read_small_file(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('hello.txt', 0, b'hello world')
        assert v.read_file('hello.txt', 0, 11) == b'hello world'
        assert v.size_of('hello.txt') == 11

    def test_first_write_associates_slot(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        assert v.is_associated is False
        v.write_file('a', 0, b'data')
        assert v.is_associated is True

    def test_reopen_preserves_data(self, container, kdf):
        Volume(container, kdf, 'alpha').write_file('note', 0, b'persisted')
        v2 = Volume(container, kdf, 'alpha')
        assert v2.list() == ['note']
        assert v2.read_file('note', 0, 100) == b'persisted'

    def test_write_at_offset_zero_fills(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('gap', 5, b'tail')
        assert v.size_of('gap') == 9
        assert v.read_file('gap', 0, 9) == b'\x00' * 5 + b'tail'

    def test_overwrite_partial(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('a', 0, b'aaaaa')
        v.write_file('a', 2, b'BB')
        assert v.read_file('a', 0, 5) == b'aaBBa'

    def test_multi_chunk_file(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        payload = bytes(range(256)) * (CHUNK_PAYLOAD_SIZE * 3 // 256 + 1)
        payload = payload[: CHUNK_PAYLOAD_SIZE * 3]
        v.write_file('big', 0, payload)
        assert v.read_file('big', 0, len(payload)) == payload
        assert v.size_of('big') == len(payload)

    def test_read_past_eof_returns_short(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('a', 0, b'abc')
        assert v.read_file('a', 0, 100) == b'abc'
        assert v.read_file('a', 10, 5) == b''


class TestUnlink:
    def test_unlink_removes_file(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('a', 0, b'1')
        v.write_file('b', 0, b'2')
        v.unlink('a')
        assert v.list() == ['b']
        assert v.read_file('b', 0, 1) == b'2'

    def test_unlink_last_file_frees_slot(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('only', 0, b'x')
        assert v.is_associated is True
        v.unlink('only')
        assert v.is_associated is False
        # The slot is back on the free list.
        assert not v.slot_table.is_occupied(v.slot_index)

    def test_unlink_unknown_raises(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        with pytest.raises(KeyError):
            v.unlink('missing')

    def test_gamma_reclaims_slot_after_alpha_unlinks(self, container, kdf):
        alpha = Volume(container, kdf, 'alpha')
        alpha.write_file('x', 0, b'1')
        alpha_slot = alpha.slot_index
        alpha.unlink('x')

        gamma = Volume(container, kdf, 'gamma')
        gamma.write_file('y', 0, b'2')
        assert gamma.slot_index == alpha_slot


class TestLegacyIndexChunkCompat:
    """Containers written before the chained-index change stored the file
    index as a plain, zero-padded serialised blob inside a single chunk.
    Opening such a container with the new code must still work; the
    chain pointer is simply absent there.
    """

    def _legacy_index_chunk(self, v: Volume, files: dict) -> int:
        """Append one legacy-format index chunk and return its id.

        Legacy layout: ``serialize(files) + zero_padding`` inside the
        4096 B chunk payload. No magic, no next-pointer.
        """
        from fyl.file_index import serialize

        blob = serialize(files)
        padded = blob + b'\x00' * (CHUNK_PAYLOAD_SIZE - len(blob))
        return v._append_plaintext(padded)

    def test_loads_legacy_index_chunk(self, container, kdf):
        from fyl.file_index import VolumeFile

        # First write a real data chunk so chunk ids > 0 exist.
        v = Volume(container, kdf, 'alpha')
        v.write_file('seed', 0, b'seed-data')

        # Now craft a legacy index chunk that references that data.
        data_chunk_id = v._files['seed'].chunk_ids[0]
        legacy_files = {
            'seed': VolumeFile(name='seed', size=9, chunk_ids=[data_chunk_id]),
        }
        legacy_cid = self._legacy_index_chunk(v, legacy_files)
        v.slot_table.update(v.slot_index, v._slot.volume_key, legacy_cid)

        # A fresh Volume must find the legacy slot and decode it.
        v2 = Volume(container, kdf, 'alpha')
        assert v2.list() == ['seed']
        assert v2.read_file('seed', 0, 9) == b'seed-data'

    def test_legacy_index_with_large_payload(self, container, kdf):
        """Legacy blob close to the chunk boundary - last bytes are real
        data, not zeros. Must still parse as a single-chunk index.
        """

        v = Volume(container, kdf, 'alpha')
        # Seed many real data chunks so chunk_ids list is long enough
        # to push the serialised blob up towards the full chunk size.
        v.write_file('seed', 0, b'x' * (200 * CHUNK_PAYLOAD_SIZE))

        legacy_files = {'seed': v._files['seed']}
        legacy_cid = self._legacy_index_chunk(v, legacy_files)
        v.slot_table.update(v.slot_index, v._slot.volume_key, legacy_cid)

        v2 = Volume(container, kdf, 'alpha')
        assert 'seed' in v2.list()
        assert v2.size_of('seed') == 200 * CHUNK_PAYLOAD_SIZE


class TestLargeFileIndex:
    """A single file whose chunk-id list overflows one index chunk.

    Each chunk_id is 8 bytes. With 600 data chunks the serialised index
    is well above the 4096-byte chunk payload, so the index must be
    stored as a chain across multiple chunks. Previously this raised
    ``RuntimeError: file index too large for one chunk`` which bubbled
    out as ``EIO`` in the middle of ``cp``.
    """

    def test_large_file_roundtrips(self, container, kdf):
        # ~600 chunks of pseudo-random payload. Enough to overflow any
        # sane single-chunk index (600 * 8 > 4096).
        payload = bytes(((i * 2654435761) & 0xFF) for i in range(600 * CHUNK_PAYLOAD_SIZE))
        v = Volume(container, kdf, 'alpha')
        v.write_file('big', 0, payload)
        # In-process read.
        assert v.read_file('big', 0, len(payload)) == payload

        # Fresh Volume on the same container must still read it.
        v2 = Volume(container, kdf, 'alpha')
        assert v2.size_of('big') == len(payload)
        assert v2.read_file('big', 0, len(payload)) == payload

    def test_growing_many_small_files_fits(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        # Many small files - stresses the index breadth rather than depth.
        for i in range(300):
            v.write_file(f'f_{i:04d}.bin', 0, f'payload-{i}'.encode() * 100)

        v2 = Volume(container, kdf, 'alpha')
        assert len(v2.list()) == 300
        assert v2.read_file('f_0000.bin', 0, 9) == b'payload-0'

    def test_cp_pattern_after_unlinking_all(self, container, kdf):
        """mount -> write -> unlink -> write large file. Used to raise EIO."""
        v = Volume(container, kdf, 'alpha')
        v.write_file('scratch.txt', 0, b'hi')
        v.unlink('scratch.txt')

        big = b'X' * (600 * CHUNK_PAYLOAD_SIZE)
        v.write_file('cover.png', 0, big)
        assert v.read_file('cover.png', 0, len(big)) == big


class TestRename:
    def test_rename_moves_entry(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('old', 0, b'payload')
        v.rename('old', 'new')
        assert v.list() == ['new']
        assert v.read_file('new', 0, 100) == b'payload'

    def test_rename_preserves_data_across_reopen(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('old', 0, b'payload')
        v.rename('old', 'new')

        v2 = Volume(container, kdf, 'alpha')
        assert v2.list() == ['new']
        assert v2.read_file('new', 0, 100) == b'payload'

    def test_rename_to_self_is_noop(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('same', 0, b'x')
        v.rename('same', 'same')
        assert v.list() == ['same']
        assert v.read_file('same', 0, 1) == b'x'

    def test_rename_missing_raises(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        with pytest.raises(KeyError):
            v.rename('missing', 'dst')

    def test_rename_overwrites_existing_destination(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('src', 0, b'SRC')
        v.write_file('dst', 0, b'DST-old')
        v.rename('src', 'dst')
        assert v.list() == ['dst']
        assert v.read_file('dst', 0, 100) == b'SRC'


class TestTruncate:
    def test_truncate_to_zero(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('a', 0, b'hello')
        v.truncate('a', 0)
        assert v.size_of('a') == 0
        assert v.read_file('a', 0, 10) == b''

    def test_truncate_shrink(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('a', 0, b'abcdefgh')
        v.truncate('a', 3)
        assert v.size_of('a') == 3
        assert v.read_file('a', 0, 10) == b'abc'

    def test_truncate_grow_zero_fills(self, container, kdf):
        v = Volume(container, kdf, 'alpha')
        v.write_file('a', 0, b'abc')
        v.truncate('a', 6)
        assert v.read_file('a', 0, 6) == b'abc\x00\x00\x00'


class TestMultiVolumeOnSameContainer:
    def test_two_volumes_independent(self, container, kdf):
        a = Volume(container, kdf, 'alpha')
        b = Volume(container, kdf, 'beta')
        a.write_file('file-a', 0, b'alpha-data')
        b.write_file('file-b', 0, b'beta-data')
        assert a.list() == ['file-a']
        assert b.list() == ['file-b']
        assert a.read_file('file-a', 0, 100) == b'alpha-data'
        assert b.read_file('file-b', 0, 100) == b'beta-data'

    def test_reopen_each_after_many_writes(self, container, kdf):
        Volume(container, kdf, 'alpha').write_file('a', 0, b'AAA')
        Volume(container, kdf, 'beta').write_file('b', 0, b'BBB')
        Volume(container, kdf, 'alpha').write_file('a', 3, b'alpha2')
        Volume(container, kdf, 'beta').write_file('b', 3, b'beta2')
        v_a = Volume(container, kdf, 'alpha')
        v_b = Volume(container, kdf, 'beta')
        assert v_a.read_file('a', 0, 100) == b'AAAalpha2'
        assert v_b.read_file('b', 0, 100) == b'BBBbeta2'
        assert v_a.list() == ['a']
        assert v_b.list() == ['b']

    def test_unknown_password_all_slots_full_raises(self, container, kdf):
        for p in (f'pw-{i}' for i in range(1, N_SLOTS)):
            Volume(container, kdf, p).write_file('f', 0, b'x')
        with pytest.raises(PasswordDoesNotMatch):
            Volume(container, kdf, 'stranger')


class TestCrashSafety:
    def test_slot_unchanged_when_write_blows_up_mid_chunk(self, container, kdf, monkeypatch):
        v = Volume(container, kdf, 'alpha')
        v.write_file('a', 0, b'initial')
        slot_before = container.read_slot(v.slot_index)

        # Simulate a mid-write failure: raise before the slot is updated.
        original_append = container.append_chunk
        call_count = {'n': 0}

        def boom(frame):
            call_count['n'] += 1
            if call_count['n'] > 1:
                raise KeyboardInterrupt('simulated')
            return original_append(frame)

        monkeypatch.setattr(container, 'append_chunk', boom)

        with pytest.raises(KeyboardInterrupt):
            v.write_file('a', 0, b'NEW')

        slot_after = container.read_slot(v.slot_index)
        assert slot_before == slot_after

        monkeypatch.undo()
        # The previous data is still intact on reopen.
        v2 = Volume(container, kdf, 'alpha')
        assert v2.read_file('a', 0, 100) == b'initial'


class TestDataOnDiskLooksRandom:
    def test_plaintext_not_in_container(self, container, kdf):
        Volume(container, kdf, 'alpha').write_file('note', 0, b'secret-payload-xyz')
        disk_bytes = container.storage.read(container.storage.size(), 0)
        assert b'secret-payload-xyz' not in disk_bytes
        assert b'note' not in disk_bytes
