"""Tests for the plaintext ``Allocation`` layer.

Allocation is the translation layer between stable logical chunk IDs and
transient physical slot positions. It owns the alloc-chunk chain that
lives in the chunk area (plaintext, addressed by byte offset) and
maps logical_id -> physical_slot or DEAD.
"""

from __future__ import annotations

import pytest

from stashfs.allocation import ALLOC_MAGIC, DEAD_ENTRY, ENTRIES_PER_CHUNK, Allocation
from stashfs.container import CHUNK_FRAME_SIZE
from stashfs.storage import FileWrapper


@pytest.fixture
def storage(tmp_path):
    """Fresh FileWrapper — allocation expects an empty chunk area."""
    return FileWrapper(tmp_path / 'backing')


def _make_frame(seed: int) -> bytes:
    """Deterministic distinct payload per logical id for round-trip tests."""
    return bytes([seed % 256]) * CHUNK_FRAME_SIZE


class TestAllocationAppendAndLookup:
    def test_initialise_writes_single_empty_alloc_chunk_at_chunk_area_start(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        # Head is at the very start of the chunk area.
        assert alloc.head_offset == 0
        # The alloc chunk starts with the magic.
        header = storage.read(len(ALLOC_MAGIC), 0)
        assert header == ALLOC_MAGIC
        # Storage now holds exactly one chunk frame.
        assert storage.size() == CHUNK_FRAME_SIZE

    def test_append_single_frame_round_trips(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        frame = _make_frame(7)
        logical_id = alloc.append(frame)
        assert logical_id == 0
        assert alloc.read(logical_id) == frame

    def test_append_returns_sequential_logical_ids(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        ids = [alloc.append(_make_frame(i)) for i in range(3)]
        assert ids == [0, 1, 2]
        for i, logical_id in enumerate(ids):
            assert alloc.read(logical_id) == _make_frame(i)

    def test_iter_live_ids_yields_all_appended(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        for i in range(4):
            alloc.append(_make_frame(i))
        assert list(alloc.iter_live_ids()) == [0, 1, 2, 3]


class TestAllocationMarkDead:
    def test_mark_dead_hides_from_iter_live_ids(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        for i in range(4):
            alloc.append(_make_frame(i))
        alloc.mark_dead(1)
        alloc.mark_dead(2)
        assert list(alloc.iter_live_ids()) == [0, 3]

    def test_read_dead_raises(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        alloc.append(_make_frame(0))
        alloc.mark_dead(0)
        with pytest.raises(KeyError):
            alloc.read(0)

    def test_mark_dead_is_idempotent(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        alloc.append(_make_frame(0))
        alloc.mark_dead(0)
        alloc.mark_dead(0)  # second call must not raise
        assert list(alloc.iter_live_ids()) == []


class TestAllocationChainGrowth:
    def test_grows_to_new_alloc_chunk_past_capacity(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        # Allocate ENTRIES_PER_CHUNK + 1 entries — forces a new alloc chunk.
        for i in range(ENTRIES_PER_CHUNK + 1):
            alloc.append(_make_frame(i % 256))
        # Every logical id should still round-trip.
        assert alloc.read(0) == _make_frame(0)
        assert alloc.read(ENTRIES_PER_CHUNK) == _make_frame(ENTRIES_PER_CHUNK % 256)

    def test_iter_live_ids_traverses_chain(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        n = ENTRIES_PER_CHUNK + 5
        for i in range(n):
            alloc.append(_make_frame(i % 256))
        assert list(alloc.iter_live_ids()) == list(range(n))


class TestAllocationReopen:
    def test_reopen_preserves_state(self, storage):
        alloc = Allocation.initialise(storage, chunk_area_start=0)
        for i in range(ENTRIES_PER_CHUNK + 3):
            alloc.append(_make_frame(i % 256))
        alloc.mark_dead(7)
        head = alloc.head_offset

        reopened = Allocation.open(storage, chunk_area_start=0, head_offset=head)
        assert list(reopened.iter_live_ids()) == [i for i in range(ENTRIES_PER_CHUNK + 3) if i != 7]
        assert reopened.read(0) == _make_frame(0)
        with pytest.raises(KeyError):
            reopened.read(7)


class TestAllocationSentinels:
    def test_sentinel_values(self):
        # u32 DEAD sentinel is 0xFFFFFFFF.
        assert DEAD_ENTRY == 0xFFFF_FFFF
        # 20 B header (8B magic + 8B next_offset + 4B count) +
        # ENTRIES_PER_CHUNK u32 entries fills a full frame.
        assert 20 + ENTRIES_PER_CHUNK * 4 == CHUNK_FRAME_SIZE
