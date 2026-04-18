"""Unit tests for ``stashfs.container.Container``.

Container is pure byte accounting - no crypto here.
"""

from __future__ import annotations

import pytest

from stashfs.container import (
    CHUNK_FRAME_SIZE,
    DATA_START,
    HEADER_SIZE,
    N_SLOTS,
    SLOT_SIZE,
    SLOT_TABLE_SIZE,
    Container,
    ContainerCorrupt,
)
from stashfs.storage import FileWrapper


@pytest.fixture
def container(tmp_path) -> Container:
    return Container(FileWrapper(tmp_path / 'backing'))


def _frame(fill: int = 0) -> bytes:
    return bytes([fill]) * CHUNK_FRAME_SIZE


class TestContainerInitialisation:
    def test_fresh_container_writes_header_and_slot_table(self, tmp_path):
        path = tmp_path / 'backing'
        Container(FileWrapper(path))
        assert path.stat().st_size == DATA_START

    def test_fresh_container_starts_with_zero_chunks(self, container):
        assert container.num_chunks() == 0

    def test_header_and_slot_table_are_randomised(self, tmp_path):
        """Two fresh containers must not share the same header+slot_table."""
        c1 = Container(FileWrapper(tmp_path / 'a'))
        c2 = Container(FileWrapper(tmp_path / 'b'))
        assert c1.read_header() != c2.read_header()
        assert c1.read_slot_table() != c2.read_slot_table()

    def test_reopen_preserves_header_and_chunks(self, tmp_path):
        path = tmp_path / 'backing'
        c1 = Container(FileWrapper(path))
        header = c1.read_header()
        slot_table = c1.read_slot_table()
        idx = c1.append_chunk(_frame(0x42))

        c2 = Container(FileWrapper(path))
        assert c2.read_header() == header
        assert c2.read_slot_table() == slot_table
        assert c2.num_chunks() == 1
        assert c2.read_chunk(idx) == _frame(0x42)

    def test_corrupt_short_container_raises(self, tmp_path):
        path = tmp_path / 'backing'
        path.write_bytes(b'\x00' * (DATA_START - 1))
        with pytest.raises(ContainerCorrupt):
            Container(FileWrapper(path))

    def test_corrupt_misaligned_chunk_region_raises(self, tmp_path):
        path = tmp_path / 'backing'
        path.write_bytes(b'\x00' * (DATA_START + CHUNK_FRAME_SIZE + 5))
        with pytest.raises(ContainerCorrupt):
            Container(FileWrapper(path))


class TestLayoutConstants:
    def test_sizes_match_plan(self):
        assert HEADER_SIZE == 16
        assert SLOT_SIZE == 80
        assert N_SLOTS == 8
        assert SLOT_TABLE_SIZE == 640
        assert DATA_START == 656
        assert CHUNK_FRAME_SIZE == 4124


class TestChunks:
    def test_append_returns_monotonic_ids(self, container):
        assert container.append_chunk(_frame(1)) == 0
        assert container.append_chunk(_frame(2)) == 1
        assert container.append_chunk(_frame(3)) == 2
        assert container.num_chunks() == 3

    def test_round_trip(self, container):
        idx = container.append_chunk(_frame(0xAB))
        assert container.read_chunk(idx) == _frame(0xAB)

    def test_write_chunk_overwrites(self, container):
        idx = container.append_chunk(_frame(0xAB))
        container.write_chunk(idx, _frame(0xCD))
        assert container.read_chunk(idx) == _frame(0xCD)

    def test_write_chunk_out_of_range_raises(self, container):
        container.append_chunk(_frame(0))
        with pytest.raises(IndexError):
            container.write_chunk(5, _frame(0))

    def test_read_chunk_out_of_range_raises(self, container):
        with pytest.raises(IndexError):
            container.read_chunk(0)

    def test_wrong_frame_size_rejected(self, container):
        with pytest.raises(ValueError, match='chunk frame'):
            container.append_chunk(b'\x00' * 10)
        with pytest.raises(ValueError, match='chunk frame'):
            container.append_chunk(b'\x00' * (CHUNK_FRAME_SIZE + 1))


class TestSlots:
    def test_slot_round_trip(self, container):
        blob = bytes(range(256)) * (SLOT_SIZE // 256 + 1)
        blob = blob[:SLOT_SIZE]
        container.write_slot(0, blob)
        assert container.read_slot(0) == blob

    def test_slots_are_independent(self, container):
        for i in range(N_SLOTS):
            container.write_slot(i, bytes([i]) * SLOT_SIZE)
        for i in range(N_SLOTS):
            assert container.read_slot(i) == bytes([i]) * SLOT_SIZE

    def test_slot_index_bounds(self, container):
        with pytest.raises(IndexError):
            container.read_slot(-1)
        with pytest.raises(IndexError):
            container.read_slot(N_SLOTS)

    def test_slot_table_size_enforced(self, container):
        with pytest.raises(ValueError, match='slot_table'):
            container.write_slot_table(b'\x00' * (SLOT_TABLE_SIZE - 1))

    def test_slot_size_enforced(self, container):
        with pytest.raises(ValueError, match='slot must be'):
            container.write_slot(0, b'\x00' * (SLOT_SIZE - 1))

    def test_slot_table_round_trip(self, container):
        blob = bytes([0xAA]) * SLOT_TABLE_SIZE
        container.write_slot_table(blob)
        assert container.read_slot_table() == blob

    def test_writing_slot_does_not_touch_chunks(self, container):
        idx = container.append_chunk(_frame(0x11))
        container.write_slot(3, bytes([0x22]) * SLOT_SIZE)
        assert container.read_chunk(idx) == _frame(0x11)

    def test_appending_chunk_does_not_touch_slot_table(self, container):
        before = container.read_slot_table()
        container.append_chunk(_frame(0x33))
        assert container.read_slot_table() == before


class TestHeader:
    def test_header_round_trip(self, container):
        container.write_header(b'\x01' * HEADER_SIZE)
        assert container.read_header() == b'\x01' * HEADER_SIZE

    def test_header_size_enforced(self, container):
        with pytest.raises(ValueError, match='header must be'):
            container.write_header(b'\x00' * (HEADER_SIZE - 1))
