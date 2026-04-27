"""Plaintext allocation table: logical chunk id -> physical slot.

The allocation layer lives in the chunk area as a chain of fixed-size
``alloc chunks``. Each alloc chunk covers ``ENTRIES_PER_CHUNK`` logical
ids and points to the next alloc chunk by absolute byte offset (or
``SENTINEL`` to end the chain).

On-disk layout of one alloc chunk (``CHUNK_FRAME_SIZE`` bytes total)::

    [8B  ALLOC_MAGIC                = b'STSHALOC']
    [8B  next_alloc_offset u64 BE   = SENTINEL for tail]
    [4B  count u32 BE]              # entries allocated in this chunk
    [ENTRIES_PER_CHUNK x u32 BE]    # physical slot index, or DEAD_ENTRY

``count`` is the high-water mark within a chunk: entries ``[0, count)``
have been allocated at some point (and may now be DEAD), entries
``[count, ENTRIES_PER_CHUNK)`` are vacant. Non-tail chunks always have
``count == ENTRIES_PER_CHUNK``. This unambiguously separates "never
allocated" (vacant) from "allocated then marked dead".

Allocation is plaintext on purpose: password-free ``optimize`` must be
able to tell live chunks from orphans without any key material. The
tradeoff is that chunk liveness (and total live/dead counts) leak to an
observer of the backing file. Slot ownership does **not** leak — no
per-chunk slot tag exists.

Concurrency: **not** thread-safe. One alloc instance per mount, the
FUSE layer serialises access.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

from stashfs.storage import Storage


ALLOC_MAGIC = b'STSHALOC'
DEAD_ENTRY = 0xFFFF_FFFF
SENTINEL = 0xFFFF_FFFF_FFFF_FFFF

CHUNK_FRAME_SIZE = 4124  # must match stashfs.container.CHUNK_FRAME_SIZE

_HEADER_SIZE = len(ALLOC_MAGIC) + 8 + 4  # magic + next_offset + count
_ENTRY_SIZE = 4
ENTRIES_PER_CHUNK = (CHUNK_FRAME_SIZE - _HEADER_SIZE) // _ENTRY_SIZE


@dataclass
class _AllocChunk:
    """One node in the allocation chain, addressed by absolute byte offset."""

    offset: int
    next_offset: int
    count: int  # number of entries ever allocated in this chunk
    entries: list[int]  # ENTRIES_PER_CHUNK u32 values (DEAD_ENTRY if vacant or freed)

    @classmethod
    def empty(cls, offset: int) -> _AllocChunk:
        return cls(
            offset=offset,
            next_offset=SENTINEL,
            count=0,
            entries=[DEAD_ENTRY] * ENTRIES_PER_CHUNK,
        )

    @classmethod
    def parse(cls, offset: int, blob: bytes) -> _AllocChunk:
        if len(blob) != CHUNK_FRAME_SIZE:
            raise ValueError(f'alloc chunk must be {CHUNK_FRAME_SIZE} bytes, got {len(blob)}')
        if blob[: len(ALLOC_MAGIC)] != ALLOC_MAGIC:
            raise ValueError(f'alloc chunk at {offset} missing magic')
        (next_offset,) = struct.unpack('>Q', blob[len(ALLOC_MAGIC) : len(ALLOC_MAGIC) + 8])
        (count,) = struct.unpack('>I', blob[len(ALLOC_MAGIC) + 8 : _HEADER_SIZE])
        entries = list(struct.unpack(f'>{ENTRIES_PER_CHUNK}I', blob[_HEADER_SIZE:]))
        if count > ENTRIES_PER_CHUNK:
            raise ValueError(f'alloc chunk at {offset} has count={count} > {ENTRIES_PER_CHUNK}')
        return cls(offset=offset, next_offset=next_offset, count=count, entries=entries)

    def serialise(self) -> bytes:
        header = ALLOC_MAGIC + struct.pack('>Q', self.next_offset) + struct.pack('>I', self.count)
        body = struct.pack(f'>{ENTRIES_PER_CHUNK}I', *self.entries)
        return header + body


class Allocation:
    """Manages the logical-id -> physical-slot mapping + data chunk I/O.

    The allocation instance owns the chunk area *end-to-end*: it appends
    both alloc chunks (plaintext, linked list) and data chunks
    (AES-GCM frames opaque to this layer) at EOF. Callers only see
    ``append(frame) -> logical_id`` / ``read(logical_id) -> frame`` and
    never need to reason about physical positions.
    """

    def __init__(self, storage: Storage, chunk_area_start: int, chunks: list[_AllocChunk]) -> None:
        self._storage = storage
        self._chunk_area_start = chunk_area_start
        self._chunks: list[_AllocChunk] = chunks

    # -------- construction / opening --------

    @classmethod
    def initialise(cls, storage: Storage, chunk_area_start: int) -> Allocation:
        """Write a fresh, empty alloc chunk at ``chunk_area_start``.

        Requires ``storage.size() == chunk_area_start`` exactly — we use
        ``write_end`` so that storage adapters like ``CoverStorage``
        which maintain a trailing footer can relocate it correctly.
        """
        if storage.size() != chunk_area_start:
            raise ValueError(
                f'cannot initialise allocation: storage size is {storage.size()}, expected {chunk_area_start}'
            )
        chunk = _AllocChunk.empty(offset=chunk_area_start)
        storage.write_end(chunk.serialise())
        return cls(storage, chunk_area_start, [chunk])

    @classmethod
    def open(cls, storage: Storage, chunk_area_start: int, head_offset: int) -> Allocation:
        """Walk the alloc chain starting at ``head_offset`` and rebuild state."""
        chunks = cls._read_chain(storage, head_offset)
        return cls(storage, chunk_area_start, chunks)

    @staticmethod
    def _read_chain(storage: Storage, head_offset: int) -> list[_AllocChunk]:
        chunks: list[_AllocChunk] = []
        seen: set[int] = set()
        current = head_offset
        while current != SENTINEL:
            if current in seen:
                raise ValueError(f'alloc chain cycle at offset {current}')
            seen.add(current)
            blob = storage.read(CHUNK_FRAME_SIZE, current)
            chunk = _AllocChunk.parse(current, blob)
            chunks.append(chunk)
            current = chunk.next_offset
        if not chunks:
            raise ValueError('alloc chain is empty')
        return chunks

    def reload(self) -> None:
        """Re-read the alloc chain from disk, replacing in-memory state.

        Use this when another writer (e.g. a sibling ``Volume`` sharing
        the same backing file) may have appended chunks since this
        instance last looked. Without it, the next ``append`` would
        ``_set_entry`` at a logical id that's already taken on disk and
        ``_bump_count`` from a stale value, corrupting the table.
        """
        self._chunks = self._read_chain(self._storage, self._chunks[0].offset)

    # -------- public API --------

    @property
    def head_offset(self) -> int:
        return self._chunks[0].offset

    @property
    def next_logical_id(self) -> int:
        """Next logical id that ``append`` will hand out."""
        # Every non-tail chunk is full; the tail chunk's count is its
        # occupancy. Sum = total allocated.
        full_chunks = len(self._chunks) - 1
        return full_chunks * ENTRIES_PER_CHUNK + self._chunks[-1].count

    def append(self, frame: bytes) -> int:
        """Append ``frame`` at EOF and assign it the next logical id."""
        if len(frame) != CHUNK_FRAME_SIZE:
            raise ValueError(f'frame must be {CHUNK_FRAME_SIZE} bytes, got {len(frame)}')

        # If the tail is full, grow the chain BEFORE picking the physical
        # slot so the data frame ends up in a contiguous, predictable
        # position.
        if self._chunks[-1].count == ENTRIES_PER_CHUNK:
            self._append_new_alloc_chunk()

        logical_id = self.next_logical_id
        physical_slot = self._next_physical_slot()
        self._storage.write_end(frame)
        self._set_entry(logical_id, physical_slot)
        self._bump_count()
        return logical_id

    def append_dead(self) -> int:
        """Reserve the next logical id without writing a physical chunk.

        Used by ``optimize`` when replaying a source allocation to keep
        logical ids stable across compaction: a dead entry in the source
        becomes a dead entry at the same logical id in the destination.
        """
        if self._chunks[-1].count == ENTRIES_PER_CHUNK:
            self._append_new_alloc_chunk()
        logical_id = self.next_logical_id
        # The entry is already DEAD_ENTRY in a fresh alloc chunk; the
        # ``_set_entry`` keeps this path symmetric with ``append`` and
        # persists the DEAD value in case the chunk was reused later.
        self._set_entry(logical_id, DEAD_ENTRY)
        self._bump_count()
        return logical_id

    def lookup(self, logical_id: int) -> int | None:
        """Return physical slot, or ``None`` if the id is dead."""
        if logical_id < 0 or logical_id >= self.next_logical_id:
            raise KeyError(logical_id)
        chunk_idx, entry_idx = divmod(logical_id, ENTRIES_PER_CHUNK)
        entry = self._chunks[chunk_idx].entries[entry_idx]
        return None if entry == DEAD_ENTRY else entry

    def read(self, logical_id: int) -> bytes:
        """Return the frame bytes for ``logical_id``; raise if dead or unknown."""
        physical_slot = self._lookup_or_raise(logical_id)
        offset = self._chunk_area_start + physical_slot * CHUNK_FRAME_SIZE
        return self._storage.read(CHUNK_FRAME_SIZE, offset)

    def mark_dead(self, logical_id: int) -> None:
        """Mark the entry dead. Idempotent; no-op for already-dead entries."""
        if logical_id < 0 or logical_id >= self.next_logical_id:
            raise KeyError(logical_id)
        self._set_entry(logical_id, DEAD_ENTRY)

    def iter_live_ids(self) -> Iterator[int]:
        """Yield live logical ids in ascending order."""
        limit = self.next_logical_id
        for logical_id in range(limit):
            chunk_idx, entry_idx = divmod(logical_id, ENTRIES_PER_CHUNK)
            if self._chunks[chunk_idx].entries[entry_idx] != DEAD_ENTRY:
                yield logical_id

    # -------- internals --------

    def _lookup_or_raise(self, logical_id: int) -> int:
        if logical_id < 0 or logical_id >= self.next_logical_id:
            raise KeyError(logical_id)
        chunk_idx, entry_idx = divmod(logical_id, ENTRIES_PER_CHUNK)
        entry = self._chunks[chunk_idx].entries[entry_idx]
        if entry == DEAD_ENTRY:
            raise KeyError(logical_id)
        return entry

    def _set_entry(self, logical_id: int, value: int) -> None:
        chunk_idx, entry_idx = divmod(logical_id, ENTRIES_PER_CHUNK)
        chunk = self._chunks[chunk_idx]
        chunk.entries[entry_idx] = value
        # Rewrite just the 4-byte entry in-place.
        offset = chunk.offset + _HEADER_SIZE + entry_idx * _ENTRY_SIZE
        self._storage.write(offset, struct.pack('>I', value))

    def _bump_count(self) -> None:
        tail = self._chunks[-1]
        tail.count += 1
        count_offset = tail.offset + len(ALLOC_MAGIC) + 8
        self._storage.write(count_offset, struct.pack('>I', tail.count))

    def _append_new_alloc_chunk(self) -> None:
        """Link a fresh empty alloc chunk at EOF and update the previous tail."""
        new_offset = self._storage.size()
        new_chunk = _AllocChunk.empty(offset=new_offset)
        self._storage.write_end(new_chunk.serialise())
        # Patch the previous tail's next_offset field.
        prev = self._chunks[-1]
        prev.next_offset = new_offset
        next_ptr_offset = prev.offset + len(ALLOC_MAGIC)
        self._storage.write(next_ptr_offset, struct.pack('>Q', new_offset))
        self._chunks.append(new_chunk)

    def _next_physical_slot(self) -> int:
        """Physical slot index where the NEXT chunk written at EOF will land."""
        used = self._storage.size() - self._chunk_area_start
        if used % CHUNK_FRAME_SIZE != 0:
            raise ValueError(f'chunk area is not frame-aligned: {used} bytes')
        return used // CHUNK_FRAME_SIZE
