"""Fixed-layout container over a ``Storage``.

The container owns the on-disk layout decisions that are *not* crypto:
where the header lives, how big a slot is, how big a chunk frame is,
and how chunks are addressed. The ``Volume`` layer will stack crypto on
top; the ``SlotTable`` layer will interpret the 768-byte slot blob.

Layout (offsets in bytes)::

    0    : 16B  global_salt (random, fed to Argon2id)
    16   : 640B slot_table (8 slots x 80B)
    656  : chunk[0]
    4780 : chunk[1]
    ...

A chunk frame is always exactly ``CHUNK_FRAME_SIZE`` bytes: Volume will
interpret it as ``12B nonce || 4096B ciphertext || 16B tag``. The
container does not decode the frame; it just stores and retrieves them.
"""

from __future__ import annotations

import os
from pathlib import Path

from fly.storage import FileWrapper, Storage


HEADER_SIZE = 16
SLOT_SIZE = 80
N_SLOTS = 8
SLOT_TABLE_SIZE = SLOT_SIZE * N_SLOTS

CHUNK_PAYLOAD_SIZE = 4096
CHUNK_FRAME_SIZE = CHUNK_PAYLOAD_SIZE + 12 + 16  # nonce + ciphertext + tag

DATA_START = HEADER_SIZE + SLOT_TABLE_SIZE


class ContainerCorrupt(Exception):
    """Raised when the backing storage cannot be interpreted as a container."""


class Container:
    """Framed chunk store over any ``Storage``.

    On first use with an empty backing, the container writes a random
    header and slot table. The caller (typically ``Volume``) is
    responsible for populating the slot table with real cryptographic
    wrappings once a password-protected volume is actually in use.
    """

    def __init__(self, storage: Storage) -> None:
        self._storage = storage
        self._ensure_initialised()

    @classmethod
    def open_path(cls, path: Path) -> Container:
        """Convenience: wrap a path in a ``FileWrapper`` and open it."""
        return cls(FileWrapper(path))

    @property
    def storage(self) -> Storage:
        return self._storage

    def _ensure_initialised(self) -> None:
        current = self._storage.size()
        if current == 0:
            # Header + slot table start as uniform random bytes so free
            # slots don't look structured on disk. We then deterministically
            # clear the first byte of every slot to 0x00, because that byte
            # is the free/occupied flag and must not accidentally read as
            # 0x01 when the slot is actually free.
            blob = bytearray(os.urandom(HEADER_SIZE + SLOT_TABLE_SIZE))
            for i in range(N_SLOTS):
                blob[HEADER_SIZE + i * SLOT_SIZE] = 0x00
            self._storage.write_end(bytes(blob))
            return
        if current < DATA_START:
            raise ContainerCorrupt(f'backing is {current} bytes, need at least {DATA_START} for header+slot_table')
        tail = (current - DATA_START) % CHUNK_FRAME_SIZE
        if tail != 0:
            raise ContainerCorrupt(f'chunk region is not a multiple of {CHUNK_FRAME_SIZE} (extra {tail} bytes)')

    def read_header(self) -> bytes:
        return self._storage.read(HEADER_SIZE, 0)

    def write_header(self, header: bytes) -> None:
        if len(header) != HEADER_SIZE:
            raise ValueError(f'header must be {HEADER_SIZE} bytes')
        self._storage.write(0, header)

    def read_slot_table(self) -> bytes:
        return self._storage.read(SLOT_TABLE_SIZE, HEADER_SIZE)

    def write_slot_table(self, blob: bytes) -> None:
        if len(blob) != SLOT_TABLE_SIZE:
            raise ValueError(f'slot_table must be {SLOT_TABLE_SIZE} bytes')
        self._storage.write(HEADER_SIZE, blob)

    def read_slot(self, index: int) -> bytes:
        self._check_slot_index(index)
        return self._storage.read(SLOT_SIZE, HEADER_SIZE + index * SLOT_SIZE)

    def write_slot(self, index: int, blob: bytes) -> None:
        self._check_slot_index(index)
        if len(blob) != SLOT_SIZE:
            raise ValueError(f'slot must be {SLOT_SIZE} bytes')
        self._storage.write(HEADER_SIZE + index * SLOT_SIZE, blob)

    def num_chunks(self) -> int:
        return (self._storage.size() - DATA_START) // CHUNK_FRAME_SIZE

    def read_chunk(self, index: int) -> bytes:
        self._check_chunk_index(index)
        return self._storage.read(CHUNK_FRAME_SIZE, DATA_START + index * CHUNK_FRAME_SIZE)

    def write_chunk(self, index: int, frame: bytes) -> None:
        self._check_chunk_index(index)
        if len(frame) != CHUNK_FRAME_SIZE:
            raise ValueError(f'chunk frame must be {CHUNK_FRAME_SIZE} bytes')
        self._storage.write(DATA_START + index * CHUNK_FRAME_SIZE, frame)

    def append_chunk(self, frame: bytes) -> int:
        if len(frame) != CHUNK_FRAME_SIZE:
            raise ValueError(f'chunk frame must be {CHUNK_FRAME_SIZE} bytes')
        index = self.num_chunks()
        self._storage.write_end(frame)
        return index

    def _check_slot_index(self, index: int) -> None:
        if not 0 <= index < N_SLOTS:
            raise IndexError(f'slot index {index} out of range [0, {N_SLOTS})')

    def _check_chunk_index(self, index: int) -> None:
        total = self.num_chunks()
        if not 0 <= index < total:
            raise IndexError(f'chunk index {index} out of range [0, {total})')
