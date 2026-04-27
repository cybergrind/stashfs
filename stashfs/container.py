"""Fixed-layout container over a ``Storage``.

The container owns the on-disk layout decisions that are *not* crypto:
where the header lives, how big a slot is, how big a chunk frame is,
and how chunks are addressed. The ``Volume`` layer will stack crypto on
top; the ``SlotTable`` layer will interpret the 768-byte slot blob.

Layout (offsets in bytes)::

    0   : 16B  global_salt (random, fed to Argon2id)
    16  :  4B  format_version u32 BE (= FORMAT_VERSION)
    20  :  4B  reserved flags u32 BE (= 0 today)
    24  :  8B  alloc_head_offset u64 BE — byte offset of the first
                alloc chunk in the chunk area
    32  : 640B slot_table (8 slots x 80 B)
    672 : chunk_area (mix of alloc chunks and data chunks, each
           CHUNK_FRAME_SIZE bytes)

Chunks are addressed by **logical id** from the outside. The translation
to physical position goes through the plaintext ``Allocation`` chain,
whose head sits at ``alloc_head_offset`` in the chunk area. Logical ids
are stable; the physical layout may change when ``optimize`` compacts.

Data chunk frames remain opaque AES-GCM envelopes to the container —
``Volume`` is responsible for seal/open.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from stashfs.allocation import ALLOC_MAGIC, Allocation
from stashfs.storage import FileWrapper, Storage


SALT_SIZE = 16
VERSION_OFFSET = SALT_SIZE  # 16
FLAGS_OFFSET = VERSION_OFFSET + 4  # 20
ALLOC_HEAD_OFFSET = FLAGS_OFFSET + 4  # 24
HEADER_SIZE = ALLOC_HEAD_OFFSET + 8  # 32

FORMAT_VERSION = 2

SLOT_SIZE = 80
N_SLOTS = 8
SLOT_TABLE_SIZE = SLOT_SIZE * N_SLOTS

CHUNK_PAYLOAD_SIZE = 4096
CHUNK_FRAME_SIZE = CHUNK_PAYLOAD_SIZE + 12 + 16  # nonce + ciphertext + tag

DATA_START = HEADER_SIZE + SLOT_TABLE_SIZE  # 672


class ContainerCorrupt(Exception):
    """Raised when the backing storage cannot be interpreted as a container."""


class Container:
    """Framed chunk store over any ``Storage``.

    On first use with an empty backing, the container writes a random
    salt, the current format version, a zero flags field, and an initial
    (empty) allocation chunk at the start of the chunk area. The
    ``SlotTable`` layer is responsible for later filling the slot
    table with real cryptographic wrappings.
    """

    def __init__(self, storage: Storage) -> None:
        self._storage = storage
        self._allocation: Allocation
        self._ensure_initialised()

    @classmethod
    def open_path(cls, path: Path) -> Container:
        """Convenience: wrap a path in a ``FileWrapper`` and open it."""
        return cls(FileWrapper(path))

    @property
    def storage(self) -> Storage:
        return self._storage

    @property
    def allocation(self) -> Allocation:
        return self._allocation

    # -------- initialisation --------

    def _ensure_initialised(self) -> None:
        current = self._storage.size()
        if current == 0:
            self._initialise_fresh()
            return
        if current < DATA_START + CHUNK_FRAME_SIZE:
            raise ContainerCorrupt(
                f'backing is {current} bytes, need at least {DATA_START + CHUNK_FRAME_SIZE} for header+slot_table+alloc'
            )
        tail = (current - DATA_START) % CHUNK_FRAME_SIZE
        if tail != 0:
            raise ContainerCorrupt(f'chunk region is not a multiple of {CHUNK_FRAME_SIZE} (extra {tail} bytes)')
        version = self._read_format_version()
        if version != FORMAT_VERSION:
            raise ContainerCorrupt(f'unsupported format version: {version}')
        head_offset = self._read_alloc_head_offset()
        head_frame = self._storage.read(len(ALLOC_MAGIC), head_offset)
        if head_frame != ALLOC_MAGIC:
            raise ContainerCorrupt(f'alloc head at {head_offset} missing magic')
        self._allocation = Allocation.open(self._storage, DATA_START, head_offset)

    def _initialise_fresh(self) -> None:
        # Salt + slot table pad are randomised so the bytes on disk
        # never betray whether a slot is occupied (apart from the flag
        # byte at offset 0 of each slot, zeroed below).
        blob = bytearray(os.urandom(HEADER_SIZE + SLOT_TABLE_SIZE))
        struct.pack_into('>I', blob, VERSION_OFFSET, FORMAT_VERSION)
        struct.pack_into('>I', blob, FLAGS_OFFSET, 0)
        struct.pack_into('>Q', blob, ALLOC_HEAD_OFFSET, DATA_START)
        for i in range(N_SLOTS):
            blob[HEADER_SIZE + i * SLOT_SIZE] = 0x00
        self._storage.write_end(bytes(blob))
        self._allocation = Allocation.initialise(self._storage, chunk_area_start=DATA_START)

    def _read_format_version(self) -> int:
        raw = self._storage.read(4, VERSION_OFFSET)
        return struct.unpack('>I', raw)[0]

    def _read_alloc_head_offset(self) -> int:
        raw = self._storage.read(8, ALLOC_HEAD_OFFSET)
        return struct.unpack('>Q', raw)[0]

    # -------- header (salt) --------

    def read_header(self) -> bytes:
        """Return the 16 B salt."""
        return self._storage.read(SALT_SIZE, 0)

    def write_header(self, salt: bytes) -> None:
        if len(salt) != SALT_SIZE:
            raise ValueError(f'header must be {SALT_SIZE} bytes')
        self._storage.write(0, salt)

    # -------- slot table --------

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

    # -------- chunks --------

    def num_chunks(self) -> int:
        """Number of live chunks currently visible through the allocation."""
        return sum(1 for _ in self._allocation.iter_live_ids())

    def append_chunk(self, frame: bytes) -> int:
        """Append ``frame`` at EOF and return a stable logical chunk id."""
        return self._allocation.append(frame)

    def read_chunk(self, logical_id: int) -> bytes:
        return self._allocation.read(logical_id)

    def mark_chunk_dead(self, logical_id: int) -> None:
        self._allocation.mark_dead(logical_id)

    def reload_allocation(self) -> None:
        """Refresh the in-memory alloc table from disk.

        Multiple ``Volume`` instances may share one backing file —
        each carries its own ``Container`` and therefore its own
        ``Allocation``. When a sibling appends chunks, our view goes
        stale; appending against the stale view would clobber its
        entries. Volumes call this before a deferred flush to pick up
        any sibling appends.
        """
        self._allocation.reload()

    # -------- internals --------

    def _check_slot_index(self, index: int) -> None:
        if not 0 <= index < N_SLOTS:
            raise IndexError(f'slot index {index} out of range [0, {N_SLOTS})')
