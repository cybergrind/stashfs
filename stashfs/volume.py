"""One password's view of a ``Container``.

A ``Volume`` owns exactly one ``SlotInfo`` and the files that live under
that slot. Storage is append-only at the chunk layer: every write
appends fresh chunks and the slot is rewritten last, so a crash before
the slot update leaves the previous state intact.

Concurrency note: this class is **not** thread-safe. Upper layers (FUSE
glue in ``fuse_app``) serialise calls through a single-process handler.
"""

from __future__ import annotations

import os
import struct

from stashfs.container import CHUNK_PAYLOAD_SIZE, Container
from stashfs.crypto import KDF, AEADChunk
from stashfs.file_index import VolumeFile, parse, serialize
from stashfs.slot_table import SlotInfo, SlotTable


class VolumeCorrupt(Exception):
    """Raised when a chunk we expected to decrypt failed authentication."""


# File-index chunk plaintext layout (v1)::
#
#     [ 8 B magic = INDEX_MAGIC ][ 8 B next_chunk_id u64 BE ][ payload ]
#
# The magic disambiguates the new versioned format from legacy containers
# that stored the index as a plain zero-padded serialised blob in a
# single chunk (no header, no chain pointer). When ``_read_index_chain``
# sees a chunk that does not begin with the magic it falls back to the
# legacy reader and treats the whole 4096-byte plaintext as a one-shot
# payload. ``INDEX_CHAIN_END`` marks the last chunk in a chain.
INDEX_MAGIC = b'FIDXv001'
INDEX_HEADER_SIZE = len(INDEX_MAGIC) + 8
INDEX_PAYLOAD_SIZE = CHUNK_PAYLOAD_SIZE - INDEX_HEADER_SIZE
INDEX_CHAIN_END = 0xFFFF_FFFF_FFFF_FFFF


def write_index_chain(container: Container, cipher: AEADChunk, blob: bytes) -> int:
    """Append the serialised index as a chain of versioned chunks.

    Each chunk's plaintext is ``INDEX_MAGIC || next_cid || page ||
    zero_pad`` filling the full chunk payload. Pages are appended in
    reverse so every non-tail chunk already knows its successor's id
    by the time it is sealed. Returns the *head* chunk id (what the
    slot should point at).
    """
    if blob == b'':
        pages: list[bytes] = [b'']
    else:
        pages = [blob[i : i + INDEX_PAYLOAD_SIZE] for i in range(0, len(blob), INDEX_PAYLOAD_SIZE)]
    next_cid = INDEX_CHAIN_END
    for page in reversed(pages):
        padded_page = page + b'\x00' * (INDEX_PAYLOAD_SIZE - len(page))
        assert len(padded_page) == INDEX_PAYLOAD_SIZE
        plaintext = INDEX_MAGIC + struct.pack('>Q', next_cid) + padded_page
        assert len(plaintext) == CHUNK_PAYLOAD_SIZE
        frame = cipher.seal(plaintext)
        next_cid = container.append_chunk(frame)
    return next_cid


class Volume:
    """Owns one slot's files.

    Typical lifecycle::

        v = Volume(container, kdf, password)
        v.write_file('hello', 0, b'world')     # associates the slot
        v.read_file('hello', 0, 5) == b'world'
        v.unlink('hello')                      # frees the slot
    """

    def __init__(self, container: Container, kdf: KDF, password: str | bytes) -> None:
        self.container = container
        self.kdf = kdf
        self.password = password
        self.slot_table = SlotTable(container, kdf, password)
        self._slot = self.slot_table.find_or_create()
        self._cipher = AEADChunk(self._slot.volume_key)
        self._files: dict[str, VolumeFile] = {}
        if self._slot.file_table_chunk_id is not None:
            self._load_file_index()

    @property
    def slot_index(self) -> int:
        return self._slot.index

    @property
    def is_associated(self) -> bool:
        return self._slot.file_table_chunk_id is not None

    def list(self) -> list[str]:
        return sorted(self._files)

    def size_of(self, name: str) -> int:
        return self._files[name].size

    def exists(self, name: str) -> bool:
        return name in self._files

    def read_file(self, name: str, offset: int, size: int) -> bytes:
        file = self._files.get(name)
        if file is None:
            raise KeyError(name)
        if offset >= file.size or size <= 0:
            return b''
        end = min(file.size, offset + size)
        pt = CHUNK_PAYLOAD_SIZE
        first_chunk = offset // pt
        last_chunk = (end - 1) // pt
        out = bytearray()
        for chunk_idx in range(first_chunk, last_chunk + 1):
            plaintext = self._decrypt_chunk(file.chunk_ids[chunk_idx])
            chunk_start = chunk_idx * pt
            take_start = max(offset, chunk_start) - chunk_start
            take_end = min(end, chunk_start + pt) - chunk_start
            out.extend(plaintext[take_start:take_end])
        return bytes(out)

    def write_file(self, name: str, offset: int, buf: bytes) -> int:
        if offset < 0:
            raise ValueError('offset must be non-negative')
        file = self._files.get(name)
        if file is None:
            file = VolumeFile(name=name)
            self._files[name] = file

        end = offset + len(buf)
        pt = CHUNK_PAYLOAD_SIZE
        # Grow chunk list to cover the end position (even if writing a
        # zero-length buffer at a new position).
        last_needed_chunk = (max(end, file.size + 1) - 1) // pt if max(end, file.size) > 0 else -1
        while len(file.chunk_ids) <= last_needed_chunk:
            file.chunk_ids.append(self._append_plaintext(b'\x00' * pt))

        if buf:
            first_chunk = offset // pt
            last_chunk = (end - 1) // pt
            for chunk_idx in range(first_chunk, last_chunk + 1):
                current = bytearray(self._decrypt_chunk(file.chunk_ids[chunk_idx]))
                if len(current) < pt:
                    current.extend(b'\x00' * (pt - len(current)))
                chunk_start = chunk_idx * pt
                write_start = max(offset, chunk_start)
                write_end = min(end, chunk_start + pt)
                src_start = write_start - offset
                src_end = write_end - offset
                dst_start = write_start - chunk_start
                dst_end = write_end - chunk_start
                current[dst_start:dst_end] = buf[src_start:src_end]
                file.chunk_ids[chunk_idx] = self._append_plaintext(bytes(current))

        file.size = max(file.size, end)
        self._persist_file_index()
        return len(buf)

    def truncate(self, name: str, size: int) -> None:
        file = self._files.get(name)
        if file is None:
            raise KeyError(name)
        if size < 0:
            raise ValueError('size must be non-negative')
        pt = CHUNK_PAYLOAD_SIZE

        if size == 0:
            file.chunk_ids = []
            file.size = 0
            self._persist_file_index()
            return

        needed_chunks = (size + pt - 1) // pt
        if needed_chunks < len(file.chunk_ids):
            file.chunk_ids = file.chunk_ids[:needed_chunks]
        while len(file.chunk_ids) < needed_chunks:
            file.chunk_ids.append(self._append_plaintext(b'\x00' * pt))

        # Zero out the tail of the last chunk beyond ``size``.
        tail_end = size % pt
        if tail_end != 0:
            last_cid = file.chunk_ids[-1]
            current = bytearray(self._decrypt_chunk(last_cid))
            if len(current) < pt:
                current.extend(b'\x00' * (pt - len(current)))
            for i in range(tail_end, pt):
                current[i] = 0
            file.chunk_ids[-1] = self._append_plaintext(bytes(current))

        file.size = size
        self._persist_file_index()

    def rename(self, old: str, new: str) -> None:
        """Rename ``old`` to ``new`` within this volume.

        Overwrites ``new`` if it already exists. Renaming to the same
        name is a no-op. Raises ``KeyError`` if ``old`` does not exist.
        The move is pure metadata: we just re-key the entry in the file
        index and rewrite the index chunk. Data chunks stay where they
        are.
        """
        if old == new:
            if old not in self._files:
                raise KeyError(old)
            return
        if old not in self._files:
            raise KeyError(old)
        entry = self._files.pop(old)
        self._files[new] = VolumeFile(name=new, size=entry.size, chunk_ids=entry.chunk_ids)
        self._persist_file_index()

    def unlink(self, name: str) -> None:
        if name not in self._files:
            raise KeyError(name)
        del self._files[name]
        if not self._files:
            if self.is_associated:
                self.slot_table.free(self._slot.index)
                self._slot = SlotInfo(
                    index=self._slot.index,
                    volume_key=os.urandom(len(self._slot.volume_key)),
                    file_table_chunk_id=None,
                    is_new=True,
                )
                # Rotate the cipher so a later first write uses a fresh
                # volume key (prevents nonce reuse against the already-
                # orphaned ciphertexts on disk).
                self._cipher = AEADChunk(self._slot.volume_key)
        else:
            self._persist_file_index()

    def _load_file_index(self) -> None:
        assert self._slot.file_table_chunk_id is not None
        blob = self._read_index_chain(self._slot.file_table_chunk_id)
        self._files = parse(blob)

    def _read_index_chain(self, head_chunk_id: int) -> bytes:
        """Walk the ``next``-pointer chain starting at ``head_chunk_id``.

        Auto-detects the legacy single-chunk index format: a chunk whose
        plaintext does *not* start with ``INDEX_MAGIC`` is treated as a
        zero-padded serialised blob with no chain pointer. This lets
        containers written before the chained-index change still open.
        """
        out = bytearray()
        cid = head_chunk_id
        seen: set[int] = set()
        while cid != INDEX_CHAIN_END:
            if cid in seen:
                raise VolumeCorrupt(f'file index chain cycle at chunk {cid}')
            seen.add(cid)
            plaintext = self._decrypt_chunk(cid)
            if plaintext[: len(INDEX_MAGIC)] == INDEX_MAGIC:
                (next_cid,) = struct.unpack('>Q', plaintext[len(INDEX_MAGIC) : INDEX_HEADER_SIZE])
                payload = plaintext[INDEX_HEADER_SIZE:]
                out.extend(payload)
                cid = next_cid
            else:
                # Legacy v0: whole plaintext is the serialised blob
                # (zero-padded). No chain, stop after this chunk.
                out.extend(plaintext)
                break
        return bytes(out)

    def _persist_file_index(self) -> None:
        blob = serialize(self._files)
        new_chunk_id = self._write_index_chain(blob)
        if self._slot.file_table_chunk_id is None:
            slot_index = self._reserve_slot_for_associate()
            self.slot_table.associate(slot_index, self._slot.volume_key, new_chunk_id)
            self._slot = SlotInfo(
                index=slot_index,
                volume_key=self._slot.volume_key,
                file_table_chunk_id=new_chunk_id,
                is_new=False,
            )
        else:
            self.slot_table.update(self._slot.index, self._slot.volume_key, new_chunk_id)
            self._slot = SlotInfo(
                index=self._slot.index,
                volume_key=self._slot.volume_key,
                file_table_chunk_id=new_chunk_id,
                is_new=False,
            )

    def _write_index_chain(self, blob: bytes) -> int:
        return write_index_chain(self.container, self._cipher, blob)

    def _reserve_slot_for_associate(self) -> int:
        """Return the slot index to associate on the first commit.

        The index reserved at construction may have been claimed by
        another in-process volume in the meantime. In that case we scan
        again; if every slot is taken we propagate the
        ``PasswordDoesNotMatch`` error up.
        """
        if not self.slot_table.is_occupied(self._slot.index):
            return self._slot.index
        refreshed = self.slot_table.find_or_create()
        if not refreshed.is_new:
            # Our password now matches an existing slot - two volumes
            # for the same password created in parallel. The safe move
            # is to refuse rather than silently diverge.
            raise RuntimeError('slot race: another volume with the same password now owns a slot')
        return refreshed.index

    def _append_plaintext(self, plaintext: bytes) -> int:
        if len(plaintext) != CHUNK_PAYLOAD_SIZE:
            raise ValueError(f'plaintext must be exactly {CHUNK_PAYLOAD_SIZE} bytes')
        frame = self._cipher.seal(plaintext)
        return self.container.append_chunk(frame)

    def _decrypt_chunk(self, chunk_id: int) -> bytes:
        frame = self.container.read_chunk(chunk_id)
        plaintext = self._cipher.open(frame)
        if plaintext is None:
            raise VolumeCorrupt(f'chunk {chunk_id} failed authentication')
        return plaintext
