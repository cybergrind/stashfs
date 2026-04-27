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
import threading
from collections.abc import Iterator

from stashfs.container import CHUNK_PAYLOAD_SIZE, Container
from stashfs.crypto import KDF, AEADChunk
from stashfs.file_index import FileIndex, VolumeFile, parse, serialize
from stashfs.slot_table import SlotInfo, SlotTable


def _parent_of(name: str) -> str:
    """Return the parent directory of ``name`` (``''`` for top level)."""
    if '/' not in name:
        return ''
    return name.rsplit('/', 1)[0]


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
INDEX_MAGIC = b'FIDXv002'
INDEX_HEADER_SIZE = len(INDEX_MAGIC) + 8
INDEX_PAYLOAD_SIZE = CHUNK_PAYLOAD_SIZE - INDEX_HEADER_SIZE
INDEX_CHAIN_END = 0xFFFF_FFFF_FFFF_FFFF

# Type aliases so pyrefly doesn't confuse the builtin ``list`` with the
# ``Volume.list`` method when evaluating annotations inside the class.
_ChunkIds = list[int]
_NameList = list[str]


def write_index_chain(container: Container, cipher: AEADChunk, blob: bytes) -> tuple[int, list[int]]:
    """Append the serialised index as a chain of versioned chunks.

    Each chunk's plaintext is ``INDEX_MAGIC || next_cid || page ||
    zero_pad`` filling the full chunk payload. Pages are appended in
    reverse so every non-tail chunk already knows its successor's id
    by the time it is sealed. Returns ``(head_chunk_id, chain_ids)``:
    the head (what the slot should point at) and the full list of
    chunk ids comprising the chain in order from head to tail, so the
    caller can later mark them dead when the chain is superseded.
    """
    if blob == b'':
        pages: list[bytes] = [b'']
    else:
        pages = [blob[i : i + INDEX_PAYLOAD_SIZE] for i in range(0, len(blob), INDEX_PAYLOAD_SIZE)]
    next_cid = INDEX_CHAIN_END
    reverse_chain: list[int] = []
    for page in reversed(pages):
        padded_page = page + b'\x00' * (INDEX_PAYLOAD_SIZE - len(page))
        assert len(padded_page) == INDEX_PAYLOAD_SIZE
        plaintext = INDEX_MAGIC + struct.pack('>Q', next_cid) + padded_page
        assert len(plaintext) == CHUNK_PAYLOAD_SIZE
        frame = cipher.seal(plaintext)
        next_cid = container.append_chunk(frame)
        reverse_chain.append(next_cid)
    chain_ids = list(reversed(reverse_chain))
    return next_cid, chain_ids


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
        self._dirs: set[str] = set()
        # The chunk ids making up the currently-live file-index chain.
        # We remember them so we can mark-dead the chain when it's
        # superseded on the next commit.
        self._index_chain_ids: list[int] = []
        # Batched-commit state: data chunks are appended eagerly, but the
        # file-index rewrite + slot wrap update are deferred until
        # ``flush()``. Without this, every FUSE write rewrote the entire
        # (linearly growing) index chain — causing O(N²) write
        # amplification on large copies. ``_pending_dead`` collects
        # chunk ids that became unreachable between commits; they get
        # marked dead only after the slot wrap commits, so a crash
        # before flush leaves the previous state intact.
        self._dirty: bool = False
        self._pending_dead: list[int] = []
        # Mutating operations (write_file/truncate/mkdir/.../flush) all
        # touch the in-memory file index, the per-volume cipher state,
        # and — through ``Container.append_chunk`` — the shared
        # ``Allocation`` table. The allocation chain in particular is
        # not safe to mutate concurrently: ``_set_entry`` and
        # ``_bump_count`` write to fixed disk offsets without locking,
        # so two concurrent appends would clobber each other and the
        # backing file would diverge from the in-memory ``_chunks``.
        # FUSE multithreaded mode happily delivers concurrent writes
        # to one inode, so we serialize them here. Reads stay
        # lock-free (storage I/O is atomic via ``os.pread``; chunk-id
        # lookups read immutable past entries).
        self._write_lock = threading.Lock()
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

    def list_dirs(self) -> _NameList:
        return sorted(self._dirs)

    def size_of(self, name: str) -> int:
        return self._files[name].size

    def exists(self, name: str) -> bool:
        return name in self._files

    # -------- directory operations --------

    def is_dir(self, name: str) -> bool:
        """True iff ``name`` is an explicit or implicit directory."""
        if name == '':
            return True  # root
        if name in self._dirs:
            return True
        prefix = name + '/'
        return any(f.startswith(prefix) for f in self._files) or any(d.startswith(prefix) for d in self._dirs)

    def mkdir(self, name: str) -> None:
        """Register an explicit empty directory at ``name``."""
        with self._write_lock:
            if name == '':
                raise FileExistsError('')
            if name in self._files:
                raise FileExistsError(name)
            if self.is_dir(name):
                raise FileExistsError(name)
            parent = _parent_of(name)
            if not self.is_dir(parent):
                raise FileNotFoundError(parent)
            self._dirs.add(name)
            self._dirty = True
            self._flush_locked()

    def rmdir(self, name: str) -> None:
        """Remove an empty directory.

        Fails if the directory has any children (implicit or explicit).
        Raises ``KeyError`` if the name isn't a directory, ``OSError``
        (``ENOTEMPTY``) if non-empty.
        """
        import errno as _errno

        with self._write_lock:
            if not self.is_dir(name):
                raise KeyError(name)
            prefix = name + '/' if name else ''
            has_child = any(f.startswith(prefix) for f in self._files) or any(
                d.startswith(prefix) and d != name for d in self._dirs
            )
            if has_child:
                raise OSError(_errno.ENOTEMPTY, f'directory not empty: {name!r}')
            self._dirs.discard(name)
            self._dirty = True
            self._flush_locked()

    def iter_children(self, parent: str) -> Iterator[tuple[str, str]]:
        """Yield ``(basename, kind)`` for direct children of ``parent``.

        ``parent=''`` means the root. ``kind`` is ``'file'`` or
        ``'dir'``. A name that matches both (shouldn't happen) is
        reported once as ``'file'``.
        """
        prefix = parent + '/' if parent else ''
        seen: set[str] = set()
        for name in self._files:
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix) :]
            if not rest or '/' in rest:
                # A child implied by a deeper descendant — surface it
                # as an implicit directory below, not a file.
                continue
            seen.add(rest)
            yield (rest, 'file')
        for name in self._dirs:
            if name == parent:
                continue
            if not name.startswith(prefix):
                continue
            head = name[len(prefix) :].split('/', 1)[0]
            if head in seen:
                continue
            seen.add(head)
            yield (head, 'dir')
        # Implicit sub-directories derived from deeper file paths.
        for name in self._files:
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix) :]
            if '/' not in rest:
                continue
            head = rest.split('/', 1)[0]
            if head in seen:
                continue
            seen.add(head)
            yield (head, 'dir')

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
        with self._write_lock:
            return self._write_file_locked(name, offset, buf)

    def _write_file_locked(self, name: str, offset: int, buf: bytes) -> int:
        file = self._files.get(name)
        if file is None:
            file = VolumeFile(name=name)
            self._files[name] = file

        end = offset + len(buf)
        pt = CHUNK_PAYLOAD_SIZE
        last_needed_chunk = (max(end, file.size + 1) - 1) // pt if max(end, file.size) > 0 else -1
        old_count = len(file.chunk_ids)

        if buf:
            first_write = offset // pt
            last_write = (end - 1) // pt
        else:
            first_write = 1
            last_write = 0  # empty range

        # Phase 1: extend chunk_ids past ``old_count``. For new chunks
        # that fall inside ``[first_write, last_write]`` we build their
        # content directly from ``buf`` and skip the historic
        # append-zeros-then-immediately-rewrite double-write. For
        # sparse-hole positions (past EOF, before the write range) we
        # still need a real zero chunk on disk.
        for idx in range(old_count, last_needed_chunk + 1):
            cs = idx * pt
            ce = cs + pt
            if first_write <= idx <= last_write:
                ws = max(offset, cs)
                we = min(end, ce)
                if ws == cs and we == ce:
                    payload = buf[ws - offset : we - offset]
                else:
                    chunk = bytearray(b'\x00' * pt)
                    chunk[ws - cs : we - cs] = buf[ws - offset : we - offset]
                    payload = bytes(chunk)
                file.chunk_ids.append(self._append_plaintext(payload))
            else:
                file.chunk_ids.append(self._append_plaintext(b'\x00' * pt))

        # Phase 2: existing chunks that overlap the write range get a
        # read-modify-write. Full-chunk overwrites skip the read.
        superseded: list[int] = []
        if buf:
            for idx in range(first_write, min(last_write, old_count - 1) + 1):
                cs = idx * pt
                ce = cs + pt
                ws = max(offset, cs)
                we = min(end, ce)
                if ws == cs and we == ce:
                    payload = buf[ws - offset : we - offset]
                else:
                    cur = bytearray(self._decrypt_chunk(file.chunk_ids[idx]))
                    if len(cur) < pt:
                        cur.extend(b'\x00' * (pt - len(cur)))
                    cur[ws - cs : we - cs] = buf[ws - offset : we - offset]
                    payload = bytes(cur)
                superseded.append(file.chunk_ids[idx])
                file.chunk_ids[idx] = self._append_plaintext(payload)

        file.size = max(file.size, end)
        self._dirty = True
        self._pending_dead.extend(superseded)
        return len(buf)

    def truncate(self, name: str, size: int) -> None:
        if size < 0:
            raise ValueError('size must be non-negative')
        with self._write_lock:
            self._truncate_locked(name, size)

    def _truncate_locked(self, name: str, size: int) -> None:
        file = self._files.get(name)
        if file is None:
            raise KeyError(name)
        pt = CHUNK_PAYLOAD_SIZE

        if size == 0:
            dropped = list(file.chunk_ids)
            file.chunk_ids = []
            file.size = 0
            self._dirty = True
            self._pending_dead.extend(dropped)
            return

        needed_chunks = (size + pt - 1) // pt
        dropped: list[int] = []
        if needed_chunks < len(file.chunk_ids):
            dropped = file.chunk_ids[needed_chunks:]
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
            self._pending_dead.append(last_cid)

        file.size = size
        self._dirty = True
        self._pending_dead.extend(dropped)

    def rename(self, old: str, new: str) -> None:
        """Rename ``old`` to ``new`` within this volume.

        ``old`` may be a file or a directory (explicit or implicit).
        Renaming a directory rewrites every child path in ``_files``
        and ``_dirs`` whose key starts with ``old + '/'``. The move is
        pure metadata; data chunks stay where they are.

        Overwrites ``new`` if it already exists as a file with the
        same role (file → file). Renaming to the same name is a no-op.
        """
        with self._write_lock:
            if old == new:
                if old not in self._files and not self.is_dir(old):
                    raise KeyError(old)
                return
            new_parent = _parent_of(new)
            if not self.is_dir(new_parent):
                raise FileNotFoundError(new_parent)

            if old in self._files:
                entry = self._files.pop(old)
                self._files[new] = VolumeFile(name=new, size=entry.size, chunk_ids=entry.chunk_ids)
                self._dirty = True
                self._flush_locked()
                return

            if self.is_dir(old):
                self._rename_subtree(old, new)
                self._dirty = True
                self._flush_locked()
                return

            raise KeyError(old)

    def _rename_subtree(self, old: str, new: str) -> None:
        """Rewrite every ``_files`` and ``_dirs`` entry under ``old/`` to ``new/``."""
        old_prefix = old + '/'
        renamed_files: list[tuple[str, str]] = []
        for name in list(self._files):
            if name == old:
                renamed_files.append((name, new))
            elif name.startswith(old_prefix):
                renamed_files.append((name, new + '/' + name[len(old_prefix) :]))
        for src, dst in renamed_files:
            entry = self._files.pop(src)
            self._files[dst] = VolumeFile(name=dst, size=entry.size, chunk_ids=entry.chunk_ids)

        renamed_dirs: list[tuple[str, str]] = []
        for name in list(self._dirs):
            if name == old:
                renamed_dirs.append((name, new))
            elif name.startswith(old_prefix):
                renamed_dirs.append((name, new + '/' + name[len(old_prefix) :]))
        for src, dst in renamed_dirs:
            self._dirs.discard(src)
            self._dirs.add(dst)

    def unlink(self, name: str) -> None:
        with self._write_lock:
            self._unlink_locked(name)

    def _unlink_locked(self, name: str) -> None:
        if name not in self._files:
            raise KeyError(name)
        victim = self._files.pop(name)
        if not self._files:
            if self.is_associated:
                self.slot_table.free(self._slot.index)
                # Every chunk this volume ever wrote under the old key
                # is now unreachable (we're about to rotate the key).
                # Mark them all dead so optimize can reclaim them —
                # including any pending-dead chunks queued by deferred
                # writes that hadn't been committed yet.
                for cid in victim.chunk_ids:
                    self.container.mark_chunk_dead(cid)
                for cid in self._index_chain_ids:
                    self.container.mark_chunk_dead(cid)
                for cid in self._pending_dead:
                    self.container.mark_chunk_dead(cid)
                self._pending_dead = []
                self._dirty = False
                self._index_chain_ids = []
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
            self._pending_dead.extend(victim.chunk_ids)
            self._dirty = True
            self._flush_locked()

    def flush(self) -> None:
        """Commit pending in-memory state to the backing container.

        Persists the file-index chain (rewriting it once per call,
        regardless of how many ``write_file`` / ``truncate`` calls
        produced the dirty state) and only then marks every queued
        superseded chunk dead. The order matters: until the slot wrap
        points at the new index chain, the OLD chain is the source of
        truth, so the chunks it references must remain live.
        """
        with self._write_lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._dirty and not self._pending_dead:
            return
        # Reload the allocation chain in case a sibling Volume on the
        # same backing file appended chunks since we last did. Without
        # this, our cached chunk count is stale and the next
        # ``append`` would clobber another volume's entries.
        self.container.reload_allocation()
        if self._dirty:
            self._persist_file_index()
            self._dirty = False
        if self._pending_dead:
            for cid in self._pending_dead:
                self.container.mark_chunk_dead(cid)
            self._pending_dead = []

    def _load_file_index(self) -> None:
        assert self._slot.file_table_chunk_id is not None
        blob, chain_ids = self._read_index_chain(self._slot.file_table_chunk_id)
        index = parse(blob)
        self._files = index.files
        self._dirs = index.dirs
        self._index_chain_ids = chain_ids

    def _read_index_chain(self, head_chunk_id: int) -> tuple[bytes, _ChunkIds]:
        """Walk the ``next``-pointer chain starting at ``head_chunk_id``.

        Every chunk must begin with ``INDEX_MAGIC`` (``FIDXv002``). The
        pre-magic legacy format (``FIDXv001`` and the earlier no-magic
        blob) is not supported; such chunks raise ``VolumeCorrupt``.

        Returns ``(blob, chain_ids)`` — the concatenated payload and the
        list of chunk ids walked (head first).
        """
        out = bytearray()
        chain_ids: list[int] = []
        cid = head_chunk_id
        seen: set[int] = set()
        while cid != INDEX_CHAIN_END:
            if cid in seen:
                raise VolumeCorrupt(f'file index chain cycle at chunk {cid}')
            seen.add(cid)
            chain_ids.append(cid)
            plaintext = self._decrypt_chunk(cid)
            if plaintext[: len(INDEX_MAGIC)] != INDEX_MAGIC:
                raise VolumeCorrupt(f'unsupported file-index version at chunk {cid}: expected {INDEX_MAGIC!r}')
            (next_cid,) = struct.unpack('>Q', plaintext[len(INDEX_MAGIC) : INDEX_HEADER_SIZE])
            payload = plaintext[INDEX_HEADER_SIZE:]
            out.extend(payload)
            cid = next_cid
        return bytes(out), chain_ids

    def _persist_file_index(self) -> None:
        blob = serialize(FileIndex(files=self._files, dirs=self._dirs))
        new_head_id, new_chain_ids = write_index_chain(self.container, self._cipher, blob)
        if self._slot.file_table_chunk_id is None:
            slot_index = self._reserve_slot_for_associate()
            self.slot_table.associate(slot_index, self._slot.volume_key, new_head_id)
            self._slot = SlotInfo(
                index=slot_index,
                volume_key=self._slot.volume_key,
                file_table_chunk_id=new_head_id,
                is_new=False,
            )
        else:
            self.slot_table.update(self._slot.index, self._slot.volume_key, new_head_id)
            self._slot = SlotInfo(
                index=self._slot.index,
                volume_key=self._slot.volume_key,
                file_table_chunk_id=new_head_id,
                is_new=False,
            )
        # Mark the previous chain dead only after the slot wrap now
        # points at the new chain. A crash before this mark-dead step
        # leaves state consistent (optimize will just miss these
        # orphans until some future commit re-marks them).
        previous_chain = self._index_chain_ids
        self._index_chain_ids = new_chain_ids
        for cid in previous_chain:
            self.container.mark_chunk_dead(cid)

    def _write_index_chain(self, blob: bytes) -> int:
        head_id, _chain = write_index_chain(self.container, self._cipher, blob)
        return head_id

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
