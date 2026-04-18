"""Offline compaction for fyl backing files.

Every mutation in ``Volume`` appends fresh chunks and orphans the old
ones by design (crash-safe append-only). ``optimize`` rebuilds the
backing file with only the live chunks of every unlocked slot,
preserving the cover bytes, the global salt, and every file's bytes.

The source container is never mutated; the rebuild is written to
``<path>.tmp`` and atomically renamed over the source so a crash
anywhere before the rename leaves the original untouched.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from fyl.container import Container
from fyl.crypto import KDF, AEADChunk
from fyl.file_index import serialize
from fyl.fuse_app import _looks_like_fuse_mount
from fyl.slot_table import FLAG_OCCUPIED, SlotTable
from fyl.storage import CoverStorage, FileWrapper
from fyl.volume import Volume, write_index_chain


@dataclass
class OptimizeReport:
    old_size: int
    new_size: int
    rebuilt_slots: list[int] = field(default_factory=list)
    dropped_slots: list[int] = field(default_factory=list)

    @property
    def reclaimed(self) -> int:
        return self.old_size - self.new_size


class OptimizeError(Exception):
    """Raised when optimize refuses to run (locked slot, live mount, ...)."""


def optimize(
    path: Path,
    passwords: Sequence[str],
    *,
    kdf: KDF | None = None,
    drop_locked: bool = False,
) -> OptimizeReport:
    path = Path(path)
    kdf = kdf or KDF()

    if _looks_like_fuse_mount(path):
        raise OptimizeError(f'{path} appears to be mounted; unmount before optimizing')

    old_size = path.stat().st_size

    src_fw = FileWrapper(path)
    src_cover = CoverStorage.attach(src_fw)
    src_container = Container(src_cover)
    salt = src_container.read_header()
    cover_length = src_cover.cover_length

    unlocked: list[_UnlockedSlot] = []
    locked: list[int] = []
    for slot_index in range(_num_slots(src_container)):
        if src_container.read_slot(slot_index)[0] != FLAG_OCCUPIED:
            continue
        match = _try_unlock(src_container, kdf, slot_index, passwords)
        if match is None:
            locked.append(slot_index)
            continue
        unlocked.append(match)

    if locked and not drop_locked:
        raise OptimizeError(f'cannot unlock occupied slot(s) {locked}; refusing to rebuild')

    tmp_path = path.with_suffix(path.suffix + '.tmp')
    try:
        _build_destination(tmp_path, cover_length, path, salt)
        dst_fw = FileWrapper(tmp_path)
        dst_cover = CoverStorage.attach(dst_fw)
        dst_container = Container(dst_cover)
        dst_container.write_header(salt)

        for slot in unlocked:
            _rebuild_slot(src_container, dst_container, kdf, slot)

        del dst_container, dst_cover, dst_fw
        del src_container, src_cover, src_fw
        os.replace(tmp_path, path)
    except BaseException:
        if tmp_path.exists():
            tmp_path.unlink()
        raise

    new_size = path.stat().st_size
    return OptimizeReport(
        old_size=old_size,
        new_size=new_size,
        rebuilt_slots=[s.index for s in unlocked],
        dropped_slots=locked,
    )


@dataclass
class _UnlockedSlot:
    index: int
    password: str
    volume_key: bytes
    files: dict


def _num_slots(container: Container) -> int:
    from fyl.container import N_SLOTS

    return N_SLOTS


def _try_unlock(
    container: Container,
    kdf: KDF,
    slot_index: int,
    passwords: Sequence[str],
) -> _UnlockedSlot | None:
    for pw in passwords:
        st = SlotTable(container, kdf, pw)
        if st.is_empty_password and slot_index != 0:
            continue
        if not st.is_empty_password and slot_index == 0:
            continue
        slot_blob = container.read_slot(slot_index)
        unwrapped = st._unwrap(slot_blob, slot_index)
        if unwrapped is None:
            continue
        volume_key, _ = unwrapped
        v = Volume(container, kdf, pw)
        if v.slot_index != slot_index:
            # Different slot — shouldn't happen if _unwrap succeeded, but be defensive.
            continue
        return _UnlockedSlot(
            index=slot_index,
            password=pw,
            volume_key=volume_key,
            files=dict(v._files),
        )
    return None


def _build_destination(tmp_path: Path, cover_length: int, src_path: Path, salt: bytes) -> None:
    # Pre-populate destination with the original cover bytes so
    # CoverStorage.attach treats them as the cover and stamps the
    # footer after them.
    if cover_length:
        with src_path.open('rb') as src, tmp_path.open('wb') as dst:
            remaining = cover_length
            while remaining:
                chunk = src.read(min(remaining, 1 << 20))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)
    else:
        tmp_path.write_bytes(b'')


def _rebuild_slot(
    src: Container,
    dst: Container,
    kdf: KDF,
    slot: _UnlockedSlot,
) -> None:
    remap: dict[int, int] = {}
    for vf in slot.files.values():
        new_ids = []
        for old_id in vf.chunk_ids:
            new_id = remap.get(old_id)
            if new_id is None:
                frame = src.read_chunk(old_id)
                new_id = dst.append_chunk(frame)
                remap[old_id] = new_id
            new_ids.append(new_id)
        vf.chunk_ids = new_ids

    blob = serialize(slot.files)
    cipher = AEADChunk(slot.volume_key)
    new_head = write_index_chain(dst, cipher, blob)
    SlotTable(dst, kdf, slot.password).associate(slot.index, slot.volume_key, new_head)
