"""Serialisable per-volume file index (FIDXv002).

v002 adds support for explicit empty directories on top of the file
list. The on-disk blob sits inside the AEAD envelope of the file-index
chunk chain — the plaintext is only ever visible after the volume is
unlocked.

Format (all integers big-endian)::

    u32     num_files
    repeat num_files times:
        u32   name_length
        bytes name (utf-8)        # may contain '/'
        u64   size
        u32   num_chunks
        u64 * num_chunks          chunk_ids
    u32     num_dirs              # v002
    repeat num_dirs times:
        u32   name_length
        bytes name (utf-8)

The version tag lives at the chunk-chain layer (``INDEX_MAGIC`` in
``stashfs.volume``). ``parse`` therefore does not re-check the version;
it trusts that the chunk-chain reader has already gated entry.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class VolumeFile:
    name: str
    size: int = 0
    chunk_ids: list[int] = field(default_factory=list)


@dataclass
class FileIndex:
    files: dict[str, VolumeFile] = field(default_factory=dict)
    dirs: set[str] = field(default_factory=set)


class FileIndexCorrupt(Exception):
    pass


def serialize(index: FileIndex) -> bytes:
    out = bytearray()
    out.extend(struct.pack('>I', len(index.files)))
    for name in sorted(index.files):
        vf = index.files[name]
        encoded = vf.name.encode('utf-8')
        out.extend(struct.pack('>I', len(encoded)))
        out.extend(encoded)
        out.extend(struct.pack('>Q', vf.size))
        out.extend(struct.pack('>I', len(vf.chunk_ids)))
        for cid in vf.chunk_ids:
            out.extend(struct.pack('>Q', cid))
    out.extend(struct.pack('>I', len(index.dirs)))
    for name in sorted(index.dirs):
        encoded = name.encode('utf-8')
        out.extend(struct.pack('>I', len(encoded)))
        out.extend(encoded)
    return bytes(out)


def parse(blob: bytes) -> FileIndex:
    try:
        pos = 0
        (num_files,) = struct.unpack_from('>I', blob, pos)
        pos += 4
        files: dict[str, VolumeFile] = {}
        for _ in range(num_files):
            (name_len,) = struct.unpack_from('>I', blob, pos)
            pos += 4
            name = blob[pos : pos + name_len].decode('utf-8')
            pos += name_len
            (size,) = struct.unpack_from('>Q', blob, pos)
            pos += 8
            (num_chunks,) = struct.unpack_from('>I', blob, pos)
            pos += 4
            chunk_ids = list(struct.unpack_from(f'>{num_chunks}Q', blob, pos))
            pos += 8 * num_chunks
            files[name] = VolumeFile(name=name, size=size, chunk_ids=chunk_ids)
        (num_dirs,) = struct.unpack_from('>I', blob, pos)
        pos += 4
        dirs: set[str] = set()
        for _ in range(num_dirs):
            (name_len,) = struct.unpack_from('>I', blob, pos)
            pos += 4
            name = blob[pos : pos + name_len].decode('utf-8')
            pos += name_len
            dirs.add(name)
        return FileIndex(files=files, dirs=dirs)
    except struct.error as e:
        raise FileIndexCorrupt(str(e)) from e
    except UnicodeDecodeError as e:
        raise FileIndexCorrupt(f'invalid utf-8 in name: {e}') from e
