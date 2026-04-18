"""Serialisable per-volume file index.

Replaces the byte-offset-based ``FileStructure`` from the legacy layout
with a chunk-id-based one. Each ``VolumeFile`` records the ordered list
of chunk ids that hold its plaintext data, plus the logical size so we
know how much of the last chunk is live.

Serialisation format (all integers big-endian)::

    u32     num_files
    repeat num_files times:
        u32   name_length
        bytes name (utf-8)
        u64   size
        u32   num_chunks
        u64 * num_chunks   chunk_ids
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class VolumeFile:
    name: str
    size: int = 0
    chunk_ids: list[int] = field(default_factory=list)


class FileIndexCorrupt(Exception):
    pass


def serialize(files: dict[str, VolumeFile]) -> bytes:
    out = bytearray()
    out.extend(struct.pack('>I', len(files)))
    for name in sorted(files):
        vf = files[name]
        encoded = vf.name.encode('utf-8')
        out.extend(struct.pack('>I', len(encoded)))
        out.extend(encoded)
        out.extend(struct.pack('>Q', vf.size))
        out.extend(struct.pack('>I', len(vf.chunk_ids)))
        for cid in vf.chunk_ids:
            out.extend(struct.pack('>Q', cid))
    return bytes(out)


def parse(blob: bytes) -> dict[str, VolumeFile]:
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
        return files
    except struct.error as e:
        raise FileIndexCorrupt(str(e)) from e
