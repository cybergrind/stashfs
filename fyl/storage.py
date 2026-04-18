"""Byte-level storage seam.

Everything above this file (legacy FS, FUSE glue, eventually the crypto
container) talks to a ``Storage`` rather than directly opening files.
This lets us layer encryption in later phases without touching the
higher layers.
"""

from __future__ import annotations

import logging
import os
import struct
from pathlib import Path
from typing import Protocol, runtime_checkable


log = logging.getLogger('fyl.storage')


@runtime_checkable
class Storage(Protocol):
    """Narrow byte-addressed storage contract.

    Deliberately smaller than today's ``FileWrapper`` - it excludes
    layout-specific helpers like ``read_meta_offset`` and
    ``remove_data`` which belong to the legacy byte-offset filesystem,
    not to storage.
    """

    def read(self, size: int, offset: int) -> bytes: ...

    def write(self, offset: int, buf: bytes) -> None: ...

    def write_end(self, buf: bytes) -> None: ...

    def size(self) -> int: ...

    def truncate(self, size: int) -> None: ...


class FileWrapper:
    """Plaintext file-backed ``Storage`` implementation.

    The extra legacy helpers (``read_meta_offset``, ``remove_data``,
    ``truncate_last``, ``reset_handlers``) exist to keep the historical
    byte-offset filesystem working during the transition; they are not
    part of the ``Storage`` protocol and new code should not depend on
    them.
    """

    MAGIC_BYTES = b'0FYLFMT0'

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        if not path.exists():
            path.touch()
        self.reset_handlers()
        self.inner_files: set[str] = set()

    def read_meta_offset(self) -> int:
        """Legacy: check MAGIC_BYTES near EOF, return meta offset or -1."""
        self.read_handle.seek(-len(self.MAGIC_BYTES) - 8, os.SEEK_END)
        if self.read_handle.read(len(self.MAGIC_BYTES)) != self.MAGIC_BYTES:
            return -1
        return int.from_bytes(self.read_handle.read(8), 'little', signed=False)

    def reset_handlers(self) -> None:
        if hasattr(self, 'read_handle'):
            self.read_handle.close()
        self.read_handle = self.path.open('rb')

    def remove_data(self, offset: int, size: int) -> None:
        """Legacy: drop ``size`` bytes starting at ``offset``, in place."""
        file_size = self.size()
        if offset + size > file_size:
            raise ValueError('offset + size > file size')
        self.read_handle.seek(0, os.SEEK_SET)
        head = self.read_handle.read(offset)
        self.read_handle.seek(offset + size, os.SEEK_SET)
        tail = self.read_handle.read()
        self.path.write_bytes(head + tail)
        self.reset_handlers()

    def truncate_last(self, size: int) -> None:
        """Legacy: drop ``size`` bytes from the tail."""
        new_size = self.size() - size
        with self.path.open('r+b') as f:
            f.truncate(new_size)
        self.reset_handlers()

    def __del__(self) -> None:
        handle = getattr(self, 'read_handle', None)
        if handle is not None:
            handle.close()

    def write(self, offset: int, buf: bytes) -> None:
        log.debug(f'write {offset=} {len(buf)=}')
        with self.path.open('r+b') as f:
            f.seek(offset, os.SEEK_SET)
            f.write(buf)
        self.reset_handlers()

    def write_end(self, buf: bytes) -> None:
        with self.path.open('r+b') as f:
            f.seek(0, os.SEEK_END)
            f.write(buf)
        self.reset_handlers()

    def read(self, size: int, offset: int) -> bytes:
        log.debug(f'read {offset=} {size=}')
        self.read_handle.seek(offset, os.SEEK_SET)
        return self.read_handle.read(size)

    def size(self) -> int:
        return self.path.stat().st_size

    def truncate(self, size: int) -> None:
        with self.path.open('r+b') as f:
            f.truncate(size)
        self.reset_handlers()


class CoverStorage:
    """``Storage`` view that hides a fyl container inside an existing file.

    Physical layout on the inner storage::

        [cover bytes][fyl container][FOOTER_MAGIC 8B][cover_length u64 8B]

    ``Container`` sits on top of this view and sees only the middle part
    as its backing, starting at offset 0. That makes cover support
    transparent - nothing else in the crypto stack needs to know.

    When the inner storage is empty the view is initialised with an
    empty cover (cover_length = 0) and only the 16-byte footer. When
    the inner storage already has bytes but no footer magic, the entire
    current content is treated as the cover and a fresh container is
    appended after it. Existing cover bytes are never rewritten.
    """

    FOOTER_MAGIC = b'FYLCOVER'
    FOOTER_SIZE = 16

    def __init__(self, inner: Storage, cover_length: int) -> None:
        self._inner = inner
        self._cover_length = cover_length

    @classmethod
    def attach(cls, inner: Storage) -> CoverStorage:
        """Open a cover view over ``inner``, creating the footer if needed."""
        total = inner.size()
        if total == 0:
            return cls._initialise(inner, cover_length=0)
        if total >= cls.FOOTER_SIZE:
            footer = inner.read(cls.FOOTER_SIZE, total - cls.FOOTER_SIZE)
            if footer[: len(cls.FOOTER_MAGIC)] == cls.FOOTER_MAGIC:
                (cover_length,) = struct.unpack('>Q', footer[len(cls.FOOTER_MAGIC) :])
                if cover_length > total - cls.FOOTER_SIZE:
                    raise ValueError(f'footer declares cover_length={cover_length} but file is only {total} bytes')
                return cls(inner, cover_length)
        return cls._initialise(inner, cover_length=total)

    @classmethod
    def _initialise(cls, inner: Storage, cover_length: int) -> CoverStorage:
        inner.write_end(cls._footer_bytes(cover_length))
        return cls(inner, cover_length)

    @classmethod
    def _footer_bytes(cls, cover_length: int) -> bytes:
        return cls.FOOTER_MAGIC + struct.pack('>Q', cover_length)

    @property
    def cover_length(self) -> int:
        return self._cover_length

    def read(self, size: int, offset: int) -> bytes:
        logical_size = self.size()
        if offset < 0 or offset >= logical_size:
            return b''
        effective = min(size, logical_size - offset)
        return self._inner.read(effective, self._cover_length + offset)

    def write(self, offset: int, buf: bytes) -> None:
        if offset < 0:
            raise ValueError('offset must be non-negative')
        self._inner.write(self._cover_length + offset, buf)

    def write_end(self, buf: bytes) -> None:
        total = self._inner.size()
        # Overwrite the trailing footer with ``buf`` followed by a fresh
        # footer at the new EOF.
        self._inner.write(
            total - self.FOOTER_SIZE,
            buf + self._footer_bytes(self._cover_length),
        )

    def size(self) -> int:
        return self._inner.size() - self._cover_length - self.FOOTER_SIZE

    def truncate(self, size: int) -> None:
        if size < 0:
            raise ValueError('size must be non-negative')
        current = self.size()
        if size > current:
            # Grow: extend the logical region with zeros. write_end
            # takes care of keeping the footer at the very end.
            self.write_end(b'\x00' * (size - current))
            return
        # Shrink or same-size: chop, then re-stamp the footer at EOF.
        self._inner.truncate(self._cover_length + size)
        self._inner.write_end(self._footer_bytes(self._cover_length))
