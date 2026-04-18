"""Slot table: map password -> (volume_key, file_table_chunk_id).

Each slot is 80 bytes. When occupied, the layout is::

    +0:  1B   flag = 0x01
    +1:  68B  AEAD frame (12B nonce || 40B ciphertext || 16B tag)
    +69: 11B  random padding

When free, the byte at +0 is 0x00 and the rest of the 80 bytes is
uniformly random. The plaintext that sits inside the AEAD frame is
exactly 40 bytes: a 32-byte volume key followed by an 8-byte (big-endian
unsigned) file_table_chunk_id.

The empty password is tied *exclusively* to slot 0: empty always tries
slot 0 and never scans 1..7; non-empty passwords never touch slot 0.

Callers construct one ``SlotTable`` per mount/password and use
``find_or_create`` to learn which slot the password maps to. The slot is
only physically marked occupied when the caller later invokes
``associate`` with a concrete ``file_table_chunk_id``; it can be freed
again via ``free`` when the last file in the volume is removed.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from stashfs.container import N_SLOTS, SLOT_SIZE, Container
from stashfs.crypto import KDF, KEY_SIZE, NONCE_SIZE, TAG_SIZE, AEADChunk


FLAG_FREE = 0x00
FLAG_OCCUPIED = 0x01

WRAP_PLAINTEXT_SIZE = KEY_SIZE + 8  # volume_key + chunk_id
AEAD_FRAME_SIZE = NONCE_SIZE + WRAP_PLAINTEXT_SIZE + TAG_SIZE
SLOT_PAD_SIZE = SLOT_SIZE - 1 - AEAD_FRAME_SIZE

assert SLOT_PAD_SIZE >= 0, 'SLOT_SIZE too small for AEAD frame'


class PasswordDoesNotMatch(Exception):
    """Raised when no slot matches the password and none is free to claim."""


@dataclass(frozen=True)
class SlotInfo:
    """Result of ``SlotTable.find_or_create``.

    ``is_new`` is true when the password did not match any occupied
    slot; the slot is *reserved* at ``index`` but not yet occupied. The
    caller must ``associate`` once it has a ``file_table_chunk_id``.
    """

    index: int
    volume_key: bytes
    file_table_chunk_id: int | None
    is_new: bool


class SlotTable:
    def __init__(self, container: Container, kdf: KDF, password: str | bytes) -> None:
        self.container = container
        self.kdf = kdf
        self.password = password
        self.is_empty_password = password in ('', b'')
        self._global_salt = container.read_header()
        self._master = kdf.master(password, self._global_salt)

    def find_or_create(self) -> SlotInfo:
        if self.is_empty_password:
            slot = self.container.read_slot(0)
            if slot[0] == FLAG_OCCUPIED:
                unwrapped = self._unwrap(slot, 0)
                if unwrapped is None:
                    # Empty password is pinned to slot 0 by design; if
                    # slot 0 is occupied and we can't unwrap it, the
                    # container is corrupt for the empty-password user.
                    raise PasswordDoesNotMatch()
                volume_key, chunk_id = unwrapped
                return SlotInfo(0, volume_key, chunk_id, is_new=False)
            return SlotInfo(0, os.urandom(KEY_SIZE), None, is_new=True)

        # Non-empty: scan occupied slots in 1..N_SLOTS-1 for a match.
        for i in range(1, N_SLOTS):
            slot = self.container.read_slot(i)
            if slot[0] != FLAG_OCCUPIED:
                continue
            unwrapped = self._unwrap(slot, i)
            if unwrapped is not None:
                volume_key, chunk_id = unwrapped
                return SlotInfo(i, volume_key, chunk_id, is_new=False)

        for i in range(1, N_SLOTS):
            slot = self.container.read_slot(i)
            if slot[0] != FLAG_OCCUPIED:
                return SlotInfo(i, os.urandom(KEY_SIZE), None, is_new=True)

        raise PasswordDoesNotMatch()

    def associate(self, slot_index: int, volume_key: bytes, file_table_chunk_id: int) -> None:
        """Mark slot ``slot_index`` occupied with the given wrapping.

        Refuses to overwrite an already-occupied slot.
        """
        self._check_slot_in_domain(slot_index)
        slot = self.container.read_slot(slot_index)
        if slot[0] == FLAG_OCCUPIED:
            raise RuntimeError(f'refusing to overwrite occupied slot {slot_index}')
        if len(volume_key) != KEY_SIZE:
            raise ValueError(f'volume_key must be {KEY_SIZE} bytes')
        if file_table_chunk_id < 0 or file_table_chunk_id >> 64:
            raise ValueError(f'file_table_chunk_id out of u64 range: {file_table_chunk_id}')

        slot_key = KDF.derive_slot(self._master, slot_index)
        cipher = AEADChunk(slot_key)
        plaintext = volume_key + struct.pack('>Q', file_table_chunk_id)
        frame = cipher.seal(plaintext)
        assert len(frame) == AEAD_FRAME_SIZE

        pad = os.urandom(SLOT_PAD_SIZE)
        blob = bytes([FLAG_OCCUPIED]) + frame + pad
        assert len(blob) == SLOT_SIZE
        self.container.write_slot(slot_index, blob)

    def update(self, slot_index: int, volume_key: bytes, file_table_chunk_id: int) -> None:
        """Rewrite an occupied slot with a new file_table_chunk_id.

        Used whenever the file table is rewritten to a new chunk (so the
        slot points to the latest copy). Preserves ``volume_key``; the
        caller passes the same key it originally associated.
        """
        self._check_slot_in_domain(slot_index)
        slot = self.container.read_slot(slot_index)
        if slot[0] != FLAG_OCCUPIED:
            raise RuntimeError(f'slot {slot_index} is not occupied, cannot update')

        slot_key = KDF.derive_slot(self._master, slot_index)
        cipher = AEADChunk(slot_key)
        plaintext = volume_key + struct.pack('>Q', file_table_chunk_id)
        frame = cipher.seal(plaintext)

        pad = os.urandom(SLOT_PAD_SIZE)
        blob = bytes([FLAG_OCCUPIED]) + frame + pad
        self.container.write_slot(slot_index, blob)

    def free(self, slot_index: int) -> None:
        self._check_slot_in_domain(slot_index)
        rnd = bytearray(os.urandom(SLOT_SIZE))
        rnd[0] = FLAG_FREE
        self.container.write_slot(slot_index, bytes(rnd))

    def is_occupied(self, slot_index: int) -> bool:
        if not 0 <= slot_index < N_SLOTS:
            raise IndexError(slot_index)
        return self.container.read_slot(slot_index)[0] == FLAG_OCCUPIED

    def _unwrap(self, slot: bytes, slot_index: int) -> tuple[bytes, int] | None:
        frame = slot[1 : 1 + AEAD_FRAME_SIZE]
        slot_key = KDF.derive_slot(self._master, slot_index)
        cipher = AEADChunk(slot_key)
        plaintext = cipher.open(frame)
        if plaintext is None:
            return None
        if len(plaintext) != WRAP_PLAINTEXT_SIZE:
            return None
        volume_key = plaintext[:KEY_SIZE]
        (chunk_id,) = struct.unpack('>Q', plaintext[KEY_SIZE:])
        return volume_key, chunk_id

    def _check_slot_in_domain(self, slot_index: int) -> None:
        if self.is_empty_password:
            if slot_index != 0:
                raise ValueError(f'empty password can only touch slot 0, got {slot_index}')
        else:
            if not 1 <= slot_index < N_SLOTS:
                raise ValueError(f'non-empty password can only touch slots 1..{N_SLOTS - 1}, got {slot_index}')
