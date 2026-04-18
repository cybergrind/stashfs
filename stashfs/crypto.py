"""Crypto primitives for the encrypted container.

Two small, independently testable pieces:

* ``KDF``      -- Argon2id for the slow password -> master key step,
                  HKDF-SHA256 for the fast master -> per-slot key step.
* ``AEADChunk`` -- AES-256-GCM seal/open with nonce + tag framed inline.

We use AES-256-GCM (32-byte keys) throughout. The plan document mentions
"AES-128-GCM" in one bullet but the same bullet also specifies a 32-byte
volume key; AES-256 is the consistent choice and gives us extra margin
for free.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

HKDF_INFO_PREFIX = b'stashfs/slot/'


@dataclass(frozen=True)
class KDFParams:
    """Argon2id cost parameters.

    Production defaults are conservative; tests use the cheaper preset
    via ``KDFParams.fast()`` so the whole suite stays well under its
    per-test time budget.
    """

    time_cost: int = 3
    memory_cost: int = 64 * 1024  # 64 MiB
    parallelism: int = 1

    @classmethod
    def fast(cls) -> KDFParams:
        return cls(time_cost=1, memory_cost=8 * 1024, parallelism=1)


class KDF:
    """Password -> master key -> per-slot key pipeline."""

    def __init__(self, params: KDFParams | None = None) -> None:
        self.params = params or KDFParams()

    def master(self, password: bytes | str, salt: bytes) -> bytes:
        """Argon2id(password, salt) -> ``KEY_SIZE`` bytes.

        The empty password is a valid, stable input; callers upstream use
        it deliberately for the slot-0 "no password" volume.
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=self.params.time_cost,
            memory_cost=self.params.memory_cost,
            parallelism=self.params.parallelism,
            hash_len=KEY_SIZE,
            type=Type.ID,
        )

    @staticmethod
    def derive_slot(master_key: bytes, slot_index: int, out_len: int = KEY_SIZE) -> bytes:
        """HKDF-SHA256 expand master_key into a per-slot key.

        The ``info`` tag binds the key to a slot index so different slots
        never share a derived key even under the same master.
        """
        info = HKDF_INFO_PREFIX + struct.pack('>I', slot_index)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=out_len,
            salt=None,
            info=info,
        )
        return hkdf.derive(master_key)


class AEADChunk:
    """AES-256-GCM seal/open with nonce + tag packed into the frame."""

    NONCE_SIZE = NONCE_SIZE
    TAG_SIZE = TAG_SIZE

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f'key must be {KEY_SIZE} bytes, got {len(key)}')
        self._aead = AESGCM(key)

    def seal(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        """Encrypt ``plaintext``. Return ``nonce || ciphertext || tag``."""
        nonce = os.urandom(NONCE_SIZE)
        ct_and_tag = self._aead.encrypt(nonce, plaintext, associated_data)
        return nonce + ct_and_tag

    def open(self, frame: bytes, associated_data: bytes | None = None) -> bytes | None:
        """Decrypt a sealed frame. Return plaintext or ``None`` on auth failure."""
        if len(frame) < NONCE_SIZE + TAG_SIZE:
            return None
        nonce = frame[:NONCE_SIZE]
        ct_and_tag = frame[NONCE_SIZE:]
        try:
            return self._aead.decrypt(nonce, ct_and_tag, associated_data)
        except InvalidTag:
            return None

    @staticmethod
    def frame_overhead() -> int:
        """Bytes added on top of plaintext length when sealing."""
        return NONCE_SIZE + TAG_SIZE
