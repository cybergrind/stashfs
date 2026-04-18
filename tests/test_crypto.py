"""Unit tests for ``stashfs.crypto``.

Argon2id parameters are dialled down to the ``fast`` preset so the whole
crypto test module stays well under the 1-second-per-test budget.
"""

from __future__ import annotations

import os

import pytest

from stashfs.crypto import KDF, KEY_SIZE, NONCE_SIZE, TAG_SIZE, AEADChunk, KDFParams


@pytest.fixture
def kdf() -> KDF:
    return KDF(KDFParams.fast())


class TestKDF:
    def test_master_is_deterministic_for_same_password_and_salt(self, kdf):
        salt = b'\x01' * 16
        k1 = kdf.master('hunter2', salt)
        k2 = kdf.master('hunter2', salt)
        assert k1 == k2
        assert len(k1) == KEY_SIZE

    def test_master_differs_on_password_change(self, kdf):
        salt = b'\x01' * 16
        assert kdf.master('alpha', salt) != kdf.master('beta', salt)

    def test_master_differs_on_salt_change(self, kdf):
        assert kdf.master('alpha', b'\x01' * 16) != kdf.master('alpha', b'\x02' * 16)

    def test_master_accepts_empty_password(self, kdf):
        salt = b'\x01' * 16
        k = kdf.master('', salt)
        assert len(k) == KEY_SIZE
        assert kdf.master('', salt) == k

    def test_master_accepts_bytes_and_str_equivalently(self, kdf):
        salt = b'\x01' * 16
        assert kdf.master('alpha', salt) == kdf.master(b'alpha', salt)

    def test_derive_slot_is_deterministic(self):
        master = b'\xaa' * KEY_SIZE
        assert KDF.derive_slot(master, 3) == KDF.derive_slot(master, 3)

    def test_derive_slot_distinct_per_index(self):
        master = b'\xaa' * KEY_SIZE
        keys = [KDF.derive_slot(master, i) for i in range(8)]
        assert len(set(keys)) == 8

    def test_derive_slot_respects_out_len(self):
        master = b'\xaa' * KEY_SIZE
        assert len(KDF.derive_slot(master, 0, out_len=16)) == 16
        assert len(KDF.derive_slot(master, 0, out_len=KEY_SIZE)) == KEY_SIZE


class TestAEADChunk:
    def test_round_trip(self):
        cipher = AEADChunk(b'\x11' * KEY_SIZE)
        frame = cipher.seal(b'payload')
        assert cipher.open(frame) == b'payload'

    def test_frame_has_nonce_plus_tag_overhead(self):
        cipher = AEADChunk(b'\x11' * KEY_SIZE)
        frame = cipher.seal(b'x' * 100)
        assert len(frame) == 100 + NONCE_SIZE + TAG_SIZE
        assert AEADChunk.frame_overhead() == NONCE_SIZE + TAG_SIZE

    def test_fresh_nonce_per_seal(self):
        cipher = AEADChunk(b'\x11' * KEY_SIZE)
        frames = {cipher.seal(b'x')[:NONCE_SIZE] for _ in range(16)}
        assert len(frames) == 16

    def test_wrong_key_returns_none(self):
        sealer = AEADChunk(b'\x11' * KEY_SIZE)
        opener = AEADChunk(b'\x22' * KEY_SIZE)
        frame = sealer.seal(b'payload')
        assert opener.open(frame) is None

    def test_flipped_byte_fails(self):
        cipher = AEADChunk(b'\x11' * KEY_SIZE)
        frame = bytearray(cipher.seal(b'payload'))
        frame[-1] ^= 0x01
        assert cipher.open(bytes(frame)) is None

    def test_flipped_nonce_fails(self):
        cipher = AEADChunk(b'\x11' * KEY_SIZE)
        frame = bytearray(cipher.seal(b'payload'))
        frame[0] ^= 0x01
        assert cipher.open(bytes(frame)) is None

    def test_short_frame_returns_none(self):
        cipher = AEADChunk(b'\x11' * KEY_SIZE)
        assert cipher.open(b'\x00' * 5) is None

    def test_associated_data_bound_to_frame(self):
        cipher = AEADChunk(b'\x11' * KEY_SIZE)
        frame = cipher.seal(b'payload', associated_data=b'context-a')
        assert cipher.open(frame, associated_data=b'context-a') == b'payload'
        assert cipher.open(frame, associated_data=b'context-b') is None
        assert cipher.open(frame) is None

    def test_rejects_wrong_key_length(self):
        with pytest.raises(ValueError, match='key must be'):
            AEADChunk(b'\x11' * 16)
        with pytest.raises(ValueError, match='key must be'):
            AEADChunk(b'')

    def test_round_trip_large_payload(self):
        cipher = AEADChunk(os.urandom(KEY_SIZE))
        plaintext = os.urandom(4096)
        assert cipher.open(cipher.seal(plaintext)) == plaintext
