"""End-to-end realistic workload across several passwords.

Drives ``Stash`` through the full set of filesystem operations a real user
touches (create, write, rename/move, userland copy, remove) while three
volumes share one backing file. At least one volume ends up with more
than 50 files, and sizes span from zero bytes up to 200 KB, crossing the
4 KiB chunk boundary in both directions.

The test is seeded (``random.Random(0)``) so failures are reproducible,
and uses the ``KDFParams.fast()`` preset so the whole scenario stays
under the 1 s per-test budget from ``CLAUDE.md``.
"""

from __future__ import annotations

import errno
import hashlib
import random

from stashfs import Stash
from stashfs.container import CHUNK_PAYLOAD_SIZE


SIZES = [
    0,
    1,
    100,
    CHUNK_PAYLOAD_SIZE - 1,
    CHUNK_PAYLOAD_SIZE,
    CHUNK_PAYLOAD_SIZE + 1,
    50 * 1024,
    200 * 1024,
]


def _payload(rng: random.Random, marker: bytes, size: int) -> bytes:
    """Size-accurate payload that always starts with a unique marker.

    The marker lets the leak-check assert specific strings are absent
    from the raw backing file without false positives from otherwise
    pseudo-random bytes.
    """
    if size == 0:
        return b''
    if size <= len(marker):
        return marker[:size]
    return marker + rng.randbytes(size - len(marker))


def _fs_copy(stash: Stash, src: str, dst: str) -> None:
    """Userland ``cp`` over the Stash FUSE surface: read-all + write-all."""
    data = _read_all(stash, src[1:])
    assert stash.mknod(dst, 0o644, 0) == 0
    if data:
        assert stash.write(dst, data, 0) == len(data)


def _read_all(stash: Stash, name: str) -> bytes:
    size = stash.volume.size_of(name)
    if size == 0:
        return b''
    data = stash.read(f'/{name}', size, 0)
    assert isinstance(data, bytes), f'unexpected error reading {name}: {data!r}'
    return data


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestRealisticWorkload:
    def test_full_workload_across_three_passwords(self, multi_stash):
        rng = random.Random(0)

        # Slot claims are lazy: a mount reserves an index but only
        # occupies it on the first write. Populate volumes in order so
        # each one lands on a distinct slot.
        empty = multi_stash.mount('')
        empty_payload = _payload(rng, b'LEAK-CHECK-EMPTY', 1234)
        assert empty.write('/public.bin', empty_payload, 0) == len(empty_payload)
        assert empty.volume.slot_index == 0

        alpha = multi_stash.mount('alpha')

        # --- alpha: populate >50 files with a mix of sizes -----------
        alpha_expected: dict[str, bytes] = {}
        for i in range(60):
            name = f'a{i}'
            size = SIZES[i % len(SIZES)]
            marker = f'LEAK-CHECK-ALPHA-{i:02d}'.encode()
            data = _payload(rng, marker, size)
            assert alpha.mknod(f'/{name}', 0o644, 0) == 0
            if data:
                assert alpha.write(f'/{name}', data, 0) == len(data)
            alpha_expected[name] = data

        assert len(alpha.volume.list()) == 60

        # --- rename (move): a handful of files ----------------------
        for i in (5, 17, 42):
            src, dst = f'/a{i}', f'/a{i}_moved'
            assert alpha.rename(src, dst) == 0
            alpha_expected[f'a{i}_moved'] = alpha_expected.pop(f'a{i}')

        # rename onto an existing destination overwrites
        assert alpha.rename('/a0', '/a1') == 0
        alpha_expected['a1'] = alpha_expected.pop('a0')

        # --- copy (userland cp): both sides must match --------------
        for i in (10, 23, 55):
            src, dst = f'/a{i}', f'/a{i}_copy'
            _fs_copy(alpha, src, dst)
            alpha_expected[f'a{i}_copy'] = alpha_expected[f'a{i}']

        # --- remove a slice -----------------------------------------
        for i in range(30, 38):
            name = f'a{i}'
            assert alpha.unlink(f'/{name}') == 0
            del alpha_expected[name]

        assert alpha.unlink('/does-not-exist') == -errno.ENOENT

        assert sorted(alpha.volume.list()) == sorted(alpha_expected)
        assert len(alpha.volume.list()) > 50
        assert alpha.volume.slot_index == 1

        # --- beta-slot: a couple of files exercised through all ops -
        beta = multi_stash.mount('beta')
        big_beta = _payload(rng, b'LEAK-CHECK-BETA', 200 * 1024)
        small_beta = _payload(rng, b'LEAK-CHECK-BETA-SMALL', 17)

        assert beta.write('/secret.bin', big_beta, 0) == len(big_beta)
        assert beta.write('/tiny', small_beta, 0) == len(small_beta)
        assert beta.rename('/tiny', '/renamed') == 0
        _fs_copy(beta, '/renamed', '/renamed_copy')
        assert beta.unlink('/renamed') == 0
        assert beta.volume.slot_index == 2

        # --- freeze expected state for every vault ------------------
        expected: dict[str, dict[str, str]] = {
            '': {'public.bin': _sha256(empty_payload)},
            'alpha': {name: _sha256(data) for name, data in alpha_expected.items()},
            'beta': {
                'secret.bin': _sha256(big_beta),
                'renamed_copy': _sha256(small_beta),
            },
        }

        # --- unmount every live Stash, then remount each vault fresh and
        # verify listings + checksums from a clean view of the on-disk
        # container.
        multi_stash.unmount_all()
        for pw, want in expected.items():
            remounted = multi_stash.mount(pw)
            assert sorted(remounted.volume.list()) == sorted(want), pw
            for name, want_hash in want.items():
                got = _read_all(remounted, name)
                assert _sha256(got) == want_hash, f'{pw!r}:{name} checksum mismatch'
            # Cross-volume isolation: no other vault's names leak in.
            foreign = {n for other_pw, other in expected.items() if other_pw != pw for n in other}
            assert foreign.isdisjoint(remounted.volume.list()), pw

        # --- plaintext leak check on the raw backing file -----------
        raw = multi_stash.path.read_bytes()
        for needle in (
            b'LEAK-CHECK-ALPHA-00',
            b'LEAK-CHECK-ALPHA-42',
            b'LEAK-CHECK-EMPTY',
            b'LEAK-CHECK-BETA',
            b'public.bin',
            b'secret.bin',
            b'renamed_copy',
            b'a10_copy',
        ):
            assert needle not in raw, f'{needle!r} leaked onto disk'
