"""Tests for the ``stashfs.optimize`` compaction command.

Every stashfs mutation leaks chunks by design (append-only layer); optimize
is the only reclamation path. Tests drive one behaviour at a time using
``KDFParams.fast()`` to stay under the 1 s per-test budget.
"""

from __future__ import annotations

import errno
import hashlib

import pytest

from stashfs.optimize import OptimizeError, optimize


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestOptimizeReclaimsSpace:
    def test_optimize_is_idempotent(self, multi_stash, fast_kdf):
        """Running optimize on an already-compacted container reclaims nothing."""
        alpha = multi_stash.mount('alpha')
        assert alpha.write('/hello', b'world', 0) == 5
        multi_stash.unmount_all()

        optimize(multi_stash.path, ['alpha'], kdf=fast_kdf)
        report = optimize(multi_stash.path, ['alpha'], kdf=fast_kdf)
        assert report.reclaimed == 0

        reopened = multi_stash.mount('alpha')
        assert reopened.read('/hello', 5, 0) == b'world'

    def test_reclaims_orphans_after_unlink(self, multi_stash, fast_kdf):
        alpha = multi_stash.mount('alpha')
        payload = b'x' * (200 * 1024)
        survivor = b'survivor' + b'y' * (200 * 1024 - len(b'survivor'))
        for i in range(5):
            data = survivor if i == 0 else payload
            assert alpha.write(f'/f{i}', data, 0) == len(data)
        for i in range(1, 5):
            assert alpha.unlink(f'/f{i}') == 0

        multi_stash.unmount_all()
        old_size = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, ['alpha'], kdf=fast_kdf)
        new_size = multi_stash.path.stat().st_size

        assert report.reclaimed == old_size - new_size
        assert new_size < old_size * 0.5, f'expected major reclaim, got {old_size} -> {new_size}'

        reopened = multi_stash.mount('alpha')
        assert reopened.volume.list() == ['f0']
        got = reopened.read('/f0', len(survivor), 0)
        assert _sha(got) == _sha(survivor)

    def test_reclaims_after_in_place_overwrite(self, multi_stash, fast_kdf):
        alpha = multi_stash.mount('alpha')
        for _ in range(20):
            assert alpha.write('/f', b'A' * 200, 0) == 200
        final = b'Z' * 200
        assert alpha.write('/f', final, 0) == 200
        multi_stash.unmount_all()

        old = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, ['alpha'], kdf=fast_kdf)
        new = multi_stash.path.stat().st_size

        assert report.reclaimed > 0
        assert new < old
        reopened = multi_stash.mount('alpha')
        assert reopened.read('/f', 200, 0) == final


class TestOptimizePreservesCover:
    def test_preserves_cover_bytes_exactly(self, tmp_path, fast_kdf):
        cover = b'\x89PNG\r\n\x1a\n' + b'cover-bytes-' * 80
        path = tmp_path / 'file.png'
        path.write_bytes(cover)

        from stashfs import Stash
        from tests.conftest import FakeArgs

        def mount(pw: str):
            f = Stash()
            f.add_args(FakeArgs(fname=path), password=pw, kdf=fast_kdf)
            return f

        alpha = mount('alpha')
        assert alpha.write('/payload', b'Z' * 5000, 0) == 5000
        assert alpha.unlink('/payload') == 0
        assert alpha.write('/kept', b'keepme', 0) == 6
        alpha.volume.flush()
        alpha.storage.read_handle.close()
        del alpha
        import gc

        gc.collect()

        optimize(path, ['alpha'], kdf=fast_kdf)

        assert path.read_bytes()[: len(cover)] == cover

        reopened = mount('alpha')
        assert reopened.read('/kept', 6, 0) == b'keepme'


class TestOptimizeMultiVolume:
    def test_rebuild_across_three_passwords(self, multi_stash, fast_kdf):
        empty = multi_stash.mount('')
        assert empty.write('/pub', b'public-bytes', 0) == 12

        alpha = multi_stash.mount('alpha')
        for i in range(4):
            assert alpha.write(f'/a{i}', bytes([i]) * 1000, 0) == 1000
        assert alpha.unlink('/a1') == 0
        assert alpha.rename('/a2', '/a2_renamed') == 0

        beta = multi_stash.mount('beta')
        assert beta.write('/b', b'beta-bytes' * 1000, 0) == 10_000

        multi_stash.unmount_all()

        expected = {
            '': {'pub': _sha(b'public-bytes')},
            'alpha': {
                'a0': _sha(bytes([0]) * 1000),
                'a2_renamed': _sha(bytes([2]) * 1000),
                'a3': _sha(bytes([3]) * 1000),
            },
            'beta': {'b': _sha(b'beta-bytes' * 1000)},
        }

        old = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, ['', 'alpha', 'beta'], kdf=fast_kdf)
        new = multi_stash.path.stat().st_size
        assert report.rebuilt_slots == [0, 1, 2]
        assert new < old

        for pw, want in expected.items():
            ro = multi_stash.mount(pw)
            assert sorted(ro.volume.list()) == sorted(want), pw
            for name, want_hash in want.items():
                size = ro.volume.size_of(name)
                got = ro.read(f'/{name}', size, 0)
                assert isinstance(got, bytes)
                assert _sha(got) == want_hash, f'{pw!r}:{name}'


class TestOptimizePasswordless:
    def test_preserves_locked_slot_without_password(self, multi_stash, fast_kdf):
        """Optimize must never need a password; locked slots pass through."""
        alpha = multi_stash.mount('alpha')
        assert alpha.write('/secret', b'hello', 0) == 5
        multi_stash.unmount_all()

        # No passwords supplied and not drop_locked: optimize succeeds
        # without touching slot 1's wrap.
        report = optimize(multi_stash.path, [], kdf=fast_kdf)
        assert report.dropped_slots == []
        assert report.rebuilt_slots == [1]

        # Remount under 'alpha' and the file still reads back.
        reopened = multi_stash.mount('alpha')
        assert reopened.read('/secret', 5, 0) == b'hello'

    def test_drop_locked_frees_unreachable_slot(self, multi_stash, fast_kdf):
        empty = multi_stash.mount('')
        assert empty.write('/pub', b'public', 0) == 6
        alpha = multi_stash.mount('alpha')
        assert alpha.write('/secret', b'alpha-data', 0) == 10
        multi_stash.unmount_all()

        # Only the empty-password is supplied; slot 1 (alpha) is locked
        # and drop_locked is on.
        report = optimize(multi_stash.path, [''], kdf=fast_kdf, drop_locked=True)
        assert report.dropped_slots == [1]
        assert 0 in report.rebuilt_slots
        assert 1 not in report.rebuilt_slots

        empty_ro = multi_stash.mount('')
        assert empty_ro.read('/pub', 6, 0) == b'public'
        # Slot 1 is free -> mounting 'alpha' creates a fresh empty volume.
        alpha_ro = multi_stash.mount('alpha')
        assert alpha_ro.volume.list() == []


class TestOptimizeRegressions:
    """User-reported bugs reproduced at the Stash/FUSE level."""

    def test_optimize_refuses_while_backing_file_is_open(self, multi_stash, fast_kdf):
        """Reproduces the user-reported EIO scenario.

        The user ran ``stashfs optimize cover.png`` while the FUSE
        mount was still live. ``_looks_like_fuse_mount`` only checks
        the *mountpoint* path (``/tmp/aaa``), not the backing file,
        so the check passed and optimize rebuilt the file. After the
        atomic rename, the live mount's in-memory allocation still
        referenced chunks at offsets beyond the new file's size;
        subsequent reads saw ``CoverStorage.size()`` shrink and
        returned short reads — AES-GCM then refused to decrypt the
        truncated frames, surfacing as ``EIO`` at every file.

        The fix is an advisory ``flock`` on the backing file: the
        mount holds ``LOCK_SH`` for its entire lifetime; optimize
        requires ``LOCK_EX`` and refuses if anything else is holding
        the file open.
        """
        alpha = multi_stash.mount('alpha')
        assert alpha.mkdir('/stashfs', 0o755) == 0
        assert alpha.mknod('/stashfs/a.py', 0o644, 0) == 0
        assert alpha.write('/stashfs/a.py', b'payload', 0) == 7
        # Do NOT unmount — the mount's FileWrapper still holds the
        # shared lock on the backing file.

        before = multi_stash.path.read_bytes()
        with pytest.raises(OptimizeError, match='in use'):
            optimize(multi_stash.path, [], kdf=fast_kdf)
        assert multi_stash.path.read_bytes() == before

    def test_cp_rename_rmrf_cp_optimize(self, multi_stash, fast_kdf):
        """User variant: cp, rename subtree, rm -rf renamed, cp again, optimize."""
        # Seed slot 0.
        empty = multi_stash.mount('')
        empty_data = b'empty-bytes-' * 2048
        assert empty.mknod('/keep.bin', 0o644, 0) == 0
        assert empty.write('/keep.bin', empty_data, 0) == len(empty_data)

        alpha = multi_stash.mount('alpha')
        files_relative = ['a.py', 'b.py', 'c.py', 'nested/x.py', 'nested/y.py']

        def payload(tag: str, i: int, size: int = 22_000) -> bytes:
            base = f'{tag}-{i}-'.encode()
            return (base * (size // len(base) + 1))[:size]

        def chunked_write(path: str, data: bytes) -> None:
            assert alpha.mknod(path, 0o644, 0) == 0
            for off in range(0, len(data), 4096):
                block = data[off : off + 4096]
                assert alpha.write(path, block, off) == len(block)

        # Round 1: cp -r stashfs /
        assert alpha.mkdir('/stashfs', 0o755) == 0
        assert alpha.mkdir('/stashfs/nested', 0o755) == 0
        for i, rel in enumerate(files_relative):
            chunked_write(f'/stashfs/{rel}', payload('v1', i))

        # mv stashfs backup
        assert alpha.rename('/stashfs', '/backup') == 0

        # rm -rf backup
        for rel in files_relative:
            assert alpha.unlink(f'/backup/{rel}') == 0
        assert alpha.rmdir('/backup/nested') == 0
        assert alpha.rmdir('/backup') == 0

        # Round 2: cp -r stashfs / again (new content)
        assert alpha.mkdir('/stashfs', 0o755) == 0
        assert alpha.mkdir('/stashfs/nested', 0o755) == 0
        final = {}
        for i, rel in enumerate(files_relative):
            data = payload('v2', i)
            chunked_write(f'/stashfs/{rel}', data)
            final[f'stashfs/{rel}'] = data

        multi_stash.unmount_all()
        old_size = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, [], kdf=fast_kdf)
        new_size = multi_stash.path.stat().st_size
        assert set(report.rebuilt_slots) == {0, 1}
        assert new_size < old_size

        empty_ro = multi_stash.mount('')
        assert empty_ro.read('/keep.bin', len(empty_data), 0) == empty_data

        alpha_ro = multi_stash.mount('alpha')
        for name, expected in final.items():
            got = alpha_ro.read(f'/{name}', len(expected), 0)
            assert got == expected, f'content mismatch for {name}'

    def test_mixed_slot_churn_optimize(self, multi_stash, fast_kdf):
        """Both slot 0 (empty) and slot 1 (alpha) touched, mirroring the
        user's ``slots rebuilt=[0, 1]`` optimize report.

        The empty-password volume gets a long-lived file so slot 0 stays
        occupied throughout; slot 1 undergoes the heavy cp/rm churn.
        """
        import hashlib as _hashlib

        # Seed slot 0 with a single long-lived file.
        empty = multi_stash.mount('')
        empty_data = b'public-bytes-' * 4096
        assert empty.mknod('/public.bin', 0o644, 0) == 0
        assert empty.write('/public.bin', empty_data, 0) == len(empty_data)
        empty_hash = _hashlib.sha256(empty_data).hexdigest()

        # Slot 1 churn.
        alpha = multi_stash.mount('alpha')
        top = ['stashfs/a.py', 'stashfs/b.py', 'stashfs/c.py', 'stashfs/d.py']
        nested = ['stashfs/__pycache__/a.pyc', 'stashfs/__pycache__/b.pyc']

        def payload(tag: str, i: int, size: int = 25_000) -> bytes:
            base = f'{tag}-{i}-'.encode()
            return (base * (size // len(base) + 1))[:size]

        def write_chunked(path: str, data: bytes) -> None:
            assert alpha.mknod(path, 0o644, 0) == 0
            for off in range(0, len(data), 4096):
                block = data[off : off + 4096]
                assert alpha.write(path, block, off) == len(block)

        for iteration in range(4):
            assert alpha.mkdir('/stashfs', 0o755) == 0
            assert alpha.mkdir('/stashfs/__pycache__', 0o755) == 0
            content = {n: payload(f'iter{iteration}', i) for i, n in enumerate(top + nested)}
            for name, data in content.items():
                write_chunked(f'/{name}', data)
            if iteration < 3:
                for n in nested:
                    assert alpha.unlink(f'/{n}') == 0
                assert alpha.rmdir('/stashfs/__pycache__') == 0
                for n in top:
                    assert alpha.unlink(f'/{n}') == 0
                assert alpha.rmdir('/stashfs') == 0

        final_content = content

        multi_stash.unmount_all()
        old_size = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, [], kdf=fast_kdf)
        new_size = multi_stash.path.stat().st_size
        assert set(report.rebuilt_slots) == {0, 1}
        assert new_size < old_size

        # Both slots still intact.
        empty_ro = multi_stash.mount('')
        got_empty = empty_ro.read('/public.bin', len(empty_data), 0)
        assert _hashlib.sha256(got_empty).hexdigest() == empty_hash

        alpha_ro = multi_stash.mount('alpha')
        for name, expected in final_content.items():
            got = alpha_ro.read(f'/{name}', len(expected), 0)
            assert got == expected, f'content mismatch for {name}'

    def test_cp_rmrf_multiple_iterations_optimize(self, multi_stash, fast_kdf):
        """Multiple cp/rm iterations like the user's real workflow."""
        alpha = multi_stash.mount('alpha')
        top = ['stashfs/a.py', 'stashfs/b.py', 'stashfs/c.py']
        nested = ['stashfs/__pycache__/a.pyc', 'stashfs/__pycache__/b.pyc']

        def payload(tag: str, i: int, size: int = 18_000) -> bytes:
            base = f'{tag}-{i}-'.encode()
            return (base * (size // len(base) + 1))[:size]

        def write_chunked(path: str, data: bytes) -> None:
            """Simulate cp's chunked writes (default 4 KiB)."""
            assert alpha.mknod(path, 0o644, 0) == 0
            for off in range(0, len(data), 4096):
                block = data[off : off + 4096]
                assert alpha.write(path, block, off) == len(block)

        for iteration in range(3):
            assert alpha.mkdir('/stashfs', 0o755) == 0
            assert alpha.mkdir('/stashfs/__pycache__', 0o755) == 0
            content = {n: payload(f'iter{iteration}', i) for i, n in enumerate(top + nested)}
            for name, data in content.items():
                write_chunked(f'/{name}', data)
            if iteration < 2:
                # Tear down between iterations.
                for n in nested:
                    assert alpha.unlink(f'/{n}') == 0
                assert alpha.rmdir('/stashfs/__pycache__') == 0
                for n in top:
                    assert alpha.unlink(f'/{n}') == 0
                assert alpha.rmdir('/stashfs') == 0

        final_content = content  # last iteration's contents

        multi_stash.unmount_all()
        old_size = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, [], kdf=fast_kdf)
        new_size = multi_stash.path.stat().st_size
        assert report.reclaimed == old_size - new_size

        reopened = multi_stash.mount('alpha')
        for name, expected in final_content.items():
            got = reopened.read(f'/{name}', len(expected), 0)
            assert got == expected, f'content mismatch for {name}'

    def test_cp_rmrf_cp_optimize_keeps_files_readable(self, multi_stash, fast_kdf):
        """User workflow: ``cp -r dir && rm -rf dir && cp -r dir && optimize``.

        After optimize, every file must still read back under its
        password. The reported bug produced ``-EIO`` on every read
        because the re-created files pointed at chunks that had been
        mis-reclaimed.

        The tree mirrors the user's real scenario: nested ``__pycache__``
        subdir, multi-chunk files, a dozen top-level entries.
        """
        alpha = multi_stash.mount('alpha')

        top = [f'stashfs/{n}' for n in ['allocation.py', 'cli.py', 'container.py', 'volume.py']]
        nested = [f'stashfs/__pycache__/{n}' for n in ['allocation.pyc', 'cli.pyc', 'container.pyc']]

        def payload(tag: str, i: int, size: int) -> bytes:
            base = f'{tag}-{i}-'.encode()
            return (base * (size // len(base) + 1))[:size]

        v1 = {name: payload('v1', i, 12_000) for i, name in enumerate(top + nested)}
        v2 = {name: payload('v2', i, 18_000) for i, name in enumerate(top + nested)}

        # --- round 1: mkdir tree + write files ---
        assert alpha.mkdir('/stashfs', 0o755) == 0
        assert alpha.mkdir('/stashfs/__pycache__', 0o755) == 0
        for name, data in v1.items():
            assert alpha.mknod(f'/{name}', 0o644, 0) == 0
            assert alpha.write(f'/{name}', data, 0) == len(data)

        # --- rm -rf (depth-first: inner files, inner dir, outer files, outer dir) ---
        for name in nested:
            assert alpha.unlink(f'/{name}') == 0
        assert alpha.rmdir('/stashfs/__pycache__') == 0
        for name in top:
            assert alpha.unlink(f'/{name}') == 0
        assert alpha.rmdir('/stashfs') == 0

        # --- round 2: recreate tree with new content ---
        assert alpha.mkdir('/stashfs', 0o755) == 0
        assert alpha.mkdir('/stashfs/__pycache__', 0o755) == 0
        for name, data in v2.items():
            assert alpha.mknod(f'/{name}', 0o644, 0) == 0
            assert alpha.write(f'/{name}', data, 0) == len(data)

        # --- unmount, optimize without password, remount ---
        multi_stash.unmount_all()
        old_size = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, [], kdf=fast_kdf)
        new_size = multi_stash.path.stat().st_size
        assert report.reclaimed == old_size - new_size
        assert new_size < old_size

        reopened = multi_stash.mount('alpha')
        for name, expected in v2.items():
            got = reopened.read(f'/{name}', len(expected), 0)
            assert got == expected, f'content mismatch for {name}'


class TestOptimizeWithDirectories:
    """`optimize` must keep shrinking the file when directories churn too."""

    def test_optimize_reclaims_after_dir_churn(self, multi_stash, fast_kdf):
        alpha = multi_stash.mount('alpha')
        # Heavy churn inside directories.
        assert alpha.mkdir('/staging', 0o755) == 0
        assert alpha.mkdir('/staging/tmp', 0o755) == 0
        payload = b'Z' * (200 * 1024)
        for i in range(6):
            path = f'/staging/tmp/f{i}'
            assert alpha.mknod(path, 0o644, 0) == 0
            assert alpha.write(path, payload, 0) == len(payload)
        # Remove all but one.
        for i in range(1, 6):
            assert alpha.unlink(f'/staging/tmp/f{i}') == 0
        # Rename the subtree, then the remaining file.
        assert alpha.rename('/staging', '/archive') == 0
        multi_stash.unmount_all()

        old_size = multi_stash.path.stat().st_size
        report = optimize(multi_stash.path, [], kdf=fast_kdf)
        new_size = multi_stash.path.stat().st_size

        assert report.reclaimed == old_size - new_size
        assert new_size < old_size * 0.4, f'expected major reclaim, got {old_size} -> {new_size}'

        # Everything still reads back; directories are intact.
        reopened = multi_stash.mount('alpha')
        assert reopened.volume.is_dir('archive')
        assert reopened.volume.is_dir('archive/tmp')
        assert reopened.read('/archive/tmp/f0', len(payload), 0) == payload
        # Deleted files truly gone.
        assert reopened.getattr('/archive/tmp/f5') == -errno.ENOENT

    def test_optimize_is_idempotent_after_dir_ops(self, multi_stash, fast_kdf):
        alpha = multi_stash.mount('alpha')
        assert alpha.mkdir('/d', 0o755) == 0
        assert alpha.mknod('/d/file', 0o644, 0) == 0
        assert alpha.write('/d/file', b'payload', 0) == 7
        multi_stash.unmount_all()

        optimize(multi_stash.path, [], kdf=fast_kdf)
        second = optimize(multi_stash.path, [], kdf=fast_kdf)
        assert second.reclaimed == 0

        reopened = multi_stash.mount('alpha')
        assert reopened.read('/d/file', 7, 0) == b'payload'
        assert reopened.volume.is_dir('d')

    def test_empty_dir_survives_optimize(self, multi_stash, fast_kdf):
        """A lone `mkdir` with no files must persist across optimize."""
        alpha = multi_stash.mount('alpha')
        assert alpha.mkdir('/just-a-dir', 0o755) == 0
        multi_stash.unmount_all()

        optimize(multi_stash.path, [], kdf=fast_kdf)

        reopened = multi_stash.mount('alpha')
        assert reopened.volume.is_dir('just-a-dir')
        # And specifically *explicit*, not just implicit (nothing lives under it).
        assert 'just-a-dir' in reopened.volume.list_dirs()

    def test_optimize_preserves_locked_slot_with_dirs(self, multi_stash, fast_kdf):
        """Locked slots that used directories must round-trip after optimize."""
        alpha = multi_stash.mount('alpha')
        assert alpha.mkdir('/secret', 0o755) == 0
        assert alpha.mknod('/secret/file', 0o644, 0) == 0
        assert alpha.write('/secret/file', b'hidden', 0) == 6
        multi_stash.unmount_all()

        # No password supplied; alpha's slot stays locked.
        optimize(multi_stash.path, [], kdf=fast_kdf)

        # Re-mount under the original password; nothing was lost.
        reopened = multi_stash.mount('alpha')
        assert reopened.volume.is_dir('secret')
        assert reopened.read('/secret/file', 6, 0) == b'hidden'


class TestOptimizeErrors:
    def test_refuses_live_mount(self, multi_stash, fast_kdf, monkeypatch):
        alpha = multi_stash.mount('alpha')
        assert alpha.write('/f', b'x', 0) == 1
        multi_stash.unmount_all()

        monkeypatch.setattr('stashfs.optimize._looks_like_fuse_mount', lambda *_a, **_k: True)
        before = multi_stash.path.read_bytes()
        with pytest.raises(OptimizeError):
            optimize(multi_stash.path, ['alpha'], kdf=fast_kdf)
        assert multi_stash.path.read_bytes() == before

    def test_atomicity_on_write_error(self, multi_stash, fast_kdf, monkeypatch):
        alpha = multi_stash.mount('alpha')
        for i in range(5):
            assert alpha.write(f'/f{i}', b'payload', 0) == 7
        multi_stash.unmount_all()

        before = multi_stash.path.read_bytes()

        # Inject a failure mid-rebuild by breaking Allocation.append,
        # which is what optimize now calls for each live chunk it
        # copies into the destination.
        from stashfs.allocation import Allocation

        call_count = {'n': 0}
        original = Allocation.append

        def flaky(self, frame):
            call_count['n'] += 1
            if call_count['n'] == 4:
                raise OSError('simulated write error')
            return original(self, frame)

        monkeypatch.setattr(Allocation, 'append', flaky)

        with pytest.raises(OSError, match='simulated write error'):
            optimize(multi_stash.path, ['alpha'], kdf=fast_kdf)

        assert multi_stash.path.read_bytes() == before
        assert not multi_stash.path.with_suffix(multi_stash.path.suffix + '.tmp').exists()
