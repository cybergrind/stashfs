"""Tests for the ``fyl.optimize`` compaction command.

Every fyl mutation leaks chunks by design (append-only layer); optimize
is the only reclamation path. Tests drive one behaviour at a time using
``KDFParams.fast()`` to stay under the 1 s per-test budget.
"""

from __future__ import annotations

import hashlib

import pytest

from fyl.optimize import OptimizeError, optimize


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestOptimizeReclaimsSpace:
    def test_optimize_is_idempotent(self, multi_fyl, fast_kdf):
        """Running optimize on an already-compacted container reclaims nothing."""
        alpha = multi_fyl.mount('alpha')
        assert alpha.write('/hello', b'world', 0) == 5
        multi_fyl.unmount_all()

        optimize(multi_fyl.path, ['alpha'], kdf=fast_kdf)
        report = optimize(multi_fyl.path, ['alpha'], kdf=fast_kdf)
        assert report.reclaimed == 0

        reopened = multi_fyl.mount('alpha')
        assert reopened.read('/hello', 5, 0) == b'world'

    def test_reclaims_orphans_after_unlink(self, multi_fyl, fast_kdf):
        alpha = multi_fyl.mount('alpha')
        payload = b'x' * (200 * 1024)
        survivor = b'survivor' + b'y' * (200 * 1024 - len(b'survivor'))
        for i in range(5):
            data = survivor if i == 0 else payload
            assert alpha.write(f'/f{i}', data, 0) == len(data)
        for i in range(1, 5):
            assert alpha.unlink(f'/f{i}') == 0

        multi_fyl.unmount_all()
        old_size = multi_fyl.path.stat().st_size
        report = optimize(multi_fyl.path, ['alpha'], kdf=fast_kdf)
        new_size = multi_fyl.path.stat().st_size

        assert report.reclaimed == old_size - new_size
        assert new_size < old_size * 0.5, f'expected major reclaim, got {old_size} -> {new_size}'

        reopened = multi_fyl.mount('alpha')
        assert reopened.volume.list() == ['f0']
        got = reopened.read('/f0', len(survivor), 0)
        assert _sha(got) == _sha(survivor)

    def test_reclaims_after_in_place_overwrite(self, multi_fyl, fast_kdf):
        alpha = multi_fyl.mount('alpha')
        for _ in range(20):
            assert alpha.write('/f', b'A' * 200, 0) == 200
        final = b'Z' * 200
        assert alpha.write('/f', final, 0) == 200
        multi_fyl.unmount_all()

        old = multi_fyl.path.stat().st_size
        report = optimize(multi_fyl.path, ['alpha'], kdf=fast_kdf)
        new = multi_fyl.path.stat().st_size

        assert report.reclaimed > 0
        assert new < old
        reopened = multi_fyl.mount('alpha')
        assert reopened.read('/f', 200, 0) == final


class TestOptimizePreservesCover:
    def test_preserves_cover_bytes_exactly(self, tmp_path, fast_kdf):
        cover = b'\x89PNG\r\n\x1a\n' + b'cover-bytes-' * 80
        path = tmp_path / 'file.png'
        path.write_bytes(cover)

        from fyl import Fyl
        from tests.conftest import FakeArgs

        def mount(pw: str):
            f = Fyl()
            f.add_args(FakeArgs(fname=path), password=pw, kdf=fast_kdf)
            return f

        alpha = mount('alpha')
        assert alpha.write('/payload', b'Z' * 5000, 0) == 5000
        assert alpha.unlink('/payload') == 0
        assert alpha.write('/kept', b'keepme', 0) == 6
        alpha.storage.read_handle.close()
        del alpha
        import gc

        gc.collect()

        optimize(path, ['alpha'], kdf=fast_kdf)

        assert path.read_bytes()[: len(cover)] == cover

        reopened = mount('alpha')
        assert reopened.read('/kept', 6, 0) == b'keepme'


class TestOptimizeMultiVolume:
    def test_rebuild_across_three_passwords(self, multi_fyl, fast_kdf):
        empty = multi_fyl.mount('')
        assert empty.write('/pub', b'public-bytes', 0) == 12

        alpha = multi_fyl.mount('alpha')
        for i in range(4):
            assert alpha.write(f'/a{i}', bytes([i]) * 1000, 0) == 1000
        assert alpha.unlink('/a1') == 0
        assert alpha.rename('/a2', '/a2_renamed') == 0

        beta = multi_fyl.mount('beta')
        assert beta.write('/b', b'beta-bytes' * 1000, 0) == 10_000

        multi_fyl.unmount_all()

        expected = {
            '': {'pub': _sha(b'public-bytes')},
            'alpha': {
                'a0': _sha(bytes([0]) * 1000),
                'a2_renamed': _sha(bytes([2]) * 1000),
                'a3': _sha(bytes([3]) * 1000),
            },
            'beta': {'b': _sha(b'beta-bytes' * 1000)},
        }

        old = multi_fyl.path.stat().st_size
        report = optimize(multi_fyl.path, ['', 'alpha', 'beta'], kdf=fast_kdf)
        new = multi_fyl.path.stat().st_size
        assert report.rebuilt_slots == [0, 1, 2]
        assert new < old

        for pw, want in expected.items():
            ro = multi_fyl.mount(pw)
            assert sorted(ro.volume.list()) == sorted(want), pw
            for name, want_hash in want.items():
                size = ro.volume.size_of(name)
                got = ro.read(f'/{name}', size, 0)
                assert isinstance(got, bytes)
                assert _sha(got) == want_hash, f'{pw!r}:{name}'


class TestOptimizeErrors:
    def test_refuses_locked_slot(self, multi_fyl, fast_kdf):
        alpha = multi_fyl.mount('alpha')
        assert alpha.write('/secret', b'hello', 0) == 5
        multi_fyl.unmount_all()

        before = multi_fyl.path.read_bytes()
        with pytest.raises(OptimizeError):
            optimize(multi_fyl.path, [''], kdf=fast_kdf)
        assert multi_fyl.path.read_bytes() == before

    def test_drop_locked_purges(self, multi_fyl, fast_kdf):
        empty = multi_fyl.mount('')
        assert empty.write('/pub', b'public', 0) == 6
        alpha = multi_fyl.mount('alpha')
        assert alpha.write('/secret', b'alpha-data', 0) == 10
        multi_fyl.unmount_all()

        report = optimize(multi_fyl.path, [''], kdf=fast_kdf, drop_locked=True)
        assert report.dropped_slots == [1]
        assert report.rebuilt_slots == [0]

        empty_ro = multi_fyl.mount('')
        assert empty_ro.read('/pub', 6, 0) == b'public'
        # Slot 1 is free -> mounting "alpha" creates a fresh, empty volume.
        alpha_ro = multi_fyl.mount('alpha')
        assert alpha_ro.volume.list() == []

    def test_refuses_live_mount(self, multi_fyl, fast_kdf, monkeypatch):
        alpha = multi_fyl.mount('alpha')
        assert alpha.write('/f', b'x', 0) == 1
        multi_fyl.unmount_all()

        monkeypatch.setattr('fyl.optimize._looks_like_fuse_mount', lambda *_a, **_k: True)
        before = multi_fyl.path.read_bytes()
        with pytest.raises(OptimizeError):
            optimize(multi_fyl.path, ['alpha'], kdf=fast_kdf)
        assert multi_fyl.path.read_bytes() == before

    def test_atomicity_on_write_error(self, multi_fyl, fast_kdf, monkeypatch):
        alpha = multi_fyl.mount('alpha')
        for i in range(5):
            assert alpha.write(f'/f{i}', b'payload', 0) == 7
        multi_fyl.unmount_all()

        before = multi_fyl.path.read_bytes()

        from fyl import Container

        call_count = {'n': 0}
        original = Container.append_chunk

        def flaky(self, frame):
            call_count['n'] += 1
            if call_count['n'] == 3:
                raise OSError('simulated write error')
            return original(self, frame)

        monkeypatch.setattr(Container, 'append_chunk', flaky)

        with pytest.raises(OSError, match='simulated write error'):
            optimize(multi_fyl.path, ['alpha'], kdf=fast_kdf)

        assert multi_fyl.path.read_bytes() == before
        assert not multi_fyl.path.with_suffix(multi_fyl.path.suffix + '.tmp').exists()
