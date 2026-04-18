"""End-to-end tests for the ``Stash`` FUSE class.

Also covers the legacy ``FileWrapper`` / ``FileStructure`` classes which
continue to live in the package for historical callers.
"""

from __future__ import annotations

import errno

import pytest

from stashfs import KDF, FileRecord, FileStructure, FileWrapper, KDFParams, Stash
from stashfs.fuse_app import _ensure_mountpoint, _looks_like_fuse_mount, _unmount_stale
from stashfs.volume import Volume
from tests.conftest import FakeArgs


class TestFileWrapper:
    def test_write(self, tmp_path):
        temp_file = tmp_path / 'test_write'
        fw = FileWrapper(temp_file)
        fw.write(10, b'hello')
        assert temp_file.read_bytes() == b'\0' * 10 + b'hello'

    def test_remove_data(self, tmp_path):
        temp_file = tmp_path / 'test_remove_data'
        temp_file.write_bytes(b'\0hello\0')
        fw = FileWrapper(temp_file)
        fw.remove_data(1, 3)
        assert temp_file.read_bytes() == b'\0lo\0'

    def test_size_reports_backing_length(self, tmp_path):
        temp_file = tmp_path / 't'
        temp_file.write_bytes(b'hello')
        assert FileWrapper(temp_file).size() == 5

    def test_truncate_shrinks(self, tmp_path):
        temp_file = tmp_path / 't'
        temp_file.write_bytes(b'hello world')
        fw = FileWrapper(temp_file)
        fw.truncate(5)
        assert temp_file.read_bytes() == b'hello'


class TestFileStructure:
    def test_empty(self):
        fs = FileStructure(b'')
        assert fs.files_list == []

    def test_some_files(self):
        fs = FileStructure(b'')
        fr = FileRecord('test_name', 99999, 0)
        fs.files_list.append(fr)
        assert fs.pack() == (
            b'\x01\x00\x00\x00\x09\x00\x00\x00test_name\x9f\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_more_files(self):
        fs = FileStructure(b'')
        fr1 = FileRecord('test_name', 99999, 0)
        fr2 = FileRecord('test_name2', 88888, 0)
        fs.files_list.extend([fr1, fr2])
        assert fs.pack() == (
            b'\x02\x00\x00\x00\x09\x00\x00\x00test_name'
            b'\x9f\x86\x01\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x0a\x00\x00\x00test_name2'
            b'\x38\x5b\x01\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        )


class TestBasicFly:
    """Behavioural end-to-end tests for the Stash FUSE class."""

    def test_add_one_file(self, make_stash, password):
        stash, _path, _reopen = make_stash(pw=password)
        stash.write('/new_file', b'new_file', 0)
        stash.write('/new_file', b'12345678', 8)
        assert stash.read('/new_file', 16, 0) == b'new_file12345678'
        assert stash.volume.size_of('new_file') == 16

    def test_add_two_files(self, make_stash, password):
        stash, _path, reopen = make_stash(pw=password)
        stash.write('/new_file', b'new_file', 0)
        stash.write('/new_file', b'12345678', 8)

        stash.write('/new_file2', b'new_file2', 0)
        stash.write('/new_file2', b'87654321', 8)

        assert stash.read('/new_file', 8, 0) == b'new_file'
        assert stash.read('/new_file2', 16, 0) == b'new_file87654321'
        assert sorted(stash.volume.list()) == ['new_file', 'new_file2']

        fly2 = reopen()
        assert fly2.read('/new_file', 8, 0) == b'new_file'
        assert fly2.read('/new_file2', 16, 0) == b'new_file87654321'

    def test_remove_file(self, make_stash, password):
        stash, _path, reopen = make_stash(pw=password)
        stash.write('/new_file', b'new_file', 0)
        stash.write('/new_file', b'12345678', 8)
        stash.write('/new_file2', b'new_file2', 0)
        stash.write('/new_file2', b'87654321', 8)

        assert stash.unlink('/new_file') == 0
        assert not stash.volume.exists('new_file')
        assert stash.read('/new_file2', 16, 0) == b'new_file87654321'

        fly2 = reopen()
        assert fly2.unlink('/new_file2') == 0
        assert fly2.volume.list() == []

        fly2.write('/new_file', b'new_file', 0)
        fly2.write('/new_file', b'12345678', 8)
        assert fly2.read('/new_file', 16, 0) == b'new_file12345678'

    def test_multi_volume_on_single_backing_file(self, backing_file, fast_kdf):
        """Full FUSE-level cycle through several passwords on one backing file."""
        path = backing_file()
        args = FakeArgs(fname=path)

        def mount(pw: str) -> Stash:
            f = Stash()
            f.add_args(args, password=pw, kdf=fast_kdf)
            return f

        # Empty password -> slot 0.
        fly_empty = mount('')
        fly_empty.write('/public.txt', b'no-password-needed', 0)
        assert fly_empty.volume.slot_index == 0

        fly_a = mount('alpha')
        fly_a.write('/a.txt', b'alpha-secret', 0)
        assert fly_a.volume.slot_index == 1

        fly_b = mount('beta')
        fly_b.write('/b.txt', b'beta-secret', 0)
        assert fly_b.volume.slot_index == 2

        # Remounts see only their own volume's files, with data intact.
        assert mount('').read('/public.txt', 100, 0) == b'no-password-needed'
        assert mount('alpha').volume.list() == ['a.txt']
        assert mount('alpha').read('/a.txt', 100, 0) == b'alpha-secret'
        assert mount('beta').volume.list() == ['b.txt']
        assert mount('beta').read('/b.txt', 100, 0) == b'beta-secret'

        # Unknown password while free slots remain -> creates a new volume
        # in the next free slot (slots 1 and 2 are taken, so 3).
        fly_c = mount('gamma')
        assert fly_c.volume.slot_index == 3
        assert fly_c.volume.list() == []
        fly_c.write('/c.txt', b'gamma-secret', 0)
        assert mount('gamma').read('/c.txt', 100, 0) == b'gamma-secret'

        # None of the plaintext leaks onto the raw backing file.
        raw = path.read_bytes()
        for needle in (
            b'no-password-needed',
            b'alpha-secret',
            b'beta-secret',
            b'gamma-secret',
            b'public.txt',
            b'a.txt',
            b'b.txt',
            b'c.txt',
        ):
            assert needle not in raw, f'{needle!r} leaked onto disk'

    def test_read_missing_returns_enoent(self, stash):
        assert stash.read('/nope', 10, 0) == -errno.ENOENT


class TestCoverFile:
    """Mounting onto a pre-existing file ("cover") must just work.

    The existing bytes stay untouched at the front of the file, the
    encrypted container lives after them, and the same file can be
    remounted later to recover everything.
    """

    def _cover_bytes(self) -> bytes:
        # Anything that is *not* the shape of a fresh stash container.
        return b'\x89PNG\r\n\x1a\n' + b'cover-bytes-' * 50

    def test_mount_on_existing_cover_file(self, tmp_path, fast_kdf):
        path = tmp_path / 'cover.png'
        cover = self._cover_bytes()
        path.write_bytes(cover)

        stash = Stash()
        stash.add_args(FakeArgs(fname=path), password='', kdf=fast_kdf)
        stash.write('/hidden.txt', b'only-inside-the-container', 0)

        on_disk = path.read_bytes()
        assert on_disk[: len(cover)] == cover, 'cover bytes were not preserved'

        fly2 = Stash()
        fly2.add_args(FakeArgs(fname=path), password='', kdf=fast_kdf)
        assert fly2.read('/hidden.txt', 100, 0) == b'only-inside-the-container'

    def test_cover_preserved_across_password_rotation(self, tmp_path, fast_kdf):
        path = tmp_path / 'cover.png'
        cover = self._cover_bytes()
        path.write_bytes(cover)

        def mount(pw: str) -> Stash:
            f = Stash()
            f.add_args(FakeArgs(fname=path), password=pw, kdf=fast_kdf)
            return f

        mount('').write('/a.txt', b'empty-pw-data', 0)
        mount('alpha').write('/b.txt', b'alpha-data', 0)

        assert mount('').read('/a.txt', 100, 0) == b'empty-pw-data'
        assert mount('alpha').read('/b.txt', 100, 0) == b'alpha-data'
        assert path.read_bytes()[: len(cover)] == cover


class TestRename:
    """FUSE-level rename contract (``mv src dst``)."""

    def test_rename_moves_file(self, stash):
        stash.write('/old', b'payload', 0)
        assert stash.rename('/old', '/new') == 0
        assert stash.read('/new', 100, 0) == b'payload'
        assert stash.read('/old', 100, 0) == -errno.ENOENT

    def test_rename_missing_source_returns_enoent(self, stash):
        assert stash.rename('/nope', '/dst') == -errno.ENOENT

    def test_rename_overwrites_existing_destination(self, stash):
        stash.write('/src', b'SRC', 0)
        stash.write('/dst', b'DST-old-content', 0)
        assert stash.rename('/src', '/dst') == 0
        assert stash.read('/dst', 100, 0) == b'SRC'
        assert stash.read('/src', 100, 0) == -errno.ENOENT

    def test_rename_to_self_is_noop(self, stash):
        stash.write('/same', b'x', 0)
        assert stash.rename('/same', '/same') == 0
        assert stash.read('/same', 1, 0) == b'x'


class TestFlyContract:
    """Behavioral tests that lock in the contract of touched Stash methods."""

    def test_write_swallows_plain_exception_as_eio(self, stash, monkeypatch):
        def boom(*_args, **_kwargs):
            raise RuntimeError('simulated IO failure')

        monkeypatch.setattr(stash.volume, 'write_file', boom)
        assert stash.write('/new_file', b'payload', 0) == -errno.EIO

    def test_write_propagates_keyboard_interrupt(self, stash, monkeypatch):
        def boom(*_args, **_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(stash.volume, 'write_file', boom)
        with pytest.raises(KeyboardInterrupt):
            stash.write('/new_file', b'payload', 0)

    def test_unlink_swallows_plain_exception_as_eio(self, stash, monkeypatch):
        stash.write('/victim', b'data', 0)

        def boom(*_args, **_kwargs):
            raise RuntimeError('simulated IO failure')

        monkeypatch.setattr(stash.volume, 'unlink', boom)
        assert stash.unlink('/victim') == -errno.EIO

    def test_unlink_propagates_keyboard_interrupt(self, stash, monkeypatch):
        stash.write('/victim', b'data', 0)

        def boom(*_args, **_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(stash.volume, 'unlink', boom)
        with pytest.raises(KeyboardInterrupt):
            stash.unlink('/victim')

    def test_unlink_missing_returns_enoent(self, stash):
        assert stash.unlink('/nope') == -errno.ENOENT

    def test_truncate_missing_returns_enoent(self, stash):
        assert stash.truncate('/nope', 0) == -errno.ENOENT


class TestFlyFixtures:
    """Smoke tests that confirm the shared fixtures wire things correctly."""

    def test_make_stash_persists_across_reopen(self, make_stash, password):
        stash, _path, reopen = make_stash(pw=password)
        stash.write('/persisted', b'abcdefgh', 0)

        fly2 = reopen()
        assert fly2.read('/persisted', 8, 0) == b'abcdefgh'

    def test_file_wrapper_fixture_is_usable(self, file_wrapper):
        file_wrapper.write(2, b'xy')
        assert file_wrapper.path.read_bytes()[2:4] == b'xy'

    def test_fly_volume_is_reachable(self, stash):
        assert isinstance(stash.volume, Volume)
        assert isinstance(stash.kdf, KDF)
        assert stash.kdf.params == KDFParams.fast()


class TestTouchSemantics:
    """``touch /mnt/foo`` does mknod(O_CREAT) + utimensat on the new path.

    fuse-python 1.0.8 dispatches utimensat as ``utimens(path, ts_acc, ts_mod)``
    - three positional args after self - so our handler must accept that
    shape and return 0 (we don't currently persist times per file, but
    the op must not crash).
    """

    def test_utimens_accepts_two_timespecs(self, stash):
        stash.write('/existing', b'x', 0)
        # Sentinels stand in for fuse.Timespec - we ignore the values.
        assert stash.utimens('/existing', object(), object()) == 0

    def test_utimens_on_missing_returns_enoent(self, stash):
        assert stash.utimens('/nope', object(), object()) == -errno.ENOENT

    def test_utimens_on_root_is_noop(self, stash):
        assert stash.utimens('/', object(), object()) == 0

    def test_touch_like_sequence_succeeds(self, stash):
        # mknod (like open O_CREAT) then utimensat.
        assert stash.mknod('/fresh', 0o644, 0) == 0
        assert stash.utimens('/fresh', object(), object()) == 0
        assert stash.getattr('/fresh').st_size == 0


class TestEnsureMountpoint:
    """``main()`` shouldn't force users to ``mkdir /tmp/aaa`` first."""

    def test_creates_missing_mountpoint(self, tmp_path):
        target = tmp_path / 'does-not-exist-yet'
        assert not target.exists()
        _ensure_mountpoint(target)
        assert target.is_dir()

    def test_creates_missing_parents(self, tmp_path):
        target = tmp_path / 'a' / 'b' / 'c'
        _ensure_mountpoint(target)
        assert target.is_dir()

    def test_idempotent_when_already_exists(self, tmp_path):
        target = tmp_path / 'already'
        target.mkdir()
        (target / 'sentinel').write_text('keep me')
        _ensure_mountpoint(target)
        assert (target / 'sentinel').read_text() == 'keep me'

    def test_rejects_existing_file_at_path(self, tmp_path):
        target = tmp_path / 'not-a-dir'
        target.write_text('i am a file')
        with pytest.raises(NotADirectoryError):
            _ensure_mountpoint(target)


class TestLooksLikeFuseMount:
    """Detect stale FUSE mounts by reading /proc/mounts.

    We avoid stat-ing the mountpoint itself because a stale FUSE mount
    whose daemon died can make stat hang or error out.
    """

    def _make_mounts(self, tmp_path, lines):
        mounts = tmp_path / 'mounts'
        mounts.write_text(''.join(line + '\n' for line in lines))
        return mounts

    def test_returns_true_for_fuse_mount(self, tmp_path):
        mp = tmp_path / 'mnt'
        mp.mkdir()
        mounts = self._make_mounts(
            tmp_path,
            [f'stashfs.py {mp} fuse.stash.py rw,nosuid,nodev 0 0'],
        )
        assert _looks_like_fuse_mount(mp, mounts_path=str(mounts)) is True

    def test_returns_false_for_regular_directory(self, tmp_path):
        mp = tmp_path / 'mnt'
        mp.mkdir()
        mounts = self._make_mounts(
            tmp_path,
            ['/dev/sda1 / ext4 rw 0 0'],
        )
        assert _looks_like_fuse_mount(mp, mounts_path=str(mounts)) is False

    def test_returns_false_for_non_fuse_mount_at_same_path(self, tmp_path):
        mp = tmp_path / 'mnt'
        mp.mkdir()
        mounts = self._make_mounts(
            tmp_path,
            [f'tmpfs {mp} tmpfs rw 0 0'],
        )
        assert _looks_like_fuse_mount(mp, mounts_path=str(mounts)) is False

    def test_returns_false_when_mounts_missing(self, tmp_path):
        mp = tmp_path / 'mnt'
        mp.mkdir()
        assert _looks_like_fuse_mount(mp, mounts_path=str(tmp_path / 'nope')) is False


class TestUnmountStale:
    """``_unmount_stale`` should transparently clean up a leftover FUSE
    mount so the user doesn't have to run ``fusermount -u`` by hand
    after every crash.
    """

    def test_no_op_when_path_is_not_a_mount(self, tmp_path, monkeypatch):
        calls = []

        def fake_runner(argv, **kw):
            calls.append(argv)

            class R:
                returncode = 0

            return R()

        monkeypatch.setattr('stashfs.fuse_app._looks_like_fuse_mount', lambda *_a, **_k: False)
        _unmount_stale(tmp_path / 'mnt', runner=fake_runner)
        assert calls == []

    def test_runs_fusermount_when_mounted(self, tmp_path, monkeypatch):
        mp = tmp_path / 'mnt'
        mp.mkdir()

        calls = []

        def fake_runner(argv, **kw):
            calls.append(argv)

            class R:
                returncode = 0

            return R()

        monkeypatch.setattr('stashfs.fuse_app._looks_like_fuse_mount', lambda *_a, **_k: True)
        _unmount_stale(mp, runner=fake_runner)
        assert calls == [['fusermount', '-u', str(mp)]]

    def test_swallows_runner_failure(self, tmp_path, monkeypatch):
        def fake_runner(argv, **kw):
            raise FileNotFoundError('fusermount not installed')

        monkeypatch.setattr('stashfs.fuse_app._looks_like_fuse_mount', lambda *_a, **_k: True)
        # Must not raise - we prefer to surface the original FUSE error
        # downstream rather than a cleanup failure.
        _unmount_stale(tmp_path / 'mnt', runner=fake_runner)
