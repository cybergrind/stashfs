"""Smoke tests for the unified ``stashfs`` CLI."""

from __future__ import annotations

import types

import pytest

from stashfs.cli import build_parser, main


class TestCLIParser:
    def test_help_lists_subcommands(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['--help'])
        captured = capsys.readouterr()
        assert 'mount' in captured.out
        assert 'optimize' in captured.out

    def test_optimize_invocation(self, multi_stash, fast_kdf, monkeypatch):
        alpha = multi_stash.mount('alpha')
        assert alpha.write('/f', b'hello', 0) == 5
        multi_stash.unmount_all()

        # Use our fast KDF instead of the default production one.
        monkeypatch.setattr('stashfs.cli._build_kdf', lambda _args: fast_kdf)

        rc = main(['optimize', str(multi_stash.path), '--password', 'alpha'])
        assert rc == 0

        reopened = multi_stash.mount('alpha')
        assert reopened.read('/f', 5, 0) == b'hello'


class TestSPEnvPassword:
    """``SP`` env var short-circuits interactive password prompts."""

    def test_mount_uses_sp_env(self, tmp_path, monkeypatch):
        """``run_mount`` must read ``SP`` instead of calling ``getpass``."""
        from stashfs.fuse_app import run_mount

        backing = tmp_path / 'backing'
        backing.touch()
        mountpoint = tmp_path / 'mnt'
        mountpoint.mkdir()

        captured: dict[str, str] = {}

        def fake_mount(args, password=''):
            captured['password'] = password

        def must_not_prompt(_msg=''):
            raise AssertionError('getpass must not be called when SP is set')

        monkeypatch.setenv('SP', 'my-secret')
        monkeypatch.setattr('stashfs.fuse_app.getpass.getpass', must_not_prompt)
        monkeypatch.setattr('stashfs.fuse_app.mount', fake_mount)
        monkeypatch.setattr('stashfs.fuse_app._unmount_stale', lambda *_a, **_k: None)

        args = types.SimpleNamespace(fname=backing, mountpoint=mountpoint)
        run_mount(args)
        assert captured['password'] == 'my-secret'

    def test_mount_falls_back_to_prompt_when_sp_unset(self, tmp_path, monkeypatch):
        """Without ``SP`` the existing ``getpass`` prompt still runs."""
        from stashfs.fuse_app import run_mount

        backing = tmp_path / 'backing'
        backing.touch()
        mountpoint = tmp_path / 'mnt'
        mountpoint.mkdir()

        captured: dict[str, str] = {}
        prompted = {'n': 0}

        def fake_mount(args, password=''):
            captured['password'] = password

        def fake_getpass(_msg=''):
            prompted['n'] += 1
            return 'from-prompt'

        monkeypatch.delenv('SP', raising=False)
        monkeypatch.setattr('stashfs.fuse_app.getpass.getpass', fake_getpass)
        monkeypatch.setattr('stashfs.fuse_app.mount', fake_mount)
        monkeypatch.setattr('stashfs.fuse_app._unmount_stale', lambda *_a, **_k: None)

        args = types.SimpleNamespace(fname=backing, mountpoint=mountpoint)
        run_mount(args)
        assert prompted['n'] == 1
        assert captured['password'] == 'from-prompt'

    def test_optimize_cli_uses_sp_env_with_drop_locked(self, multi_stash, fast_kdf, monkeypatch):
        """``--drop-locked`` with ``SP`` set skips the interactive prompt
        and uses the env value as the password to try against slots."""
        alpha = multi_stash.mount('alpha')
        assert alpha.write('/secret', b'hidden', 0) == 6
        multi_stash.unmount_all()

        def must_not_prompt(_msg=''):
            raise AssertionError('getpass must not be called when SP is set')

        monkeypatch.setenv('SP', 'alpha')
        monkeypatch.setattr('stashfs.cli.getpass.getpass', must_not_prompt)
        monkeypatch.setattr('stashfs.cli._build_kdf', lambda _args: fast_kdf)

        rc = main(['optimize', str(multi_stash.path), '--drop-locked'])
        assert rc == 0

        # Slot was unlockable via SP, so it was preserved (not dropped).
        reopened = multi_stash.mount('alpha')
        assert reopened.read('/secret', 6, 0) == b'hidden'


class TestOptimizeCLIPasswordless:
    """``stashfs optimize <file>`` must not prompt for any password.

    Password-free optimize is the whole point of the allocation-layer
    change; the CLI is the user-visible surface of that promise.
    """

    def test_no_prompt_on_fresh_cover(self, tmp_path, fast_kdf, monkeypatch):
        cover = tmp_path / 'cover.png'
        cover.write_bytes(b'\x89PNG\r\n\x1a\n' + b'cover-bytes-' * 40)

        def must_not_prompt(_msg=''):
            raise AssertionError('getpass must not be called under plain optimize')

        monkeypatch.setattr('stashfs.cli.getpass.getpass', must_not_prompt)
        monkeypatch.setattr('stashfs.cli._build_kdf', lambda _args: fast_kdf)

        rc = main(['optimize', str(cover)])
        assert rc == 0

    def test_no_prompt_on_populated_file(self, multi_stash, fast_kdf, monkeypatch):
        alpha = multi_stash.mount('alpha')
        assert alpha.write('/f', b'hello', 0) == 5
        multi_stash.unmount_all()

        def must_not_prompt(_msg=''):
            raise AssertionError('getpass must not be called under plain optimize')

        monkeypatch.setattr('stashfs.cli.getpass.getpass', must_not_prompt)
        monkeypatch.setattr('stashfs.cli._build_kdf', lambda _args: fast_kdf)

        rc = main(['optimize', str(multi_stash.path)])
        assert rc == 0

        # File still readable under its password.
        reopened = multi_stash.mount('alpha')
        assert reopened.read('/f', 5, 0) == b'hello'


class TestUnmount:
    """`stashfs unmount` (alias `u`) scans /proc/mounts and `fusermount -u`s
    every active stashfs mount."""

    SAMPLE_MOUNTS = (
        'fusectl /sys/fs/fuse/connections fusectl rw 0 0\n'
        'encfs /home/u/.keys fuse.encfs rw 0 0\n'
        'stashfs.py /mnt/one fuse.stashfs.py rw,nosuid 0 0\n'
        'gvfsd-fuse /run/user/1000/gvfs fuse.gvfsd-fuse rw 0 0\n'
        'stashfs.py /mnt/two fuse.stashfs.py rw,nodev 0 0\n'
    )

    def test_iter_stashfs_mounts_filters_to_stashfs(self, tmp_path):
        from pathlib import Path

        from stashfs.fuse_app import iter_stashfs_mounts

        mounts_file = tmp_path / 'mounts'
        mounts_file.write_text(self.SAMPLE_MOUNTS)

        found = iter_stashfs_mounts(str(mounts_file))
        assert found == [Path('/mnt/one'), Path('/mnt/two')]

    def test_iter_stashfs_mounts_missing_file_is_empty(self, tmp_path):
        from stashfs.fuse_app import iter_stashfs_mounts

        assert iter_stashfs_mounts(str(tmp_path / 'nope')) == []

    def test_unmount_runs_fusermount_on_each(self, monkeypatch, capsys):
        from pathlib import Path

        monkeypatch.setattr(
            'stashfs.cli.iter_stashfs_mounts',
            lambda *_a, **_k: [Path('/mnt/one'), Path('/mnt/two')],
        )

        calls: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            return types.SimpleNamespace(returncode=0, stderr='')

        monkeypatch.setattr('stashfs.cli.subprocess.run', fake_run)

        rc = main(['unmount'])
        assert rc == 0
        assert calls == [
            ['fusermount', '-u', '/mnt/one'],
            ['fusermount', '-u', '/mnt/two'],
        ]

    def test_u_alias_dispatches_to_unmount(self, monkeypatch):
        called = {'n': 0}
        monkeypatch.setattr('stashfs.cli._run_unmount', lambda args: called.update(n=called['n'] + 1) or 0)
        rc = main(['u'])
        assert rc == 0
        assert called['n'] == 1

    def test_unmount_no_mounts(self, monkeypatch, capsys):
        monkeypatch.setattr('stashfs.cli.iter_stashfs_mounts', lambda *_a, **_k: [])
        ran = {'n': 0}
        monkeypatch.setattr('stashfs.cli.subprocess.run', lambda *a, **k: ran.update(n=ran['n'] + 1))
        rc = main(['unmount'])
        assert rc == 0
        assert ran['n'] == 0

    def test_unmount_reports_failure(self, monkeypatch):
        from pathlib import Path

        monkeypatch.setattr('stashfs.cli.iter_stashfs_mounts', lambda *_a, **_k: [Path('/mnt/one')])

        def fake_run(cmd, **_kwargs):
            return types.SimpleNamespace(returncode=1, stderr='busy')

        monkeypatch.setattr('stashfs.cli.subprocess.run', fake_run)
        rc = main(['unmount'])
        assert rc == 1


class TestImplicitMount:
    """`stash <existing-file>` should behave like `stash mount <existing-file>`.

    A single path argument that points at an existing file is the
    overwhelmingly common case; making the user type ``mount`` every
    time is friction.
    """

    def test_bare_existing_path_dispatches_to_mount(self, tmp_path, monkeypatch):
        backing = tmp_path / 'backing'
        backing.touch()

        seen: dict[str, object] = {}

        def fake_run_mount(args):
            seen['fname'] = args.fname
            seen['command'] = args.command

        monkeypatch.setattr('stashfs.cli._run_mount', lambda args: fake_run_mount(args) or 0)

        rc = main([str(backing)])
        assert rc == 0
        assert seen['command'] == 'mount'
        assert seen['fname'] == backing.resolve()

    def test_bare_nonexistent_path_still_errors_cleanly(self, tmp_path, capsys):
        missing = tmp_path / 'does-not-exist'
        with pytest.raises(SystemExit):
            main([str(missing)])
        captured = capsys.readouterr()
        # argparse prints the usage/error on stderr when no subcommand matched.
        assert 'mount' in captured.err or 'invalid' in captured.err.lower() or missing.name in captured.err

    def test_explicit_mount_still_works(self, tmp_path, monkeypatch):
        backing = tmp_path / 'backing'
        backing.touch()

        called = {'n': 0}
        monkeypatch.setattr('stashfs.cli._run_mount', lambda args: called.update(n=called['n'] + 1) or 0)

        rc = main(['mount', str(backing)])
        assert rc == 0
        assert called['n'] == 1
