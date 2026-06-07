"""Unified ``stashfs`` command-line entry point.

Exposes two subcommands:

* ``stashfs mount <backing> [mountpoint]`` — mount the FUSE filesystem.
* ``stashfs optimize <backing>`` — rebuild the backing file, reclaiming
  space left behind by deletions, overwrites, and renames.

Installed as a console script via ``[project.scripts]`` so users can
run it as ``stashfs ...`` after ``uv tool install .``.

A bare path to an existing file (``stashfs /path/to/backing``) is treated
as shorthand for ``stashfs mount /path/to/backing`` — mounting is the
overwhelmingly common case and typing ``mount`` every time is friction.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import subprocess
import sys
from pathlib import Path

from stashfs.crypto import KDF
from stashfs.fuse_app import _configure_logging, iter_stashfs_mounts, run_mount


log = logging.getLogger('stashfs.cli')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='stashfs', description='Encrypted single-file FUSE filesystem')
    sub = parser.add_subparsers(dest='command', required=True)

    mount_p = sub.add_parser('mount', help='Mount the filesystem')
    mount_p.add_argument('fname', type=lambda x: Path(x).resolve())
    mount_p.add_argument('mountpoint', nargs='?', default='/tmp/aaa', type=Path)
    mount_p.add_argument('--ttl', type=int, default=300)
    mount_p.add_argument('--debug', action='store_true')

    opt_p = sub.add_parser('optimize', help='Rebuild the backing file to reclaim space')
    opt_p.add_argument('fname', type=lambda x: Path(x).resolve())
    opt_p.add_argument(
        '--password',
        action='append',
        default=[],
        help='Password for an occupied slot (repeatable). Omit to be prompted interactively.',
    )
    opt_p.add_argument(
        '--drop-locked',
        action='store_true',
        help='Dangerous: purge any occupied slot whose password is unknown.',
    )
    opt_p.add_argument('--debug', action='store_true')

    sub.add_parser('unmount', aliases=['u'], help='Unmount every mounted stashfs filesystem')

    return parser


_SUBCOMMANDS = frozenset({'mount', 'optimize', 'unmount', 'u'})


def _inject_implicit_mount(argv: list[str] | None) -> list[str] | None:
    """If the user typed ``stashfs <existing-file>``, prepend ``mount``.

    We only kick in when the first positional argument is neither a
    known subcommand nor a help/option flag, and it points at an
    existing filesystem path. Anything else falls through to argparse
    untouched so error messages stay accurate.
    """
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return argv
    first = argv[0]
    if first in _SUBCOMMANDS or first.startswith('-'):
        return argv
    if Path(first).exists():
        return ['mount', *argv]
    return argv


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_inject_implicit_mount(argv))
    _configure_logging(getattr(args, 'debug', False))

    if args.command == 'mount':
        return _run_mount(args)
    if args.command == 'optimize':
        return _run_optimize(args)
    if args.command in ('unmount', 'u'):
        return _run_unmount(args)
    parser.error(f'unknown command {args.command!r}')
    return 2


def _build_kdf(_args: argparse.Namespace) -> KDF:
    """Seam for tests to inject a faster KDF."""
    return KDF()


def _run_mount(args: argparse.Namespace) -> int:
    run_mount(args)
    return 0


def _run_optimize(args: argparse.Namespace) -> int:
    from stashfs.optimize import OptimizeError, optimize

    if not args.fname.exists():
        print(f'error: {args.fname} does not exist', file=sys.stderr)
        return 1

    passwords = list(args.password)
    # SP env var contributes a password (useful for scripting); it's
    # additive to --password flags so users can supply multiple
    # passwords via a mix of both.
    env_pw = os.environ.get('SP')
    if env_pw is not None and env_pw not in passwords:
        passwords.append(env_pw)
    # Only prompt when --drop-locked is set AND nothing supplied
    # password(s): the user has opted in to a destructive action and
    # must distinguish "truly locked" from "I just forgot to pass
    # --password". Without --drop-locked, optimize is non-destructive
    # and needs no password at all — locked slots pass through
    # untouched.
    if args.drop_locked and not passwords:
        while True:
            pw = getpass.getpass('Password (enter on empty line to finish): ')
            if pw == '' and passwords:
                break
            passwords.append(pw)
            if pw == '':
                break

    try:
        report = optimize(args.fname, passwords, kdf=_build_kdf(args), drop_locked=args.drop_locked)
    except OptimizeError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    print(
        f'optimize: {args.fname} {report.old_size} -> {report.new_size} bytes '
        f'(reclaimed {report.reclaimed}), slots rebuilt={report.rebuilt_slots} '
        f'dropped={report.dropped_slots}'
    )
    return 0


def _run_unmount(_args: argparse.Namespace) -> int:
    mounts = iter_stashfs_mounts()
    if not mounts:
        print('no stashfs filesystems are currently mounted')
        return 0

    failures = 0
    for mountpoint in mounts:
        try:
            result = subprocess.run(
                ['fusermount', '-u', str(mountpoint)],
                check=False,
                timeout=5,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            print(f'error: failed to unmount {mountpoint}: {exc}', file=sys.stderr)
            failures += 1
            continue
        if result.returncode == 0:
            print(f'unmounted {mountpoint}')
        else:
            print(f'error: failed to unmount {mountpoint}: {result.stderr.strip()}', file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
