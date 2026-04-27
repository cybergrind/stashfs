"""FUSE glue layer backed by the encrypted ``Volume``.

The FUSE operations here are deliberately thin: almost every call
delegates straight to ``Volume`` / ``Container``. Error handling
converts plain Python exceptions into ``-errno.EIO`` while allowing
``KeyboardInterrupt`` (and other ``BaseException``s) to propagate
unharmed.
"""

from __future__ import annotations

import argparse
import errno
import getpass
import logging
import multiprocessing
import os
import re
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import fuse

from stashfs.container import Container
from stashfs.crypto import KDF
from stashfs.slot_table import PasswordDoesNotMatch
from stashfs.storage import CoverStorage, FileWrapper
from stashfs.volume import Volume


log = logging.getLogger('stashfs')
fuse.fuse_python_api = (0, 2)
TIME_PAT = re.compile(r'.*\/\d+\.\d+')

if not hasattr(fuse, '__version__'):
    raise RuntimeError("your fuse-py doesn't know of fuse.__version__, probably it's too old.")


def _configure_logging(debug: bool) -> None:
    """Set up logging only when the app actually runs.

    Doing this at import time would (a) spam /tmp/stashfs.log whenever the
    package is imported by a test or a library user, and (b) leak
    filenames/offsets via ``log.debug`` calls even when ``--debug`` was
    not requested. Gate everything behind an explicit call from
    ``main()``.
    """
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        filename='/tmp/stashfs.log',
    )
    update_log_level(logging.DEBUG if debug else logging.INFO)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    parser.add_argument('fname', type=lambda x: Path(x).resolve())
    parser.add_argument('mountpoint', nargs='?', default='/tmp/aaa', type=Path)
    parser.add_argument('--ttl', type=int, default=300)
    parser.add_argument('--debug', action='store_true')
    return parser.parse_args()


def update_log_level(level: int) -> None:
    """Update the level for every existing logger."""
    for name in logging.Logger.manager.loggerDict:
        logging.getLogger(name).setLevel(level)


def call_fuse_exit(mountpoint: Path) -> None:
    multiprocessing.Process(target=auto_unmount, args=(mountpoint,)).start()


class MyStat(fuse.Stat):
    def __init__(self) -> None:
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0


class Stash(fuse.Fuse):
    def add_args(
        self,
        args,
        password: str = '',
        kdf: KDF | None = None,
    ) -> None:
        self._ctime = time.time()
        self._args = args
        self.dst = args.fname
        self.mountpoint = args.mountpoint
        self.password = password
        self.storage = FileWrapper(self.dst)
        # CoverStorage wraps the raw file so any existing bytes are
        # preserved at the front (steganography-lite cover mode) and
        # fresh mounts get a minimal footer stamp.
        self.cover = CoverStorage.attach(self.storage)
        self.container = Container(self.cover)
        self.kdf = kdf or KDF()
        self.volume = Volume(self.container, self.kdf, password)
        log.info(f'Stash mounted slot {self.volume.slot_index} with {len(self.volume.list())} files')

    def getattr(self, path: str):
        if time.time() - self._ctime > self._args.ttl:
            # Flush any deferred index commit before letting the
            # filesystem unmount, otherwise writes that arrived
            # without a closing ``flush(2)`` (e.g. a process killed
            # mid-copy) would be silently dropped on the way out.
            try:
                self.volume.flush()
            except Exception:
                log.exception('flush before auto-unmount')
            call_fuse_exit(self.mountpoint)
            return -errno.ENOENT

        st = MyStat()
        st.st_ctime = st.st_mtime = st.st_atime = int(time.time())

        if path == '/':
            st.st_mode = stat.S_IFDIR | 0o755
            st.st_nlink = 2
            return st

        name = path[1:]
        if self.volume.exists(name):
            st.st_mode = stat.S_IFREG | 0o644
            st.st_nlink = 1
            st.st_size = self.volume.size_of(name)
        elif self.volume.is_dir(name):
            st.st_mode = stat.S_IFDIR | 0o755
            st.st_nlink = 2
        elif TIME_PAT.match(name):
            st.st_mode = stat.S_IFREG | 0o444
            st.st_nlink = 1
            st.st_size = 0
        else:
            return -errno.ENOENT
        return st

    def readdir(self, path: str, offset: int):
        self._ctime = time.time()
        name = path[1:] if path != '/' else ''
        for f in ['.', '..']:
            yield fuse.Direntry(f)
        for child, kind in self.volume.iter_children(name):
            if kind == 'file':
                full = child if not name else f'{name}/{child}'
                yield fuse.Direntry(child, st_size=self.volume.size_of(full))
            else:
                yield fuse.Direntry(child)

    def mkdir(self, path: str, mode: int) -> int:
        self._ctime = time.time()
        name = path[1:]
        try:
            self.volume.mkdir(name)
            return 0
        except FileExistsError:
            return -errno.EEXIST
        except FileNotFoundError:
            return -errno.ENOENT
        except Exception:
            log.exception('mkdir')
            return -errno.EIO

    def rmdir(self, path: str) -> int:
        self._ctime = time.time()
        name = path[1:]
        try:
            self.volume.rmdir(name)
            return 0
        except KeyError:
            return -errno.ENOENT
        except OSError as exc:
            if exc.errno == errno.ENOTEMPTY:
                return -errno.ENOTEMPTY
            log.exception('rmdir')
            return -errno.EIO
        except Exception:
            log.exception('rmdir')
            return -errno.EIO

    def rename(self, old: str, new: str) -> int:
        self._ctime = time.time()
        old_name = old[1:]
        new_name = new[1:]
        if not self.volume.exists(old_name) and not self.volume.is_dir(old_name):
            return -errno.ENOENT
        try:
            self.volume.rename(old_name, new_name)
            return 0
        except FileNotFoundError:
            return -errno.ENOENT
        except KeyError:
            return -errno.ENOENT
        except Exception:
            log.exception('rename')
            return -errno.EIO

    def create(self, path: str, flags: int, mode: int) -> int:
        self._ctime = time.time()
        name = path[1:]
        if self.volume.exists(name):
            return -errno.EEXIST
        if self.volume.is_dir(name):
            return -errno.EISDIR
        parent = name.rsplit('/', 1)[0] if '/' in name else ''
        if parent and not self.volume.is_dir(parent):
            return -errno.ENOENT
        try:
            self.volume.write_file(name, 0, b'')
        except Exception:
            log.exception('create')
            return -errno.EIO
        return 0

    def mknod(self, path: str, mode: int, dev: int) -> int:
        self._ctime = time.time()
        name = path[1:]
        if self.volume.exists(name):
            return -errno.EEXIST
        if self.volume.is_dir(name):
            return -errno.EISDIR
        parent = name.rsplit('/', 1)[0] if '/' in name else ''
        if parent and not self.volume.is_dir(parent):
            return -errno.ENOENT
        try:
            self.volume.write_file(name, 0, b'')
        except Exception:
            log.exception('mknod')
            return -errno.EIO
        return 0

    def write(self, path: str, buf: bytes, offset: int) -> int:
        self._ctime = time.time()
        name = path[1:]
        if self.volume.is_dir(name):
            return -errno.EISDIR
        try:
            self.volume.write_file(name, offset, buf)
            return len(buf)
        except Exception:
            log.exception('write')
            return -errno.EIO

    def read(self, path: str, size: int, offset: int):
        self._ctime = time.time()
        name = path[1:]
        if not self.volume.exists(name):
            return -errno.ENOENT
        try:
            return self.volume.read_file(name, offset, size)
        except Exception:
            log.exception('read')
            return -errno.EIO

    def unlink(self, path: str) -> int:
        self._ctime = time.time()
        try:
            name = path[1:]
            if self.volume.is_dir(name) and not self.volume.exists(name):
                return -errno.EISDIR
            if not self.volume.exists(name):
                return -errno.ENOENT
            self.volume.unlink(name)
            return 0
        except Exception:
            log.exception('unlink')
            return -errno.EIO

    def truncate(self, path: str, size: int) -> int:
        self._ctime = time.time()
        try:
            name = path[1:]
            if self.volume.is_dir(name) and not self.volume.exists(name):
                return -errno.EISDIR
            if not self.volume.exists(name):
                return -errno.ENOENT
            self.volume.truncate(name, size)
            return 0
        except Exception:
            log.exception('truncate')
            return -errno.EIO

    def flush(self, path: str) -> int:
        """Persist deferred file-index updates on close(2).

        ``Volume.write_file`` only mutates in-memory state and queues
        chunks for mark-dead; the actual file-index rewrite + slot
        wrap commit happen here. ``cp`` (and any other userland
        writer) calls ``close(2)`` at the end of a copy, which the
        kernel forwards to FUSE as ``flush``, so this is the natural
        commit point.
        """
        self._ctime = time.time()
        try:
            self.volume.flush()
            return 0
        except Exception:
            log.exception('flush')
            return -errno.EIO

    def fsync(self, path: str, isfsyncfile: int) -> int:
        self._ctime = time.time()
        try:
            self.volume.flush()
            return 0
        except Exception:
            log.exception('fsync')
            return -errno.EIO

    def release(self, path: str, flags: int) -> int:
        self._ctime = time.time()
        try:
            self.volume.flush()
            return 0
        except Exception:
            log.exception('release')
            return -errno.EIO

    def chmod(self, path: str, mode: int) -> int:
        return 0

    def chown(self, path: str, uid: int, gid: int) -> int:
        return 0

    def utime(self, path: str, times) -> int:
        self._ctime = time.time()
        if path != '/' and not self.volume.exists(path[1:]):
            return -errno.ENOENT
        return 0

    def utimens(self, path: str, ts_acc, ts_mod) -> int:
        """Update access / modification times.

        fuse-python 1.0.8 invokes this as ``utimens(path, ts_acc, ts_mod)``
        where each ts is a ``fuse.Timespec``. We don't persist times per
        file today, so this is effectively a no-op, but accepting the
        correct signature is what lets ``touch`` succeed (otherwise the
        arity mismatch surfaces as ``EINVAL`` to userspace).
        """
        self._ctime = time.time()
        if path != '/' and not self.volume.exists(path[1:]):
            return -errno.ENOENT
        return 0


def auto_unmount(mountpoint: Path) -> None:
    """Wait a beat, then unmount."""
    time.sleep(0.01)
    os.system(f'fusermount -u {mountpoint}')


def mount(args, password: str = '') -> None:
    f = Stash(
        version='%prog ' + fuse.__version__,
        usage='%(prog)s [options] <mountpoint>',
        dash_s_do='setsingle',
    )
    f.add_args(args, password=password)
    f.parser.add_option(mountopt=args.mountpoint, metavar='PATH', default=args.mountpoint)
    f.main(['stashfs.py', str(args.mountpoint)])


def _ensure_mountpoint(mountpoint: Path) -> None:
    """Make sure ``mountpoint`` exists as a directory before FUSE asks for it.

    The default mountpoint is ``/tmp/aaa`` which is almost never there
    on a fresh boot. Creating it automatically (including parents) is a
    lot friendlier than failing with a confusing FUSE error. If the
    path already exists but is a file, we refuse rather than silently
    do the wrong thing.
    """
    if mountpoint.exists():
        if not mountpoint.is_dir():
            raise NotADirectoryError(f'{mountpoint} exists and is not a directory')
        return
    mountpoint.mkdir(parents=True, exist_ok=True)
    log.info('created mountpoint %s', mountpoint)


def _looks_like_fuse_mount(mountpoint: Path, mounts_path: str = '/proc/mounts') -> bool:
    """True iff ``/proc/mounts`` advertises ``mountpoint`` as a FUSE mount.

    We deliberately parse ``/proc/mounts`` rather than calling
    ``os.path.ismount`` or ``stat`` on the path itself: a FUSE daemon
    that died without cleanup leaves the kernel mount in place, and any
    syscall that has to talk to the (gone) daemon will hang or return
    ``ENOTCONN``. Reading ``/proc/mounts`` only touches kernel state so
    it is safe even for a broken mount.
    """
    target = str(mountpoint)
    try:
        with open(mounts_path, encoding='utf-8') as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == target and parts[2].startswith('fuse'):
                    return True
    except OSError:
        pass
    return False


def _unmount_stale(
    mountpoint: Path,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    """Best-effort cleanup of a leftover FUSE mount at ``mountpoint``.

    If a previous run crashed or was killed, the kernel keeps the FUSE
    mount point around and subsequent mounts fail with
    ``mountpoint is not empty``. Detect that case via ``/proc/mounts``
    and run ``fusermount -u`` to free the path before re-mounting.
    Failures in the cleanup are logged and swallowed - we'd rather
    surface the *original* FUSE error downstream than obscure it with a
    misleading cleanup failure.
    """
    if not _looks_like_fuse_mount(mountpoint):
        return
    log.info('mountpoint %s appears to be a stale FUSE mount; unmounting', mountpoint)
    try:
        runner(['fusermount', '-u', str(mountpoint)], check=False, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning('failed to clean up stale mount at %s: %s', mountpoint, exc)


def run_mount(args) -> None:
    """Mount ``args.fname`` at ``args.mountpoint``. Caller handles argv+logging.

    Split out of ``main`` so the unified ``stashfs`` CLI can call the same
    post-parse flow after dispatching from its subparser.

    Password sourcing: if the ``SP`` environment variable is set, its
    value is used verbatim (empty string counted) and the interactive
    prompt is skipped. Otherwise fall back to ``getpass``. Useful for
    automation / mounting from cron where ``getpass`` would hang.
    """
    if not args.fname.exists():
        log.error('File %s does not exist', args.fname)
        raise SystemExit(1)

    _unmount_stale(args.mountpoint)
    _ensure_mountpoint(args.mountpoint)

    # ``SP`` env var skips the interactive prompt (empty string counts
    # as a real password = slot 0). Fall back to getpass when unset.
    env_pw = os.environ.get('SP')
    password = env_pw if env_pw is not None else getpass.getpass('Press enter: ')
    try:
        mount(args, password=password)
    except PasswordDoesNotMatch:
        log.error('password does not match any slot and no free slots remain')
        raise SystemExit(1) from None


def main() -> None:
    args = parse_args()
    _configure_logging(args.debug)
    run_mount(args)


if __name__ == '__main__':
    main()
