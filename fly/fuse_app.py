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
import time
from pathlib import Path

import fuse

from fly.container import Container
from fly.crypto import KDF
from fly.slot_table import PasswordDoesNotMatch
from fly.storage import CoverStorage, FileWrapper
from fly.volume import Volume


log = logging.getLogger('fly')
fuse.fuse_python_api = (0, 2)
TIME_PAT = re.compile(r'.*\/\d+\.\d+')

if not hasattr(fuse, '__version__'):
    raise RuntimeError("your fuse-py doesn't know of fuse.__version__, probably it's too old.")


def _configure_logging(debug: bool) -> None:
    """Set up logging only when the app actually runs.

    Doing this at import time would (a) spam /tmp/fly.log whenever the
    package is imported by a test or a library user, and (b) leak
    filenames/offsets via ``log.debug`` calls even when ``--debug`` was
    not requested. Gate everything behind an explicit call from
    ``main()``.
    """
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        filename='/tmp/fly.log',
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


class Fly(fuse.Fuse):
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
        log.info(f'Fly mounted slot {self.volume.slot_index} with {len(self.volume.list())} files')

    def getattr(self, path: str):
        if time.time() - self._ctime > self._args.ttl:
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
        elif TIME_PAT.match(name):
            st.st_mode = stat.S_IFREG | 0o444
            st.st_nlink = 1
            st.st_size = 0
        else:
            return -errno.ENOENT
        return st

    def readdir(self, path: str, offset: int):
        self._ctime = time.time()
        for f in ['.', '..']:
            yield fuse.Direntry(f)
        for name in self.volume.list():
            yield fuse.Direntry(name, st_size=self.volume.size_of(name))

    def rename(self, old: str, new: str) -> int:
        self._ctime = time.time()
        log.debug(f'rename {old=} {new=}')
        return -errno.ENOENT

    def create(self, path: str, flags: int, mode: int) -> int:
        self._ctime = time.time()
        name = path[1:]
        if self.volume.exists(name):
            return -errno.EEXIST
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
        try:
            self.volume.write_file(name, 0, b'')
        except Exception:
            log.exception('mknod')
            return -errno.EIO
        return 0

    def write(self, path: str, buf: bytes, offset: int) -> int:
        self._ctime = time.time()
        try:
            name = path[1:]
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
            if not self.volume.exists(name):
                return -errno.ENOENT
            self.volume.truncate(name, size)
            return 0
        except Exception:
            log.exception('truncate')
            return -errno.EIO

    def chmod(self, path: str, mode: int) -> int:
        return 0

    def chown(self, path: str, uid: int, gid: int) -> int:
        return 0

    def utime(self, path: str, times) -> int:
        self._ctime = time.time()
        log.debug(f'utime {path=} {times=}')
        return 0

    def utimens(self, path: str, times=None) -> int:
        self._ctime = time.time()
        log.debug(f'utimens {path=} {times=}')
        return 0


def auto_unmount(mountpoint: Path) -> None:
    """Wait a beat, then unmount."""
    time.sleep(0.01)
    os.system(f'fusermount -u {mountpoint}')


def mount(args, password: str = '') -> None:
    f = Fly(
        version='%prog ' + fuse.__version__,
        usage='%(prog)s [options] <mountpoint>',
        dash_s_do='setsingle',
    )
    f.add_args(args, password=password)
    f.parser.add_option(mountopt=args.mountpoint, metavar='PATH', default=args.mountpoint)
    f.main(['fly.py', str(args.mountpoint)])


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


def main() -> None:
    args = parse_args()
    _configure_logging(args.debug)

    if not args.fname.exists():
        log.error('File %s does not exist', args.fname)
        raise SystemExit(1)

    _ensure_mountpoint(args.mountpoint)

    # Always prompt. An empty string is a real, valid password bound to
    # slot 0 - a convenient "no password" mode.
    password = getpass.getpass('Press enter: ')
    try:
        mount(args, password=password)
    except PasswordDoesNotMatch:
        log.error('password does not match any slot and no free slots remain')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
