#!/usr/bin/env python3
import argparse
import errno
import logging
import multiprocessing
import os
import re
import stat
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from shutil import copyfile

import fuse


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    filename='/tmp/fly.log',
)

log = logging.getLogger('fly')
fuse.fuse_python_api = (0, 2)
TIME_PAT = re.compile(r'.*\/\d+\.\d+')
MAGIC_BYTES = b'0FLYFMT0'
# num files, array[name_length, name]

if not hasattr(fuse, '__version__'):
    raise RuntimeError("your fuse-py doesn't know of fuse.__version__, probably it's too old.")


def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    parser.add_argument('fname', type=lambda x: Path(x).resolve())
    parser.add_argument('mountpoint', nargs='?', default='/tmp/aaa', type=Path)
    parser.add_argument('--ttl', type=int, default=300)
    parser.add_argument('--debug', action='store_true')
    return parser.parse_args()


def update_log_level(level):
    """
    update for all existing loggers
    """
    for name in logging.Logger.manager.loggerDict:
        logging.getLogger(name).setLevel(level)


def call_fuse_exit(mountpoint):
    # start with nohup
    multiprocessing.Process(target=auto_unmount, args=(mountpoint,)).start()


hello_path = '/hello'
hello_str = b'Hello World!\n'


class MyStat(fuse.Stat):
    def __init__(self):
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


class FileWrapper:
    """
    know how to write to the arbitrary parts of the file
    """

    def __init__(self, path: Path):
        self.path = path.resolve()
        if not path.exists():
            path.touch()
        self.reset_handlers()
        self.inner_files = set()

    def read_meta_offset(self):
        """
        check MAGIC_BYTES in the end of file
        <MAGIC_BYTES><QWORD_META_OFFSET><EOF>
        """
        self.read_handle.seek(-len(MAGIC_BYTES) - 8, os.SEEK_END)
        if self.read_handle.read(len(MAGIC_BYTES)) != MAGIC_BYTES:
            return -1
        return struct.unpack('Q', self.read_handle.read(8))[0]

    def reset_handlers(self):
        if hasattr(self, 'read_handle'):
            self.read_handle.close()
        self.read_handle = self.path.open('rb')

    def remove_data(self, offset, size):
        """
        remove data in file and free space
        """
        if offset + size > self.path.stat().st_size:
            raise ValueError('offset + size > file size')
        with tempfile.NamedTemporaryFile() as temp:
            self.read_handle.seek(0, os.SEEK_SET)
            temp.write(self.read_handle.read(offset))
            self.read_handle.seek(offset + size, os.SEEK_SET)
            temp.write(self.read_handle.read())
            temp.seek(0, os.SEEK_SET)
            self.path.write_bytes(temp.read())
            self.read_handle.close()
            self.read_handle = self.path.open('rb')

    def truncate_last(self, size):
        """
        truncate file to size
        """
        size_before = self.path.stat().st_size
        new_size = size_before - size
        with self.path.open('r+b') as f:
            f.truncate(new_size)
        self.reset_handlers()

    def __del__(self):
        self.read_handle.close()

    def write(self, offset, buff):
        log.debug(f'write {offset=} {len(buff)=}')
        # if offset > self.path.stat().st_size:
        #     # increase size
        #     self.path.write_bytes(b'\0' * (offset - self.path.stat().st_size))
        with self.path.open('r+b') as f:
            f.seek(offset, os.SEEK_SET)
            f.write(buff)
        self.reset_handlers()

    def write_end(self, bytes):
        with self.path.open('r+b') as f:
            f.seek(0, os.SEEK_END)
            f.write(bytes)
        self.reset_handlers()

    def read(self, size, offset):
        log.debug(f'read {offset=} {size=}')
        self.read_handle.seek(offset, os.SEEK_SET)
        return self.read_handle.read(size)


@dataclass
class FileRecord:
    name: str
    size: int
    offset: int = 0

    def __iter__(self):
        return iter((self.name, self.size, self.offset))


class FileStructure:
    def __init__(self, structure: bytes, base_offset=0):
        """
        base_offset: offset of metadata itself
        """
        # num_files: int, file_name_length: int, file_name: str, file_size: big int...
        self.base_offset = base_offset
        self.files_list = []
        if structure:
            self._parse(structure)
        self.files_dict = {f.name: f for f in self.files_list}

    def _parse(self, structure):
        log.debug(f'{structure=}')
        (num_files,) = struct.unpack('I', structure[:4])
        structure = structure[4:]
        for _ in range(num_files):
            name_length = struct.unpack('I', structure[:4])[0]
            structure = structure[4:]
            name = structure[:name_length].decode()
            structure = structure[name_length:]
            log.debug(f'{name=} {name_length=} {structure[:8]=}')
            size = struct.unpack('Q', structure[:8])[0]
            structure = structure[8:]
            offset = struct.unpack('Q', structure[:8])[0]
            structure = structure[8:]
            log.debug(f'FileRecord {name=} {size=} {offset=}')
            self.files_list.append(FileRecord(name, size, offset))

    def pack(self):
        res = struct.pack('I', len(self.files_list))
        for name, size, offset in self.files_list:
            encoded_name = name.encode()
            res += struct.pack('I', len(encoded_name))
            res += encoded_name
            res += struct.pack('Q', size)
            res += struct.pack('Q', offset)
        return res

    def add(self, fname, size) -> tuple[FileRecord, int]:
        log.debug(f'{self.base_offset=}')
        if fname in self.files_dict:
            log.debug('return existing record')
            last_file = self.files_list[-1]
            return self.files_dict[fname], last_file.offset + last_file.size

        record = FileRecord(fname, size, 0)
        self.files_list.append(record)
        self.files_dict[fname] = record

        if len(self.files_list) > 1:
            last_file = self.files_list[-2]
            file_offset = last_file.offset + last_file.size
            log.debug(f'{self.base_offset=} {file_offset=}')
        else:
            packed = self.pack()
            file_offset = self.base_offset - 8
            log.debug(f'Add new with: {self.base_offset=} {len(packed)=}')
        record.offset = file_offset
        last_file = self.files_list[-1]
        self.base_offset = last_file.offset + last_file.size + 8
        return record, last_file.offset + last_file.size

    def update_size(self, fname, new_size) -> tuple[FileRecord, int]:
        record = self.files_dict[fname]
        log.debug(f'Update size {fname=} {record.size} => {new_size}')
        record.size = new_size
        last_file = self.files_list[-1]
        self.base_offset = last_file.offset + last_file.size + 8
        return record, last_file.offset + last_file.size

    def remove(self, fname):
        record = self.files_dict[fname]
        self.files_list.remove(record)
        del self.files_dict[fname]


class Fly(fuse.Fuse):
    def add_args(self, args):
        self._ctime = time.time()
        self._args = args
        self.dst = args.fname
        self.mountpoint = args.mountpoint
        self.file_wrapper = FileWrapper(self.dst)
        self.meta_offset = -1
        fs_bytes = b''
        meta_offset = self.file_wrapper.read_meta_offset()
        if meta_offset > 0:
            self.meta_offset = meta_offset
            log.debug(f'{self.meta_offset=}')
            fs_size_packed = self.file_wrapper.read(8, meta_offset)
            assert len(fs_size_packed) == 8, fs_size_packed[:8]
            log.debug(f'{fs_size_packed=}')
            fs_size = struct.unpack('Q', fs_size_packed)[0]
            log.debug(f'{meta_offset=} {fs_size=}')
            fs_bytes = self.file_wrapper.read(fs_size, meta_offset + 8)
        base_offset = (meta_offset if meta_offset > 0 else self.dst.stat().st_size) + len(MAGIC_BYTES) + 8
        log.debug(f'Original file size: {self.dst.stat().st_size} {base_offset=}')
        self.fs_structure = FileStructure(fs_bytes, base_offset)
        log.info(f'Init FS with {len(self.fs_structure.files_list)} files')

    def getattr(self, path):
        # log.debug(f'getattr {path=}')

        if time.time() - self._ctime > self._args.ttl:
            call_fuse_exit(self.mountpoint)
            return -errno.ENOENT

        st = MyStat()
        st.st_ctime = st.st_mtime = st.st_atime = int(time.time())

        if path == '/':
            st.st_mode = stat.S_IFDIR | 0o755
            st.st_nlink = 2
            return st

        path = path[1:]
        if path in self.fs_structure.files_dict:
            st.st_mode = stat.S_IFREG | 0o644
            st.st_nlink = 1
            st.st_size = self.fs_structure.files_dict[path].size
        elif TIME_PAT.match(path):
            st.st_mode = stat.S_IFREG | 0o444
            st.st_nlink = 1
            st.st_size = 0
        else:
            # log.debug(f'File not found: {path}')
            return -errno.ENOENT
        log.debug(f'{st=} {st.st_mode=} {st.st_size=}')
        return st

    def readdir(self, path, offset):
        self._ctime = time.time()
        for f in ['.', '..']:
            yield fuse.Direntry(f)

        for f in self.fs_structure.files_list:
            yield fuse.Direntry(f.name, st_size=f.size)

    def rename(self, old, new):
        self._ctime = time.time()
        log.debug(f'rename {old=} {new=}')
        return -errno.ENOENT

    def create(self, path, flags, mode):
        self._ctime = time.time()
        log.debug(f'create {path=} {flags=}')
        path = path[1:]
        if path in self.fs_structure.files_dict:
            return -errno.EEXIST
        _, self.meta_offset = self.fs_structure.add(path, 0)
        return 0

    def mknod(self, path, mode, dev):
        log.debug(f'Filepath: {path} {mode=} {dev=}')
        path = path[1:]
        if path in self.fs_structure.files_dict:
            return -errno.EEXIST
        self.fs_structure.add(path, 0)
        return 0

    def write(self, path, buf, offset):
        self._ctime = time.time()
        log.debug(f'write {path=} {len(buf)=} {offset=}')
        try:
            path = path[1:]
            if self.meta_offset == -1:
                log.debug('no meta_offset. creating new...')
                self.file_wrapper.write_end(MAGIC_BYTES)
                record, self.meta_offset = self.fs_structure.add(path, len(buf) + offset)
            elif path not in self.fs_structure.files_dict:
                log.debug('has meta offset but new file')
                record, self.meta_offset = self.fs_structure.add(path, len(buf) + offset)
            else:
                log.debug('has meta offset')
                record = self.fs_structure.files_dict[path]
                if record.size < len(buf) + offset:
                    record, self.meta_offset = self.fs_structure.update_size(path, len(buf) + offset)
            log.debug(f'record offset = {record.offset} {record.size} {self.fs_structure.base_offset=}')
            self.file_wrapper.write(record.offset + offset, buf)
            struct_bytes = self.fs_structure.pack()
            self.file_wrapper.write(self.meta_offset, struct.pack('Q', len(struct_bytes)))
            self.file_wrapper.write(self.meta_offset + 8, struct_bytes)

            packed_offset = struct.pack('Q', self.meta_offset)
            end_buffer = MAGIC_BYTES + packed_offset
            self.file_wrapper.write_end(end_buffer)
            return len(buf)
        except Exception:
            log.exception('write')
            return -errno.EIO

    def read(self, path, size, offset):
        self._ctime = time.time()
        log.debug(f'read {path=} {size=} {offset=}')
        path = path[1:]
        if path not in self.fs_structure.files_dict:
            return -errno.ENOENT

        record = self.fs_structure.files_dict[path]
        file_offset = record.offset
        file_len = record.size

        if offset <= file_len:
            if offset + size > file_len:
                size = file_len - offset
            buf = self.file_wrapper.read(size, file_offset + offset)
        else:
            log.info('return empty bytes')
            buf = b''
        return buf

    def unlink(self, path):
        self._ctime = time.time()
        log.debug(f'unlink {path=}')
        try:
            path = path[1:]

            if path not in self.fs_structure.files_dict:
                log.debug(f'UNLINK File not found: {path}')
                return -errno.ENOENT

            # # when last: keep all previous offsets
            # last_file = self.fs_structure.files_list[-1]
            # if last_file.name == last_file:
            #     log.debug('last file. easy mode')
            #     self.fs_structure.files_list.remove(path)
            #     self.meta_offset = last_file.offset + last_file.size
            #     self.file_wrapper.truncate_last(last_file.size)
            #     self.fs_structure.remove(path)
            #     self.file_wrapper.write_end(self.fs_structure.pack())
            #     self.file_wrapper.write_end(MAGIC_BYTES)
            #     self.file_wrapper.write_end(struct.pack('Q', self.meta_offset))
            #     return 0

            # if not last: copy and iteratively calculate new base
            is_first = True
            current_base = 0
            with tempfile.NamedTemporaryFile() as temp:
                read_handle = self.dst.open('rb')

                log.debug(f'Iterate over list: {self.fs_structure.files_list}')

                for file_record in self.fs_structure.files_list:
                    log.debug(f'processing {file_record.name=} {file_record.size=} {file_record.offset=}')
                    if is_first:
                        is_first = False
                        temp.write(read_handle.read(file_record.offset))

                    if file_record.name == path:
                        current_base = -file_record.size
                        continue

                    read_handle.seek(file_record.offset, os.SEEK_SET)
                    temp.write(read_handle.read(file_record.size))

                    file_record.offset += current_base

                self.fs_structure.remove(path)
                new_meta_offset = temp.tell()
                log.debug(f'{new_meta_offset=} {self.dst.name}')
                packed_bytes = self.fs_structure.pack()
                temp.write(struct.pack('Q', len(packed_bytes)))
                temp.write(packed_bytes)
                temp.write(MAGIC_BYTES)
                temp.write(struct.pack('Q', new_meta_offset))
                temp.flush()
                read_handle.close()

                self.file_wrapper.reset_handlers()
                log.debug(f'{temp.name} => {self.dst}')
                log.debug(f'old: {self.dst.stat().st_size} new: {Path(temp.name).stat().st_size} {current_base=}')
                copyfile(temp.name, self.dst)

            return 0
        except Exception:
            log.exception('unlink')
            return -errno.EIO

    def truncate(self, path, size):
        """
        used when you copy over existing file
        """
        self._ctime = time.time()
        self.unlink(path)

    # change permissions
    def chmod(self, path, mode):
        return 0

    # change owner
    def chown(self, path, uid, gid):
        return 0

    def utime(self, path, times):
        self._ctime = time.time()
        log.debug(f'utime {path=} {times=}')
        return 0

    def utimens(self, path, times=None):
        self._ctime = time.time()
        log.debug(f'utimens {path=} {times=}')
        return 0


def auto_unmount(mountpoint):
    """
    wait 10 sec and unmount
    """
    time.sleep(0.01)
    os.system(f'fusermount -u {mountpoint}')


def mount(args):
    f = Fly(
        version='%prog ' + fuse.__version__,
        usage='%(prog)s [options] <mountpoint>',
        dash_s_do='setsingle',
    )
    f.add_args(args)
    f.parser.add_option(mountopt=args.mountpoint, metavar='PATH', default=args.mountpoint)
    f.main(['fly.py', str(args.mountpoint)])


def main():
    args = parse_args()
    if args.debug:
        update_log_level(logging.DEBUG)
    else:
        update_log_level(logging.INFO)

    if not args.fname.exists():
        log.error('File %s does not exist', args.fname)
        exit(1)
    mount(args)


if __name__ == '__main__':
    main()
