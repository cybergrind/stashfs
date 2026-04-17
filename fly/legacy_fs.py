"""Legacy byte-offset filesystem layout.

This is the pre-encryption on-disk format kept intact so the existing
tests and ``Fly`` FUSE integration keep working during the migration.
It will be replaced by the chunk-id-based ``FileIndex`` in Phase 5.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass


log = logging.getLogger('fly.legacy_fs')

MAGIC_BYTES = b'0FLYFMT0'


@dataclass
class FileRecord:
    name: str
    size: int
    offset: int = 0

    def __iter__(self):
        return iter((self.name, self.size, self.offset))


class FileStructure:
    def __init__(self, structure: bytes, base_offset: int = 0) -> None:
        """``base_offset`` is the offset at which the metadata itself lives."""
        self.base_offset = base_offset
        self.files_list: list[FileRecord] = []
        if structure:
            self._parse(structure)
        self.files_dict: dict[str, FileRecord] = {f.name: f for f in self.files_list}

    def _parse(self, structure: bytes) -> None:
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

    def pack(self) -> bytes:
        res = struct.pack('I', len(self.files_list))
        for record in self.files_list:
            encoded_name = record.name.encode()
            res += struct.pack('I', len(encoded_name))
            res += encoded_name
            res += struct.pack('Q', record.size)
            res += struct.pack('Q', record.offset)
        return res

    def add(self, fname: str, size: int) -> tuple[FileRecord, int]:
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

    def update_size(self, fname: str, new_size: int) -> tuple[FileRecord, int]:
        record = self.files_dict[fname]
        log.debug(f'Update size {fname=} {record.size} => {new_size}')
        record.size = new_size
        last_file = self.files_list[-1]
        self.base_offset = last_file.offset + last_file.size + 8
        return record, last_file.offset + last_file.size

    def remove(self, fname: str) -> None:
        record = self.files_dict[fname]
        self.files_list.remove(record)
        del self.files_dict[fname]
