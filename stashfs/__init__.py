"""stashfs package - FUSE-based single-file filesystem (formerly ``fly`` / ``fyl``).

Public API is re-exported here so callers and tests can continue to do
``from stashfs import ...``. Implementation is split across submodules to
leave room for the crypto stack.
"""

from stashfs.container import (
    CHUNK_FRAME_SIZE,
    CHUNK_PAYLOAD_SIZE,
    DATA_START,
    HEADER_SIZE,
    N_SLOTS,
    SLOT_SIZE,
    SLOT_TABLE_SIZE,
    Container,
    ContainerCorrupt,
)
from stashfs.crypto import KDF, KEY_SIZE, NONCE_SIZE, TAG_SIZE, AEADChunk, KDFParams
from stashfs.file_index import FileIndexCorrupt, VolumeFile
from stashfs.fuse_app import (
    TIME_PAT,
    MyStat,
    Stash,
    auto_unmount,
    call_fuse_exit,
    log,
    main,
    mount,
    parse_args,
    update_log_level,
)
from stashfs.legacy_fs import MAGIC_BYTES, FileRecord, FileStructure
from stashfs.slot_table import FLAG_FREE, FLAG_OCCUPIED, PasswordDoesNotMatch, SlotInfo, SlotTable
from stashfs.storage import CoverStorage, FileWrapper, Storage
from stashfs.volume import Volume, VolumeCorrupt


__all__ = [
    'CHUNK_FRAME_SIZE',
    'CHUNK_PAYLOAD_SIZE',
    'DATA_START',
    'FLAG_FREE',
    'FLAG_OCCUPIED',
    'HEADER_SIZE',
    'KDF',
    'KEY_SIZE',
    'MAGIC_BYTES',
    'NONCE_SIZE',
    'N_SLOTS',
    'SLOT_SIZE',
    'SLOT_TABLE_SIZE',
    'TAG_SIZE',
    'TIME_PAT',
    'AEADChunk',
    'Container',
    'ContainerCorrupt',
    'CoverStorage',
    'FileIndexCorrupt',
    'FileRecord',
    'FileStructure',
    'FileWrapper',
    'KDFParams',
    'MyStat',
    'PasswordDoesNotMatch',
    'SlotInfo',
    'SlotTable',
    'Stash',
    'Storage',
    'Volume',
    'VolumeCorrupt',
    'VolumeFile',
    'auto_unmount',
    'call_fuse_exit',
    'log',
    'main',
    'mount',
    'parse_args',
    'update_log_level',
]
