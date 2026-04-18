"""fyl package - FUSE-based single-file filesystem (formerly ``fly``).

Public API is re-exported here so callers and tests can continue to do
``from fyl import ...``. Implementation is split across submodules to
leave room for the crypto stack.
"""

from fyl.container import (
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
from fyl.crypto import KDF, KEY_SIZE, NONCE_SIZE, TAG_SIZE, AEADChunk, KDFParams
from fyl.file_index import FileIndexCorrupt, VolumeFile
from fyl.fuse_app import (
    TIME_PAT,
    Fyl,
    MyStat,
    auto_unmount,
    call_fuse_exit,
    log,
    main,
    mount,
    parse_args,
    update_log_level,
)
from fyl.legacy_fs import MAGIC_BYTES, FileRecord, FileStructure
from fyl.slot_table import FLAG_FREE, FLAG_OCCUPIED, PasswordDoesNotMatch, SlotInfo, SlotTable
from fyl.storage import CoverStorage, FileWrapper, Storage
from fyl.volume import Volume, VolumeCorrupt


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
    'Fyl',
    'KDFParams',
    'MyStat',
    'PasswordDoesNotMatch',
    'SlotInfo',
    'SlotTable',
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
