"""fly package - FUSE-based single-file filesystem.

Public API is re-exported here so callers and tests can continue to do
``from fly import ...``. Implementation is split across submodules to
leave room for the crypto stack.
"""

from fly.container import (
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
from fly.crypto import KDF, KEY_SIZE, NONCE_SIZE, TAG_SIZE, AEADChunk, KDFParams
from fly.file_index import FileIndexCorrupt, VolumeFile
from fly.fuse_app import (
    TIME_PAT,
    Fly,
    MyStat,
    auto_unmount,
    call_fuse_exit,
    log,
    main,
    mount,
    parse_args,
    update_log_level,
)
from fly.legacy_fs import MAGIC_BYTES, FileRecord, FileStructure
from fly.slot_table import FLAG_FREE, FLAG_OCCUPIED, PasswordDoesNotMatch, SlotInfo, SlotTable
from fly.storage import CoverStorage, FileWrapper, Storage
from fly.volume import Volume, VolumeCorrupt


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
    'Fly',
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
